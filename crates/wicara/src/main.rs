//! wicara — a terminal messenger where a contact is a public key, not a phone number.

mod identity;
mod store;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::broadcast,
};
use wicara_core::wire::{Frame, read_frame, write_frame};

use crate::store::Store;

/// Bump this whenever the wire format changes incompatibly.
const ALPN: &[u8] = b"wicara/0";
const HISTORY_ON_CONNECT: usize = 20;

#[derive(Parser)]
#[command(version, about = "P2P encrypted chat. You are your public key.")]
struct Cli {
    /// Directory holding the identity file and message store.
    #[arg(long, env = "WICARA_HOME", global = true)]
    home: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print your EndpointId — the only thing a peer needs in order to reach you.
    Id,
    /// Bring the endpoint up, and optionally dial a peer.
    Run {
        /// EndpointId to dial, as pasted from the peer's `wicara id`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        connect: Option<String>,
        /// Refuse direct paths, to demo that the relay fallback is real.
        #[arg(long)]
        relay_only: bool,
        /// Display name shown to peers. Local metadata, never your identity.
        #[arg(long)]
        nick: Option<String>,
    },
}

/// Shared across the accept loop, the dialer, and every live session.
#[derive(Clone)]
struct App {
    store: Arc<Mutex<Store>>,
    nickname: String,
    /// Lines typed on stdin. M1 is 1:1, so every session gets every line.
    // ponytail: broadcast to all peers; M2's TUI adds per-peer routing.
    outbound: broadcast::Sender<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wicara=info,iroh=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let home = identity::home(cli.home)?;
    let identity::Identity { secret, vault } = identity::load_or_create(&home)?;

    match cli.cmd {
        Cmd::Id => {
            println!("{}", secret.public());
            Ok(())
        }
        Cmd::Run {
            connect,
            relay_only,
            nick,
        } => {
            let me = *secret.public().as_bytes();
            let store = Store::open(&home.join("messages.db"), vault, me)?;
            run(secret, store, connect, relay_only, nick).await
        }
    }
}

async fn run(
    secret: iroh::SecretKey,
    store: Store,
    connect: Option<String>,
    relay_only: bool,
    nick: Option<String>,
) -> Result<()> {
    let peer = connect
        .map(|s| s.trim().parse::<EndpointId>())
        .transpose()
        .context("that is not a valid EndpointId")?;

    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(secret)
        .alpns(vec![ALPN.to_vec()]);
    if relay_only {
        // Dropping the IP transports is a cleaner demo of the relay fallback
        // than blocking UDP at the firewall, and it needs no root.
        builder = builder.clear_ip_transports();
        println!("relay-only mode: direct paths disabled");
    }
    let ep = builder.bind().await?;

    let app = App {
        store: Arc::new(Mutex::new(store)),
        nickname: nick.unwrap_or_else(|| ep.id().fmt_short().to_string()),
        outbound: broadcast::channel(256).0,
    };

    println!("your endpoint id: {}", ep.id());
    println!("type to chat, /quit to leave");

    tokio::spawn(accept_loop(ep.clone(), app.clone()));

    if let Some(peer) = peer {
        println!("dialing {peer}");
        let conn = ep.connect(peer, ALPN).await?;
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(err) = session(conn, app, true).await {
                eprintln!("session ended: {err:#}");
            }
        });
    }

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line == "/quit" {
            break;
        }
        if line.is_empty() {
            continue;
        }
        if app.outbound.send(line).is_err() {
            println!("— no peers connected, message not sent —");
        }
    }
    ep.close().await;
    Ok(())
}

async fn accept_loop(ep: Endpoint, app: App) {
    while let Some(incoming) = ep.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(err) = session(conn, app, false).await {
                        eprintln!("session ended: {err:#}");
                    }
                }
                Err(err) => tracing::warn!(%err, "incoming connection failed"),
            }
        });
    }
}

/// One live conversation. `dialed` decides who opens the bidirectional stream.
async fn session(conn: Connection, app: App, dialed: bool) -> Result<()> {
    let (mut send, mut recv) = if dialed {
        conn.open_bi().await?
    } else {
        conn.accept_bi().await?
    };
    // TLS 1.3 already authenticated this key, so it is safe to trust as the
    // conversation's identity.
    let peer = *conn.remote_id().as_bytes();

    write_frame(
        &mut send,
        &Frame::Hello {
            nickname: app.nickname.clone(),
        },
    )
    .await?;
    let Some(Frame::Hello { nickname: them }) = read_frame(&mut recv).await? else {
        bail!("peer did not open with a hello");
    };

    println!(
        "— connected to {them} ({}), {} —",
        conn.remote_id().fmt_short(),
        describe_path(&conn).1
    );
    for msg in app.store.lock().unwrap().history(&peer, HISTORY_ON_CONNECT)? {
        let who = if msg.outbound { &app.nickname } else { &them };
        println!("  [{}] {who}: {}", msg.id, msg.body);
    }

    // A relayed connection usually upgrades to direct within a second or two,
    // and showing that upgrade is the M0 checkpoint.
    tokio::spawn({
        let conn = conn.clone();
        async move { watch_path(&conn, Duration::from_secs(10)).await }
    });

    let mut outbound = app.outbound.subscribe();
    loop {
        tokio::select! {
            frame = read_frame(&mut recv) => match frame? {
                Some(Frame::Chat { id, body }) => {
                    // A peer may only mint ids under its own key. TLS proves who
                    // it is; this ties the application-level id to that proof.
                    if id.sender != peer {
                        bail!("peer sent a message minted under someone else's key");
                    }
                    if app.store.lock().unwrap().insert(&peer, id, &body)? {
                        println!("{them}: {body}");
                    }
                }
                Some(other) => tracing::debug!(?other, "ignoring unexpected frame"),
                None => {
                    println!("— {them} disconnected —");
                    return Ok(());
                }
            },
            line = outbound.recv() => {
                let Ok(body) = line else { continue };
                let id = {
                    let mut store = app.store.lock().unwrap();
                    let id = store.next_id();
                    store.insert(&peer, id, &body)?;
                    id
                };
                write_frame(&mut send, &Frame::Chat { id, body }).await?;
            }
        }
    }
}

/// Whether the live path is hole-punched or relayed. Returns the kind on its
/// own too, because rtt jitters on every sample and would spam a change log.
fn describe_path(conn: &Connection) -> (String, String) {
    let paths = conn.paths();
    let Some(p) = paths.iter().find(|p| p.is_selected()) else {
        return ("negotiating".into(), "negotiating".into());
    };
    let kind = if p.is_ip() { "direct" } else { "relayed" };
    let addr = format!("{:?}", p.remote_addr());
    (
        format!("{kind} {addr}"),
        format!("{kind} — {addr} ({}ms rtt)", p.rtt().as_millis()),
    )
}

async fn watch_path(conn: &Connection, window: Duration) {
    let deadline = tokio::time::Instant::now() + window;
    let mut last = String::new();
    while tokio::time::Instant::now() < deadline {
        let (kind, line) = describe_path(conn);
        if kind != last {
            println!("path: {line}");
            last = kind;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}
