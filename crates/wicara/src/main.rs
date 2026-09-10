//! wicara — a terminal messenger where a contact is a public key, not a phone number.

mod identity;
mod store;
mod ui;

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use tokio::sync::{broadcast, mpsc};
use wicara_core::wire::{Frame, read_frame, write_frame};

use crate::{
    store::Store,
    ui::{Ui, UiCommand, UiEvent},
};

/// Bump this whenever the wire format changes incompatibly.
const ALPN: &[u8] = b"wicara/0";
const HISTORY_ON_START: usize = 200;

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
    /// Open the chat UI, and optionally dial a peer.
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
    events: mpsc::UnboundedSender<UiEvent>,
    /// Fanned out to every session; each keeps only the lines addressed to it.
    outbound: broadcast::Sender<([u8; 32], String)>,
}

#[tokio::main]
async fn main() -> Result<()> {
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
            init_logging(&home)?;
            let me = *secret.public().as_bytes();
            let store = Store::open(&home.join("messages.db"), vault, me)?;
            run(secret, store, connect, relay_only, nick).await
        }
    }
}

/// Logs go to a file: anything written to stdout would land on top of the UI.
fn init_logging(home: &Path) -> Result<()> {
    let file = std::fs::File::options()
        .create(true)
        .append(true)
        .open(home.join("wicara.log"))?;
    tracing_subscriber::fmt()
        .with_writer(Mutex::new(file))
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wicara=info,iroh=warn".into()),
        )
        .init();
    Ok(())
}

async fn run(
    secret: iroh::SecretKey,
    store: Store,
    connect: Option<String>,
    relay_only: bool,
    nick: Option<String>,
) -> Result<()> {
    let dial = connect
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
    }
    let ep = builder.bind().await?;

    let (events, event_rx) = mpsc::unbounded_channel();
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let app = App {
        store: Arc::new(Mutex::new(store)),
        nickname: nick.unwrap_or_else(|| ep.id().fmt_short().to_string()),
        events,
        outbound: broadcast::channel(256).0,
    };

    replay_history(&app)?;
    let _ = app.events.send(UiEvent::Status(if relay_only {
        "relay-only: direct paths disabled".into()
    } else {
        "listening".into()
    }));

    tokio::spawn(accept_loop(ep.clone(), app.clone()));

    if let Some(peer) = dial {
        let (ep, app) = (ep.clone(), app.clone());
        tokio::spawn(async move {
            match ep.connect(peer, ALPN).await {
                Ok(conn) => {
                    if let Err(err) = session(conn, app.clone(), true).await {
                        let _ = app.events.send(UiEvent::Status(format!("session ended: {err}")));
                    }
                }
                Err(err) => {
                    let _ = app
                        .events
                        .send(UiEvent::Status(format!("could not reach {peer}: {err}")));
                }
            }
        });
    }

    let outbound = app.outbound.clone();
    tokio::spawn(async move {
        while let Some(cmd) = command_rx.recv().await {
            match cmd {
                UiCommand::Send { peer, body } => {
                    let _ = outbound.send((peer, body));
                }
                UiCommand::Quit => break,
            }
        }
    });

    let ui = Ui::new(ep.id().to_string(), app.nickname.clone(), commands);
    let result = ui::run(ui, event_rx).await;
    ep.close().await;
    result
}

/// Seeds the UI with every known peer and their stored history, so the log is
/// already there before anyone comes online.
fn replay_history(app: &App) -> Result<()> {
    let store = app.store.lock().unwrap();
    for peer in store.peers()? {
        let _ = app.events.send(UiEvent::Known { peer });
        for msg in store.history(&peer, HISTORY_ON_START)? {
            let _ = app.events.send(UiEvent::Message {
                peer,
                id: msg.id,
                body: msg.body,
                outbound: msg.outbound,
            });
        }
    }
    Ok(())
}

async fn accept_loop(ep: Endpoint, app: App) {
    while let Some(incoming) = ep.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(err) = session(conn, app.clone(), false).await {
                        let _ = app.events.send(UiEvent::Status(format!("session ended: {err}")));
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

    let _ = app.events.send(UiEvent::Connected {
        peer,
        nick: them,
        path: describe_path(&conn).1,
    });
    tokio::spawn(watch_path(conn.clone(), app.events.clone(), peer));

    let mut outbound = app.outbound.subscribe();
    let result = loop {
        tokio::select! {
            frame = read_frame(&mut recv) => match frame {
                Err(err) => break Err(err),
                Ok(Some(Frame::Chat { id, body })) => {
                    // A peer may only mint ids under its own key. TLS proves who
                    // it is; this ties the application-level id to that proof.
                    if id.sender != peer {
                        break Err(anyhow::anyhow!("peer minted an id under someone else's key"));
                    }
                    if app.store.lock().unwrap().insert(&peer, id, &body)? {
                        let _ = app.events.send(UiEvent::Message { peer, id, body, outbound: false });
                    }
                }
                Ok(Some(other)) => tracing::debug!(?other, "ignoring unexpected frame"),
                Ok(None) => break Ok(()),
            },
            line = outbound.recv() => {
                let Ok((target, body)) = line else { continue };
                if target != peer {
                    continue;
                }
                let id = {
                    let mut store = app.store.lock().unwrap();
                    let id = store.next_id();
                    store.insert(&peer, id, &body)?;
                    id
                };
                write_frame(&mut send, &Frame::Chat { id, body: body.clone() }).await?;
                let _ = app.events.send(UiEvent::Message { peer, id, body, outbound: true });
            }
        }
    };

    let _ = app.events.send(UiEvent::Disconnected { peer });
    result
}

/// Whether the live path is hole-punched or relayed. Returns the kind on its
/// own too, because rtt jitters on every sample and would spam a change log.
fn describe_path(conn: &Connection) -> (String, String) {
    let paths = conn.paths();
    let Some(p) = paths.iter().find(|p| p.is_selected()) else {
        return ("negotiating".into(), "negotiating".into());
    };
    let kind = if p.is_ip() { "direct" } else { "relayed" };
    // TransportAddr's Debug is `Ip(1.2.3.4:5)` / `Relay(https://…)`; the wrapper
    // is noise once `kind` has already said which it is.
    let addr = format!("{:?}", p.remote_addr());
    let addr = addr
        .split_once('(')
        .map(|(_, rest)| rest.trim_end_matches(')').to_string())
        .unwrap_or(addr);
    (
        format!("{kind} {addr}"),
        format!("{kind} — {addr} ({}ms rtt)", p.rtt().as_millis()),
    )
}

/// A relayed connection usually upgrades to direct within a second or two, and
/// showing that upgrade live is the M0 checkpoint.
///
// ponytail: 1s poll rather than paths_stream, which needs a Stream adapter
// dependency for one line of output.
async fn watch_path(conn: Connection, events: mpsc::UnboundedSender<UiEvent>, peer: [u8; 32]) {
    let mut last = String::new();
    loop {
        let (kind, line) = describe_path(&conn);
        if kind != last {
            if events.send(UiEvent::Path { peer, path: line }).is_err() {
                return;
            }
            last = kind;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
