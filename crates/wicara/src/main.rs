//! wicara — a terminal messenger where a contact is a public key, not a phone number.

mod identity;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use tokio::io::AsyncReadExt;

/// Bump this whenever the wire format changes incompatibly.
const ALPN: &[u8] = b"wicara/0";

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
    /// Bring the endpoint up, and optionally dial a peer and exchange a hello.
    Run {
        /// EndpointId to dial, as pasted from the peer's `wicara id`.
        #[arg(long, value_name = "ENDPOINT_ID")]
        connect: Option<String>,
        /// Refuse direct paths, to demo that the relay fallback is real.
        #[arg(long)]
        relay_only: bool,
    },
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
    let me = identity::load_or_create(&home)?;

    match cli.cmd {
        Cmd::Id => {
            println!("{}", me.secret.public());
            Ok(())
        }
        Cmd::Run {
            connect,
            relay_only,
        } => run(me, connect, relay_only).await,
    }
}

async fn run(me: identity::Identity, connect: Option<String>, relay_only: bool) -> Result<()> {
    let peer = connect
        .map(|s| s.trim().parse::<EndpointId>())
        .transpose()
        .context("that is not a valid EndpointId")?;

    let mut builder = Endpoint::builder(presets::N0)
        .secret_key(me.secret)
        .alpns(vec![ALPN.to_vec()]);
    if relay_only {
        // Dropping the IP transports is a cleaner demo of the relay fallback
        // than blocking UDP at the firewall, and it needs no root.
        builder = builder.clear_ip_transports();
        println!("relay-only mode: direct paths disabled");
    }
    let ep = builder.bind().await?;

    println!("your endpoint id: {}", ep.id());
    println!("waiting for peers — paste that into their `wicara run --connect`");

    let listener = tokio::spawn(accept_loop(ep.clone()));

    if let Some(peer) = peer {
        println!("dialing {peer}");
        let conn = ep.connect(peer, ALPN).await?;
        let greeting = format!("hello from {}", ep.id());
        let mut stream = conn.open_bi().await?;
        stream.0.write_all(greeting.as_bytes()).await?;
        stream.0.finish()?;
        let reply = read_hello(&mut stream.1).await?;
        println!("peer said: {reply}");
        watch_path(&conn, Duration::from_secs(5)).await;
        conn.close(0u32.into(), b"done");
    }

    listener.await?
}

async fn accept_loop(ep: Endpoint) -> Result<()> {
    while let Some(incoming) = ep.accept().await {
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(err) => {
                tracing::warn!(%err, "incoming connection failed");
                continue;
            }
        };
        let me = ep.id();
        tokio::spawn(async move {
            if let Err(err) = greet(&conn, me).await {
                tracing::warn!(%err, "hello exchange failed");
            }
        });
    }
    Ok(())
}

async fn greet(conn: &Connection, me: EndpointId) -> Result<()> {
    println!("incoming connection from {}", conn.remote_id());
    let (mut send, mut recv) = conn.accept_bi().await?;
    println!("peer said: {}", read_hello(&mut recv).await?);
    send.write_all(format!("hello from {me}").as_bytes()).await?;
    send.finish()?;
    watch_path(conn, Duration::from_secs(5)).await;
    Ok(())
}

/// M0 hello frames are bare UTF-8 and capped; M1 replaces this with
/// length-prefixed postcard.
async fn read_hello(recv: &mut iroh::endpoint::RecvStream) -> Result<String> {
    let mut buf = Vec::new();
    recv.take(256).read_to_end(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Reports whether the live path is hole-punched or relayed, and prints again
/// when it changes — a relayed connection usually upgrades to direct within a
/// second or two, and the checkpoint is showing exactly that.
///
// ponytail: 250ms poll rather than paths_stream, which needs a Stream adapter
// dependency; swap it in if the TUI ever wants live path state.
async fn watch_path(conn: &Connection, window: Duration) {
    let deadline = tokio::time::Instant::now() + window;
    let mut last = String::new();
    while tokio::time::Instant::now() < deadline {
        let (kind, line) = describe_path(conn);
        // Compare the kind, not the line: rtt jitters every sample.
        if kind != last {
            println!("path: {line}");
            last = kind;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

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
