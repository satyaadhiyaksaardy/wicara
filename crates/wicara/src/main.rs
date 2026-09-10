//! wicara — a terminal messenger where a contact is a public key, not a phone number.

mod hub;
mod files;
mod identity;
mod store;
mod ui;

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, presets},
};
use tokio::sync::{broadcast, mpsc};
use wicara_core::{
    e2e::{Envelope, VerifiedPrekey},
    room::{Room, RoomEntry, RoomId, RoomOp, verify_log},
    wire::{Frame, now_ms, read_frame, write_frame},
};
use x25519_dalek::StaticSecret;

use crate::{
    hub::Hub,
    store::Store,
    ui::{Ui, UiCommand, UiEvent},
};

/// Bump this whenever the wire format changes incompatibly.
const ALPN: &[u8] = b"wicara/0";
const HISTORY_ON_START: usize = 200;
/// The hub is polled rather than held open, which is also why there is no
/// keepalive to write: Cloudflare's 100s idle cutoff has nothing to cut.
const DRAIN_EVERY: Duration = Duration::from_secs(30);

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
        /// Hub base URL, for offline delivery. Leave it out and wicara is
        /// exactly what M0-M2 shipped: no servers, at all.
        #[arg(long, value_name = "URL", env = "WICARA_HUB")]
        hub: Option<String>,
    },
}

/// Shared across the accept loop, the dialer, and every live session.
#[derive(Clone)]
struct App {
    me: [u8; 32],
    store: Arc<Mutex<Store>>,
    /// Local metadata, changeable at runtime with `/nick`.
    nickname: Arc<Mutex<String>>,
    events: mpsc::UnboundedSender<UiEvent>,
    /// Fanned out to every session; `None` means every peer, which is what a
    /// nickname change is.
    outbound: broadcast::Sender<(Option<[u8; 32]>, Frame)>,
    /// Absent means no offline delivery, and no server anywhere.
    hub: Option<Arc<Hub>>,
    /// The long-lived X25519 key others seal offline messages to.
    prekey: Arc<StaticSecret>,
    home: Arc<PathBuf>,
    /// Live connections, which is both what decides whether an op goes down the
    /// wire or into the mailbox, and where an attachment finds its stream.
    live: Arc<Mutex<HashMap<[u8; 32], Connection>>>,
    prekeys: Arc<Mutex<HashMap<[u8; 32], VerifiedPrekey>>>,
    /// Rooms as their verified chains say they stand. Nothing here was taken
    /// on the hub's word.
    rooms: Arc<Mutex<HashMap<RoomId, Room>>>,
    identity: ed25519_dalek::SigningKey,
    /// Kept so `/connect` can dial without restarting the process.
    endpoint: Endpoint,
}

impl App {
    fn nickname(&self) -> String {
        self.nickname.lock().unwrap().clone()
    }

    fn status(&self, msg: impl Into<String>) {
        let _ = self.events.send(UiEvent::Status(msg.into()));
    }

    /// Files an incoming op under the right conversation, after checking the
    /// sender was entitled to write there. Returns the conversation when the op
    /// was new — an op that arrived twice, live and by mailbox, lands here
    /// twice and is stored once.
    async fn accept(&self, sender: [u8; 32], frame: Frame) -> Result<Option<[u8; 32]>> {
        if let Frame::RoomUpdated { room } = frame {
            let _ = fetch_room(self, room).await;
            return Ok(None);
        }
        let Some(id) = frame.id() else { return Ok(None) };
        // Whoever carried it, the op must be minted under the key that
        // authenticated: TLS on the live path, the envelope signature on the
        // mailbox path.
        ensure!(
            id.sender == sender,
            "op is minted under a key other than the sender's"
        );

        if let Frame::InRoom { room, .. } = &frame {
            if !self.is_member(room, &sender) {
                // Either the room is new to us or they were kicked. Ask the
                // chain, not the sender.
                fetch_room(self, *room).await?;
                ensure!(
                    self.is_member(room, &sender),
                    "op for a room the chain does not put that sender in"
                );
            }
            ensure!(
                self.is_member(room, &self.me),
                "op for a room this endpoint is not in"
            );
        }

        let conversation = frame.conversation(sender);
        let fresh = self
            .store
            .lock()
            .unwrap()
            .record(&conversation, &frame.unwrap_room())?;
        Ok(fresh.then_some(conversation))
    }

    fn is_member(&self, room: &RoomId, who: &[u8; 32]) -> bool {
        self.rooms
            .lock()
            .unwrap()
            .get(room)
            .is_some_and(|r| r.members.contains(who))
    }

    /// Decrypts one mailbox envelope and files it.
    async fn absorb(&self, envelope: &Envelope) -> Result<Option<[u8; 32]>> {
        let (plaintext, sender) = wicara_core::e2e::open(envelope, &self.prekey, &self.me)?;
        self.accept(sender, postcard::from_bytes(&plaintext)?).await
    }

    /// Refolds the conversation and hands the UI the whole thing. One fold, in
    /// the store, rather than the same rules written twice.
    fn send_log(&self, peer: [u8; 32]) -> Result<()> {
        let entries = self
            .store
            .lock()
            .unwrap()
            .history(&peer, HISTORY_ON_START)?
            .into_iter()
            .map(|m| ui::Entry {
                id: m.id,
                body: m.body,
                outbound: m.outbound,
                deleted: m.deleted,
                reply_to: m.reply_to,
                reactions: m.reactions,
                attachment: m.attachment.map(|a| ui::Attach {
                    name: a.name,
                    size: a.size,
                    hash: a.hash,
                    path: a.path,
                }),
            })
            .collect();
        let _ = self.events.send(UiEvent::Log { peer, entries });
        Ok(())
    }
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
            hub,
        } => {
            init_logging(&home)?;
            let me = *secret.public().as_bytes();
            let store = Store::open(&home.join("messages.db"), vault, me)?;
            run(home, secret, store, connect, relay_only, nick, hub).await
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
    home: PathBuf,
    secret: iroh::SecretKey,
    store: Store,
    connect: Option<String>,
    relay_only: bool,
    nick: Option<String>,
    hub_url: Option<String>,
) -> Result<()> {
    let dial = connect
        .map(|s| s.trim().parse::<EndpointId>())
        .transpose()
        .context("that is not a valid EndpointId")?;

    let secret_bytes = secret.to_bytes();
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
    let (commands, command_rx) = mpsc::unbounded_channel();
    // An explicit --nick wins for this run; otherwise the last /nick sticks.
    let nickname = match nick {
        Some(nick) => nick,
        None => store
            .setting("nickname")?
            .unwrap_or_else(|| ep.id().fmt_short().to_string()),
    };
    let prekey = load_or_create_prekey(&store)?;
    let identity = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
    let hub = hub_url
        .as_deref()
        .map(|url| Hub::new(url, identity.clone()).map(Arc::new))
        .transpose()?;

    let app = App {
        me: *ep.id().as_bytes(),
        endpoint: ep.clone(),
        identity: identity.clone(),
        rooms: Arc::new(Mutex::new(HashMap::new())),
        store: Arc::new(Mutex::new(store)),
        nickname: Arc::new(Mutex::new(nickname)),
        events,
        outbound: broadcast::channel(256).0,
        hub,
        prekey: Arc::new(prekey),
        home: Arc::new(home.clone()),
        live: Arc::new(Mutex::new(HashMap::new())),
        prekeys: Arc::new(Mutex::new(HashMap::new())),
    };

    replay_history(&app)?;
    load_rooms(&app)?;
    app.status(if relay_only {
        "relay-only: direct paths disabled"
    } else if app.hub.is_some() {
        "listening, offline delivery on"
    } else {
        "listening, no hub — live chat only"
    });
    if app.hub.is_some() {
        tokio::spawn(mailbox_loop(app.clone()));
    }

    tokio::spawn(accept_loop(ep.clone(), app.clone()));

    if let Some(peer) = dial {
        dial_peer(&app, *peer.as_bytes());
    }

    tokio::spawn(dispatch(app.clone(), command_rx));

    let ui = Ui::new(ep.id().to_string(), app.nickname(), commands);
    let result = ui::run(ui, event_rx).await;
    ep.close().await;
    result
}

/// Dials a peer and runs the session, adding them as a contact either way.
///
/// A peer you named is a contact whether or not the dial lands: without that
/// you could not address someone who is offline, which is the whole point of
/// having a mailbox.
fn dial_peer(app: &App, peer: [u8; 32]) {
    if peer == app.me {
        app.status("that is your own endpoint id");
        return;
    }
    if app.live.lock().unwrap().contains_key(&peer) {
        app.status(format!("already connected to {}", ui::short(&peer)));
        return;
    }
    match app.store.lock().unwrap().setting(&nick_key(&peer)) {
        Ok(nick) => {
            let _ = app.events.send(UiEvent::Known { peer, nick });
        }
        Err(err) => tracing::warn!(%err, "could not read a remembered nickname"),
    }

    let app = app.clone();
    tokio::spawn(async move {
        let Ok(id) = iroh::EndpointId::from_bytes(&peer) else {
            app.status("that is not a valid endpoint id");
            return;
        };
        app.status(format!("dialing {}", ui::short(&peer)));
        match app.endpoint.connect(id, ALPN).await {
            Ok(conn) => {
                if let Err(err) = session(conn, app.clone(), true).await {
                    app.status(format!("session ended: {err}"));
                }
            }
            Err(err) => app.status(format!("could not reach {}: {err}", ui::short(&peer))),
        }
    });
}

/// A peer's last-seen nickname, so an offline contact is still a name rather
/// than a hex string.
fn nick_key(peer: &[u8; 32]) -> String {
    format!("nick:{}", ui::short(peer))
}

/// Seeds the UI with every known peer and their stored history, so the log is
/// already there before anyone comes online.
fn replay_history(app: &App) -> Result<()> {
    let peers = app.store.lock().unwrap().peers()?;
    for peer in peers {
        let nick = app.store.lock().unwrap().setting(&nick_key(&peer))?;
        let _ = app.events.send(UiEvent::Known { peer, nick });
        app.send_log(peer)?;
    }
    Ok(())
}

/// Turns what the user did into an op: mints its id, records it, refolds the
/// conversation, and puts it on the wire. Minting in one place is what keeps
/// the local view and the peer's view of an id identical.
async fn dispatch(app: App, mut commands: mpsc::UnboundedReceiver<UiCommand>) {
    while let Some(cmd) = commands.recv().await {
        let (peer, frame) = match cmd {
            UiCommand::Quit => return,
            UiCommand::SendFile { peer, path } => {
                let conn = app.live.lock().unwrap().get(&peer).cloned();
                match conn {
                    Some(conn) => {
                        let app = app.clone();
                        tokio::spawn(async move {
                            if let Err(err) =
                                files::send(app.clone(), conn, peer, PathBuf::from(path)).await
                            {
                                app.status(format!("could not send that file: {err:#}"));
                            }
                        });
                    }
                    // The bytes need a live stream. Mailing a header for a file
                    // that can never arrive would be worse than saying so.
                    None => app.status("attachments need a live connection to that peer"),
                }
                continue;
            }
            UiCommand::Connect(peer) => {
                dial_peer(&app, peer);
                continue;
            }
            UiCommand::Room(cmd) => {
                tokio::spawn(room_command(app.clone(), cmd));
                continue;
            }
            UiCommand::Nick(nick) => {
                *app.nickname.lock().unwrap() = nick.clone();
                if let Err(err) = app.store.lock().unwrap().set_setting("nickname", &nick) {
                    let _ = app.events.send(UiEvent::Status(format!("could not save nick: {err}")));
                }
                let _ = app
                    .outbound
                    .send((None, Frame::Hello { nickname: nick }));
                continue;
            }
            UiCommand::Send {
                peer,
                body,
                reply_to,
            } => {
                let id = app.store.lock().unwrap().next_id();
                (peer, Frame::Chat { id, body, reply_to })
            }
            UiCommand::Edit { peer, target, body } => {
                let id = app.store.lock().unwrap().next_id();
                (peer, Frame::Edit { id, target, body })
            }
            UiCommand::Delete { peer, target } => {
                let id = app.store.lock().unwrap().next_id();
                (peer, Frame::Delete { id, target })
            }
            UiCommand::React {
                peer,
                target,
                emoji,
                on,
            } => {
                let id = app.store.lock().unwrap().next_id();
                (
                    peer,
                    Frame::React {
                        id,
                        target,
                        emoji,
                        on,
                    },
                )
            }
        };

        let recorded = app.store.lock().unwrap().record(&peer, &frame);
        if let Err(err) = recorded.and_then(|_| app.send_log(peer)) {
            app.status(format!("could not save: {err}"));
            continue;
        }

        deliver(&app, peer, frame);
    }
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
            nickname: app.nickname(),
        },
    )
    .await?;
    let Some(Frame::Hello { nickname: them }) = read_frame(&mut recv).await? else {
        bail!("peer did not open with a hello");
    };

    remember_nick(&app, &peer, &them);
    app.live.lock().unwrap().insert(peer, conn.clone());
    tokio::spawn(files::accept_loop(app.clone(), conn.clone(), peer));
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
                Ok(None) => break Ok(()),
                Ok(Some(Frame::Hello { nickname })) => {
                    // Sent again after the peer runs /nick.
                    remember_nick(&app, &peer, &nickname);
                    let _ = app.events.send(UiEvent::Connected {
                        peer,
                        nick: nickname,
                        path: describe_path(&conn).1,
                    });
                }
                Ok(Some(frame)) => match app.accept(peer, frame).await {
                    Ok(Some(conversation)) => app.send_log(conversation)?,
                    Ok(None) => {}
                    // A bad op is that peer's problem, not a reason to drop a
                    // conversation that is otherwise fine.
                    Err(err) => tracing::warn!(%err, "refused an incoming op"),
                },
            },
            outgoing = outbound.recv() => {
                let Ok((target, frame)) = outgoing else { continue };
                if target.is_some_and(|t| t != peer) {
                    continue;
                }
                write_frame(&mut send, &frame).await?;
            }
        }
    };

    app.live.lock().unwrap().remove(&peer);
    let _ = app.events.send(UiEvent::Disconnected { peer });
    result
}

fn remember_nick(app: &App, peer: &[u8; 32], nick: &str) {
    if let Err(err) = app.store.lock().unwrap().set_setting(&nick_key(peer), nick) {
        tracing::warn!(%err, "could not remember peer nickname");
    }
}

/// Routes one op: down the wire if that peer is connected, into their mailbox
/// if not. A room fans out pairwise — one copy per member, each over their own
/// connection or into their own mailbox.
fn deliver(app: &App, conversation: [u8; 32], frame: Frame) {
    let members = app.rooms.lock().unwrap().get(&conversation).map(|room| {
        (
            room.members.clone(),
            room.members.contains(&app.me),
        )
    });

    let Some((members, joined)) = members else {
        return deliver_to(app, conversation, frame);
    };
    if !joined {
        app.status("you are not in that room any more");
        return;
    }
    let wrapped = Frame::InRoom {
        room: conversation,
        op: Box::new(frame),
    };
    for member in members {
        if member == app.me {
            continue;
        }
        deliver_to(app, member, wrapped.clone());
    }
}

fn deliver_to(app: &App, peer: [u8; 32], frame: Frame) {
    if app.live.lock().unwrap().contains_key(&peer) {
        let _ = app.outbound.send((Some(peer), frame));
    } else if app.hub.is_some() {
        tokio::spawn(mail_to(app.clone(), peer, frame));
    } else {
        app.status("peer is offline and no hub is configured — saved locally only");
    }
}

/// Appends one signed entry to a room's chain, verifies the result here, stores
/// it, publishes it, and tells the members to go and look.
async fn room_command(app: App, cmd: ui::RoomCommand) {
    let result = match cmd {
        ui::RoomCommand::Create(name) => append(&app, None, RoomOp::Create { name }).await,
        ui::RoomCommand::Invite { room, member } => {
            append(&app, Some(room), RoomOp::Invite { member }).await
        }
        ui::RoomCommand::Kick { room, member } => {
            append(&app, Some(room), RoomOp::Kick { member }).await
        }
    };
    if let Err(err) = result {
        app.status(format!("room: {err:#}"));
    }
}

async fn append(app: &App, room: Option<RoomId>, op: RoomOp) -> Result<()> {
    let mut entries = match room {
        Some(id) => app
            .store
            .lock()
            .unwrap()
            .rooms()?
            .into_iter()
            .find(|(known, _)| known == &id)
            .map(|(_, log)| log)
            .context("that room is not one this endpoint knows about")?,
        None => Vec::new(),
    };
    let before: BTreeSet<[u8; 32]> = verify_log(&entries)
        .map(|r| r.members)
        .unwrap_or_default();
    let prev = entries
        .last()
        .map(|e: &RoomEntry| e.hash())
        .transpose()?
        .unwrap_or([0u8; 32]);
    entries.push(RoomEntry::new(&app.identity, prev, now_ms(), op)?);

    // Verified here before it is stored or published: an entry this endpoint
    // cannot itself accept has no business going to anyone else.
    let verified = verify_log(&entries)?;
    let id = verified.id;
    // Whoever was in the room and whoever is in it now — so the person just
    // kicked is told to go and check, and finds the chain agreeing.
    let notify: BTreeSet<[u8; 32]> = before.union(&verified.members).copied().collect();

    app.store.lock().unwrap().save_room(&id, &entries)?;
    publish_room(app, verified, entries).await?;

    for member in notify {
        if member != app.me {
            deliver_to(app, member, Frame::RoomUpdated { room: id });
        }
    }
    Ok(())
}

/// Puts a verified room into the local state and the sidebar.
fn show_room(app: &App, room: Room) -> Result<()> {
    let id = room.id;
    let view = ui::RoomView {
        name: room.name.clone(),
        members: room.members.len(),
        joined: room.members.contains(&app.me),
    };
    app.rooms.lock().unwrap().insert(id, room);
    let _ = app.events.send(UiEvent::Room { id, view });
    app.send_log(id)
}

async fn publish_room(app: &App, room: Room, entries: Vec<RoomEntry>) -> Result<()> {
    let id = room.id;
    show_room(app, room)?;
    if let Some(hub) = app.hub.clone() {
        hub.put_room(&id, &entries).await?;
    }
    Ok(())
}

/// Fetches a room's log from the hub and replays it here. The hub's copy is a
/// claim; the chain is the evidence, and `Hub::room` will not return a room it
/// could not verify.
async fn fetch_room(app: &App, id: RoomId) -> Result<()> {
    let hub = app.hub.clone().context("no hub configured")?;
    let (room, entries) = hub.room(&id).await?;
    app.store.lock().unwrap().save_room(&id, &entries)?;
    let joined = room.members.contains(&app.me);
    let name = room.name.clone();
    show_room(app, room)?;
    app.status(if joined {
        format!("#{name} membership updated")
    } else {
        format!("#{name}: you are no longer a member")
    });
    Ok(())
}

/// Replays every room this endpoint already knows, then asks the hub whether
/// anything moved while it was away.
fn load_rooms(app: &App) -> Result<()> {
    // Bound first: a `for` loop holds the scrutinee's temporaries for the whole
    // body, and `show_room` reaches for the same lock.
    let stored = app.store.lock().unwrap().rooms()?;
    for (id, entries) in stored {
        match verify_log(&entries) {
            Ok(room) if room.id == id => show_room(app, room)?,
            Ok(_) => tracing::warn!("stored room log does not match its id"),
            Err(err) => tracing::warn!(%err, "stored room log no longer verifies"),
        }
        if app.hub.is_some() {
            let app = app.clone();
            tokio::spawn(async move {
                if let Err(err) = fetch_room(&app, id).await {
                    tracing::warn!(%err, "could not refresh a room from the hub");
                }
            });
        }
    }
    Ok(())
}

/// The X25519 key others seal offline messages to. Long-lived and kept in the
/// encrypted store, so a restart does not orphan mail already sealed to it.
///
// ponytail: one prekey, never rotated. Rotation needs a table of retired
// secrets so old mail still opens; add it if forward secrecy needs to bite
// harder than "the sender kept nothing".
fn load_or_create_prekey(store: &Store) -> Result<StaticSecret> {
    if let Some(hex) = store.setting("prekey")? {
        let bytes: [u8; 32] = data_encoding::HEXLOWER
            .decode(hex.as_bytes())
            .context("stored prekey is not hex")?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("stored prekey is not 32 bytes"))?;
        return Ok(StaticSecret::from(bytes));
    }
    let secret = StaticSecret::random();
    store.set_setting("prekey", &data_encoding::HEXLOWER.encode(&secret.to_bytes()))?;
    Ok(secret)
}

/// Seals one op to a peer who is not connected and leaves it on the hub.
async fn mail_to(app: App, peer: [u8; 32], frame: Frame) {
    let Some(hub) = app.hub.clone() else { return };
    let cached = app.prekeys.lock().unwrap().get(&peer).copied();

    let sent = async {
        let prekey = match cached {
            Some(prekey) => prekey,
            None => {
                // Verified against `peer` inside `prekey_for` — the whole point.
                let fetched = hub.prekey_for(&peer).await?;
                app.prekeys.lock().unwrap().insert(peer, fetched);
                fetched
            }
        };
        hub.mail(&prekey, &peer, &postcard::to_stdvec(&frame)?).await
    }
    .await;

    match sent {
        Ok(()) => app.status(format!("{} is offline — left it on the hub", ui::short(&peer))),
        Err(err) => app.status(format!("could not mail to {}: {err}", ui::short(&peer))),
    }
}

/// Publishes this endpoint's prekey, then drains the mailbox on a timer.
async fn mailbox_loop(app: App) {
    let Some(hub) = app.hub.clone() else { return };
    if let Err(err) = hub.publish_prekey(&app.prekey).await {
        app.status(format!("could not publish prekey: {err}"));
    }
    loop {
        match hub.fetch_mail().await {
            Ok(mail) if !mail.is_empty() => {
                let mut collected = Vec::new();
                let mut touched = HashSet::new();
                let mut arrived = 0;
                for (row, envelope) in mail {
                    match app.absorb(&envelope).await {
                        Ok(conversation) => {
                            collected.push(row);
                            if let Some(conversation) = conversation {
                                touched.insert(conversation);
                                arrived += 1;
                            }
                        }
                        // Leave it on the hub rather than lose it: the next
                        // poll retries, and the TTL sweep is the backstop.
                        Err(err) => tracing::warn!(%err, "could not accept a mailbox envelope"),
                    }
                }
                for peer in touched {
                    if let Err(err) = app.send_log(peer) {
                        tracing::warn!(%err, "could not refold after mailbox delivery");
                    }
                }
                // Only after everything is in the local store: until then the
                // hub holds the only copy.
                if let Err(err) = hub.delete_mail(&collected).await {
                    app.status(format!("could not clear the mailbox: {err}"));
                }
                if arrived > 0 {
                    app.status(format!("{arrived} message(s) delivered from the hub"));
                }
            }
            Ok(_) => {}
            Err(err) => tracing::warn!(%err, "mailbox drain failed"),
        }
        tokio::time::sleep(DRAIN_EVERY).await;
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
