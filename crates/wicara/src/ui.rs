//! The terminal UI.
//!
//! It talks to the network over two channels and knows nothing else about it,
//! so it can be driven by a stub just as well as by a live iroh endpoint.

use std::collections::HashMap;

use anyhow::Result;
use ratatui::{
    Frame,
    crossterm::{
        event::{
            self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
            KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
        },
        execute,
    },
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
};
use tokio::sync::mpsc;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
use wicara_core::wire::MessageId;

/// The five reactions bound to keys 1-5. A picker would be a lot of UI for a
/// feature whose whole point is that it is one keystroke.
pub const REACTIONS: [&str; 5] = ["👍", "❤️", "😂", "😮", "😢"];

/// One message as the UI shows it, after the store has folded edits, deletes
/// and reactions into it.
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: MessageId,
    pub body: String,
    pub outbound: bool,
    pub deleted: bool,
    pub reply_to: Option<MessageId>,
    /// `(emoji, count, whether you are one of them)`.
    pub reactions: Vec<(String, usize, bool)>,
    pub attachment: Option<Attach>,
}

/// A room as the verified chain says it stands.
#[derive(Debug, Clone)]
pub struct RoomView {
    pub name: String,
    pub members: usize,
    /// False once you have been kicked — the room stays visible with its
    /// history, but you can no longer post to it.
    pub joined: bool,
}

/// How an outgoing op actually left this machine. The whole point of the design
/// is that there are two paths; without this they look identical on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Delivery {
    /// Straight down a live QUIC connection.
    Wire,
    /// Sealed and left on the hub for someone who is not there.
    Mailbox,
    /// Neither worked. It is saved locally and nowhere else.
    Failed,
}

impl Delivery {
    fn glyph(self) -> (&'static str, Color) {
        match self {
            Delivery::Wire => ("→", Color::DarkGray),
            Delivery::Mailbox => ("✉", Color::Yellow),
            Delivery::Failed => ("!", Color::Red),
        }
    }
}

/// A file hanging off a message.
#[derive(Debug, Clone)]
pub struct Attach {
    pub name: String,
    pub size: u64,
    /// Shown short, so "the hashes match" is something a viewer can check
    /// against the sender's screen rather than take on trust.
    pub hash: [u8; 32],
    /// Where it landed on this machine, once the bytes arrived and matched.
    pub path: Option<String>,
}

/// Pushed in by the network side.
#[derive(Debug)]
pub enum UiEvent {
    /// A peer we know about, from the store, before anyone is online. The
    /// nickname is whatever it last called itself.
    Known {
        peer: [u8; 32],
        /// What they call themselves.
        nick: Option<String>,
        /// What you decided to call them, which wins.
        alias: Option<String>,
    },
    Connected {
        peer: [u8; 32],
        nick: String,
        path: String,
    },
    Path {
        peer: [u8; 32],
        path: String,
    },
    Disconnected {
        peer: [u8; 32],
    },
    /// The whole conversation, refolded. Replacing it wholesale keeps one
    /// implementation of the fold, in the store, instead of two.
    Log {
        peer: [u8; 32],
        entries: Vec<Entry>,
    },
    /// How an outgoing op left. A room fans out to several peers, so the worst
    /// outcome of the fan-out is the one worth showing.
    Delivery {
        id: MessageId,
        state: Delivery,
    },
    /// Progress on an attachment, in either direction.
    Transfer {
        id: MessageId,
        done: u64,
        total: u64,
    },
    /// A conversation was deleted from this machine.
    Forgotten { peer: [u8; 32] },
    /// Everything was. The UI starts over from whatever is reloaded after.
    Wiped,
    /// A room appeared or its membership changed.
    Room {
        id: [u8; 32],
        view: RoomView,
    },
    Status(String),
}

/// What `/room` asked for.
#[derive(Debug, PartialEq)]
pub enum RoomCommand {
    Create(String),
    Leave { room: [u8; 32] },
    Invite { room: [u8; 32], member: [u8; 32] },
    Kick { room: [u8; 32], member: [u8; 32] },
}

/// Pushed back out to the network side.
#[derive(Debug, PartialEq)]
pub enum UiCommand {
    Send {
        peer: [u8; 32],
        body: String,
        reply_to: Option<MessageId>,
    },
    Edit {
        peer: [u8; 32],
        target: MessageId,
        body: String,
    },
    Delete {
        peer: [u8; 32],
        target: MessageId,
    },
    React {
        peer: [u8; 32],
        target: MessageId,
        emoji: String,
        on: bool,
    },
    Nick(String),
    /// Your own name for a peer. `None` forgets it and falls back to whatever
    /// they call themselves.
    Name {
        peer: [u8; 32],
        alias: Option<String>,
    },
    /// Dial a peer without restarting.
    Connect([u8; 32]),
    /// Delete a conversation from this machine. Local, and irreversible.
    /// `confirm: false` only asks what would go.
    Forget { peer: [u8; 32], confirm: bool },
    /// Empty a conversation but keep whose it was.
    Clear { peer: [u8; 32], confirm: bool },
    /// Every conversation on this machine. Keeps the identity.
    Wipe { confirm: bool },
    Room(RoomCommand),
    SendFile {
        peer: [u8; 32],
        path: String,
    },
    Quit,
}

#[derive(PartialEq, Clone, Copy, Debug)]
enum Focus {
    Peers,
    Chat,
    Input,
}

/// What the next Enter will do, when it is not simply a new message.
#[derive(Clone, Copy, PartialEq)]
enum Pending {
    Reply(MessageId),
    Edit(MessageId),
}

struct Peer {
    key: [u8; 32],
    /// The name the peer sends in its hello. It picks this, so on its own it
    /// proves nothing: two peers can claim the same one.
    nick: Option<String>,
    /// The name you gave them with `/name`. Yours, so it is the trustworthy one.
    alias: Option<String>,
    online: bool,
    path: String,
    log: Vec<Entry>,
    unread: usize,
    /// Index into `log` of the message the chat cursor is on.
    cursor: usize,
    /// Where the messages you have not seen begin.
    unread_from: Option<usize>,
    /// Set when this conversation is a room rather than a person. A room id is
    /// 32 bytes exactly like an endpoint id, which is why one list holds both.
    room: Option<RoomView>,
}

impl Peer {
    fn label(&self) -> String {
        match (&self.room, &self.alias, &self.nick) {
            (Some(room), _, _) => format!("#{}", room.name),
            (None, Some(alias), _) => alias.clone(),
            (None, None, Some(nick)) => nick.clone(),
            (None, None, None) => short(&self.key),
        }
    }

    /// True when the displayed name is one you chose. An unnamed peer is shown
    /// dimmed with a `?`, because the alternative — rendering a string the peer
    /// picked as if it were their identity — is how you get impersonated by
    /// someone who simply called themselves your friend's name.
    fn named(&self) -> bool {
        self.room.is_some() || self.alias.is_some() || self.nick.is_none()
    }

    fn subtitle(&self) -> String {
        match &self.room {
            Some(room) if !room.joined => "you are not in this room".into(),
            Some(room) => format!("{} member(s)", room.members),
            None if self.path.is_empty() => "offline".into(),
            None => self.path.clone(),
        }
    }
}

pub struct Ui {
    me: String,
    nickname: String,
    peers: Vec<Peer>,
    index: HashMap<[u8; 32], usize>,
    sel: usize,
    focus: Focus,
    pending: Option<Pending>,
    input: String,
    /// Byte offset of the caret within `input`.
    caret: usize,
    /// Wrapped chat lines scrolled up from the bottom; 0 pins to the newest.
    scroll: usize,
    status: String,
    /// Attachments in flight, by message id.
    transfers: HashMap<MessageId, (u64, u64)>,
    delivery: HashMap<MessageId, Delivery>,
    commands: mpsc::UnboundedSender<UiCommand>,
    /// `/help` takes over the chat pane until the next keypress.
    help: bool,
    /// Whether the terminal is handing us mouse events. While it is, dragging
    /// selects nothing, so `/mouse` turns it off when you want to copy text.
    mouse: bool,
    /// Where each pane was drawn last frame, for hit-testing clicks.
    peers_area: Rect,
    chat_area: Rect,
    input_area: Rect,
    /// Scroll offset of the peer list, so a click maps to the right peer.
    peer_state: ListState,
    /// For each visible chat row, the message it belongs to.
    chat_rows: Vec<usize>,
}

pub fn short(key: &[u8; 32]) -> String {
    key[..5].iter().map(|b| format!("{b:02x}")).collect()
}

impl Ui {
    pub fn new(me: String, nickname: String, commands: mpsc::UnboundedSender<UiCommand>) -> Self {
        Self {
            me,
            nickname,
            peers: Vec::new(),
            index: HashMap::new(),
            sel: 0,
            focus: Focus::Input,
            pending: None,
            input: String::new(),
            caret: 0,
            scroll: 0,
            status: "waiting for peers".into(),
            transfers: HashMap::new(),
            delivery: HashMap::new(),
            commands,
            help: false,
            mouse: true,
            peers_area: Rect::ZERO,
            chat_area: Rect::ZERO,
            input_area: Rect::ZERO,
            peer_state: ListState::default(),
            chat_rows: Vec::new(),
        }
    }

    fn peer_mut(&mut self, key: [u8; 32]) -> &mut Peer {
        let idx = *self.index.entry(key).or_insert_with(|| {
            self.peers.push(Peer {
                key,
                nick: None,
                alias: None,
                online: false,
                path: String::new(),
                log: Vec::new(),
                unread: 0,
                unread_from: None,
                cursor: 0,
                room: None,
            });
            self.peers.len() - 1
        });
        &mut self.peers[idx]
    }

    fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::Known { peer, nick, alias } => {
                let p = self.peer_mut(peer);
                p.nick = nick;
                p.alias = alias;
            }
            UiEvent::Connected { peer, nick, path } => {
                let p = self.peer_mut(peer);
                p.nick = Some(nick);
                p.online = true;
                p.path = path;
            }
            UiEvent::Path { peer, path } => self.peer_mut(peer).path = path,
            UiEvent::Disconnected { peer } => {
                let p = self.peer_mut(peer);
                p.online = false;
                p.path.clear();
            }
            UiEvent::Log { peer, entries } => {
                let selected = self.selected_key() == Some(peer);
                let p = self.peer_mut(peer);
                let before = p.log.len();
                let grew = entries.len() > before;
                let at_end = p.cursor + 1 >= p.log.len();
                p.log = entries;
                if at_end {
                    p.cursor = p.log.len().saturating_sub(1);
                }
                p.cursor = p.cursor.min(p.log.len().saturating_sub(1));
                if grew && !selected {
                    p.unread += 1;
                    p.unread_from.get_or_insert(before);
                }
                if selected {
                    self.scroll = 0;
                }
            }
            UiEvent::Delivery { id, state } => {
                let seen = self.delivery.entry(id).or_insert(state);
                *seen = (*seen).max(state);
            }
            UiEvent::Transfer { id, done, total } => {
                if done >= total {
                    self.transfers.remove(&id);
                } else {
                    self.transfers.insert(id, (done, total));
                }
            }
            UiEvent::Forgotten { peer } => {
                self.peers.retain(|p| p.key != peer);
                // Indices shifted, so the lookup has to be rebuilt rather than
                // patched.
                self.index = self
                    .peers
                    .iter()
                    .enumerate()
                    .map(|(i, p)| (p.key, i))
                    .collect();
                self.sel = self.sel.min(self.peers.len().saturating_sub(1));
                self.scroll = 0;
                self.delivery.clear();
            }
            UiEvent::Wiped => {
                self.peers.clear();
                self.index.clear();
                self.delivery.clear();
                self.transfers.clear();
                self.sel = 0;
                self.scroll = 0;
            }
            UiEvent::Room { id, view } => self.peer_mut(id).room = Some(view),
            UiEvent::Status(s) => self.status = s,
        }
    }

    fn selected_key(&self) -> Option<[u8; 32]> {
        self.peers.get(self.sel).map(|p| p.key)
    }

    fn cursor_entry(&self) -> Option<(&[u8; 32], &Entry)> {
        let p = self.peers.get(self.sel)?;
        Some((&p.key, p.log.get(p.cursor)?))
    }

    /// Returns false when the app should quit.
    fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return true;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            let _ = self.commands.send(UiCommand::Quit);
            return false;
        }
        if self.help {
            self.help = false;
            // The key that dismissed it should not also do something else.
            if !matches!(key.code, KeyCode::Char(_)) {
                return true;
            }
        }

        match key.code {
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Peers,
                    Focus::Peers => Focus::Chat,
                    Focus::Chat => Focus::Input,
                }
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Chat,
                    Focus::Chat => Focus::Peers,
                    Focus::Peers => Focus::Input,
                }
            }
            KeyCode::Esc => {
                self.pending = None;
                self.input.clear();
                self.caret = 0;
            }
            KeyCode::PageUp => self.scroll += 5,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(5),
            KeyCode::Up if self.focus == Focus::Peers => self.select_peer(-1),
            KeyCode::Down if self.focus == Focus::Peers => self.select_peer(1),
            KeyCode::Up if self.focus == Focus::Chat => self.move_cursor(-1),
            KeyCode::Down if self.focus == Focus::Chat => self.move_cursor(1),
            KeyCode::Up => self.scroll += 1,
            KeyCode::Down => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Enter => return self.submit(),
            KeyCode::Char(c) if self.focus == Focus::Chat => self.chat_action(c),
            KeyCode::Char(c) if self.focus == Focus::Input => {
                self.input.insert(self.caret, c);
                self.caret += c.len_utf8();
            }
            KeyCode::Backspace if self.focus == Focus::Input => {
                if let Some((i, c)) = self.input[..self.caret].char_indices().next_back() {
                    self.input.remove(i);
                    self.caret -= c.len_utf8();
                }
            }
            KeyCode::Delete if self.focus == Focus::Input => {
                if self.caret < self.input.len() {
                    self.input.remove(self.caret);
                }
            }
            KeyCode::Left if self.focus == Focus::Input => {
                if let Some((i, _)) = self.input[..self.caret].char_indices().next_back() {
                    self.caret = i;
                }
            }
            KeyCode::Right if self.focus == Focus::Input => {
                if let Some(c) = self.input[self.caret..].chars().next() {
                    self.caret += c.len_utf8();
                }
            }
            KeyCode::Home => self.caret = 0,
            KeyCode::End => self.caret = self.input.len(),
            _ => {}
        }
        true
    }

    /// Reply, edit, delete and react, all keyed by the message the chat cursor
    /// is on — which is why the id scheme had to exist before any of this did.
    fn chat_action(&mut self, c: char) {
        let Some((&peer, entry)) = self.cursor_entry().map(|(k, e)| (k, e.clone())) else {
            return;
        };
        match c {
            'r' => {
                self.pending = Some(Pending::Reply(entry.id));
                self.focus = Focus::Input;
            }
            'e' if entry.outbound && !entry.deleted => {
                self.pending = Some(Pending::Edit(entry.id));
                self.input = entry.body.clone();
                self.caret = self.input.len();
                self.focus = Focus::Input;
            }
            'e' => self.status = "you can only edit your own messages".into(),
            'd' if entry.outbound && !entry.deleted => {
                let _ = self.commands.send(UiCommand::Delete {
                    peer,
                    target: entry.id,
                });
            }
            'd' => self.status = "you can only delete your own messages".into(),
            '1'..='5' => {
                let emoji = REACTIONS[c as usize - '1' as usize];
                let on = !entry
                    .reactions
                    .iter()
                    .any(|(e, _, mine)| e == emoji && *mine);
                let _ = self.commands.send(UiCommand::React {
                    peer,
                    target: entry.id,
                    emoji: emoji.to_string(),
                    on,
                });
            }
            _ => {}
        }
    }

    /// Maps a click to whatever was drawn under it last frame.
    fn on_mouse(&mut self, ev: MouseEvent) {
        let (x, y) = (ev.column, ev.row);
        match ev.kind {
            MouseEventKind::ScrollUp if inside(inner(self.chat_area), x, y) => self.scroll += 3,
            MouseEventKind::ScrollDown if inside(inner(self.chat_area), x, y) => {
                self.scroll = self.scroll.saturating_sub(3)
            }
            MouseEventKind::ScrollUp => self.select_peer(-1),
            MouseEventKind::ScrollDown => self.select_peer(1),
            MouseEventKind::Down(MouseButton::Left) => {
                let peers = inner(self.peers_area);
                let chat = inner(self.chat_area);
                let input = inner(self.input_area);
                if inside(peers, x, y) {
                    self.focus = Focus::Peers;
                    let row = (y - peers.y) as usize + self.peer_state.offset();
                    if row < self.peers.len() {
                        self.sel = row;
                        self.scroll = 0;
                        self.peers[row].unread = 0;
                        self.peers[row].unread_from = None;
                    }
                } else if inside(chat, x, y) {
                    self.focus = Focus::Chat;
                    let clicked = self.chat_rows.get((y - chat.y) as usize).copied();
                    if let (Some(owner), Some(p)) = (clicked, self.peers.get_mut(self.sel))
                        && owner != usize::MAX
                    {
                        p.cursor = owner.min(p.log.len().saturating_sub(1));
                    }
                } else if inside(input, x, y) {
                    self.focus = Focus::Input;
                    self.caret = byte_at_column(&self.input, (x - input.x) as usize);
                }
            }
            _ => {}
        }
    }

    fn select_peer(&mut self, delta: isize) {
        if self.peers.is_empty() {
            return;
        }
        let n = self.peers.len() as isize;
        self.sel = ((self.sel as isize + delta).rem_euclid(n)) as usize;
        self.scroll = 0;
        self.peers[self.sel].unread = 0;
        self.peers[self.sel].unread_from = None;
    }

    fn move_cursor(&mut self, delta: isize) {
        let Some(p) = self.peers.get_mut(self.sel) else {
            return;
        };
        if p.log.is_empty() {
            return;
        }
        p.cursor = (p.cursor as isize + delta).clamp(0, p.log.len() as isize - 1) as usize;
    }

    /// Returns false when the line was a command that quits.
    fn submit(&mut self) -> bool {
        let body = std::mem::take(&mut self.input).trim().to_string();
        self.caret = 0;
        if let Some(rest) = body.strip_prefix('/') {
            return self.slash(rest);
        }
        if body.is_empty() {
            self.pending = None;
            return true;
        }
        let Some(peer) = self.selected_key() else {
            self.status = "no peer selected — nothing to send to".into();
            return true;
        };
        let _ = self.commands.send(match self.pending.take() {
            Some(Pending::Edit(target)) => UiCommand::Edit { peer, target, body },
            Some(Pending::Reply(target)) => UiCommand::Send {
                peer,
                body,
                reply_to: Some(target),
            },
            None => UiCommand::Send {
                peer,
                body,
                reply_to: None,
            },
        });
        self.scroll = 0;
        true
    }

    fn slash(&mut self, rest: &str) -> bool {
        let (cmd, arg) = rest.split_once(' ').unwrap_or((rest, ""));
        match cmd {
            "quit" => {
                let _ = self.commands.send(UiCommand::Quit);
                return false;
            }
            "whoami" => {
                copy_to_clipboard(&self.me);
                self.status = format!("{} — {} (copied)", self.nickname, self.me);
            }
            "peers" => {
                self.status = if self.peers.is_empty() {
                    "no peers yet".into()
                } else {
                    self.peers
                        .iter()
                        .map(|p| format!("{}{}", if p.online { "●" } else { "○" }, p.label()))
                        .collect::<Vec<_>>()
                        .join("  ")
                }
            }
            "nick" if !arg.trim().is_empty() => {
                self.nickname = arg.trim().to_string();
                let _ = self.commands.send(UiCommand::Nick(self.nickname.clone()));
                self.status = format!("you are now {}", self.nickname);
            }
            "nick" => self.status = "usage: /nick <name>".into(),
            "room" => self.room_command(arg.trim()),
            "name" => self.name_command(arg.trim()),
            "whois" => self.whois(),
            "help" => self.help = true,
            "leave" => match self.peers.get(self.sel) {
                Some(p) if p.room.is_some() => {
                    let _ = self
                        .commands
                        .send(UiCommand::Room(RoomCommand::Leave { room: p.key }));
                }
                Some(_) => self.status = "/leave is for rooms — use /forget for a peer".into(),
                None => self.status = "select a room first".into(),
            },
            "forget" => self.forget_command(arg.trim()),
            "clear" => match self.selected_key() {
                Some(peer) => {
                    let _ = self.commands.send(UiCommand::Clear {
                        peer,
                        confirm: arg.trim() == "yes",
                    });
                }
                None => self.status = "select a conversation first".into(),
            },
            "wipe" => {
                let _ = self.commands.send(UiCommand::Wipe {
                    confirm: arg.trim() == "yes",
                });
            }
            "mouse" => {
                self.mouse = !self.mouse;
                self.status = if self.mouse {
                    "mouse on — click to move around; /mouse again to select text".into()
                } else {
                    "mouse off — drag to select and copy; /mouse to turn it back on".into()
                };
            }
            "connect" => match parse_key(arg.trim()) {
                Some(peer) => {
                    let _ = self.commands.send(UiCommand::Connect(peer));
                }
                None => self.status = "usage: /connect <endpoint-id>".into(),
            },
            "send" if !arg.trim().is_empty() => match self.selected_key() {
                Some(peer) => {
                    let _ = self.commands.send(UiCommand::SendFile {
                        peer,
                        path: arg.trim().to_string(),
                    });
                }
                None => self.status = "select a peer first".into(),
            },
            "send" => self.status = "usage: /send <path>".into(),
            other => self.status = format!("unknown command /{other}"),
        }
        true
    }

    /// `/name <alias>` on the selected peer, or bare `/name` to forget it.
    fn name_command(&mut self, arg: &str) {
        let Some(peer) = self.peers.get_mut(self.sel) else {
            self.status = "select a peer first".into();
            return;
        };
        if peer.room.is_some() {
            self.status = "rooms are named by whoever created them".into();
            return;
        }
        let key = peer.key;
        let alias = (!arg.is_empty()).then(|| arg.to_string());
        peer.alias = alias.clone();
        self.status = match &alias {
            Some(alias) => format!("you now call {} {alias}", short(&key)),
            None => format!("forgot your name for {}", short(&key)),
        };
        let _ = self.commands.send(UiCommand::Name { peer: key, alias });
    }

    /// Deleting is irreversible, so a bare `/forget` only says what would go;
    /// `/forget yes` is the one that does it.
    fn forget_command(&mut self, arg: &str) {
        let Some(peer) = self.peers.get(self.sel) else {
            self.status = "select a conversation first".into();
            return;
        };
        let key = peer.key;
        // The store knows what is actually there, so the warning comes back
        // from it rather than being guessed at here.
        let _ = self.commands.send(UiCommand::Forget {
            peer: key,
            confirm: arg == "yes",
        });
    }

    /// The full key for the selected conversation, and both names it goes by.
    /// The key is the only part that means anything.
    fn whois(&mut self) {
        let Some(peer) = self.peers.get(self.sel) else {
            self.status = "select a peer first".into();
            return;
        };
        let hex: String = peer.key.iter().map(|b| format!("{b:02x}")).collect();
        copy_to_clipboard(&hex);
        self.status = match (&peer.room, &peer.alias, &peer.nick) {
            (Some(room), _, _) => format!("#{} · {} members · {hex}", room.name, room.members),
            (None, Some(alias), Some(nick)) => {
                format!("{alias} (your name; they call themselves {nick}) · {hex}")
            }
            (None, Some(alias), None) => format!("{alias} (your name) · {hex}"),
            (None, None, Some(nick)) => {
                format!("{nick} — their claim, unverified; /name to set yours · {hex}")
            }
            (None, None, None) => format!("no name yet · {hex}"),
        };
    }

    /// `/room create <name>`, `/room invite <endpoint-id>`, `/room kick <id>`.
    /// Invite and kick act on the room the sidebar is on, so there is no room
    /// id to paste as well as the member's.
    fn room_command(&mut self, arg: &str) {
        let (verb, rest) = arg.split_once(' ').unwrap_or((arg, ""));
        let rest = rest.trim();
        match verb {
            "create" if !rest.is_empty() => {
                let _ = self
                    .commands
                    .send(UiCommand::Room(RoomCommand::Create(rest.to_string())));
            }
            "invite" | "kick" => {
                let Some(peer) = self.peers.get(self.sel) else {
                    self.status = "select a room first".into();
                    return;
                };
                if peer.room.is_none() {
                    self.status = "select a room first — invite and kick act on it".into();
                    return;
                }
                let room = peer.key;
                match parse_key(rest) {
                    Some(member) => {
                        let _ = self.commands.send(UiCommand::Room(if verb == "invite" {
                            RoomCommand::Invite { room, member }
                        } else {
                            RoomCommand::Kick { room, member }
                        }));
                    }
                    None => self.status = format!("usage: /room {verb} <endpoint-id>"),
                }
            }
            _ => self.status = "usage: /room create <name> | invite <id> | kick <id>".into(),
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let [top, input, status] = Layout::vertical([
            Constraint::Fill(1),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        let [sidebar, chat] =
            Layout::horizontal([Constraint::Length(22), Constraint::Fill(1)]).areas(top);

        self.peers_area = sidebar;
        self.chat_area = chat;
        self.input_area = input;
        self.draw_peers(frame, sidebar);
        self.draw_chat(frame, chat);
        self.draw_input(frame, input);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    format!(" {} ", self.nickname),
                    Style::new().fg(Color::Black).bg(Color::Cyan),
                ),
                Span::raw(format!(" {}  ", self.me)),
                Span::styled(&self.status, Style::new().fg(Color::DarkGray)),
                Span::styled(self.hints(), Style::new().fg(Color::DarkGray)),
            ])),
            status,
        );
    }

    fn hints(&self) -> &'static str {
        match self.focus {
            Focus::Chat => "  ↑↓ pick · r reply · e edit · d delete · 1-5 react",
            _ => "  tab · enter · /help · ^c quit",
        }
    }

    fn draw_peers(&mut self, frame: &mut Frame, area: Rect) {
        // Rooms and people share this list: a room id is 32 bytes, exactly
        // like an endpoint id, so nothing needed a second list.
        let items: Vec<ListItem> = self
            .peers
            .iter()
            .map(|p| {
                let dot = if p.online { "●" } else { "○" };
                let colour = if p.online { Color::Green } else { Color::DarkGray };
                let (dot, colour) = match &p.room {
                    Some(room) if room.joined => ("#", Color::Blue),
                    Some(_) => ("#", Color::DarkGray),
                    None => (dot, colour),
                };
                let mut spans = vec![Span::styled(format!("{dot} "), Style::new().fg(colour))];
                if p.named() {
                    spans.push(Span::raw(p.label()));
                } else {
                    // Their claim, not your decision. Shown so it cannot be
                    // mistaken for a name you verified.
                    spans.push(Span::styled(p.label(), Style::new().fg(Color::DarkGray)));
                    spans.push(Span::styled("?", Style::new().fg(Color::Yellow)));
                }
                if p.unread > 0 {
                    spans.push(Span::styled(
                        format!(" ({})", p.unread),
                        Style::new().fg(Color::Yellow),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        self.peer_state.select(Some(self.sel));
        let block = self.block("peers", Focus::Peers);
        frame.render_stateful_widget(
            List::new(items)
                .block(block)
                .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
            area,
            &mut self.peer_state,
        );
    }

    fn draw_chat(&mut self, frame: &mut Frame, area: Rect) {
        if self.help {
            return self.draw_help(frame, area);
        }
        let Some(peer) = self.peers.get(self.sel) else {
            frame.render_widget(
                Paragraph::new(
                    "No conversations yet.\n\n\
                     /whoami  copies your EndpointId — send it to someone.\n\
                     /connect <their-id>  starts talking to them.\n\
                     /help  for everything else.",
                )
                    .block(self.block("chat", Focus::Chat)),
                area,
            );
            return;
        };

        let width = (area.width.saturating_sub(2) as usize).max(8);
        // A bubble needs room; four tmux panes on one screen do not have it.
        let bubbles = width >= BUBBLE_MIN_PANE;
        let mut lines: Vec<Line> = Vec::new();
        // Which message each rendered row came from, so a click can land on it.
        let mut owners: Vec<usize> = Vec::new();
        // Where the cursor's message starts and ends, so it can be scrolled to.
        let mut cursor_span = (0usize, 0usize);
        let mut last_day = None;
        for (i, entry) in peer.log.iter().enumerate() {
            if let Some(date) = day(entry.id.ts_ms)
                && last_day != Some(date)
            {
                last_day = Some(date);
                lines.push(Line::from(Span::styled(
                    rule(&day_label(date), width),
                    Style::new().fg(Color::DarkGray),
                )));
                owners.push(usize::MAX);
            }
            if peer.unread_from == Some(i) {
                lines.push(Line::from(Span::styled(
                    rule("new", width),
                    Style::new().fg(Color::Yellow),
                )));
                owners.push(usize::MAX);
            }
            let start = lines.len();
            let (who, colour) = if entry.outbound {
                (self.nickname.clone(), Color::Cyan)
            } else if peer.named() {
                (peer.label(), Color::Magenta)
            } else {
                // Dimmed, because this is what they call themselves.
                (peer.label(), Color::DarkGray)
            };
            let stamp = clock(entry.id.ts_ms);
            // Consecutive messages from one person within a few minutes read as
            // one run, so only the first carries the name.
            let grouped = i > 0 && {
                let prev = &peer.log[i - 1];
                prev.id.sender == entry.id.sender
                    && entry.id.ts_ms.saturating_sub(prev.id.ts_ms) < 5 * 60 * 1000
                    && peer.unread_from != Some(i)
                    && day(prev.id.ts_ms) == day(entry.id.ts_ms)
            };
            let quoted = entry.reply_to.map(|target| {
                let text = match peer.log.iter().find(|e| e.id == target) {
                    Some(e) if e.deleted => "(deleted)",
                    Some(e) => e.body.as_str(),
                    None => "(message not here)",
                };
                format!("┆ {}", first_line(text, width / 2))
            });
            let marker = entry
                .outbound
                .then(|| self.delivery.get(&entry.id).map(|d| d.glyph()))
                .flatten();

            // What goes inside, whichever layout draws it.
            let (body, style) = if let Some(file) = &entry.attachment {
                let state = match (self.transfers.get(&entry.id), &file.path) {
                    (Some((done, total)), _) => progress_bar(*done, *total),
                    (None, Some(path)) => format!("saved to {path}"),
                    (None, None) => "waiting for the bytes".into(),
                };
                (
                    vec![
                        format!(
                            "📎 {} · {} · blake3 {}",
                            file.name,
                            human(file.size),
                            file.hash[..4].iter().map(|b| format!("{b:02x}")).collect::<String>()
                        ),
                        state,
                    ],
                    Style::new().add_modifier(Modifier::BOLD),
                )
            } else if entry.deleted {
                (
                    vec!["(deleted)".to_string()],
                    Style::new().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
                )
            } else {
                let room = if bubbles {
                    width.min(BUBBLE_MAX).saturating_sub(6).max(8)
                } else {
                    width.saturating_sub(stamp.width() + who.width() + 2).max(8)
                };
                (wrap(&entry.body, room), Style::new())
            };

            if bubbles {
                Bubble {
                    body,
                    quoted,
                    name: (!grouped && !entry.outbound).then(|| who.clone()),
                    meta: stamp.clone(),
                    colour,
                    mine: entry.outbound,
                    pane: width,
                    style,
                    marker,
                }
                .render(&mut lines);
            } else {
                let prefix = format!("{stamp} {who}: ");
                if let Some(quote) = quoted {
                    lines.push(Line::from(Span::styled(
                        format!("  {quote}"),
                        Style::new().fg(Color::DarkGray),
                    )));
                }
                for (n, chunk) in body.into_iter().enumerate() {
                    let mut spans = if n == 0 && !grouped {
                        vec![
                            Span::styled(format!("{stamp} "), Style::new().fg(Color::DarkGray)),
                            Span::styled(format!("{who}: "), Style::new().fg(colour)),
                        ]
                    } else {
                        vec![Span::raw(format!("{:w$}", "", w = prefix.width()))]
                    };
                    spans.extend(mention_spans(&chunk, &self.nickname));
                    lines.push(Line::from(spans));
                }
                if let Some((glyph, colour)) = marker {
                    let last = lines.len() - 1;
                    lines[last]
                        .spans
                        .push(Span::styled(format!(" {glyph}"), Style::new().fg(colour)));
                }
            }

            if !entry.reactions.is_empty() {
                let chips = entry
                    .reactions
                    .iter()
                    .map(|(e, n, mine)| if *mine { format!("[{e} {n}]") } else { format!("{e} {n}") })
                    .collect::<Vec<_>>()
                    .join(" ");
                let indent = if bubbles && entry.outbound {
                    width.saturating_sub(chips.width() + 3)
                } else {
                    2
                };
                lines.push(Line::from(Span::styled(
                    format!("{:indent$}{chips}", ""),
                    Style::new().fg(Color::Yellow),
                )));
            }

            owners.resize(lines.len(), i);
            if i == peer.cursor && self.focus == Focus::Chat {
                cursor_span = (start, lines.len());
                for line in &mut lines[start..] {
                    *line = line.clone().style(Style::new().add_modifier(Modifier::REVERSED));
                }
            }
        }

        let height = (area.height.saturating_sub(2)) as usize;
        let max_scroll = lines.len().saturating_sub(height);
        if self.focus == Focus::Chat && height > 0 {
            // Keep the cursor's message on screen.
            let above = max_scroll.saturating_sub(self.scroll);
            if cursor_span.0 < above {
                self.scroll = max_scroll - cursor_span.0;
            } else if cursor_span.1 > above + height {
                self.scroll = max_scroll.saturating_sub(cursor_span.1.saturating_sub(height));
            }
        }
        self.scroll = self.scroll.min(max_scroll);
        let start = max_scroll - self.scroll;
        let mut view: Vec<Line> = lines.into_iter().skip(start).take(height).collect();
        let mut rows: Vec<usize> = owners.into_iter().skip(start).take(height).collect();
        // Chat reads from the bottom, so a short log is padded above, not below.
        while view.len() < height {
            view.insert(0, Line::default());
            rows.insert(0, usize::MAX);
        }
        self.chat_rows = rows;

        let mut title = if peer.named() {
            format!("{} — {}", peer.label(), peer.subtitle())
        } else {
            format!("{}? — unverified name — {}", peer.label(), peer.subtitle())
        };
        if self.scroll > 0 {
            title.push_str(&format!("  ↑{} scrolled back", self.scroll));
        }
        frame.render_widget(
            Paragraph::new(view).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(if self.focus == Focus::Chat {
                        Style::new().fg(Color::Cyan)
                    } else {
                        Style::new().fg(Color::DarkGray)
                    })
                    .title(title),
            ),
            area,
        );
    }

    fn draw_help(&self, frame: &mut Frame, area: Rect) {
        let dim = Style::new().fg(Color::DarkGray);
        let key = Style::new().fg(Color::Cyan);
        let rows: Vec<(&str, &str)> = vec![
            ("tab / shift-tab", "move between the peer list, the chat and the input"),
            ("↑ ↓", "pick a peer, or a message when the chat has focus"),
            ("r  e  d", "reply · edit · delete the message under the cursor"),
            ("1 – 5", "react 👍 ❤️ 😂 😮 😢"),
            ("esc", "abandon a pending reply or edit"),
            ("", ""),
            ("/connect <id>", "dial a peer by the EndpointId they gave you"),
            ("/name <alias>", "your own name for this peer — outranks their claim"),
            ("/whois", "their full EndpointId, which is the real identity"),
            ("/nick <name>", "change what you call yourself"),
            ("/send <path>", "send a file — needs a live connection"),
            ("/room create <name>", "start a room; then /room invite and /room kick"),
            ("/peers  /whoami", "who is around · your own key, copied to the clipboard"),
            ("/mouse", "hand the mouse back so you can select and copy text"),
            ("/leave", "sign yourself out of the selected room"),
            ("/clear", "empty this conversation but keep the contact"),
            ("/forget", "delete a conversation and the contact — no undo"),
            ("/wipe", "delete every conversation on this machine"),
            ("/quit", "leave"),
            ("", ""),
            ("→ ✉ !", "sent over the wire · left on the hub · went nowhere"),
            ("name?", "a name they claim, that you have not confirmed"),
        ];
        let lines: Vec<Line> = rows
            .into_iter()
            .map(|(k, v)| {
                if k.is_empty() {
                    Line::default()
                } else {
                    Line::from(vec![
                        Span::styled(format!("  {k:<20}"), key),
                        Span::styled(v.to_string(), dim),
                    ])
                }
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(Color::Cyan))
                    .title(" help — any key to close "),
            ),
            area,
        );
    }

    fn draw_input(&self, frame: &mut Frame, area: Rect) {
        let title = match self.pending {
            Some(Pending::Reply(id)) => format!("reply to {id} — esc cancels"),
            Some(Pending::Edit(id)) => format!("edit {id} — esc cancels"),
            None => "message".into(),
        };
        let inner_width = (area.width.saturating_sub(2) as usize).max(1);
        // Scroll the single-line editor so the caret stays visible.
        let caret_col = self.input[..self.caret].width();
        let offset = caret_col.saturating_sub(inner_width.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(self.input.as_str())
                .scroll((0, offset as u16))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(if self.focus == Focus::Input {
                            Style::new().fg(Color::Cyan)
                        } else {
                            Style::new().fg(Color::DarkGray)
                        })
                        .title(title),
                ),
            area,
        );
        if self.focus == Focus::Input {
            frame.set_cursor_position((area.x + 1 + (caret_col - offset) as u16, area.y + 1));
        }
    }

    fn block(&self, title: &'static str, focus: Focus) -> Block<'static> {
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(if self.focus == focus {
                Style::new().fg(Color::Cyan)
            } else {
                Style::new().fg(Color::DarkGray)
            })
            .title(title)
    }
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn progress_bar(done: u64, total: u64) -> String {
    const WIDTH: usize = 20;
    let filled = if total == 0 {
        0
    } else {
        (done as u128 * WIDTH as u128 / total.max(1) as u128) as usize
    }
    .min(WIDTH);
    format!(
        "[{}{}] {}/{}",
        "=".repeat(filled),
        " ".repeat(WIDTH - filled),
        human(done),
        human(total)
    )
}

fn first_line(text: &str, width: usize) -> String {
    let one = text.split('\n').next().unwrap_or("");
    match wrap(one, width).into_iter().next() {
        Some(l) if l.width() < one.width() => format!("{l}…"),
        Some(l) => l,
        None => String::new(),
    }
}

/// The drawable area inside a bordered block.
fn inner(area: Rect) -> Rect {
    Rect {
        x: area.x.saturating_add(1),
        y: area.y.saturating_add(1),
        width: area.width.saturating_sub(2),
        height: area.height.saturating_sub(2),
    }
}

fn inside(area: Rect, x: u16, y: u16) -> bool {
    x >= area.x && x < area.x + area.width && y >= area.y && y < area.y + area.height
}

/// Byte offset of the character drawn at `column`, so clicking in the input bar
/// puts the caret where it looks like it should be.
fn byte_at_column(text: &str, column: usize) -> usize {
    let mut width = 0;
    for (i, c) in text.char_indices() {
        if width >= column {
            return i;
        }
        width += c.width().unwrap_or(0);
    }
    text.len()
}

/// `MessageId` has carried a timestamp since the first milestone; this is where
/// it finally gets used. The sender's clock is not trusted for ordering — `seq`
/// does that — so this is a display hint and nothing more.
fn clock(ts_ms: u64) -> String {
    chrono::DateTime::from_timestamp_millis(ts_ms as i64)
        .map(|t| t.with_timezone(&chrono::Local).format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

/// The day a message landed on, for the separator between them.
fn day(ts_ms: u64) -> Option<chrono::NaiveDate> {
    chrono::DateTime::from_timestamp_millis(ts_ms as i64)
        .map(|t| t.with_timezone(&chrono::Local).date_naive())
}

/// A centred `──── label ────` rule, used for day breaks and the unread mark.
fn rule(label: &str, width: usize) -> String {
    let bar = "─".repeat(width.saturating_sub(label.width() + 2) / 2);
    format!("{bar} {label} {bar}")
}

fn day_label(date: chrono::NaiveDate) -> String {
    let today = chrono::Local::now().date_naive();
    match (today - date).num_days() {
        0 => "today".into(),
        1 => "yesterday".into(),
        2..=6 => date.format("%A").to_string(),
        _ => date.format("%A, %e %B").to_string().replace("  ", " "),
    }
}

fn parse_key(hex: &str) -> Option<[u8; 32]> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .ok()?
        .as_slice()
        .try_into()
        .ok()
}

/// Splits a line so `@nickname` stands out, and stands out more when it is
/// yours. Nicknames are local metadata, so this is a display convenience and
/// nothing addresses anyone by it.
fn mention_spans(text: &str, me: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut rest = text;
    while let Some(at) = rest.find('@') {
        if at > 0 {
            spans.push(Span::raw(rest[..at].to_string()));
        }
        let tail = &rest[at..];
        let end = tail[1..]
            .find(|c: char| c.is_whitespace() || c == ',' || c == '.')
            .map_or(tail.len(), |i| i + 1);
        let (mention, after) = tail.split_at(end);
        let style = if mention[1..].eq_ignore_ascii_case(me) {
            Style::new().fg(Color::Black).bg(Color::Yellow)
        } else {
            Style::new().fg(Color::Blue).add_modifier(Modifier::BOLD)
        };
        spans.push(Span::styled(mention.to_string(), style));
        rest = after;
    }
    if !rest.is_empty() {
        spans.push(Span::raw(rest.to_string()));
    }
    spans
}

/// Puts text on the system clipboard with OSC 52, which the terminal forwards
/// even over ssh — the reason `/whoami` can hand you a 64-character key without
/// you dragging across a pane to select it.
///
// ponytail: no check that the terminal honours it. The status line says what
// was copied, so a terminal that ignores OSC 52 still shows you the value.
fn copy_to_clipboard(text: &str) {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(text);
    // Written straight to the tty: ratatui's buffer would treat it as content.
    let _ = std::io::Write::write_all(
        &mut std::io::stdout(),
        format!("\x1b]52;c;{encoded}\x07").as_bytes(),
    );
    let _ = std::io::Write::flush(&mut std::io::stdout());
}

/// Below this a bubble has no room to breathe, so the pane falls back to the
/// compact layout. Four tmux panes on one screen land right around here.
const BUBBLE_MIN_PANE: usize = 50;
/// Long lines are hard to read however much room there is.
const BUBBLE_MAX: usize = 60;

/// One message drawn as a bubble, returning the lines it occupies.
///
/// `mine` puts it against the right edge with no name on it — yours is obvious
/// — and `theirs` against the left under a name. The meta line underneath
/// carries the clock and, for your own, the delivery mark, which is where a
/// phone would put its ticks.
struct Bubble<'a> {
    body: Vec<String>,
    quoted: Option<String>,
    name: Option<String>,
    meta: String,
    colour: Color,
    mine: bool,
    pane: usize,
    style: Style,
    marker: Option<(&'a str, Color)>,
}

impl Bubble<'_> {
    fn render(self, out: &mut Vec<Line<'static>>) {
        let inner = self
            .body
            .iter()
            .chain(self.quoted.iter())
            .map(|l| l.width())
            .max()
            .unwrap_or(0)
            .max(self.meta.width())
            .min(self.pane.saturating_sub(5));
        let box_w = inner + 4;
        // One column of air on the right, so a bubble never fuses with the
        // pane border.
        let pad = if self.mine {
            self.pane.saturating_sub(box_w + 1)
        } else {
            0
        };
        let gap = " ".repeat(pad);
        let bar = "─".repeat(box_w.saturating_sub(2));
        let edge = Style::new().fg(self.colour);

        if let Some(name) = self.name {
            out.push(Line::from(Span::styled(format!("{gap}{name}"), edge)));
        }
        out.push(Line::from(Span::styled(format!("{gap}╭{bar}╮"), edge)));
        if let Some(quote) = self.quoted {
            out.push(Line::from(vec![
                Span::styled(format!("{gap}│ "), edge),
                Span::styled(
                    format!("{quote:<inner$}"),
                    Style::new().fg(Color::DarkGray).add_modifier(Modifier::ITALIC),
                ),
                Span::styled(" │", edge),
            ]));
        }
        for line in self.body {
            let pad_to = inner.saturating_sub(line.width());
            out.push(Line::from(vec![
                Span::styled(format!("{gap}│ "), edge),
                Span::styled(line, self.style),
                Span::styled(format!("{:pad_to$} │", ""), edge),
            ]));
        }
        out.push(Line::from(Span::styled(format!("{gap}╰{bar}╯"), edge)));

        // The clock sits under the bubble on the side the bubble is on. The
        // delivery mark is counted in the alignment, or it lands past the edge.
        let mark_w = self.marker.map_or(0, |(g, _)| g.width() + 1);
        let mut meta = vec![Span::styled(
            if self.mine {
                format!(
                    "{:>w$}",
                    self.meta,
                    w = (pad + box_w).saturating_sub(1 + mark_w)
                )
            } else {
                format!("{gap} {}", self.meta)
            },
            Style::new().fg(Color::DarkGray),
        )];
        if let Some((glyph, colour)) = self.marker {
            meta.push(Span::styled(format!(" {glyph}"), Style::new().fg(colour)));
        }
        out.push(Line::from(meta));
    }
}

/// Word wrap on display width, hard-splitting any word wider than the column.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut out = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split_whitespace() {
            if !line.is_empty() && line.width() + 1 + word.width() > width {
                out.push(std::mem::take(&mut line));
            }
            if word.width() > width {
                // A word that can never fit is split mid-word rather than
                // pushed past the border.
                for c in word.chars() {
                    if !line.is_empty() && line.width() + c.width().unwrap_or(0) > width {
                        out.push(std::mem::take(&mut line));
                    }
                    line.push(c);
                }
            } else {
                if !line.is_empty() {
                    line.push(' ');
                }
                line.push_str(word);
            }
        }
        out.push(line);
    }
    out
}

/// Runs the UI until the user quits or the network side hangs up.
pub async fn run(mut ui: Ui, mut events: mpsc::UnboundedReceiver<UiEvent>) -> Result<()> {
    // `init` installs the panic hook that restores the terminal — without it a
    // crash mid-demo leaves the shell in raw mode with no echo.
    let mut terminal = ratatui::init();
    let result = event_loop(&mut ui, &mut events, &mut terminal).await;
    // Mouse capture is ours, not ratatui's, so it is ours to hand back.
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    result
}

async fn event_loop(
    ui: &mut Ui,
    events: &mut mpsc::UnboundedReceiver<UiEvent>,
    terminal: &mut ratatui::DefaultTerminal,
) -> Result<()> {
    // crossterm's reader is blocking, so it lives on its own thread rather than
    // pulling in the async event-stream feature.
    let (keys_tx, mut keys) = mpsc::unbounded_channel();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if keys_tx.send(ev).is_err() {
                break;
            }
        }
    });

    let mut capturing = false;
    terminal.draw(|f| ui.draw(f))?;
    loop {
        // `/mouse` flips the flag; the terminal is told here, where the IO lives.
        if ui.mouse != capturing {
            let out = &mut std::io::stdout();
            let _ = if ui.mouse {
                execute!(out, EnableMouseCapture)
            } else {
                execute!(out, DisableMouseCapture)
            };
            capturing = ui.mouse;
        }
        tokio::select! {
            key = keys.recv() => match key {
                Some(Event::Key(key)) => if !ui.on_key(key) { return Ok(()) },
                Some(Event::Mouse(m)) => ui.on_mouse(m),
                Some(_) => {}
                None => return Ok(()),
            },
            ev = events.recv() => match ev {
                Some(ev) => ui.apply(ev),
                None => return Ok(()),
            },
        }
        terminal.draw(|f| ui.draw(f))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: MessageId, body: &str, outbound: bool) -> Entry {
        Entry {
            id,
            body: body.into(),
            outbound,
            deleted: false,
            reply_to: None,
            reactions: Vec::new(),
            attachment: None,
        }
    }

    #[test]
    fn sizes_and_progress_read_sensibly() {
        assert_eq!(human(512), "512 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(1536), "1.5 KiB");
        assert_eq!(human(3 * 1024 * 1024), "3.0 MiB");
        assert!(progress_bar(0, 100).starts_with("[                    ]"));
        assert!(progress_bar(50, 100).starts_with("[==========          ]"));
        assert!(progress_bar(100, 100).starts_with("[====================]"));
        // A peer that lies about the size must not panic the renderer.
        assert!(progress_bar(200, 100).starts_with("[====================]"));
        assert!(progress_bar(5, 0).starts_with("["));
    }

    fn id(sender: u8, seq: u64) -> MessageId {
        MessageId {
            sender: [sender; 32],
            seq,
            ts_ms: seq,
        }
    }

    fn ui() -> (Ui, mpsc::UnboundedReceiver<UiCommand>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Ui::new("mykey".into(), "me".into(), tx), rx)
    }

    fn press(ui: &mut Ui, c: char) -> bool {
        ui.on_key(KeyEvent::from(KeyCode::Char(c)))
    }

    #[test]
    fn wrapping_respects_width_and_splits_long_words() {
        assert_eq!(wrap("a b c", 5), vec!["a b c"]);
        assert_eq!(wrap("hello world", 5), vec!["hello", "world"]);
        assert_eq!(wrap("aaaaaaa", 3), vec!["aaa", "aaa", "a"]);
        assert_eq!(wrap("one\ntwo", 10), vec!["one", "two"]);
        assert!(wrap("日本語のテキスト", 6).iter().all(|l| l.width() <= 6));
        assert_eq!(first_line("a long line here", 6), "a long…");
    }

    #[test]
    fn caret_edits_stay_on_char_boundaries() {
        let (mut ui, _rx) = ui();
        for c in "héllo".chars() {
            press(&mut ui, c);
        }
        assert_eq!(ui.input, "héllo");
        for _ in 0..3 {
            ui.on_key(KeyEvent::from(KeyCode::Left));
        }
        ui.on_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(ui.input, "hllo");
        ui.on_key(KeyEvent::from(KeyCode::Home));
        ui.on_key(KeyEvent::from(KeyCode::Delete));
        assert_eq!(ui.input, "llo");
    }

    #[test]
    fn ctrl_c_and_slash_quit_both_stop() {
        let (mut ui, mut rx) = ui();
        assert!(!ui.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Quit));

        for c in "/quit".chars() {
            press(&mut ui, c);
        }
        assert!(!ui.on_key(KeyEvent::from(KeyCode::Enter)));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Quit));
    }

    #[test]
    fn slash_commands_report_without_sending() {
        let (mut ui, mut rx) = ui();
        ui.apply(UiEvent::Connected {
            peer: [7; 32],
            nick: "bob".into(),
            path: "direct".into(),
        });
        for line in ["/whoami", "/peers", "/nope"] {
            for c in line.chars() {
                press(&mut ui, c);
            }
            assert!(ui.on_key(KeyEvent::from(KeyCode::Enter)));
        }
        assert!(ui.status.contains("unknown command /nope"));
        assert!(rx.try_recv().is_err(), "no network traffic from a report");

        for c in "/nick satya".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Nick("satya".into())));
        assert_eq!(ui.nickname, "satya");
    }

    #[test]
    fn reply_edit_delete_and_react_key_off_the_cursor() {
        let (mut ui, mut rx) = ui();
        let peer = [7u8; 32];
        let theirs = id(7, 1);
        let mine = id(1, 2);
        ui.apply(UiEvent::Log {
            peer,
            entries: vec![entry(theirs, "their message", false), entry(mine, "mine", true)],
        });
        ui.focus = Focus::Chat;

        // Cursor lands on the newest message, which is mine.
        press(&mut ui, 'd');
        assert_eq!(rx.try_recv(), Ok(UiCommand::Delete { peer, target: mine }));

        press(&mut ui, 'e');
        assert_eq!(ui.input, "mine");
        for c in " edited".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Edit {
                peer,
                target: mine,
                body: "mine edited".into()
            })
        );

        // Move up to theirs: editing and deleting are refused, replying is not.
        ui.focus = Focus::Chat;
        ui.on_key(KeyEvent::from(KeyCode::Up));
        press(&mut ui, 'e');
        assert!(ui.status.contains("only edit your own"));
        press(&mut ui, 'd');
        assert!(ui.status.contains("only delete your own"));
        assert!(rx.try_recv().is_err());

        press(&mut ui, 'r');
        for c in "sure".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Send {
                peer,
                body: "sure".into(),
                reply_to: Some(theirs)
            })
        );

        // Reacting toggles against what is already there.
        ui.focus = Focus::Chat;
        press(&mut ui, '1');
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::React {
                peer,
                target: theirs,
                emoji: "👍".into(),
                on: true
            })
        );
        let mut reacted = entry(theirs, "their message", false);
        reacted.reactions = vec![("👍".into(), 1, true)];
        ui.apply(UiEvent::Log {
            peer,
            entries: vec![reacted, entry(mine, "mine", true)],
        });
        ui.focus = Focus::Chat;
        ui.on_key(KeyEvent::from(KeyCode::Up));
        press(&mut ui, '1');
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::React {
                peer,
                target: theirs,
                emoji: "👍".into(),
                on: false
            })
        );
    }

    #[test]
    fn mentions_are_split_out_and_yours_looks_different() {
        let spans = mention_spans("hey @satya and @bob, look", "satya");
        let text: Vec<&str> = spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, vec!["hey ", "@satya", " and ", "@bob", ", look"]);
        assert_ne!(spans[1].style, spans[3].style, "your own mention stands out");
        assert_eq!(mention_spans("no mentions", "satya").len(), 1);
        assert_eq!(mention_spans("", "satya").len(), 0);
    }

    #[test]
    fn clicks_land_on_whatever_was_drawn_under_them() {
        let (mut ui, _rx) = ui();
        ui.apply(UiEvent::Known { peer: [1; 32], nick: Some("one".into()), alias: None });
        ui.apply(UiEvent::Known { peer: [2; 32], nick: Some("two".into()), alias: None });
        // Pretend a frame was drawn: 20-wide sidebar, chat beside it, input below.
        ui.peers_area = Rect { x: 0, y: 0, width: 20, height: 10 };
        ui.chat_area = Rect { x: 20, y: 0, width: 40, height: 10 };
        ui.input_area = Rect { x: 0, y: 10, width: 60, height: 3 };
        ui.chat_rows = vec![usize::MAX, 0, 1];

        let click = |x, y| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        };

        // Second row of the peer list is the second peer.
        ui.on_mouse(click(3, 2));
        assert_eq!(ui.focus, Focus::Peers);
        assert_eq!(ui.sel, 1);

        // A click past the last peer moves focus but selects nothing new.
        ui.on_mouse(click(3, 8));
        assert_eq!(ui.sel, 1);

        // The input bar takes the caret to the character under the pointer.
        ui.on_mouse(click(1, 11));
        assert_eq!(ui.focus, Focus::Input);
        for c in "hello".chars() {
            press(&mut ui, c);
        }
        assert_eq!(ui.caret, 5);
        ui.on_mouse(click(3, 11));
        assert_eq!(ui.caret, 2, "caret follows the pointer");

        // Padding rows in the chat pane are not messages.
        ui.on_mouse(click(25, 1));
        assert_eq!(ui.focus, Focus::Chat);

        // Scrolling over the chat pane scrolls; elsewhere it changes peer.
        let wheel = |kind, x, y| MouseEvent { kind, column: x, row: y, modifiers: KeyModifiers::NONE };
        ui.on_mouse(wheel(MouseEventKind::ScrollUp, 25, 5));
        assert_eq!(ui.scroll, 3);
        ui.on_mouse(wheel(MouseEventKind::ScrollDown, 25, 5));
        assert_eq!(ui.scroll, 0);
        let before = ui.sel;
        ui.on_mouse(wheel(MouseEventKind::ScrollDown, 3, 3));
        assert_ne!(ui.sel, before, "wheel over the sidebar changes conversation");
    }

    #[test]
    fn byte_at_column_respects_wide_characters() {
        assert_eq!(byte_at_column("hello", 0), 0);
        assert_eq!(byte_at_column("hello", 3), 3);
        assert_eq!(byte_at_column("hello", 99), 5);
        // 'é' is two bytes, one column.
        assert_eq!(byte_at_column("héllo", 2), 3);
        // CJK is one char, two columns.
        assert_eq!(byte_at_column("日本", 2), 3);
    }

    #[test]
    fn mouse_toggle_flips_and_reports() {
        let (mut ui, _rx) = ui();
        assert!(ui.mouse, "clicking works out of the box");
        for c in "/mouse".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(!ui.mouse && ui.status.contains("select and copy"));
        for c in "/mouse".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(ui.mouse);
    }

    #[test]
    fn shift_tab_cycles_the_other_way() {
        let (mut ui, _rx) = ui();
        assert_eq!(ui.focus, Focus::Input);
        ui.on_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(ui.focus, Focus::Chat);
        ui.on_key(KeyEvent::from(KeyCode::BackTab));
        assert_eq!(ui.focus, Focus::Peers);
        ui.on_key(KeyEvent::from(KeyCode::Tab));
        assert_eq!(ui.focus, Focus::Chat);
    }

    #[test]
    fn forget_asks_before_it_deletes() {
        let (mut ui, mut rx) = ui();
        let peer = [7u8; 32];
        ui.apply(UiEvent::Known { peer, nick: Some("bob".into()), alias: None });

        // A bare /forget only warns.
        for c in "/forget".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Forget { peer, confirm: false }),
            "a bare /forget only asks"
        );
        assert_eq!(ui.peers.len(), 1);

        // Confirming does.
        for c in "/forget yes".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Forget { peer, confirm: true }));

        // The peer only leaves the list when the store says it is gone.
        assert_eq!(ui.peers.len(), 1);
        ui.apply(UiEvent::Forgotten { peer });
        assert!(ui.peers.is_empty());
        assert_eq!(ui.sel, 0, "selection must not dangle past the end");
    }

    #[test]
    fn forgetting_keeps_the_peer_index_consistent() {
        let (mut ui, _rx) = ui();
        for n in [1u8, 2, 3] {
            ui.apply(UiEvent::Known { peer: [n; 32], nick: None, alias: None });
        }
        ui.sel = 2;
        ui.apply(UiEvent::Forgotten { peer: [1; 32] });
        assert_eq!(ui.peers.len(), 2);
        // The survivors keep working: a log for the last one must still land.
        ui.apply(UiEvent::Log {
            peer: [3; 32],
            entries: vec![entry(id(3, 1), "still here", false)],
        });
        let three = ui.peers.iter().find(|p| p.key == [3u8; 32]).unwrap();
        assert_eq!(three.log.len(), 1, "index rebuilt correctly after removal");
    }

    #[test]
    fn a_name_you_chose_outranks_the_one_they_claim() {
        let (mut ui, mut rx) = ui();
        let peer = [7u8; 32];

        // Nothing known: fall back to the key, which is at least true.
        ui.apply(UiEvent::Known { peer, nick: None, alias: None });
        assert_eq!(ui.peers[0].label(), short(&peer));
        assert!(ui.peers[0].named(), "a key is not a claim");

        // They introduce themselves. That is a claim, not a fact.
        ui.apply(UiEvent::Known { peer, nick: Some("bob".into()), alias: None });
        assert_eq!(ui.peers[0].label(), "bob");
        assert!(!ui.peers[0].named(), "an unverified name must be marked");

        // You name them. Yours wins, and the display is trusted again.
        for c in "/name Bob from work".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Name { peer, alias: Some("Bob from work".into()) })
        );
        assert_eq!(ui.peers[0].label(), "Bob from work");
        assert!(ui.peers[0].named());

        // An impostor cannot take the name over by claiming it.
        ui.apply(UiEvent::Known {
            peer,
            nick: Some("Bob from work".into()),
            alias: Some("Bob from work".into()),
        });
        assert_eq!(ui.peers[0].label(), "Bob from work");

        // whois always shows the key, which is the part that means something.
        for c in "/whois".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(ui.status.contains(&"07".repeat(32)), "{}", ui.status);

        // Bare /name forgets it and the claim goes back to being a claim.
        for c in "/name".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Name { peer, alias: None }));
        assert!(!ui.peers[0].named());
    }

    #[test]
    fn connect_takes_an_endpoint_id_and_rejects_junk() {
        let (mut ui, mut rx) = ui();
        let peer = [9u8; 32];
        for c in format!("/connect {}", data_encoding::HEXLOWER.encode(&peer)).chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(rx.try_recv(), Ok(UiCommand::Connect(peer)));

        for line in ["/connect", "/connect nonsense", "/connect abcd"] {
            for c in line.chars() {
                press(&mut ui, c);
            }
            ui.on_key(KeyEvent::from(KeyCode::Enter));
            assert!(ui.status.contains("usage: /connect"), "{line}");
            assert!(rx.try_recv().is_err(), "{line} must not dial");
        }
    }

    #[test]
    fn room_commands_need_a_room_selected() {
        let (mut ui, mut rx) = ui();
        let member = [7u8; 32];
        let member_hex = data_encoding::HEXLOWER.encode(&member);

        for c in "/room create kitchen".chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Room(RoomCommand::Create("kitchen".into())))
        );

        // Invite with a person selected, not a room.
        ui.apply(UiEvent::Known {
            peer: member,
            nick: None,
            alias: None,
        });
        for c in format!("/room invite {member_hex}").chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(ui.status.contains("select a room first"));
        assert!(rx.try_recv().is_err());

        // Now with the room selected.
        let room = [1u8; 32];
        ui.apply(UiEvent::Room {
            id: room,
            view: RoomView {
                name: "kitchen".into(),
                members: 1,
                joined: true,
            },
        });
        ui.sel = 1;
        for c in format!("/room kick {member_hex}").chars() {
            press(&mut ui, c);
        }
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(
            rx.try_recv(),
            Ok(UiCommand::Room(RoomCommand::Kick { room, member }))
        );
    }

    #[test]
    fn escape_abandons_a_pending_edit() {
        let (mut ui, mut rx) = ui();
        ui.apply(UiEvent::Log {
            peer: [7; 32],
            entries: vec![entry(id(1, 1), "mine", true)],
        });
        ui.focus = Focus::Chat;
        press(&mut ui, 'e');
        assert!(ui.pending.is_some());
        ui.on_key(KeyEvent::from(KeyCode::Esc));
        assert!(ui.pending.is_none() && ui.input.is_empty());
        ui.on_key(KeyEvent::from(KeyCode::Enter));
        assert!(rx.try_recv().is_err());
    }
}
