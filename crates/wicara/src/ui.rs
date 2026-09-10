//! The terminal UI.
//!
//! It talks to the network over two channels and knows nothing else about it,
//! so it can be driven by a stub just as well as by a live iroh endpoint.

use std::collections::HashMap;

use anyhow::Result;
use ratatui::{
    Frame,
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
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
}

/// Pushed in by the network side.
#[derive(Debug)]
pub enum UiEvent {
    /// A peer we know about, from the store, before anyone is online. The
    /// nickname is whatever it last called itself.
    Known {
        peer: [u8; 32],
        nick: Option<String>,
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
    Status(String),
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
    Quit,
}

#[derive(PartialEq, Clone, Copy)]
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
    nick: Option<String>,
    online: bool,
    path: String,
    log: Vec<Entry>,
    unread: usize,
    /// Index into `log` of the message the chat cursor is on.
    cursor: usize,
}

impl Peer {
    fn label(&self) -> String {
        self.nick.clone().unwrap_or_else(|| short(&self.key))
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
    commands: mpsc::UnboundedSender<UiCommand>,
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
            commands,
        }
    }

    fn peer_mut(&mut self, key: [u8; 32]) -> &mut Peer {
        let idx = *self.index.entry(key).or_insert_with(|| {
            self.peers.push(Peer {
                key,
                nick: None,
                online: false,
                path: String::new(),
                log: Vec::new(),
                unread: 0,
                cursor: 0,
            });
            self.peers.len() - 1
        });
        &mut self.peers[idx]
    }

    fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::Known { peer, nick } => {
                self.peer_mut(peer).nick = nick;
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
                let grew = entries.len() > p.log.len();
                let at_end = p.cursor + 1 >= p.log.len();
                p.log = entries;
                if at_end {
                    p.cursor = p.log.len().saturating_sub(1);
                }
                p.cursor = p.cursor.min(p.log.len().saturating_sub(1));
                if grew && !selected {
                    p.unread += 1;
                }
                if selected {
                    self.scroll = 0;
                }
            }
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

        match key.code {
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Input => Focus::Peers,
                    Focus::Peers => Focus::Chat,
                    Focus::Chat => Focus::Input,
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

    fn select_peer(&mut self, delta: isize) {
        if self.peers.is_empty() {
            return;
        }
        let n = self.peers.len() as isize;
        self.sel = ((self.sel as isize + delta).rem_euclid(n)) as usize;
        self.scroll = 0;
        self.peers[self.sel].unread = 0;
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
            "whoami" => self.status = format!("{} — {}", self.nickname, self.me),
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
            other => self.status = format!("unknown command /{other}"),
        }
        true
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
            _ => "  tab focus · enter send · /peers /whoami /nick · ^c quit",
        }
    }

    fn draw_peers(&self, frame: &mut Frame, area: Rect) {
        // ponytail: peers only; rooms join this list at M4.
        let items: Vec<ListItem> = self
            .peers
            .iter()
            .map(|p| {
                let dot = if p.online { "●" } else { "○" };
                let colour = if p.online { Color::Green } else { Color::DarkGray };
                let mut spans = vec![
                    Span::styled(format!("{dot} "), Style::new().fg(colour)),
                    Span::raw(p.label()),
                ];
                if p.unread > 0 {
                    spans.push(Span::styled(
                        format!(" ({})", p.unread),
                        Style::new().fg(Color::Yellow),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let mut state = ListState::default().with_selected(Some(self.sel));
        frame.render_stateful_widget(
            List::new(items)
                .block(self.block("peers", Focus::Peers))
                .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
            area,
            &mut state,
        );
    }

    fn draw_chat(&mut self, frame: &mut Frame, area: Rect) {
        let Some(peer) = self.peers.get(self.sel) else {
            frame.render_widget(
                Paragraph::new("Paste a peer's EndpointId into `wicara run --connect` to begin.")
                    .block(self.block("chat", Focus::Chat)),
                area,
            );
            return;
        };

        let width = (area.width.saturating_sub(2) as usize).max(8);
        let mut lines: Vec<Line> = Vec::new();
        // Where the cursor's message starts and ends, so it can be scrolled to.
        let mut cursor_span = (0usize, 0usize);
        for (i, entry) in peer.log.iter().enumerate() {
            let start = lines.len();
            let (who, colour) = if entry.outbound {
                (self.nickname.as_str(), Color::Cyan)
            } else {
                (peer.nick.as_deref().unwrap_or("them"), Color::Magenta)
            };

            if let Some(target) = entry.reply_to {
                let quoted = match peer.log.iter().find(|e| e.id == target) {
                    Some(e) if e.deleted => "(deleted)",
                    Some(e) => e.body.as_str(),
                    None => "(message not here)",
                };
                lines.push(Line::from(Span::styled(
                    format!("  ┆ {}", first_line(quoted, width.saturating_sub(4))),
                    Style::new().fg(Color::DarkGray),
                )));
            }

            let prefix = format!("{who}: ");
            let body_width = width.saturating_sub(prefix.width()).max(8);
            if entry.deleted {
                lines.push(Line::from(vec![
                    Span::styled(prefix.clone(), Style::new().fg(colour)),
                    Span::styled("(deleted)", Style::new().fg(Color::DarkGray)),
                ]));
            } else {
                for (n, chunk) in wrap(&entry.body, body_width).into_iter().enumerate() {
                    lines.push(if n == 0 {
                        Line::from(vec![
                            Span::styled(prefix.clone(), Style::new().fg(colour)),
                            Span::raw(chunk),
                        ])
                    } else {
                        Line::from(format!("{:w$}{chunk}", "", w = prefix.width()))
                    });
                }
            }

            if !entry.reactions.is_empty() {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{:w$}{}",
                        "",
                        entry
                            .reactions
                            .iter()
                            .map(|(e, n, mine)| if *mine {
                                format!("[{e} {n}]")
                            } else {
                                format!("{e} {n}")
                            })
                            .collect::<Vec<_>>()
                            .join(" "),
                        w = prefix.width()
                    ),
                    Style::new().fg(Color::Yellow),
                )));
            }

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
        // Chat reads from the bottom, so a short log is padded above, not below.
        for _ in view.len()..height {
            view.insert(0, Line::default());
        }

        let title = if peer.path.is_empty() {
            format!("{} — offline", peer.label())
        } else {
            format!("{} — {}", peer.label(), peer.path)
        };
        frame.render_widget(
            Paragraph::new(view).block(
                Block::default()
                    .borders(Borders::ALL)
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
            .border_style(if self.focus == focus {
                Style::new().fg(Color::Cyan)
            } else {
                Style::new().fg(Color::DarkGray)
            })
            .title(title)
    }
}

fn first_line(text: &str, width: usize) -> String {
    let one = text.split('\n').next().unwrap_or("");
    match wrap(one, width).into_iter().next() {
        Some(l) if l.width() < one.width() => format!("{l}…"),
        Some(l) => l,
        None => String::new(),
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

    terminal.draw(|f| ui.draw(f))?;
    loop {
        tokio::select! {
            key = keys.recv() => match key {
                Some(Event::Key(key)) => if !ui.on_key(key) { return Ok(()) },
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
        }
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
