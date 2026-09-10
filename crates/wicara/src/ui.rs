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

/// Pushed in by the network side.
#[derive(Debug)]
pub enum UiEvent {
    /// A peer we know about, from the store, before anyone is online.
    Known { peer: [u8; 32] },
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
    Message {
        peer: [u8; 32],
        id: MessageId,
        body: String,
        outbound: bool,
    },
    Status(String),
}

/// Pushed back out to the network side.
#[derive(Debug)]
pub enum UiCommand {
    Send { peer: [u8; 32], body: String },
    Quit,
}

#[derive(PartialEq, Clone, Copy)]
enum Focus {
    Peers,
    Input,
}

struct Entry {
    id: MessageId,
    body: String,
    outbound: bool,
}

struct Peer {
    key: [u8; 32],
    nick: Option<String>,
    online: bool,
    path: String,
    log: Vec<Entry>,
    unread: usize,
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
            });
            self.peers.len() - 1
        });
        &mut self.peers[idx]
    }

    fn apply(&mut self, ev: UiEvent) {
        match ev {
            UiEvent::Known { peer } => {
                self.peer_mut(peer);
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
            UiEvent::Message {
                peer,
                id,
                body,
                outbound,
            } => {
                let selected = self.selected_key() == Some(peer);
                let p = self.peer_mut(peer);
                p.log.push(Entry { id, body, outbound });
                if !selected && !outbound {
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

    /// Returns false when the app should quit.
    fn on_key(&mut self, key: KeyEvent) -> bool {
        if key.kind != KeyEventKind::Press {
            return true;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('q'))
        {
            let _ = self.commands.send(UiCommand::Quit);
            return false;
        }

        match key.code {
            KeyCode::Tab => {
                self.focus = if self.focus == Focus::Input {
                    Focus::Peers
                } else {
                    Focus::Input
                }
            }
            KeyCode::PageUp => self.scroll += 5,
            KeyCode::PageDown => self.scroll = self.scroll.saturating_sub(5),
            KeyCode::Up if self.focus == Focus::Peers => self.select(-1),
            KeyCode::Down if self.focus == Focus::Peers => self.select(1),
            KeyCode::Up => self.scroll += 1,
            KeyCode::Down => self.scroll = self.scroll.saturating_sub(1),
            KeyCode::Enter => return self.submit(),
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

    fn select(&mut self, delta: isize) {
        if self.peers.is_empty() {
            return;
        }
        let n = self.peers.len() as isize;
        self.sel = ((self.sel as isize + delta).rem_euclid(n)) as usize;
        self.scroll = 0;
        self.peers[self.sel].unread = 0;
    }

    /// Returns false when the line was a command that quits.
    fn submit(&mut self) -> bool {
        let body = std::mem::take(&mut self.input);
        self.caret = 0;
        let body = body.trim().to_string();
        if body.is_empty() {
            return true;
        }
        if body == "/quit" {
            let _ = self.commands.send(UiCommand::Quit);
            return false;
        }
        match self.selected_key() {
            Some(peer) => {
                let _ = self.commands.send(UiCommand::Send { peer, body });
                self.scroll = 0;
            }
            None => self.status = "no peer selected — nothing to send to".into(),
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
                Span::styled(format!(" {} ", self.nickname), Style::new().fg(Color::Black).bg(Color::Cyan)),
                Span::raw(format!(" {}  ", self.me)),
                Span::styled(&self.status, Style::new().fg(Color::DarkGray)),
                Span::styled(
                    "  tab · ↑↓ · enter · ^c",
                    Style::new().fg(Color::DarkGray),
                ),
            ])),
            status,
        );
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
                    .block(self.block("chat", Focus::Peers)),
                area,
            );
            return;
        };

        let width = area.width.saturating_sub(2).max(8) as usize;
        let mut lines: Vec<Line> = Vec::new();
        for entry in &peer.log {
            let (who, colour) = if entry.outbound {
                (self.nickname.as_str(), Color::Cyan)
            } else {
                (peer.nick.as_deref().unwrap_or("them"), Color::Magenta)
            };
            let prefix = format!("{who}: ");
            for (n, chunk) in wrap(&entry.body, width.saturating_sub(prefix.width()).max(8))
                .into_iter()
                .enumerate()
            {
                lines.push(if n == 0 {
                    Line::from(vec![
                        Span::styled(prefix.clone(), Style::new().fg(colour)),
                        Span::raw(chunk),
                    ])
                } else {
                    Line::from(format!("{:width$}{chunk}", "", width = prefix.width()))
                });
            }
            let _ = entry.id;
        }

        let height = area.height.saturating_sub(2) as usize;
        let max_scroll = lines.len().saturating_sub(height);
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
            Paragraph::new(view).block(Block::default().borders(Borders::ALL).title(title)),
            area,
        );
    }

    fn draw_input(&self, frame: &mut Frame, area: Rect) {
        let inner_width = area.width.saturating_sub(2).max(1) as usize;
        // Scroll the single-line editor so the caret stays visible.
        let caret_col = self.input[..self.caret].width();
        let offset = caret_col.saturating_sub(inner_width.saturating_sub(1));
        frame.render_widget(
            Paragraph::new(self.input.as_str())
                .scroll((0, offset as u16))
                .block(self.block("message", Focus::Input)),
            area,
        );
        if self.focus == Focus::Input {
            frame.set_cursor_position((
                area.x + 1 + (caret_col - offset) as u16,
                area.y + 1,
            ));
        }
    }

    fn block(&self, title: &'static str, focus: Focus) -> Block<'static> {
        let style = if self.focus == focus {
            Style::new().fg(Color::Cyan)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        Block::default()
            .borders(Borders::ALL)
            .border_style(style)
            .title(title)
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

    #[test]
    fn wrapping_respects_width_and_splits_long_words() {
        assert_eq!(wrap("a b c", 5), vec!["a b c"]);
        assert_eq!(wrap("hello world", 5), vec!["hello", "world"]);
        assert_eq!(wrap("aaaaaaa", 3), vec!["aaa", "aaa", "a"]);
        assert_eq!(wrap("one\ntwo", 10), vec!["one", "two"]);
        assert!(wrap("日本語のテキスト", 6).iter().all(|l| l.width() <= 6));
    }

    #[test]
    fn caret_edits_stay_on_char_boundaries() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut ui = Ui::new("me".into(), "me".into(), tx);
        for c in "héllo".chars() {
            ui.on_key(KeyEvent::from(KeyCode::Char(c)));
        }
        assert_eq!(ui.input, "héllo");
        ui.on_key(KeyEvent::from(KeyCode::Left));
        ui.on_key(KeyEvent::from(KeyCode::Left));
        ui.on_key(KeyEvent::from(KeyCode::Left));
        ui.on_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(ui.input, "hllo");
        ui.on_key(KeyEvent::from(KeyCode::Home));
        ui.on_key(KeyEvent::from(KeyCode::Delete));
        assert_eq!(ui.input, "llo");
    }

    #[test]
    fn ctrl_c_and_slash_quit_both_stop() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut ui = Ui::new("me".into(), "me".into(), tx);
        assert!(!ui.on_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
        assert!(matches!(rx.try_recv(), Ok(UiCommand::Quit)));

        for c in "/quit".chars() {
            ui.on_key(KeyEvent::from(KeyCode::Char(c)));
        }
        assert!(!ui.on_key(KeyEvent::from(KeyCode::Enter)));
        assert!(matches!(rx.try_recv(), Ok(UiCommand::Quit)));
    }
}
