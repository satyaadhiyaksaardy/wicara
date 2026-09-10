//! The local message store: sqlite, with every operation sealed in application
//! code under the same passphrase-derived key as the identity file.
//!
//! Not SQLCipher — that is a C dependency that would fight the Windows
//! cross-compile in M6, for a job this column does already.
//!
//! One table holds every op — a message, an edit, a delete, a reaction — keyed
//! by its own [`MessageId`]. That makes replay idempotent for free (the M3
//! mailbox can redeliver anything), and it keeps who-replied-to-what inside the
//! sealed payload instead of in an indexable column.

use std::{
    collections::HashMap,
    path::Path,
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use wicara_core::{
    room::{RoomEntry, RoomId},
    vault::VaultKey,
    wire::{Counter, Frame, MessageId},
};

pub struct Store {
    conn: Connection,
    vault: VaultKey,
    counter: Counter,
    me: [u8; 32],
}

pub struct Message {
    pub id: MessageId,
    pub body: String,
    /// True when this endpoint sent it.
    pub outbound: bool,
    pub deleted: bool,
    pub reply_to: Option<MessageId>,
    /// `(emoji, count, whether this endpoint is one of them)`.
    pub reactions: Vec<(String, usize, bool)>,
}

impl Store {
    /// `me` is this endpoint's key; the send counter resumes from the highest
    /// `seq` already on disk so a restart never reissues an id.
    pub fn open(path: &Path, vault: VaultKey, me: [u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening message store at {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS ops (
                 sender  BLOB    NOT NULL,
                 seq     INTEGER NOT NULL,
                 ts_ms   INTEGER NOT NULL,
                 peer    BLOB    NOT NULL,
                 payload BLOB    NOT NULL,
                 PRIMARY KEY (sender, seq, ts_ms)
             );
             CREATE INDEX IF NOT EXISTS ops_by_peer ON ops (peer, ts_ms);
             CREATE TABLE IF NOT EXISTS rooms (id BLOB PRIMARY KEY, log BLOB NOT NULL);",
        )?;
        let resume: i64 = conn
            .query_row(
                "SELECT MAX(seq) FROM ops WHERE sender = ?1",
                params![&me[..]],
                |row| row.get(0),
            )
            .optional()?
            .flatten()
            .unwrap_or(0);
        Ok(Self {
            conn,
            vault,
            counter: Counter::new(me, resume as u64),
            me,
        })
    }

    pub fn next_id(&mut self) -> MessageId {
        self.counter.mint()
    }

    /// `peer` is always the other end of the conversation, whichever direction
    /// the op went. Returns false when the id was already stored — that is the
    /// dedup M3 needs, since an op can legitimately arrive by both the live
    /// path and the mailbox.
    pub fn record(&self, peer: &[u8; 32], frame: &Frame) -> Result<bool> {
        let Some(id) = frame.id() else {
            return Ok(false);
        };
        let payload = self.vault.seal(&postcard::to_stdvec(frame)?)?;
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO ops (sender, seq, ts_ms, peer, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                &id.sender[..],
                id.seq as i64,
                id.ts_ms as i64,
                &peer[..],
                payload
            ],
        )?;
        Ok(rows == 1)
    }

    /// Every peer this endpoint has exchanged an op with, most recent first.
    pub fn peers(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self
            .conn
            .prepare("SELECT peer FROM ops GROUP BY peer ORDER BY MAX(ts_ms) DESC")?;
        let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(
                row?.as_slice()
                    .try_into()
                    .context("message store holds a malformed peer key")?,
            );
        }
        Ok(out)
    }

    /// Folds the op log into the conversation as it stands, newest `limit`
    /// messages, oldest first.
    ///
    /// Edits and deletes are honoured only when the op's sender is the author of
    /// the message it targets. That check lives here rather than at the network
    /// edge so it holds however the op arrived — live, mailbox, or replay.
    ///
    // ponytail: the whole log is refolded on every call. Fine into the tens of
    // thousands of ops; materialise a rolled-up table if a conversation outgrows
    // that.
    pub fn history(&self, peer: &[u8; 32], limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT sender, seq, ts_ms, payload FROM ops
             WHERE peer = ?1 ORDER BY ts_ms, seq",
        )?;
        let rows = stmt.query_map(params![&peer[..]], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut messages: Vec<Message> = Vec::new();
        let mut at: HashMap<MessageId, usize> = HashMap::new();
        // (target, emoji, reactor) -> on. Last op wins, so a toggle is settled
        // by order, not by both ends agreeing on a count.
        let mut reactions: HashMap<(MessageId, String, [u8; 32]), bool> = HashMap::new();

        for row in rows {
            let (sender, seq, ts_ms, payload) = row?;
            let sender: [u8; 32] = sender
                .as_slice()
                .try_into()
                .context("message store holds a malformed sender key")?;
            let id = MessageId {
                sender,
                seq: seq as u64,
                ts_ms: ts_ms as u64,
            };
            let frame: Frame = postcard::from_bytes(&self.vault.open(&payload)?)?;

            match frame {
                Frame::Chat { body, reply_to, .. } => {
                    at.insert(id, messages.len());
                    messages.push(Message {
                        id,
                        body,
                        outbound: sender == self.me,
                        deleted: false,
                        reply_to,
                        reactions: Vec::new(),
                    });
                }
                Frame::Edit { target, body, .. } if target.sender == sender => {
                    if let Some(&i) = at.get(&target) {
                        messages[i].body = body;
                    }
                }
                Frame::Delete { target, .. } if target.sender == sender => {
                    if let Some(&i) = at.get(&target) {
                        messages[i].deleted = true;
                        messages[i].body.clear();
                    }
                }
                Frame::React {
                    target, emoji, on, ..
                } => {
                    reactions.insert((target, emoji, sender), on);
                }
                // An edit or delete of someone else's message, or a Hello that
                // should never have been stored.
                _ => tracing::debug!(%id, "ignoring op that is not the author's to make"),
            }
        }

        for ((target, emoji, reactor), on) in reactions {
            if !on {
                continue;
            }
            let Some(&i) = at.get(&target) else { continue };
            let mine = reactor == self.me;
            match messages[i].reactions.iter_mut().find(|(e, _, _)| *e == emoji) {
                Some(slot) => {
                    slot.1 += 1;
                    slot.2 |= mine;
                }
                None => messages[i].reactions.push((emoji, 1, mine)),
            }
        }
        for msg in &mut messages {
            msg.reactions.sort_by(|a, b| a.0.cmp(&b.0));
        }

        let skip = messages.len().saturating_sub(limit);
        Ok(messages.split_off(skip))
    }

    /// Keeps the room's log locally so membership survives a hub that is down
    /// or hostile. It is re-verified on the way out, never trusted for being
    /// on our own disk.
    pub fn save_room(&self, id: &RoomId, entries: &[RoomEntry]) -> Result<()> {
        self.conn.execute(
            "INSERT INTO rooms (id, log) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET log = excluded.log",
            params![&id[..], self.vault.seal(&postcard::to_stdvec(entries)?)?],
        )?;
        Ok(())
    }

    pub fn rooms(&self) -> Result<Vec<(RoomId, Vec<RoomEntry>)>> {
        let mut stmt = self.conn.prepare("SELECT id, log FROM rooms")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, log) = row?;
            let id: RoomId = id
                .as_slice()
                .try_into()
                .context("message store holds a malformed room id")?;
            out.push((id, postcard::from_bytes(&self.vault.open(&log)?)?));
        }
        Ok(out)
    }

    /// Local, freely changeable display name. Kept beside the ops rather than in
    /// a config file so it travels with the encrypted store.
    pub fn setting(&self, key: &str) -> Result<Option<String>> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )?;
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?;
        sealed
            .map(|v| Ok(String::from_utf8_lossy(&self.vault.open(&v)?).into_owned()))
            .transpose()
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
            [],
        )?;
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, self.vault.seal(value.as_bytes())?],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicara_core::vault::SALT_LEN;

    fn open(path: &Path, me: [u8; 32]) -> Store {
        Store::open(
            path,
            VaultKey::derive("test passphrase", &[3u8; SALT_LEN]).unwrap(),
            me,
        )
        .unwrap()
    }

    fn chat(id: MessageId, body: &str) -> Frame {
        Frame::Chat {
            id,
            body: body.into(),
            reply_to: None,
        }
    }

    #[test]
    fn folds_edits_deletes_and_reactions_and_refuses_forgeries() {
        let dir = std::env::temp_dir().join(format!("wicara-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ops.db");
        let _ = std::fs::remove_file(&path);

        let me = [1u8; 32];
        let peer = [2u8; 32];
        let mut store = open(&path, me);

        let mine = store.next_id();
        assert!(store.record(&peer, &chat(mine, "helo")).unwrap());
        // The same op arriving twice — live delivery and the M3 mailbox — stores once.
        assert!(!store.record(&peer, &chat(mine, "helo")).unwrap());

        let theirs = MessageId {
            sender: peer,
            seq: 1,
            ts_ms: mine.ts_ms + 1,
        };
        assert!(store.record(&peer, &chat(theirs, "hi")).unwrap());

        // I may fix my own typo.
        let fix = store.next_id();
        store
            .record(
                &peer,
                &Frame::Edit {
                    id: fix,
                    target: mine,
                    body: "hello".into(),
                },
            )
            .unwrap();

        // The peer may not edit or delete mine, however it asks.
        let forged_edit = MessageId {
            sender: peer,
            seq: 2,
            ts_ms: mine.ts_ms + 2,
        };
        store
            .record(
                &peer,
                &Frame::Edit {
                    id: forged_edit,
                    target: mine,
                    body: "words I never wrote".into(),
                },
            )
            .unwrap();
        let forged_delete = MessageId {
            sender: peer,
            seq: 3,
            ts_ms: mine.ts_ms + 3,
        };
        store
            .record(
                &peer,
                &Frame::Delete {
                    id: forged_delete,
                    target: mine,
                },
            )
            .unwrap();

        // Reactions are a toggle, and anyone may react.
        for (n, on) in [(4u64, true), (5, false), (6, true)] {
            store
                .record(
                    &peer,
                    &Frame::React {
                        id: MessageId {
                            sender: peer,
                            seq: n,
                            ts_ms: mine.ts_ms + n,
                        },
                        target: mine,
                        emoji: "👍".into(),
                        on,
                    },
                )
                .unwrap();
        }
        let my_react = store.next_id();
        store
            .record(
                &peer,
                &Frame::React {
                    id: my_react,
                    target: mine,
                    emoji: "👍".into(),
                    on: true,
                },
            )
            .unwrap();

        let history = store.history(&peer, 10).unwrap();
        assert_eq!(history.len(), 2, "ops are not messages");
        assert_eq!(history[0].body, "hello", "my own edit applied");
        assert!(!history[0].deleted, "the peer's delete was refused");
        assert!(history[0].outbound);
        assert_eq!(history[0].reactions, vec![("👍".to_string(), 2, true)]);
        assert_eq!(history[1].body, "hi");
        assert!(!history[1].outbound);

        // I may delete my own.
        let del = store.next_id();
        store
            .record(&peer, &Frame::Delete { id: del, target: mine })
            .unwrap();
        let history = store.history(&peer, 10).unwrap();
        assert!(history[0].deleted && history[0].body.is_empty());

        // Reopening resumes the counter and reads everything back.
        drop(store);
        let mut reopened = open(&path, me);
        assert!(reopened.next_id().seq > del.seq);
        assert_eq!(reopened.history(&peer, 10).unwrap().len(), 2);
        reopened.set_setting("nickname", "satya").unwrap();
        assert_eq!(reopened.setting("nickname").unwrap().as_deref(), Some("satya"));

        // A different passphrase cannot read any of it back.
        let wrong = Store::open(
            &path,
            VaultKey::derive("wrong passphrase", &[3u8; SALT_LEN]).unwrap(),
            me,
        )
        .unwrap();
        assert!(wrong.history(&peer, 10).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
