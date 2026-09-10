//! The local message store: sqlite, with the message body encrypted in
//! application code under the same passphrase-derived key as the identity file.
//!
//! Not SQLCipher — that is a C dependency that would fight the Windows
//! cross-compile in M6, for a job this column does already. The metadata columns
//! stay in the clear so sqlite can index them; the threat model says so plainly.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use wicara_core::{
    vault::VaultKey,
    wire::{Counter, MessageId},
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
}

impl Store {
    /// `me` is this endpoint's key; the send counter resumes from the highest
    /// `seq` already on disk so a restart never reissues an id.
    pub fn open(path: &Path, vault: VaultKey, me: [u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening message store at {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS messages (
                 sender  BLOB    NOT NULL,
                 seq     INTEGER NOT NULL,
                 ts_ms   INTEGER NOT NULL,
                 peer    BLOB    NOT NULL,
                 payload BLOB    NOT NULL,
                 PRIMARY KEY (sender, seq, ts_ms)
             );
             CREATE INDEX IF NOT EXISTS messages_by_peer ON messages (peer, ts_ms);",
        )?;
        let resume: i64 = conn
            .query_row(
                "SELECT MAX(seq) FROM messages WHERE sender = ?1",
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
    /// the message went. Returns false when the id was already stored — that is
    /// the dedup M3 needs, since a message can legitimately arrive by both the
    /// live path and the mailbox.
    pub fn insert(&self, peer: &[u8; 32], id: MessageId, body: &str) -> Result<bool> {
        let payload = self.vault.seal(body.as_bytes())?;
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO messages (sender, seq, ts_ms, peer, payload)
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

    /// Every peer this endpoint has exchanged a message with, most recent first.
    pub fn peers(&self) -> Result<Vec<[u8; 32]>> {
        let mut stmt = self.conn.prepare(
            "SELECT peer FROM messages GROUP BY peer ORDER BY MAX(ts_ms) DESC",
        )?;
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

    /// The most recent `limit` messages with `peer`, oldest first.
    pub fn history(&self, peer: &[u8; 32], limit: usize) -> Result<Vec<Message>> {
        let mut stmt = self.conn.prepare(
            "SELECT sender, seq, ts_ms, payload FROM messages
             WHERE peer = ?1 ORDER BY ts_ms DESC, seq DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![&peer[..], limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (sender, seq, ts_ms, payload) = row?;
            let sender: [u8; 32] = sender
                .as_slice()
                .try_into()
                .context("message store holds a malformed sender key")?;
            out.push(Message {
                id: MessageId {
                    sender,
                    seq: seq as u64,
                    ts_ms: ts_ms as u64,
                },
                body: String::from_utf8_lossy(&self.vault.open(&payload)?).into_owned(),
                outbound: sender == self.me,
            });
        }
        out.reverse();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wicara_core::vault::{SALT_LEN, VaultKey};

    fn open(path: &Path, me: [u8; 32]) -> Store {
        Store::open(path, VaultKey::derive("test passphrase", &[3u8; SALT_LEN]).unwrap(), me)
            .unwrap()
    }

    #[test]
    fn dedup_history_and_counter_resume() {
        let dir = std::env::temp_dir().join(format!("wicara-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("messages.db");
        let _ = std::fs::remove_file(&path);

        let me = [1u8; 32];
        let peer = [2u8; 32];
        let mut store = open(&path, me);

        let mine = store.next_id();
        assert!(store.insert(&peer, mine, "from me").unwrap());
        // The same id arriving twice — live delivery and the M3 mailbox — stores once.
        assert!(!store.insert(&peer, mine, "from me").unwrap());

        let theirs = MessageId {
            sender: peer,
            seq: 1,
            ts_ms: mine.ts_ms + 1,
        };
        assert!(store.insert(&peer, theirs, "from them").unwrap());

        let history = store.history(&peer, 10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].body, "from me");
        assert!(history[0].outbound);
        assert_eq!(history[1].body, "from them");
        assert!(!history[1].outbound);

        // A peer's message with the same seq as ours is a different message.
        assert_eq!(mine.seq, theirs.seq);

        // Reopening resumes the counter instead of reissuing ids.
        drop(store);
        let mut reopened = open(&path, me);
        assert!(reopened.next_id().seq > mine.seq);
        assert_eq!(reopened.history(&peer, 10).unwrap().len(), 2);

        // A different passphrase cannot read the bodies back.
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
