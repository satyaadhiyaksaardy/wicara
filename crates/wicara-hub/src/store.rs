//! The hub's sqlite. Everything it holds is opaque to it.

use std::{path::Path, sync::Mutex, time::Duration};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};
use wicara_core::e2e::{Envelope, SignedPrekey};

use crate::now_ms;

// ponytail: one connection behind a mutex. Requests are tiny and rare; swap in
// a pool the day the hub sees real traffic.
pub struct HubStore(Mutex<Connection>);

impl HubStore {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("opening hub database at {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS prekeys (
                 owner      BLOB    PRIMARY KEY,
                 created_ms INTEGER NOT NULL,
                 blob       BLOB    NOT NULL
             );
             CREATE TABLE IF NOT EXISTS mail (
                 id          INTEGER PRIMARY KEY,
                 recipient   BLOB    NOT NULL,
                 sender      BLOB    NOT NULL,
                 received_ms INTEGER NOT NULL,
                 blob        BLOB    NOT NULL
             );
             CREATE INDEX IF NOT EXISTS mail_by_recipient ON mail (recipient, id);
             CREATE INDEX IF NOT EXISTS mail_by_age ON mail (received_ms);
             CREATE TABLE IF NOT EXISTS rooms (
                 id     BLOB    PRIMARY KEY,
                 length INTEGER NOT NULL,
                 blob   BLOB    NOT NULL
             );",
        )?;
        Ok(Self(Mutex::new(conn)))
    }

    /// Last publish wins. A client that rotates its prekey simply overwrites.
    pub fn put_prekey(&self, prekey: &SignedPrekey, blob: &[u8]) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO prekeys (owner, created_ms, blob) VALUES (?1, ?2, ?3)
             ON CONFLICT(owner) DO UPDATE SET created_ms = excluded.created_ms,
                                              blob = excluded.blob",
            params![&prekey.owner[..], prekey.created_ms as i64, blob],
        )?;
        Ok(())
    }

    pub fn prekey(&self, owner: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .query_row(
                "SELECT blob FROM prekeys WHERE owner = ?1",
                params![&owner[..]],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn put_mail(&self, sender: &[u8; 32], recipient: &[u8; 32], blob: &[u8]) -> Result<()> {
        self.0.lock().unwrap().execute(
            "INSERT INTO mail (recipient, sender, received_ms, blob) VALUES (?1, ?2, ?3, ?4)",
            params![&recipient[..], &sender[..], now_ms() as i64, blob],
        )?;
        Ok(())
    }

    pub fn pending_from(&self, sender: &[u8; 32], recipient: &[u8; 32]) -> Result<usize> {
        let n: i64 = self.0.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM mail WHERE sender = ?1 AND recipient = ?2",
            params![&sender[..], &recipient[..]],
            |row| row.get(0),
        )?;
        Ok(n as usize)
    }

    pub fn mail_for(&self, recipient: &[u8; 32]) -> Result<Vec<(i64, Envelope)>> {
        let conn = self.0.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, blob FROM mail WHERE recipient = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![&recipient[..]], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, blob) = row?;
            match postcard::from_bytes(&blob) {
                Ok(envelope) => out.push((id, envelope)),
                // Stored before a format change, or corrupt. Skipping beats
                // failing the whole fetch for one bad row.
                Err(err) => tracing::warn!(id, %err, "undecodable envelope skipped"),
            }
        }
        Ok(out)
    }

    /// Scoped to `recipient`, so an id belonging to someone else is a no-op
    /// rather than a way to delete other people's mail.
    pub fn delete_mail(&self, recipient: &[u8; 32], ids: &[i64]) -> Result<usize> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut deleted = 0;
        {
            let mut stmt = tx.prepare("DELETE FROM mail WHERE id = ?1 AND recipient = ?2")?;
            for id in ids {
                deleted += stmt.execute(params![id, &recipient[..]])?;
            }
        }
        tx.commit()?;
        Ok(deleted)
    }

    /// Stores a membership log verbatim, verifying nothing about it — that is
    /// the clients' job and the reason this server cannot forge membership.
    ///
    /// The one rule is that a log may not get shorter. It costs no verification
    /// and stops anyone who can reach the hub from erasing a room by PUTting a
    /// one-entry chain over it.
    pub fn put_room(&self, id: &[u8; 32], length: usize, blob: &[u8]) -> Result<bool> {
        let rows = self.0.lock().unwrap().execute(
            "INSERT INTO rooms (id, length, blob) VALUES (?1, ?2, ?3)
             ON CONFLICT(id) DO UPDATE SET length = excluded.length, blob = excluded.blob
             WHERE excluded.length > rooms.length",
            params![&id[..], length as i64, blob],
        )?;
        Ok(rows == 1)
    }

    pub fn room(&self, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .query_row("SELECT blob FROM rooms WHERE id = ?1", params![&id[..]], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// Undelivered mail is not storage anyone signed up to provide forever.
    pub fn sweep(&self, ttl: Duration) -> Result<usize> {
        let cutoff = now_ms().saturating_sub(ttl.as_millis() as u64) as i64;
        Ok(self.0.lock().unwrap().execute(
            "DELETE FROM mail WHERE received_ms < ?1",
            params![cutoff],
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use wicara_core::e2e::{seal, SignedPrekey};
    use x25519_dalek::StaticSecret;

    fn envelope(from: u8, to: u8) -> (Envelope, Vec<u8>) {
        let sender = SigningKey::from_bytes(&[from; 32]);
        let recipient = SigningKey::from_bytes(&[to; 32]);
        let prekey = StaticSecret::from([to.wrapping_add(50); 32]);
        let verified = SignedPrekey::new(&recipient, &prekey, 1)
            .verify(&recipient.verifying_key().to_bytes())
            .unwrap();
        let env = seal(&sender, &verified, b"offline hello").unwrap();
        let blob = postcard::to_stdvec(&env).unwrap();
        (env, blob)
    }

    #[test]
    fn quota_sweep_and_scoped_deletes() {
        let dir = std::env::temp_dir().join(format!("wicara-hub-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hub.db");
        let _ = std::fs::remove_file(&path);
        let store = HubStore::open(&path).unwrap();

        let (env, blob) = envelope(1, 2);
        let (alice, bob) = (env.sender, env.recipient);
        let (other, other_blob) = envelope(3, 2);

        for _ in 0..3 {
            store.put_mail(&alice, &bob, &blob).unwrap();
        }
        store.put_mail(&other.sender, &bob, &other_blob).unwrap();

        // The quota counts one sender's backlog, not the mailbox's total.
        assert_eq!(store.pending_from(&alice, &bob).unwrap(), 3);
        assert_eq!(store.pending_from(&other.sender, &bob).unwrap(), 1);
        assert_eq!(store.mail_for(&bob).unwrap().len(), 4);
        assert!(store.mail_for(&alice).unwrap().is_empty());

        // Deletes are scoped: Alice cannot clear Bob's mailbox with his row ids.
        let ids: Vec<i64> = store.mail_for(&bob).unwrap().iter().map(|(i, _)| *i).collect();
        assert_eq!(store.delete_mail(&alice, &ids).unwrap(), 0);
        assert_eq!(store.mail_for(&bob).unwrap().len(), 4);
        assert_eq!(store.delete_mail(&bob, &ids[..2]).unwrap(), 2);
        assert_eq!(store.mail_for(&bob).unwrap().len(), 2);

        // The sweep takes expired rows and leaves fresh ones.
        assert_eq!(store.sweep(Duration::from_secs(60 * 60)).unwrap(), 0);
        store
            .0
            .lock()
            .unwrap()
            .execute("UPDATE mail SET received_ms = 0 WHERE id = ?1", params![ids[2]])
            .unwrap();
        assert_eq!(store.sweep(Duration::from_secs(60 * 60)).unwrap(), 1);
        assert_eq!(store.mail_for(&bob).unwrap().len(), 1);

        // Prekeys: last publish wins.
        let bob_key = SigningKey::from_bytes(&[2u8; 32]);
        for (n, seed) in [(1u64, 60u8), (2, 61)] {
            let pk = SignedPrekey::new(&bob_key, &StaticSecret::from([seed; 32]), n);
            store.put_prekey(&pk, &postcard::to_stdvec(&pk).unwrap()).unwrap();
        }
        let stored: SignedPrekey = postcard::from_bytes(&store.prekey(&bob).unwrap().unwrap()).unwrap();
        assert_eq!(stored.created_ms, 2);
        assert!(stored.verify(&bob).is_ok());

        // Rooms: a log may grow, never shrink.
        let room_id = [42u8; 32];
        assert!(store.put_room(&room_id, 3, b"three-entry log").unwrap());
        assert!(store.put_room(&room_id, 5, b"five-entry log").unwrap());
        assert!(!store.put_room(&room_id, 2, b"erased").unwrap());
        assert_eq!(store.room(&room_id).unwrap().unwrap(), b"five-entry log");

        std::fs::remove_dir_all(&dir).ok();
    }
}
