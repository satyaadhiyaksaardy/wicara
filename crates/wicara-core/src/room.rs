//! Rooms as a signed, hash-chained membership log.
//!
//! The hub stores the log and verifies nothing; clients verify all of it. That
//! is what resolves the obvious contradiction in "admin controls enforced by an
//! untrusted server": the hub here can *withhold* the log, or refuse to serve
//! it, but it cannot forge an invite or a kick, because every entry is signed
//! by an admin and names the hash of the entry before it.
//!
//! Membership is whatever replaying the chain says it is. There is no other
//! source of truth, and no server opinion to disagree with.

use std::collections::BTreeSet;

use anyhow::{Result, bail, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const ENTRY_CONTEXT: &[u8] = b"wicara room entry v1";
/// The `prev` of the first entry. A chain that starts anywhere else is not one.
const GENESIS: [u8; 32] = [0u8; 32];

/// A room's identity is the hash of the entry that created it, so it cannot be
/// claimed, renamed onto, or collided with.
pub type RoomId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomOp {
    Create { name: String },
    Invite { member: [u8; 32] },
    Kick { member: [u8; 32] },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoomEntry {
    /// Hash of the entry before this one; zeros for the `Create`.
    pub prev: [u8; 32],
    /// Must be an admin *as of the entry before this one*.
    pub author: [u8; 32],
    pub ts_ms: u64,
    pub op: RoomOp,
    /// Ed25519 by `author`, 64 bytes.
    pub signature: Vec<u8>,
}

impl RoomEntry {
    pub fn new(author: &SigningKey, prev: [u8; 32], ts_ms: u64, op: RoomOp) -> Result<Self> {
        let author_key = author.verifying_key().to_bytes();
        let transcript = transcript(&prev, &author_key, ts_ms, &op)?;
        Ok(Self {
            prev,
            author: author_key,
            ts_ms,
            op,
            signature: author.sign(&transcript).to_bytes().to_vec(),
        })
    }

    /// Covers the signature as well as the content, so an entry cannot be
    /// re-signed into the same position with a different key.
    pub fn hash(&self) -> Result<[u8; 32]> {
        let mut h = blake3::Hasher::new();
        h.update(&transcript(&self.prev, &self.author, self.ts_ms, &self.op)?);
        h.update(&self.signature);
        Ok(*h.finalize().as_bytes())
    }

    fn verify_signature(&self) -> Result<()> {
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow::anyhow!("room entry signature is not 64 bytes"))?;
        VerifyingKey::from_bytes(&self.author)
            .map_err(|_| anyhow::anyhow!("room entry author is not a valid Ed25519 key"))?
            .verify_strict(
                &transcript(&self.prev, &self.author, self.ts_ms, &self.op)?,
                &signature,
            )
            .map_err(|_| anyhow::anyhow!("room entry is not signed by the author it names"))
    }
}

fn transcript(prev: &[u8; 32], author: &[u8; 32], ts_ms: u64, op: &RoomOp) -> Result<Vec<u8>> {
    let mut t = ENTRY_CONTEXT.to_vec();
    t.extend(prev);
    t.extend(author);
    t.extend(ts_ms.to_le_bytes());
    t.extend(postcard::to_stdvec(op)?);
    Ok(t)
}

/// A room as the chain says it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Room {
    pub id: RoomId,
    pub name: String,
    pub founder: [u8; 32],
    pub members: BTreeSet<[u8; 32]>,
    /// Hash to put in the next entry's `prev`.
    pub head: [u8; 32],
    pub length: usize,
}

impl Room {
    // ponytail: the founder is the only admin. Promote/demote ops if a room
    // ever needs more than one, which for ~20 members it does not.
    pub fn is_admin(&self, who: &[u8; 32]) -> bool {
        &self.founder == who
    }
}

/// Replays a log from scratch and returns the room it describes, or an error
/// naming the first entry that does not hold up.
///
/// Called on everything the hub hands back, every time. Verification is cheap
/// and a room log is short; trusting a cached result would be trusting the hub.
pub fn verify_log(entries: &[RoomEntry]) -> Result<Room> {
    let Some(create) = entries.first() else {
        bail!("room log is empty");
    };
    ensure!(create.prev == GENESIS, "room log does not start at a create");
    create.verify_signature()?;
    let RoomOp::Create { name } = &create.op else {
        bail!("first room entry is not a create");
    };

    let id = create.hash()?;
    let mut room = Room {
        id,
        name: name.clone(),
        founder: create.author,
        members: BTreeSet::from([create.author]),
        head: id,
        length: 1,
    };

    for (n, entry) in entries.iter().enumerate().skip(1) {
        ensure!(
            entry.prev == room.head,
            "room log entry {n} does not follow the one before it"
        );
        entry.verify_signature()?;
        ensure!(
            room.is_admin(&entry.author),
            "room log entry {n} was written by someone who is not an admin"
        );
        match &entry.op {
            RoomOp::Create { .. } => bail!("room log entry {n} creates a second room"),
            RoomOp::Invite { member } => {
                room.members.insert(*member);
            }
            RoomOp::Kick { member } => {
                ensure!(
                    member != &room.founder,
                    "room log entry {n} kicks the founder"
                );
                room.members.remove(member);
            }
        }
        room.head = entry.hash()?;
        room.length += 1;
    }
    Ok(room)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn build() -> (SigningKey, SigningKey, SigningKey, Vec<RoomEntry>) {
        let (alice, bob, carol) = (key(1), key(2), key(3));
        let create = RoomEntry::new(
            &alice,
            GENESIS,
            1,
            RoomOp::Create {
                name: "kitchen".into(),
            },
        )
        .unwrap();
        let invite_bob = RoomEntry::new(
            &alice,
            create.hash().unwrap(),
            2,
            RoomOp::Invite {
                member: bob.verifying_key().to_bytes(),
            },
        )
        .unwrap();
        let invite_carol = RoomEntry::new(
            &alice,
            invite_bob.hash().unwrap(),
            3,
            RoomOp::Invite {
                member: carol.verifying_key().to_bytes(),
            },
        )
        .unwrap();
        (
            alice,
            bob,
            carol,
            vec![create, invite_bob, invite_carol],
        )
    }

    #[test]
    fn a_well_formed_log_replays_to_the_expected_room() {
        let (alice, bob, carol, log) = build();
        let room = verify_log(&log).unwrap();
        assert_eq!(room.name, "kitchen");
        assert_eq!(room.members.len(), 3);
        assert!(room.is_admin(&alice.verifying_key().to_bytes()));
        assert!(!room.is_admin(&bob.verifying_key().to_bytes()));

        // A kick by the admin takes effect.
        let mut kicked = log.clone();
        kicked.push(
            RoomEntry::new(
                &alice,
                room.head,
                4,
                RoomOp::Kick {
                    member: carol.verifying_key().to_bytes(),
                },
            )
            .unwrap(),
        );
        let after = verify_log(&kicked).unwrap();
        assert_eq!(after.members.len(), 2);
        assert!(!after.members.contains(&carol.verifying_key().to_bytes()));
        // The room's identity does not change when its membership does.
        assert_eq!(after.id, room.id);
    }

    #[test]
    fn a_tampered_log_is_rejected() {
        let (alice, bob, carol, log) = build();
        let room = verify_log(&log).unwrap();
        let mallory = key(9);
        let mallory_id = mallory.verifying_key().to_bytes();

        // The hub invents an invite for itself.
        let mut forged = log.clone();
        forged.push(
            RoomEntry::new(
                &mallory,
                room.head,
                4,
                RoomOp::Invite {
                    member: mallory_id,
                },
            )
            .unwrap(),
        );
        assert!(verify_log(&forged).unwrap_err().to_string().contains("not an admin"));

        // A member who is not an admin kicks someone.
        let mut forged = log.clone();
        forged.push(
            RoomEntry::new(
                &bob,
                room.head,
                4,
                RoomOp::Kick {
                    member: carol.verifying_key().to_bytes(),
                },
            )
            .unwrap(),
        );
        assert!(verify_log(&forged).is_err());

        // An entry is dropped from the middle: the chain no longer links up.
        let mut cut = log.clone();
        cut.remove(1);
        assert!(verify_log(&cut).unwrap_err().to_string().contains("does not follow"));

        // An entry is reordered.
        let mut swapped = log.clone();
        swapped.swap(1, 2);
        assert!(verify_log(&swapped).is_err());

        // The op is edited in place, keeping the old signature.
        let mut edited = log.clone();
        edited[1].op = RoomOp::Invite {
            member: mallory_id,
        };
        assert!(verify_log(&edited).is_err());

        // The signature is edited.
        let mut resigned = log.clone();
        resigned[2].signature[0] ^= 1;
        assert!(verify_log(&resigned).is_err());

        // A non-admin's entry is relabelled as the admin's to get it past the
        // authorisation check. The signature no longer matches the author.
        let mut relabelled = log.clone();
        let mut bobs = RoomEntry::new(
            &bob,
            room.head,
            4,
            RoomOp::Invite {
                member: mallory_id,
            },
        )
        .unwrap();
        bobs.author = alice.verifying_key().to_bytes();
        relabelled.push(bobs);
        assert!(
            verify_log(&relabelled)
                .unwrap_err()
                .to_string()
                .contains("not signed by the author")
        );

        // The founder cannot be kicked, not even by the founder.
        let mut coup = log.clone();
        coup.push(
            RoomEntry::new(
                &alice,
                room.head,
                4,
                RoomOp::Kick {
                    member: alice.verifying_key().to_bytes(),
                },
            )
            .unwrap(),
        );
        assert!(verify_log(&coup).unwrap_err().to_string().contains("kicks the founder"));

        // A log that does not start at a create.
        assert!(verify_log(&log[1..]).is_err());
        assert!(verify_log(&[]).is_err());
    }
}
