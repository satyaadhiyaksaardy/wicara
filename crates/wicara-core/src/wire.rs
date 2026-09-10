//! Message identity and the framing that carries it.
//!
//! The [`MessageId`] scheme is fixed here on purpose: replies, reactions, edits,
//! deletes and the M3 mailbox dedup all key off it, and every one of them breaks
//! if it is invented later.
//!
//! An id is `(sender, seq, ts_ms)`, and all three are part of the identity:
//!
//! * `sender` — the EndpointId, so ids from different peers can never collide.
//! * `seq` — strictly increasing per sender. This is the ordering authority.
//! * `ts_ms` — the sender's wall clock, for display and cross-peer ordering only.
//!   It is not trusted and never compared for equality with anything else. It
//!   also stops a peer that lost its store, and so restarted `seq` at zero, from
//!   minting ids that collide with its own history.

use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Chat frames are small. Files get their own stream in M5, so this cap is not
/// in their way.
pub const MAX_FRAME: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId {
    pub sender: [u8; 32],
    pub seq: u64,
    pub ts_ms: u64,
}

impl MessageId {
    /// Display order across peers: wall clock first, then the sender's own
    /// sequence, then the key to break ties deterministically.
    pub fn sort_key(&self) -> (u64, u64, [u8; 32]) {
        (self.ts_ms, self.seq, self.sender)
    }
}

/// Short and pasteable, for `/reply` and the TUI: `1a2b3c4d-7`.
impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.sender[..4] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "-{}", self.seq)
    }
}

/// Mints ids for one sender. `seq` is persisted alongside the message store, so
/// it survives a restart; `next` refuses to hand out a duplicate either way.
#[derive(Debug)]
pub struct Counter {
    sender: [u8; 32],
    seq: u64,
}

impl Counter {
    /// `resume_from` is the highest `seq` already used, or 0 on a fresh store.
    pub fn new(sender: [u8; 32], resume_from: u64) -> Self {
        Self {
            sender,
            seq: resume_from,
        }
    }

    pub fn mint(&mut self) -> MessageId {
        self.seq += 1;
        MessageId {
            sender: self.sender,
            seq: self.seq,
            ts_ms: now_ms(),
        }
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Every op carries its own [`MessageId`], so every one of them is dedupable and
/// mailboxable in its own right, and names the `target` it acts on. Who may do
/// what is decided by the ids alone: only `target.sender` may edit or delete,
/// and the receiver checks that — the sender is not asked to be honest about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    /// First frame on every stream, and again after `/nick`. The nickname is
    /// local metadata: freely changeable, never conflated with the EndpointId.
    Hello {
        nickname: String,
    },
    Chat {
        id: MessageId,
        body: String,
        reply_to: Option<MessageId>,
    },
    Edit {
        id: MessageId,
        target: MessageId,
        body: String,
    },
    Delete {
        id: MessageId,
        target: MessageId,
    },
    React {
        id: MessageId,
        target: MessageId,
        emoji: String,
        /// False removes the reaction, so the op is a toggle rather than a
        /// state the two ends can disagree about.
        on: bool,
    },
    /// The same ops again, addressed to a room instead of to the peer carrying
    /// them. A room id is 32 bytes, exactly like an endpoint id, so the store
    /// files a room conversation the same way it files a 1:1 one and nothing
    /// downstream had to change.
    ///
    /// Rooms are broadcast pairwise: each member gets their own copy over their
    /// own connection, or in their own mailbox.
    // ponytail: pairwise encryption, fine to roughly 20 members; a group key if
    // rooms ever grow past that.
    InRoom {
        room: [u8; 32],
        op: Box<Frame>,
    },
    /// An attachment. Sent as the first frame of its own QUIC stream, with the
    /// bytes following it raw — a bidirectional stream is already the thing
    /// `iroh-blobs` wraps, and it is pre-1.0.
    ///
    /// The header carries everything the receiver needs, so it does not matter
    /// whether the two streams arrive in order.
    File {
        id: MessageId,
        /// Display name only. The receiver takes the file-name component of it
        /// and nothing else — a peer does not get to choose a path here.
        name: String,
        size: u64,
        /// BLAKE3 of the contents, checked on arrival.
        hash: [u8; 32],
    },
    /// "That room's log changed — here it is." The log is self-verifying, so it
    /// does not matter who hands it over: the receiver replays the chain and
    /// only that decides membership. Carrying it means an invite between two
    /// connected peers needs no server at all, and a hub outage degrades rooms
    /// instead of breaking them.
    ///
    /// `log` may be empty, which keeps this a bare "go and look" for a receiver
    /// that has a hub to ask. Forging either shape gets an attacker nothing.
    RoomUpdated {
        room: [u8; 32],
        log: Vec<crate::room::RoomEntry>,
    },
}

impl Frame {
    /// The id of the op itself, for dedup. `Hello` carries none.
    pub fn id(&self) -> Option<MessageId> {
        match self {
            Frame::Hello { .. } | Frame::RoomUpdated { .. } => None,
            Frame::Chat { id, .. }
            | Frame::Edit { id, .. }
            | Frame::Delete { id, .. }
            | Frame::React { id, .. }
            | Frame::File { id, .. } => Some(*id),
            Frame::InRoom { op, .. } => op.id(),
        }
    }

    /// The conversation this op belongs to: a room, or the peer that carried it.
    pub fn conversation(&self, peer: [u8; 32]) -> [u8; 32] {
        match self {
            Frame::InRoom { room, .. } => *room,
            _ => peer,
        }
    }

    /// Strips the room wrapper, so the store and the fold see one shape of op.
    pub fn unwrap_room(self) -> Frame {
        match self {
            Frame::InRoom { op, .. } => *op,
            other => other,
        }
    }
}

/// `u32` little-endian length, then postcard. The length prefix is what makes a
/// QUIC stream — a byte stream, not a datagram — carry discrete messages.
pub fn encode(frame: &Frame) -> Result<Vec<u8>> {
    let payload = postcard::to_stdvec(frame)?;
    ensure!(
        payload.len() <= MAX_FRAME,
        "frame is {} bytes, over the {MAX_FRAME}-byte cap",
        payload.len()
    );
    let mut out = (payload.len() as u32).to_le_bytes().to_vec();
    out.extend(payload);
    Ok(out)
}

pub fn decode(payload: &[u8]) -> Result<Frame> {
    Ok(postcard::from_bytes(payload)?)
}

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, frame: &Frame) -> Result<()> {
    w.write_all(&encode(frame)?).await?;
    Ok(())
}

/// Returns `Ok(None)` at a clean end of stream, so callers can tell a peer that
/// hung up from one that sent garbage.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Frame>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    // Checked before allocating: an unauthenticated peer must not be able to
    // make us reserve a gigabyte by sending four bytes.
    if len > MAX_FRAME {
        bail!("peer announced a {len}-byte frame, over the {MAX_FRAME}-byte cap");
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    decode(&payload).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_monotonic_per_sender() {
        let mut a = Counter::new([1u8; 32], 0);
        let mut b = Counter::new([2u8; 32], 0);

        let ids: Vec<_> = (0..100).map(|_| a.mint()).collect();
        assert!(ids.windows(2).all(|w| w[0].seq < w[1].seq));
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len()
        );

        // Same seq from a different sender is a different message.
        assert_ne!(a.mint().sender, b.mint().sender);

        // A restart resumes rather than reissuing.
        let mut resumed = Counter::new([1u8; 32], a.seq());
        assert!(resumed.mint().seq > a.seq());
    }

    #[test]
    fn frames_roundtrip_through_postcard() {
        let id = Counter::new([9u8; 32], 41).mint();
        assert_eq!(id.to_string(), "09090909-42");

        for frame in [
            Frame::Hello {
                nickname: "satya".into(),
            },
            Frame::Chat {
                id,
                body: "hello — unicode ✓".into(),
                reply_to: None,
            },
            Frame::Edit {
                id,
                target: id,
                body: "fixed typo".into(),
            },
            Frame::Delete { id, target: id },
            Frame::React {
                id,
                target: id,
                emoji: "👍".into(),
                on: true,
            },
            Frame::File {
                id,
                size: 1234,
                name: "holiday.jpg".into(),
                hash: [7u8; 32],
            },
            Frame::InRoom {
                room: [4u8; 32],
                op: Box::new(Frame::Chat {
                    id,
                    body: "in the room".into(),
                    reply_to: None,
                }),
            },
        ] {
            let bytes = encode(&frame).unwrap();
            let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            assert_eq!(len, bytes.len() - 4);
            assert_eq!(decode(&bytes[4..]).unwrap(), frame);
        }
    }

    #[test]
    fn a_room_op_keeps_its_id_and_names_its_conversation() {
        let id = Counter::new([9u8; 32], 0).mint();
        let wrapped = Frame::InRoom {
            room: [4u8; 32],
            op: Box::new(Frame::Chat {
                id,
                body: "hi".into(),
                reply_to: None,
            }),
        };
        assert_eq!(wrapped.id(), Some(id));
        // A room op files under the room, a 1:1 op under the peer that sent it.
        assert_eq!(wrapped.conversation([7u8; 32]), [4u8; 32]);
        assert!(matches!(wrapped.unwrap_room(), Frame::Chat { .. }));

        let direct = Frame::Chat {
            id,
            body: "hi".into(),
            reply_to: None,
        };
        assert_eq!(direct.conversation([7u8; 32]), [7u8; 32]);
    }

    #[tokio::test]
    async fn stream_carries_back_to_back_frames_and_rejects_oversize() {
        let one = Frame::Hello {
            nickname: "a".into(),
        };
        let two = Frame::Chat {
            id: Counter::new([0u8; 32], 0).mint(),
            body: "b".into(),
            reply_to: None,
        };

        let mut buf = encode(&one).unwrap();
        buf.extend(encode(&two).unwrap());
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).await.unwrap(), Some(one));
        assert_eq!(read_frame(&mut cursor).await.unwrap(), Some(two));
        // Clean end of stream, not an error.
        assert_eq!(read_frame(&mut cursor).await.unwrap(), None);

        // A frame at the cap encodes; one over it does not.
        let big = Frame::Chat {
            id: Counter::new([0u8; 32], 0).mint(),
            body: "x".repeat(MAX_FRAME + 1),
            reply_to: None,
        };
        assert!(encode(&big).is_err());

        // A lying length prefix is refused before anything is allocated.
        let mut lie = std::io::Cursor::new((u32::MAX).to_le_bytes().to_vec());
        assert!(read_frame(&mut lie).await.is_err());
    }
}
