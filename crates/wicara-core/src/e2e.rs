//! Application-level end-to-end encryption, for exactly one job: a message that
//! must sit on the hub while the recipient is offline.
//!
//! Live chat uses none of this. iroh's QUIC/TLS 1.3 already authenticates both
//! endpoints by their Ed25519 keys and is end-to-end, relay included, so a
//! second layer there would prove nothing — which is why the proof that this
//! layer exists is an unreadable row in the hub's database, not a packet
//! capture.
//!
//! The rule that matters: **a prekey is only usable after its signature has been
//! checked against the recipient's EndpointId.** Without that check the hub can
//! hand out its own key and read every offline message. It is enforced by the
//! types here — [`SignedPrekey::verify`] is the only way to obtain the X25519
//! key that [`seal`] demands, and it takes the expected owner as an argument
//! rather than trusting the `owner` field it was handed.

use anyhow::{Result, anyhow, ensure};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, StaticSecret};

use crate::vault::random;

/// Domain separation. Bump the version if either format changes.
const PREKEY_CONTEXT: &[u8] = b"wicara prekey signature v1";
const ENVELOPE_CONTEXT: &[u8] = b"wicara envelope signature v1";
const KDF_CONTEXT: &str = "wicara envelope key v1";

/// An X25519 prekey, signed by the Ed25519 identity that owns it. Published to
/// the hub so a sender can encrypt to someone who is not online.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPrekey {
    /// Who claims to own this. Never trusted: [`SignedPrekey::verify`] takes the
    /// owner you already know and checks against that.
    pub owner: [u8; 32],
    pub prekey: [u8; 32],
    pub created_ms: u64,
    /// Ed25519, 64 bytes. `Vec` because serde has no array impls past 32.
    pub signature: Vec<u8>,
}

/// A verified X25519 prekey. The only way to get one is [`SignedPrekey::verify`],
/// and [`seal`] takes nothing else, so an unverified prekey cannot be used.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedPrekey {
    owner: [u8; 32],
    key: x25519_dalek::PublicKey,
}

impl SignedPrekey {
    pub fn new(identity: &SigningKey, prekey: &StaticSecret, created_ms: u64) -> Self {
        let owner = identity.verifying_key().to_bytes();
        let prekey = x25519_dalek::PublicKey::from(prekey).to_bytes();
        let signature = identity
            .sign(&prekey_transcript(&owner, &prekey, created_ms))
            .to_bytes()
            .to_vec();
        Self {
            owner,
            prekey,
            created_ms,
            signature,
        }
    }

    /// Checks the signature against the EndpointId you already have — from the
    /// contact you pasted, never from the hub's copy of `owner`.
    pub fn verify(&self, expected_owner: &[u8; 32]) -> Result<VerifiedPrekey> {
        ensure!(
            &self.owner == expected_owner,
            "the hub returned a prekey for a different endpoint"
        );
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| anyhow!("prekey signature is not 64 bytes"))?;
        VerifyingKey::from_bytes(expected_owner)
            .map_err(|_| anyhow!("that endpoint id is not a valid Ed25519 key"))?
            // Strict: rejects the small-order and torsion keys that make a
            // signature verify under more than one public key.
            .verify_strict(
                &prekey_transcript(expected_owner, &self.prekey, self.created_ms),
                &signature,
            )
            .map_err(|_| anyhow!("prekey is not signed by that endpoint — refusing to use it"))?;
        Ok(VerifiedPrekey {
            owner: *expected_owner,
            key: x25519_dalek::PublicKey::from(self.prekey),
        })
    }
}

fn prekey_transcript(owner: &[u8; 32], prekey: &[u8; 32], created_ms: u64) -> Vec<u8> {
    let mut t = PREKEY_CONTEXT.to_vec();
    t.extend(owner);
    t.extend(prekey);
    t.extend(created_ms.to_le_bytes());
    t
}

/// One sealed message, as it sits in the hub's mailbox. Everything outside
/// `ciphertext` is metadata the hub can see anyway — the threat model says so.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    /// The sender's throwaway X25519 key for this one message. Discarding its
    /// secret is what gives sender-side forward secrecy.
    pub ephemeral: [u8; 32],
    /// Which of the recipient's prekeys this was sealed to.
    pub prekey: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    /// Ed25519 by `sender` over everything above. Without it anyone could drop
    /// a message in your mailbox wearing someone else's name.
    pub signature: Vec<u8>,
}

/// Binds the message to this sender, this recipient and this key pair. Used as
/// AEAD associated data, so a re-addressed envelope fails to decrypt.
fn binding(sender: &[u8; 32], recipient: &[u8; 32], ephemeral: &[u8; 32], prekey: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(128);
    for part in [sender, recipient, ephemeral, prekey] {
        b.extend(part);
    }
    b
}

fn envelope_transcript(binding: &[u8], nonce: &[u8; 24], ciphertext: &[u8]) -> Vec<u8> {
    let mut t = ENVELOPE_CONTEXT.to_vec();
    t.extend(binding);
    t.extend(nonce);
    t.extend(ciphertext);
    t
}

fn envelope_key(shared: &[u8; 32], binding: &[u8]) -> [u8; 32] {
    let mut material = shared.to_vec();
    material.extend(binding);
    blake3::derive_key(KDF_CONTEXT, &material)
}

/// Seals `plaintext` to a prekey that has already been verified.
///
/// A fresh ephemeral keypair per message means the sender holds nothing that
/// could decrypt it afterwards. The recipient's prekey is long-lived, so this is
/// forward secrecy on the sender's side only — say so in the README.
pub fn seal(identity: &SigningKey, to: &VerifiedPrekey, plaintext: &[u8]) -> Result<Envelope> {
    let sender = identity.verifying_key().to_bytes();
    let ephemeral_secret = EphemeralSecret::random();
    let ephemeral = x25519_dalek::PublicKey::from(&ephemeral_secret).to_bytes();
    let prekey = to.key.to_bytes();

    let shared = ephemeral_secret.diffie_hellman(&to.key);
    ensure!(
        shared.was_contributory(),
        "recipient prekey is a small-order point"
    );

    let binding = binding(&sender, &to.owner, &ephemeral, &prekey);
    let nonce = random::<24>()?;
    let ciphertext = XChaCha20Poly1305::new(&envelope_key(shared.as_bytes(), &binding).into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &binding,
            },
        )
        .map_err(|_| anyhow!("sealing failed"))?;

    let signature = identity
        .sign(&envelope_transcript(&binding, &nonce, &ciphertext))
        .to_bytes()
        .to_vec();

    Ok(Envelope {
        sender,
        recipient: to.owner,
        ephemeral,
        prekey,
        nonce,
        ciphertext,
        signature,
    })
}

/// Checks that an envelope really was signed by the endpoint it names.
///
/// Separate from [`open`] because the hub needs exactly this and nothing more:
/// it cannot decrypt, but it must not let one sender fill another's quota, or
/// let anyone leave mail wearing a name that is not theirs.
pub fn verify_envelope_signature(envelope: &Envelope) -> Result<()> {
    let binding = binding(
        &envelope.sender,
        &envelope.recipient,
        &envelope.ephemeral,
        &envelope.prekey,
    );
    let signature = Signature::from_slice(&envelope.signature)
        .map_err(|_| anyhow!("envelope signature is not 64 bytes"))?;
    VerifyingKey::from_bytes(&envelope.sender)
        .map_err(|_| anyhow!("envelope sender is not a valid Ed25519 key"))?
        .verify_strict(
            &envelope_transcript(&binding, &envelope.nonce, &envelope.ciphertext),
            &signature,
        )
        .map_err(|_| anyhow!("envelope is not signed by the sender it names"))
}

/// Opens an envelope addressed to `me`, returning the authenticated sender.
///
/// The sender's signature is checked before anything is decrypted, so a
/// plaintext that comes out of here really was written by `Envelope::sender`.
pub fn open(envelope: &Envelope, my_prekey: &StaticSecret, me: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32])> {
    ensure!(&envelope.recipient == me, "envelope is addressed elsewhere");
    ensure!(
        envelope.prekey == x25519_dalek::PublicKey::from(my_prekey).to_bytes(),
        "envelope was sealed to a prekey this endpoint no longer holds"
    );

    verify_envelope_signature(envelope)?;
    let binding = binding(
        &envelope.sender,
        &envelope.recipient,
        &envelope.ephemeral,
        &envelope.prekey,
    );

    let shared = my_prekey.diffie_hellman(&x25519_dalek::PublicKey::from(envelope.ephemeral));
    ensure!(
        shared.was_contributory(),
        "envelope carries a small-order ephemeral key"
    );

    let plaintext = XChaCha20Poly1305::new(&envelope_key(shared.as_bytes(), &binding).into())
        .decrypt(
            &XNonce::from(envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &binding,
            },
        )
        .map_err(|_| anyhow!("envelope did not decrypt"))?;

    Ok((plaintext, envelope.sender))
}

/// Proof, to the hub, that you are the endpoint whose mailbox you are reading.
///
/// The hub cannot read the mail, but it must not hand it to the wrong person
/// either. A timestamp inside the signature keeps a captured header from being
/// replayed a week later.
pub mod mailbox_auth {
    use super::*;

    const CONTEXT: &[u8] = b"wicara mailbox auth v1";
    /// How far a client's clock may be off before its requests are refused.
    pub const WINDOW_MS: u64 = 5 * 60 * 1000;

    fn transcript(endpoint: &[u8; 32], ts_ms: u64) -> Vec<u8> {
        let mut t = CONTEXT.to_vec();
        t.extend(endpoint);
        t.extend(ts_ms.to_le_bytes());
        t
    }

    pub fn sign(identity: &SigningKey, ts_ms: u64) -> Vec<u8> {
        identity
            .sign(&transcript(&identity.verifying_key().to_bytes(), ts_ms))
            .to_bytes()
            .to_vec()
    }

    pub fn verify(endpoint: &[u8; 32], ts_ms: u64, signature: &[u8], now_ms: u64) -> Result<()> {
        ensure!(
            now_ms.abs_diff(ts_ms) <= WINDOW_MS,
            "request timestamp is outside the {WINDOW_MS}ms window"
        );
        let signature = Signature::from_slice(signature)
            .map_err(|_| anyhow!("auth signature is not 64 bytes"))?;
        VerifyingKey::from_bytes(endpoint)
            .map_err(|_| anyhow!("that endpoint id is not a valid Ed25519 key"))?
            .verify_strict(&transcript(endpoint, ts_ms), &signature)
            .map_err(|_| anyhow!("auth signature does not match that endpoint"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn a_prekey_signed_by_the_wrong_identity_is_refused() {
        let alice = identity(1);
        let mallory = identity(9);
        let alice_prekey = StaticSecret::from([3u8; 32]);

        let honest = SignedPrekey::new(&alice, &alice_prekey, 1_000);
        assert!(honest.verify(&alice.verifying_key().to_bytes()).is_ok());

        // The hub substitutes its own key, keeping Alice's name on it. This is
        // the attack the signature check exists for.
        let substituted = SignedPrekey {
            owner: alice.verifying_key().to_bytes(),
            ..SignedPrekey::new(&mallory, &StaticSecret::from([4u8; 32]), 1_000)
        };
        assert!(substituted.verify(&alice.verifying_key().to_bytes()).is_err());

        // The hub answers with someone else's prekey entirely.
        let wrong_owner = SignedPrekey::new(&mallory, &StaticSecret::from([4u8; 32]), 1_000);
        assert!(wrong_owner.verify(&alice.verifying_key().to_bytes()).is_err());

        // A flipped bit anywhere in the signed material.
        let mut tampered = honest.clone();
        tampered.created_ms += 1;
        assert!(tampered.verify(&alice.verifying_key().to_bytes()).is_err());
        let mut tampered = honest.clone();
        tampered.prekey[0] ^= 1;
        assert!(tampered.verify(&alice.verifying_key().to_bytes()).is_err());
        let mut tampered = honest;
        tampered.signature[0] ^= 1;
        assert!(tampered.verify(&alice.verifying_key().to_bytes()).is_err());
    }

    #[test]
    fn envelopes_roundtrip_and_reject_tampering() {
        let alice = identity(1);
        let bob = identity(2);
        let bob_prekey = StaticSecret::from([7u8; 32]);
        let bob_id = bob.verifying_key().to_bytes();
        let to_bob = SignedPrekey::new(&bob, &bob_prekey, 1_000)
            .verify(&bob_id)
            .unwrap();

        let sealed = seal(&alice, &to_bob, b"see you at six").unwrap();
        let (plaintext, sender) = open(&sealed, &bob_prekey, &bob_id).unwrap();
        assert_eq!(plaintext, b"see you at six");
        assert_eq!(sender, alice.verifying_key().to_bytes());

        // Fresh ephemeral per message: the same plaintext seals differently.
        let again = seal(&alice, &to_bob, b"see you at six").unwrap();
        assert_ne!(sealed.ciphertext, again.ciphertext);
        assert_ne!(sealed.ephemeral, again.ephemeral);

        // Someone else's prekey secret does not open it.
        assert!(open(&sealed, &StaticSecret::from([8u8; 32]), &bob_id).is_err());

        // Re-addressing it to another recipient fails the signature.
        let mut readdressed = sealed.clone();
        readdressed.recipient = alice.verifying_key().to_bytes();
        assert!(open(&readdressed, &bob_prekey, &readdressed.recipient.clone()).is_err());

        // Claiming a different sender fails too — a mailbox anyone can forge
        // into is worse than no mailbox.
        let mut impersonated = sealed.clone();
        impersonated.sender = bob_id;
        assert!(open(&impersonated, &bob_prekey, &bob_id).is_err());

        // Flipped ciphertext bit.
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(open(&tampered, &bob_prekey, &bob_id).is_err());

        // Delivered to the wrong mailbox.
        assert!(open(&sealed, &bob_prekey, &alice.verifying_key().to_bytes()).is_err());
    }

    #[test]
    fn mailbox_auth_binds_the_endpoint_and_the_clock() {
        let alice = identity(1);
        let bob = identity(2);
        let (alice_id, bob_id) = (
            alice.verifying_key().to_bytes(),
            bob.verifying_key().to_bytes(),
        );
        let now = 1_700_000_000_000u64;
        let sig = mailbox_auth::sign(&alice, now);

        assert!(mailbox_auth::verify(&alice_id, now, &sig, now).is_ok());
        // Someone else cannot read Alice's mail with Alice's captured header.
        assert!(mailbox_auth::verify(&bob_id, now, &sig, now).is_err());
        // Nor can the header be replayed outside the window.
        assert!(
            mailbox_auth::verify(&alice_id, now, &sig, now + mailbox_auth::WINDOW_MS + 1).is_err()
        );
        // Nor can the timestamp be edited to bring it back in.
        assert!(mailbox_auth::verify(&alice_id, now + 1, &sig, now + 1).is_err());
    }

    #[test]
    fn a_small_order_ephemeral_is_refused() {
        let bob = identity(2);
        let bob_prekey = StaticSecret::from([7u8; 32]);
        let bob_id = bob.verifying_key().to_bytes();
        let to_bob = SignedPrekey::new(&bob, &bob_prekey, 1)
            .verify(&bob_id)
            .unwrap();
        let alice = identity(1);
        let mut sealed = seal(&alice, &to_bob, b"x").unwrap();

        // The all-zero point forces an all-zero shared secret.
        sealed.ephemeral = [0u8; 32];
        let binding = binding(&sealed.sender, &sealed.recipient, &sealed.ephemeral, &sealed.prekey);
        sealed.signature = alice
            .sign(&envelope_transcript(&binding, &sealed.nonce, &sealed.ciphertext))
            .to_bytes()
            .to_vec();
        assert!(open(&sealed, &bob_prekey, &bob_id).is_err());
    }
}
