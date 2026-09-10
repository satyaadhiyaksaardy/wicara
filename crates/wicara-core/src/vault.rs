//! At-rest encryption: passphrase -> Argon2id -> XChaCha20-Poly1305.
//!
//! One derived key protects the identity file and (from M1b) the sqlite payload
//! column. The passphrase is stored nowhere: losing it loses the data, by design.
//!
//! XChaCha20's 192-bit nonce is what makes a fresh random nonce per message safe
//! here — the 96-bit variant would need a counter to stay off the birthday bound.

use anyhow::{Result, anyhow, ensure};
use argon2::Argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use zeroize::Zeroize;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;

/// Fills `N` bytes from the system CSPRNG.
pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| anyhow!("system rng unavailable: {e}"))?;
    Ok(buf)
}

/// A passphrase-derived key. Zeroized on drop; never written to disk.
pub struct VaultKey([u8; 32]);

impl Drop for VaultKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl VaultKey {
    /// Argon2id with the crate defaults (m=19 MiB, t=2, p=1) — the OWASP baseline.
    pub fn derive(passphrase: &str, salt: &[u8; SALT_LEN]) -> Result<Self> {
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("argon2: {e}"))?;
        Ok(Self(key))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&self.0).into())
    }

    /// Returns `nonce || ciphertext || tag`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = XNonce::from(random::<NONCE_LEN>()?);
        let mut out = nonce.to_vec();
        out.extend(
            self.cipher()
                .encrypt(&nonce, plaintext)
                .map_err(|_| anyhow!("encryption failed"))?,
        );
        Ok(out)
    }

    /// Inverse of [`VaultKey::seal`]. A wrong passphrase is indistinguishable
    /// from tampering, and both land here as the same error.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>> {
        ensure!(blob.len() >= NONCE_LEN + TAG_LEN, "sealed blob is truncated");
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        self.cipher()
            .decrypt(&XNonce::try_from(nonce).expect("checked length"), ct)
            .map_err(|_| anyhow!("wrong passphrase, or the file has been tampered with"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_rejections() {
        let salt = [7u8; SALT_LEN];
        let key = VaultKey::derive("correct horse", &salt).unwrap();

        let blob = key.seal(b"identity secret").unwrap();
        assert_eq!(key.open(&blob).unwrap(), b"identity secret");

        // Same plaintext twice must not produce the same bytes (fresh nonce).
        assert_ne!(blob, key.seal(b"identity secret").unwrap());

        // Wrong passphrase.
        let wrong = VaultKey::derive("battery staple", &salt).unwrap();
        assert!(wrong.open(&blob).is_err());

        // Wrong salt with the right passphrase.
        let other_salt = VaultKey::derive("correct horse", &[8u8; SALT_LEN]).unwrap();
        assert!(other_salt.open(&blob).is_err());

        // Tampered ciphertext.
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(key.open(&bad).is_err());

        // Truncated blob.
        assert!(key.open(&blob[..NONCE_LEN]).is_err());
    }
}
