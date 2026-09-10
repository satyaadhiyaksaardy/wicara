//! The client's side of the hub: publish a prekey, mail to someone offline,
//! drain your own mailbox.
//!
//! All of it is optional. With no `--hub` the app is exactly what milestones 0
//! to 2 shipped: no servers, at all, and no offline delivery.

use anyhow::{Context, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use wicara_core::{
    e2e::{Envelope, SignedPrekey, VerifiedPrekey, mailbox_auth, seal},
    wire::now_ms,
};
use x25519_dalek::StaticSecret;

pub struct Hub {
    base: String,
    http: reqwest::Client,
    identity: SigningKey,
}

impl Hub {
    pub fn new(base: &str, identity: SigningKey) -> Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                // Cloudflare closes idle connections at 100s. Nothing here is
                // long-lived — the drain is a poll, not a stream — so a
                // per-request timeout is the whole of the story.
                .timeout(std::time::Duration::from_secs(20))
                .build()?,
            identity,
        })
    }

    pub async fn publish_prekey(&self, prekey: &StaticSecret) -> Result<()> {
        let signed = SignedPrekey::new(&self.identity, prekey, now_ms());
        let res = self
            .http
            .put(format!("{}/prekey", self.base))
            .body(postcard::to_stdvec(&signed)?)
            .send()
            .await
            .context("publishing prekey")?;
        ensure!(res.status().is_success(), "hub refused the prekey: {}", res.status());
        Ok(())
    }

    /// Fetches `owner`'s prekey **and checks its signature against the
    /// EndpointId you already have**. Without that check the hub could hand
    /// back its own key and read every offline message you ever send.
    pub async fn prekey_for(&self, owner: &[u8; 32]) -> Result<VerifiedPrekey> {
        let res = self
            .http
            .get(format!(
                "{}/prekey/{}",
                self.base,
                data_encoding::HEXLOWER.encode(owner)
            ))
            .send()
            .await
            .context("fetching prekey")?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            bail!("that endpoint has not published a prekey");
        }
        ensure!(res.status().is_success(), "hub returned {}", res.status());
        let signed: SignedPrekey = postcard::from_bytes(&res.bytes().await?)?;
        signed.verify(owner)
    }

    pub async fn mail(&self, to: &VerifiedPrekey, recipient: &[u8; 32], plaintext: &[u8]) -> Result<()> {
        let envelope = seal(&self.identity, to, plaintext)?;
        let res = self
            .http
            .post(format!(
                "{}/mail/{}",
                self.base,
                data_encoding::HEXLOWER.encode(recipient)
            ))
            .body(postcard::to_stdvec(&envelope)?)
            .send()
            .await
            .context("mailing to the hub")?;
        ensure!(
            res.status().is_success(),
            "hub refused the message: {} {}",
            res.status(),
            res.text().await.unwrap_or_default()
        );
        Ok(())
    }

    pub async fn fetch_mail(&self) -> Result<Vec<(i64, Envelope)>> {
        let res = self
            .http
            .get(format!("{}/mail", self.base))
            .headers(self.auth()?)
            .send()
            .await
            .context("draining the mailbox")?;
        ensure!(res.status().is_success(), "hub returned {}", res.status());
        Ok(postcard::from_bytes(&res.bytes().await?)?)
    }

    /// Only after the messages are safely in the local store: the hub is the
    /// only copy until then.
    pub async fn delete_mail(&self, ids: &[i64]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let res = self
            .http
            .delete(format!("{}/mail", self.base))
            .headers(self.auth()?)
            .body(postcard::to_stdvec(ids)?)
            .send()
            .await
            .context("clearing the mailbox")?;
        ensure!(res.status().is_success(), "hub returned {}", res.status());
        Ok(())
    }

    fn auth(&self) -> Result<reqwest::header::HeaderMap> {
        let ts = now_ms();
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "x-wicara-endpoint",
            data_encoding::HEXLOWER
                .encode(&self.identity.verifying_key().to_bytes())
                .parse()?,
        );
        headers.insert("x-wicara-timestamp", ts.to_string().parse()?);
        headers.insert(
            "x-wicara-signature",
            data_encoding::HEXLOWER
                .encode(&mailbox_auth::sign(&self.identity, ts))
                .parse()?,
        );
        Ok(headers)
    }
}
