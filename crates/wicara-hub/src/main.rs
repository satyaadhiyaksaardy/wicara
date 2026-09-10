//! wicara-hub — a server. Calling it anything else would be dishonest.
//!
//! It does three things and nothing else:
//!
//! * **prekey directory** — hands out signed X25519 prekeys. It cannot forge
//!   one: clients check the signature against the EndpointId they already have.
//! * **mailbox** — holds sealed envelopes for endpoints that are offline. It
//!   cannot read them.
//! * **room registry** — arrives in M4.
//!
//! It never carries live chat. It *does* learn who mails whom and when, and how
//! large the message was. That is a real metadata leak and it belongs in the
//! threat model, not in a footnote.

mod store;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, put},
};
use clap::Parser;
use wicara_core::e2e::{Envelope, SignedPrekey, mailbox_auth};

use crate::store::HubStore;

/// A single envelope. Chat text; attachments go peer-to-peer in M5.
const MAX_ENVELOPE: usize = 64 * 1024;
/// Undelivered envelopes one sender may leave for one recipient. An
/// unauthenticated mailbox is free disk for anyone who wants it; an
/// authenticated one still needs a ceiling.
const QUOTA_PER_SENDER: usize = 200;
const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const SWEEP_EVERY: Duration = Duration::from_secs(60 * 60);

#[derive(Parser)]
#[command(version, about = "wicara hub: prekey directory and offline mailbox")]
struct Cli {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:8787", env = "WICARA_HUB_LISTEN")]
    listen: SocketAddr,
    /// sqlite file holding prekeys and undelivered mail.
    #[arg(long, default_value = "wicara-hub.db", env = "WICARA_HUB_DB")]
    db: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wicara_hub=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let store = Arc::new(HubStore::open(&cli.db)?);

    tokio::spawn({
        let store = store.clone();
        async move {
            loop {
                match store.sweep(TTL) {
                    Ok(n) if n > 0 => tracing::info!(swept = n, "expired mail deleted"),
                    Ok(_) => {}
                    Err(err) => tracing::error!(%err, "sweep failed"),
                }
                tokio::time::sleep(SWEEP_EVERY).await;
            }
        }
    });

    let app = Router::new()
        .route("/prekey", put(put_prekey))
        .route("/prekey/{endpoint}", get(get_prekey))
        .route("/mail/{recipient}", axum::routing::post(post_mail))
        .route("/mail", get(get_mail))
        .route("/mail", delete(delete_mail))
        .route("/health", get(|| async { "ok" }))
        .with_state(store);

    let listener = tokio::net::TcpListener::bind(cli.listen).await?;
    tracing::info!(addr = %listener.local_addr()?, "hub listening");
    axum::serve(listener, app).await?;
    Ok(())
}

type Hub = State<Arc<HubStore>>;

/// Publishes your own prekey. The signature is checked here as a courtesy so
/// junk does not accumulate — it is *not* what makes the prekey trustworthy.
/// The recipient's client checks it again, and that check is the one that
/// matters, because this server is not trusted.
async fn put_prekey(State(store): Hub, body: Bytes) -> Result<StatusCode, Error> {
    let prekey: SignedPrekey = decode(&body)?;
    prekey
        .verify(&prekey.owner)
        .map_err(|e| Error(StatusCode::BAD_REQUEST, e.to_string()))?;
    store.put_prekey(&prekey, &body)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_prekey(State(store): Hub, Path(endpoint): Path<String>) -> Result<Vec<u8>, Error> {
    let endpoint = parse_endpoint(&endpoint)?;
    store
        .prekey(&endpoint)?
        .ok_or_else(|| Error(StatusCode::NOT_FOUND, "no prekey published".into()))
}

/// Accepts a sealed envelope for someone else. The sender is authenticated by
/// the envelope's own signature, which is what the quota counts against.
async fn post_mail(
    State(store): Hub,
    Path(recipient): Path<String>,
    body: Bytes,
) -> Result<StatusCode, Error> {
    if body.len() > MAX_ENVELOPE {
        return Err(Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("envelope is over the {MAX_ENVELOPE}-byte limit"),
        ));
    }
    let recipient = parse_endpoint(&recipient)?;
    let envelope: Envelope = decode(&body)?;
    if envelope.recipient != recipient {
        return Err(Error(
            StatusCode::BAD_REQUEST,
            "envelope is addressed to a different endpoint".into(),
        ));
    }
    // Not decryptable here, but the signature still proves who sent it — so the
    // quota cannot be dodged by claiming to be someone else.
    verify_envelope_sender(&envelope)?;

    if store.pending_from(&envelope.sender, &recipient)? >= QUOTA_PER_SENDER {
        return Err(Error(
            StatusCode::TOO_MANY_REQUESTS,
            format!("{QUOTA_PER_SENDER} messages already waiting for that recipient"),
        ));
    }
    store.put_mail(&envelope.sender, &recipient, &body)?;
    Ok(StatusCode::ACCEPTED)
}

/// Your own mail, and only your own. Returns postcard `Vec<(row_id, Envelope)>`.
async fn get_mail(State(store): Hub, headers: HeaderMap) -> Result<Vec<u8>, Error> {
    let me = authenticate(&headers)?;
    let mail = store.mail_for(&me)?;
    encode(&mail)
}

/// Deletes rows you have already taken delivery of. Body is postcard `Vec<i64>`.
async fn delete_mail(
    State(store): Hub,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, Error> {
    let me = authenticate(&headers)?;
    let ids: Vec<i64> = decode(&body)?;
    // Scoped to the caller's own rows, so an id from someone else's mailbox is
    // simply not found.
    store.delete_mail(&me, &ids)?;
    Ok(StatusCode::NO_CONTENT)
}

fn authenticate(headers: &HeaderMap) -> Result<[u8; 32], Error> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| Error(StatusCode::UNAUTHORIZED, format!("missing {name}")))
    };
    let endpoint = parse_endpoint(header("x-wicara-endpoint")?)?;
    let ts: u64 = header("x-wicara-timestamp")?
        .parse()
        .map_err(|_| Error(StatusCode::UNAUTHORIZED, "bad timestamp".into()))?;
    let signature = data_encoding::HEXLOWER_PERMISSIVE
        .decode(header("x-wicara-signature")?.as_bytes())
        .map_err(|_| Error(StatusCode::UNAUTHORIZED, "signature is not hex".into()))?;

    mailbox_auth::verify(&endpoint, ts, &signature, now_ms())
        .map_err(|e| Error(StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok(endpoint)
}

fn verify_envelope_sender(envelope: &Envelope) -> Result<(), Error> {
    // Opening it is the recipient's job; here only the outer signature is
    // checkable, and wicara-core is the one place that knows how.
    wicara_core::e2e::verify_envelope_signature(envelope)
        .map_err(|err: anyhow::Error| Error(StatusCode::BAD_REQUEST, err.to_string()))
}

fn parse_endpoint(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = data_encoding::HEXLOWER_PERMISSIVE
        .decode(hex.trim().as_bytes())
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "endpoint id is not hex".into()))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error(StatusCode::BAD_REQUEST, "endpoint id is not 32 bytes".into()))
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    postcard::from_bytes(bytes)
        .map_err(|e| Error(StatusCode::BAD_REQUEST, format!("malformed body: {e}")))
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    postcard::to_stdvec(value)
        .map_err(|e| Error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct Error(StatusCode, String);

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        (self.0, self.1).into_response()
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!(%err, "request failed");
        Error(StatusCode::INTERNAL_SERVER_ERROR, "internal error".into())
    }
}
