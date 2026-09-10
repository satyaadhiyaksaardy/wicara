//! Attachments over their own QUIC stream.
//!
//! Not `iroh-blobs`: it is pre-1.0 and still moving, and a bidirectional QUIC
//! stream is already the thing it wraps. The header frame carries the name,
//! size and BLAKE3 hash, then the bytes follow raw until the stream ends.
//!
//! There is no offline path for a file. The bytes need a live connection, and
//! saying so is better than mailing a header for something that will never
//! arrive.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use iroh::endpoint::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wicara_core::wire::{Frame, read_frame, write_frame};

use crate::{App, ui::UiEvent};

/// Bigger than a QUIC packet, small enough that the progress bar moves.
const CHUNK: usize = 64 * 1024;
/// A ceiling on what one attachment may be.
///
/// The size in the header is chosen by the sender and the BLAKE3 check only
/// runs once the stream has ended, so without a limit here a peer that
/// announces an enormous size can write until the disk is full before anything
/// rejects it.
const MAX_FILE: u64 = 256 * 1024 * 1024;

pub async fn send(app: App, conn: Connection, peer: [u8; 32], path: PathBuf) -> Result<()> {
    let meta = tokio::fs::metadata(&path)
        .await
        .with_context(|| format!("cannot read {}", path.display()))?;
    ensure!(meta.is_file(), "{} is not a file", path.display());
    ensure!(
        meta.len() <= MAX_FILE,
        "{} is {} bytes, over the {MAX_FILE}-byte limit",
        path.display(),
        meta.len()
    );
    let name = path
        .file_name()
        .context("that path has no file name")?
        .to_string_lossy()
        .into_owned();
    let size = meta.len();

    // ponytail: hashes the file, then sends it — one extra read of the file.
    // Streaming the hash would mean putting it after the bytes, and the
    // receiver wants to know what it is checking before it starts.
    let hash = hash_file(&path).await?;

    let id = app.store.lock().unwrap().next_id();
    let header = Frame::File {
        id,
        name: name.clone(),
        size,
        hash,
    };
    app.store.lock().unwrap().record(&peer, &header)?;
    app.store
        .lock()
        .unwrap()
        .set_file_path(&id, &path.to_string_lossy())?;
    app.send_log(peer)?;

    let (mut send, _recv) = conn.open_bi().await?;
    write_frame(&mut send, &header).await?;

    let mut file = tokio::fs::File::open(&path).await?;
    let mut buf = vec![0u8; CHUNK];
    let mut sent = 0u64;
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        send.write_all(&buf[..n]).await?;
        sent += n as u64;
        let _ = app.events.send(UiEvent::Transfer {
            id,
            done: sent,
            total: size,
        });
    }
    send.finish()?;
    // The peer has to actually take delivery before this returns, or dropping
    // the connection would cut the stream short.
    send.stopped().await?;
    app.status(format!("sent {name}"));
    Ok(())
}

/// Accepts every stream after the chat one and treats each as an attachment.
pub async fn accept_loop(app: App, conn: Connection, peer: [u8; 32]) {
    while let Ok((_send, recv)) = conn.accept_bi().await {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(err) = receive(&app, peer, recv).await {
                app.status(format!("attachment failed: {err:#}"));
            }
        });
    }
}

async fn receive(app: &App, peer: [u8; 32], mut recv: iroh::endpoint::RecvStream) -> Result<()> {
    let Some(header @ Frame::File { .. }) = read_frame(&mut recv).await? else {
        bail!("stream did not open with an attachment header");
    };
    let Frame::File {
        id,
        ref name,
        size,
        hash,
    } = header
    else {
        unreachable!("matched above")
    };
    // Same rule as every other op: minted under the key TLS authenticated.
    ensure!(
        id.sender == peer,
        "attachment is minted under a key other than the sender's"
    );
    // Checked before a byte is written, not after.
    ensure!(
        size <= MAX_FILE,
        "peer announced a {size}-byte attachment, over the {MAX_FILE}-byte limit"
    );

    app.store.lock().unwrap().record(&peer, &header)?;
    app.send_log(peer)?;

    let dir = app.home.join("files");
    tokio::fs::create_dir_all(&dir).await?;
    let path = dir.join(format!("{id}-{}", safe_name(name)));

    let mut file: tokio::fs::File = tokio::fs::File::create(&path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; CHUNK];
    let mut got = 0u64;
    loop {
        let n = recv.read(&mut buf).await?.unwrap_or(0);
        if n == 0 {
            break;
        }
        got += n as u64;
        if got > size {
            let _ = tokio::fs::remove_file(&path).await;
            bail!("peer sent more than the {size} bytes it announced");
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await?;
        let _ = app.events.send(UiEvent::Transfer {
            id,
            done: got,
            total: size,
        });
    }
    file.flush().await?;
    drop(file);

    if got != size || hasher.finalize().as_bytes() != &hash {
        let _ = tokio::fs::remove_file(&path).await;
        bail!("{name} did not match the hash it was sent with — discarded");
    }

    app.store
        .lock()
        .unwrap()
        .set_file_path(&id, &path.to_string_lossy())?;
    app.send_log(peer)?;
    app.status(format!("saved {} ({} bytes, blake3 ok)", path.display(), got));
    Ok(())
}

async fn hash_file(path: &Path) -> Result<[u8; 32]> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update_reader(std::fs::File::open(&path)?)?;
        Ok(*hasher.finalize().as_bytes())
    })
    .await?
}

/// A peer chooses the display name, never the path. Everything but the final
/// component is dropped, and anything left that could still climb out of the
/// directory is replaced.
fn safe_name(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " ._-".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(['.', ' ']).to_string();
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_cannot_choose_where_its_file_lands() {
        assert_eq!(safe_name("holiday.jpg"), "holiday.jpg");
        assert_eq!(safe_name("../../../etc/passwd"), "passwd");
        assert_eq!(safe_name("/etc/shadow"), "shadow");
        assert_eq!(safe_name(".."), "attachment");
        assert_eq!(safe_name(""), "attachment");
        assert_eq!(safe_name("."), "attachment");
        assert_eq!(safe_name("a/b/c.txt"), "c.txt");
        assert_eq!(safe_name("weird;rm -rf.txt"), "weird_rm -rf.txt");
        assert_eq!(safe_name("note\u{0}.txt"), "note_.txt");
        // Nothing that comes out of here has a separator left in it.
        for hostile in ["../x", "/x", "a\\b", "..\\..\\x"] {
            let out = safe_name(hostile);
            assert!(!out.contains('/') && !out.contains('\\'), "{out}");
            assert!(!out.starts_with('.'), "{out}");
        }
    }
}
