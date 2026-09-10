//! The Ed25519 identity, encrypted at rest.
//!
//! File layout: `[16-byte Argon2id salt][sealed 32-byte secret key]`. The public
//! half is the iroh EndpointId, so it is stable for the life of the file.

use std::{
    fs,
    io::{BufRead, IsTerminal, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::SecretKey;
use wicara_core::vault::{SALT_LEN, VaultKey, random};

pub const FILE_NAME: &str = "identity.key";
const MIN_PASSPHRASE: usize = 8;

#[allow(dead_code)]
pub struct Identity {
    // ponytail: `vault` is unused until M1b wires up the encrypted store.

    pub secret: SecretKey,
    /// Kept so the sqlite payload column (M1b) reuses the same derived key
    /// instead of prompting again.
    pub vault: VaultKey,
}

/// `$WICARA_HOME`, else the platform config dir (`~/.config/wicara` on Linux).
pub fn home(explicit: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = explicit {
        return Ok(dir);
    }
    directories::ProjectDirs::from("", "", "wicara")
        .map(|d| d.config_dir().to_path_buf())
        .context("no home directory; set WICARA_HOME")
}

pub fn load_or_create(home: &Path) -> Result<Identity> {
    let path = home.join(FILE_NAME);
    if path.exists() {
        load(&path)
    } else {
        create(&path)
    }
}

fn load(path: &Path) -> Result<Identity> {
    let blob = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    ensure!(
        blob.len() > SALT_LEN,
        "{} is truncated; it is not a wicara identity file",
        path.display()
    );
    let (salt, sealed) = blob.split_at(SALT_LEN);
    let salt: [u8; SALT_LEN] = salt.try_into().expect("checked length");

    let vault = VaultKey::derive(&ask("Passphrase: ")?, &salt)?;
    let secret = vault.open(sealed)?;
    let secret: [u8; 32] = secret
        .as_slice()
        .try_into()
        .context("identity file does not hold a 32-byte key")?;
    Ok(Identity {
        secret: SecretKey::from(secret),
        vault,
    })
}

fn create(path: &Path) -> Result<Identity> {
    eprintln!(
        "No identity found. Creating one at {}.\n\
         \n\
         It is encrypted with a passphrase that is stored nowhere. If you lose the\n\
         passphrase, your identity and message history are gone — there is no reset,\n\
         no recovery code, and no one to ask. That is the design, not an oversight.\n",
        path.display()
    );

    let passphrase = ask("Choose a passphrase: ")?;
    ensure!(
        passphrase.chars().count() >= MIN_PASSPHRASE,
        "passphrase must be at least {MIN_PASSPHRASE} characters"
    );
    if ask("Confirm passphrase: ")? != passphrase {
        bail!("passphrases do not match");
    }

    let salt = random::<SALT_LEN>()?;
    let vault = VaultKey::derive(&passphrase, &salt)?;
    let secret = random::<32>()?;

    let mut blob = salt.to_vec();
    blob.extend(vault.seal(&secret)?);

    fs::create_dir_all(path.parent().expect("identity path has a parent"))?;
    fs::write(path, &blob).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(Identity {
        secret: SecretKey::from(secret),
        vault,
    })
}

/// Prompts on a terminal; reads one line from stdin when piped, so the demo and
/// the self-check can drive it without an env var that leaks into `ps`.
fn ask(prompt: &str) -> Result<String> {
    if std::io::stdin().is_terminal() {
        return rpassword::prompt_password(prompt).context("reading passphrase");
    }
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    ensure!(
        std::io::stdin().lock().read_line(&mut line)? > 0,
        "no passphrase on stdin"
    );
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}
