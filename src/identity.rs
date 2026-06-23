//! Persisted iroh identity (stable node id) and the per-process instance nonce.
//!
//! By default duopipe generates an ephemeral iroh `SecretKey` each run, so the
//! node id changes every time. A configured peer can opt into a *stable* node id
//! via `identity_file` (config) — [`load_identity`] reads an existing one and
//! [`create_identity`] mints a new one. The key is stored base64-encoded in a
//! `0o600` file, mirroring how `encryption_key_file` (an age identity) is handled
//! in [`crate::encryption`].
//!
//! Separately, [`self_instance_id`] returns a random per-*process* nonce. It is
//! independent of the iroh key: the key says "who I claim to be" (node id), the
//! instance id says "which running process I am". Two processes that share one
//! identity key have the same node id but distinct instance ids, which is how a
//! cloned identity is detected (see `app_state::admit_peer`).

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::SecretKey;

/// Encode a secret key as a single-line base64 string (32 raw bytes).
pub fn encode_secret_key(key: &SecretKey) -> String {
    BASE64.encode(key.to_bytes())
}

/// Parse a secret key from the base64 form produced by [`encode_secret_key`].
pub fn parse_secret_key(s: &str) -> Result<SecretKey> {
    let bytes = BASE64
        .decode(s.trim())
        .context("identity key is not valid base64")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("identity key must decode to 32 bytes, got {}", bytes.len()))?;
    Ok(SecretKey::from_bytes(&arr))
}

/// Load an existing stable identity from `path`. Errors if the file is missing,
/// empty, or invalid; use [`create_identity`] to mint a new one.
///
/// The file holds the base64-encoded 32-byte secret on a single line; comment
/// lines (starting with `#`) and blank lines are ignored, so the format is
/// forgiving. Tolerates a brief window where a concurrent [`create_identity`] has
/// created the file but not yet flushed its contents, by retrying on an
/// empty/unparseable read for a short time.
pub fn load_identity(path: &Path) -> Result<SecretKey> {
    const RETRIES: u32 = 20;
    let mut last_err = None;
    for attempt in 0..=RETRIES {
        match try_read_identity_file(path) {
            Ok(key) => return Ok(key),
            Err(e) => {
                // A genuinely missing file won't appear by waiting; only the
                // create-race empty/unparseable window is worth retrying.
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(e);
                }
                last_err = Some(e);
                if attempt < RETRIES {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            }
        }
    }
    Err(last_err.expect("at least one read attempt was made"))
}

/// Generate a new stable identity and persist it to `path` (mode `0o600`, parent
/// dirs created as needed). Creation is atomic: if a concurrent process won the
/// race, re-read its key via [`load_identity`] so both processes converge on one
/// identity instead of each keeping its own.
pub fn create_identity(path: &Path) -> Result<SecretKey> {
    let key = SecretKey::generate();
    match write_identity_file(path, &key) {
        Ok(()) => {
            log::info!(
                "Generated a new stable identity at {} (node id {})",
                path.display(),
                key.public()
            );
            Ok(key)
        }
        // Lost the creation race with a concurrent process (atomic `create_new`
        // let exactly one win). Re-read the key the winner wrote.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            log::info!(
                "Identity file {} was created concurrently; using the existing key",
                path.display()
            );
            load_identity(path)
        }
        Err(e) => Err(anyhow::Error::new(e))
            .with_context(|| format!("Failed to write identity file: {}", path.display())),
    }
}

/// Single read+parse attempt. Errors if the file is missing, empty, or invalid.
fn try_read_identity_file(path: &Path) -> Result<SecretKey> {
    ensure_owner_only(path)?;
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read identity file: {}", path.display()))?;
    let line = contents
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .with_context(|| format!("Identity file is empty: {}", path.display()))?;
    parse_secret_key(line).with_context(|| format!("Invalid identity file: {}", path.display()))
}

/// Ensure the identity file is not readable by group/other. A user-managed
/// `identity_file` could be copied or restored with loose permissions (e.g.
/// `0644`); a secret key must stay owner-only, so tighten it in place rather than
/// silently reading a world-readable secret. No-op on non-unix.
#[cfg(unix)]
fn ensure_owner_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("Failed to stat identity file: {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        log::warn!(
            "Identity file {} had insecure permissions {:#o}; tightening to 0o600",
            path.display(),
            mode
        );
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).with_context(
            || format!("Failed to tighten identity file permissions: {}", path.display()),
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owner_only(_path: &Path) -> Result<()> {
    Ok(())
}

/// Atomically create and write the secret key to `path` with owner-only
/// permissions (`0o600` on unix). Uses `create_new` so a concurrent first run
/// can't have two processes each persist a different key: the loser gets
/// [`std::io::ErrorKind::AlreadyExists`] and re-reads the winner's file.
fn write_identity_file(path: &Path, key: &SecretKey) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "# duopipe iroh identity (keep secret)\n# node id: {}\n{}\n",
        key.public(),
        encode_secret_key(key)
    );

    use std::io::Write;

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(content.as_bytes())?;
        // `mode()` is subject to umask on creation; pin perms to exactly 0o600.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }

    #[cfg(not(unix))]
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(content.as_bytes())?;
    }

    Ok(())
}

/// This process's random instance nonce, generated once and cached for the
/// lifetime of the process. Independent of the iroh identity key.
pub fn self_instance_id() -> u128 {
    static INSTANCE_ID: OnceLock<u128> = OnceLock::new();
    *INSTANCE_ID.get_or_init(rand::random::<u128>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_key_encode_parse_roundtrip() {
        let key = SecretKey::generate();
        let encoded = encode_secret_key(&key);
        let parsed = parse_secret_key(&encoded).unwrap();
        assert_eq!(parsed.to_bytes(), key.to_bytes());
        assert_eq!(parsed.public(), key.public());
    }

    #[test]
    fn test_parse_secret_key_rejects_garbage() {
        assert!(parse_secret_key("not base64 @@@").is_err());
        // Valid base64 but wrong length.
        assert!(parse_secret_key(&BASE64.encode([0u8; 8])).is_err());
    }

    #[test]
    fn test_create_then_load_is_stable() {
        let dir = std::env::temp_dir().join(format!("duopipe-id-test-{}", self_instance_id()));
        let path = dir.join("identity.key");
        let _ = std::fs::remove_file(&path);

        let created = create_identity(&path).unwrap();
        // load_identity reads the same key back.
        let loaded = load_identity(&path).unwrap();
        assert_eq!(created.to_bytes(), loaded.to_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_load_identity_errors_when_missing() {
        let dir = std::env::temp_dir().join(format!("duopipe-id-missing-{}", rand::random::<u64>()));
        let path = dir.join("identity.key");
        let err = load_identity(&path).expect_err("missing file must error");
        // Fail fast on NotFound rather than retrying the create-race window.
        assert_eq!(
            err.downcast_ref::<std::io::Error>().map(|io| io.kind()),
            Some(std::io::ErrorKind::NotFound),
        );
    }

    #[test]
    fn test_create_is_atomic_and_loser_reads_winner_key() {
        // The creation race: the first create wins; a second create must not
        // overwrite but converge on the winner's key (re-read via load_identity).
        let dir = std::env::temp_dir().join(format!("duopipe-id-race-{}", rand::random::<u64>()));
        let path = dir.join("identity.key");

        let winner = create_identity(&path).expect("winner creates");
        let second = create_identity(&path).expect("second create converges");
        assert_eq!(
            second.to_bytes(),
            winner.to_bytes(),
            "a second create must re-read the winner's key, not mint a new one"
        );

        // The underlying write is atomic (`create_new`): a direct second write fails.
        let err =
            write_identity_file(&path, &SecretKey::generate()).expect_err("second write must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_read_tightens_insecure_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("duopipe-id-perm-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.key");

        let key = SecretKey::generate();
        std::fs::write(&path, format!("{}\n", encode_secret_key(&key))).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Reading a world-readable key must succeed but leave it owner-only.
        let got = load_identity(&path).unwrap();
        assert_eq!(got.to_bytes(), key.to_bytes());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions should be tightened to 0o600");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn test_self_instance_id_is_constant() {
        assert_eq!(self_instance_id(), self_instance_id());
    }
}
