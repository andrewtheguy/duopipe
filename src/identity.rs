//! Persisted iroh identity (stable node id) and the per-process instance nonce.
//!
//! By default duopipe generates an ephemeral iroh `SecretKey` each run, so the
//! node id changes every time. A configured peer can opt into a *stable* node id
//! via `identity_file` (config) — see [`load_or_create_identity`]. The key is
//! stored base64-encoded in a `0o600` file, mirroring how `encryption_key_file`
//! (an age identity) is handled in [`crate::encryption`].
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

/// Load a stable identity from `path`, or generate and persist one on first run.
///
/// The file holds the base64-encoded 32-byte secret on a single line. When it
/// does not exist it is created with mode `0o600` (parent dirs created as
/// needed). Comment lines (starting with `#`) and blank lines are ignored so the
/// file format is forgiving.
pub fn load_or_create_identity(path: &Path) -> Result<SecretKey> {
    if path.exists() {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read identity file: {}", path.display()))?;
        let line = contents
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .with_context(|| format!("Identity file is empty: {}", path.display()))?;
        return parse_secret_key(line)
            .with_context(|| format!("Invalid identity file: {}", path.display()));
    }

    let key = SecretKey::generate();
    write_identity_file(path, &key)
        .with_context(|| format!("Failed to write identity file: {}", path.display()))?;
    log::info!(
        "Generated a new stable identity at {} (node id {})",
        path.display(),
        key.public()
    );
    Ok(key)
}

/// Write the secret key to `path` with owner-only permissions (`0o600` on unix).
fn write_identity_file(path: &Path, key: &SecretKey) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).context("Failed to create identity directory")?;
    }
    let content = format!(
        "# duopipe iroh identity (keep secret)\n# node id: {}\n{}\n",
        key.public(),
        encode_secret_key(key)
    );

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .context("Failed to open identity file")?;
        file.write_all(content.as_bytes())
            .context("Failed to write identity file")?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .context("Failed to set identity file permissions")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, content.as_bytes()).context("Failed to write identity file")?;
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
    fn test_load_or_create_is_stable() {
        let dir = std::env::temp_dir().join(format!("duopipe-id-test-{}", self_instance_id()));
        let path = dir.join("identity.key");
        let _ = std::fs::remove_file(&path);

        let first = load_or_create_identity(&path).unwrap();
        // Second call reads the same key back.
        let second = load_or_create_identity(&path).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());

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
    fn test_self_instance_id_is_constant() {
        assert_eq!(self_instance_id(), self_instance_id());
    }
}
