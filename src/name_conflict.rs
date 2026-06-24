//! Local name-conflict flag files.
//!
//! In nostr mode a peer publishes its current node id under a name-derived `d` tag.
//! Two of the user's devices accidentally using the same `name` would otherwise
//! clobber each other silently (newest publish wins). To make a name effectively
//! owned by one device at a time, a device that loses the name writes a small flag
//! file here; on its next startup the flag is found and the user is prompted to take
//! over, rename, or decline before the name is reclaimed.
//!
//! The flag is purely local state — it never depends on any persisted *identifier*
//! (which could be duplicated by a disk-image clone or a copied `~/.config`).
//! Conflict *detection* compares the relay's current node id against the running
//! peer's own ephemeral node id; this file only records that a conflict happened so
//! the decision survives a restart.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Recorded conflict for a name: this device was superseded (or declined to claim)
/// and should ask the user before publishing under `name` again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictFlag {
    /// The name (this peer's config `name`) that is in conflict.
    pub name: String,
    /// The other device's node id observed on the relay when the conflict was
    /// detected (for display in the prompt). Empty if it was a stored startup flag.
    pub other_node_id: String,
    /// Unix seconds when the conflict was detected.
    pub detected_at: u64,
}

/// Filename for a name's flag file: hashed so arbitrary `name` values are
/// filesystem-safe and don't leak the name into the path.
fn flag_path_in(dir: &Path, name: &str) -> PathBuf {
    use std::fmt::Write as _;
    let mut hasher = Sha256::new();
    hasher.update(name.trim().as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(16);
    for b in &digest[..8] {
        let _ = write!(hex, "{b:02x}");
    }
    dir.join(format!("name-conflict-{hex}.json"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the conflict flag for `name`, if one exists (and parses). Any error
/// (missing file, unreadable, malformed) is treated as "no flag".
pub fn read_flag(name: &str) -> Option<ConflictFlag> {
    let dir = crate::config::duopipe_config_dir()?;
    let path = flag_path_in(&dir, name);
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Write (or overwrite) the conflict flag for `name`, creating the config dir if
/// needed.
pub fn write_flag(name: &str, other_node_id: &str) -> std::io::Result<()> {
    let dir = crate::config::duopipe_config_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "could not determine the duopipe config directory",
        )
    })?;
    std::fs::create_dir_all(&dir)?;
    let path = flag_path_in(&dir, name);
    let flag = ConflictFlag {
        name: name.trim().to_string(),
        other_node_id: other_node_id.to_string(),
        detected_at: now_secs(),
    };
    let json = serde_json::to_string_pretty(&flag)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, json)
}

/// Remove the conflict flag for `name`. A missing file is success (idempotent).
pub fn clear_flag(name: &str) -> std::io::Result<()> {
    let Some(dir) = crate::config::duopipe_config_dir() else {
        return Ok(());
    };
    let path = flag_path_in(&dir, name);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_in(dir: &Path, name: &str, other: &str) {
        let path = flag_path_in(dir, name);
        let flag = ConflictFlag {
            name: name.trim().to_string(),
            other_node_id: other.to_string(),
            detected_at: 42,
        };
        std::fs::write(&path, serde_json::to_string_pretty(&flag).unwrap()).unwrap();
    }

    fn read_in(dir: &Path, name: &str) -> Option<ConflictFlag> {
        let content = std::fs::read_to_string(flag_path_in(dir, name)).ok()?;
        serde_json::from_str(&content).ok()
    }

    #[test]
    fn flag_path_is_deterministic_and_name_specific() {
        let dir = Path::new("/tmp/duopipe-test");
        assert_eq!(flag_path_in(dir, "web1"), flag_path_in(dir, "  web1  "));
        assert_ne!(flag_path_in(dir, "web1"), flag_path_in(dir, "web2"));
        let p = flag_path_in(dir, "web1");
        let fname = p.file_name().unwrap().to_string_lossy();
        assert!(fname.starts_with("name-conflict-"), "was: {fname}");
        assert!(fname.ends_with(".json"));
    }

    #[test]
    fn write_read_clear_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_in(dir.path(), "homelab").is_none(), "no flag initially");

        write_in(dir.path(), "homelab", "node-abc");
        let flag = read_in(dir.path(), "homelab").expect("flag present after write");
        assert_eq!(flag.name, "homelab");
        assert_eq!(flag.other_node_id, "node-abc");

        // Clearing removes it; a different name is unaffected.
        write_in(dir.path(), "other", "node-xyz");
        std::fs::remove_file(flag_path_in(dir.path(), "homelab")).unwrap();
        assert!(read_in(dir.path(), "homelab").is_none(), "cleared");
        assert!(read_in(dir.path(), "other").is_some(), "other untouched");
    }
}
