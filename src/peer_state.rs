//! Per-name local state file: a process-lifetime lock plus the nostr conflict flag.
//!
//! In config mode a peer is identified by its config `name`. We keep a single small
//! state file per name under the config dir and use it two ways:
//!
//! 1. **Local lock.** While a peer runs, it holds an OS advisory lock (flock) on this
//!    file for its entire lifetime. A second local process started with the same name
//!    fails to acquire the lock and quits at startup — the same-machine counterpart to
//!    the cross-device nostr conflict resolution. Because the lock is held for the
//!    whole process, there is no mid-session local conflict to handle.
//!
//! 2. **Conflict flag.** The file body stores the cross-device conflict flag JSON (a
//!    different machine using the same name superseded us on nostr). Its presence on a
//!    later startup prompts the user to take over / rename / decline before the name is
//!    reclaimed. "No flag" is simply an empty body — the file itself stays put so the
//!    lock target is stable.
//!
//! Detection never depends on any persisted *identifier* (which could be duplicated by
//! an accidental clone); the lock keys only off the local file, and the cross-device
//! flag records the *other* device's ephemeral node id for display.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Recorded cross-device conflict for a name: another machine superseded us (or we
/// declined to claim) and should ask the user before publishing under `name` again.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConflictFlag {
    /// The name (this peer's config `name`) that is in conflict.
    pub name: String,
    /// The other device's node id observed on the relay when the conflict was
    /// detected (for display in the prompt).
    pub other_node_id: String,
    /// Unix seconds when the conflict was detected.
    pub detected_at: u64,
}

/// Why a per-name lock could not be acquired.
#[derive(Debug)]
pub enum NameLockError {
    /// Another local process already holds the lock for this name.
    Held,
    /// The lock file could not be opened or locked for another reason.
    Io(io::Error),
}

/// Path of a name's state file. Namespaced by the token `fingerprint` (so different
/// pairings sharing a `name` get distinct state/lock files) and then the `name` used
/// verbatim — safe because `name` is validated to ASCII letters, digits, and `_`
/// (see `config::validate_name`), so the file is human-readable. Generic `state-`
/// prefix (the file holds both the lock and the conflict flag).
fn state_path_in(dir: &Path, name: &str, fingerprint: &str) -> PathBuf {
    let fp = fingerprint.trim().to_ascii_lowercase();
    dir.join(format!("state-{fp}-{}.json", name.trim()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Open (creating if needed) the state file for `name` without truncating, so any
/// existing conflict flag is preserved.
fn open_state_file(dir: &Path, name: &str, fingerprint: &str) -> io::Result<File> {
    std::fs::create_dir_all(dir)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(state_path_in(dir, name, fingerprint))
}

/// Acquire the process-lifetime exclusive lock for `name` in `dir`. The returned
/// `File` holds an OS advisory lock for as long as it is alive (drop it — e.g. on
/// process exit — to release).
fn acquire_lock_in(dir: &Path, name: &str, fingerprint: &str) -> Result<File, NameLockError> {
    let file = open_state_file(dir, name, fingerprint).map_err(NameLockError::Io)?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(NameLockError::Held),
        Err(TryLockError::Error(e)) => Err(NameLockError::Io(e)),
    }
}

/// Acquire the process-lifetime exclusive lock for `name` (in the duopipe config dir),
/// scoped to the token `fingerprint`. Keep the returned `File` alive for as long as the
/// process should hold the name; the lock releases when it is dropped. Returns
/// `Err(NameLockError::Held)` if another local duopipe process is already running under
/// this name and token.
pub fn acquire_name_lock(name: &str, fingerprint: &str) -> Result<File, NameLockError> {
    let dir = crate::config::duopipe_config_dir().ok_or_else(|| {
        NameLockError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine the duopipe config directory",
        ))
    })?;
    acquire_lock_in(&dir, name, fingerprint)
}

/// Read the conflict flag for `name` (under the token `fingerprint`), if its state file
/// holds one. An empty body, missing file, or unparseable content is treated as "no
/// flag".
pub fn read_flag(name: &str, fingerprint: &str) -> Option<ConflictFlag> {
    let dir = crate::config::duopipe_config_dir()?;
    let content = std::fs::read_to_string(state_path_in(&dir, name, fingerprint)).ok()?;
    serde_json::from_str(content.trim()).ok()
}

/// Write (or overwrite) the conflict flag into `name`'s state file (under the token
/// `fingerprint`). The file is the lock target, so this updates the body in place and
/// never removes it.
pub fn write_flag(name: &str, fingerprint: &str, other_node_id: &str) -> io::Result<()> {
    let dir = crate::config::duopipe_config_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "could not determine the duopipe config directory",
        )
    })?;
    std::fs::create_dir_all(&dir)?;
    let flag = ConflictFlag {
        name: name.trim().to_string(),
        other_node_id: other_node_id.to_string(),
        detected_at: now_secs(),
    };
    let json = serde_json::to_string_pretty(&flag)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(state_path_in(&dir, name, fingerprint), json)
}

/// Clear the conflict flag for `name` (under the token `fingerprint`) by truncating its
/// state file to an empty body. The file itself is kept (it is the lock target), so this
/// never unlinks it.
pub fn clear_flag(name: &str, fingerprint: &str) -> io::Result<()> {
    let Some(dir) = crate::config::duopipe_config_dir() else {
        return Ok(());
    };
    let path = state_path_in(&dir, name, fingerprint);
    if path.exists() {
        std::fs::write(path, b"")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "abcd1234";

    fn write_in(dir: &Path, name: &str, other: &str) {
        let flag = ConflictFlag {
            name: name.trim().to_string(),
            other_node_id: other.to_string(),
            detected_at: 42,
        };
        std::fs::write(
            state_path_in(dir, name, FP),
            serde_json::to_string_pretty(&flag).unwrap(),
        )
        .unwrap();
    }

    fn read_in(dir: &Path, name: &str) -> Option<ConflictFlag> {
        let content = std::fs::read_to_string(state_path_in(dir, name, FP)).ok()?;
        serde_json::from_str(content.trim()).ok()
    }

    #[test]
    fn state_path_is_deterministic_name_and_fingerprint_specific() {
        let dir = Path::new("/tmp/duopipe-test");
        assert_eq!(
            state_path_in(dir, "web1", FP),
            state_path_in(dir, "  web1  ", FP)
        );
        assert_ne!(
            state_path_in(dir, "web1", FP),
            state_path_in(dir, "web2", FP)
        );
        // Same name, different token fingerprint ⇒ different file.
        assert_ne!(
            state_path_in(dir, "web1", FP),
            state_path_in(dir, "web1", "00112233")
        );
        let p = state_path_in(dir, "web1", FP);
        let fname = p.file_name().unwrap().to_string_lossy();
        // The name appears verbatim (not hashed) for visibility.
        assert_eq!(fname, format!("state-{FP}-web1.json"), "was: {fname}");
    }

    #[test]
    fn write_read_clear_flag_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_in(dir.path(), "homelab").is_none(), "no flag initially");

        write_in(dir.path(), "homelab", "node-abc");
        let flag = read_in(dir.path(), "homelab").expect("flag present after write");
        assert_eq!(flag.name, "homelab");
        assert_eq!(flag.other_node_id, "node-abc");

        // Clearing truncates the body to empty but keeps the file present (the lock
        // target). A different name is unaffected.
        write_in(dir.path(), "other", "node-xyz");
        std::fs::write(state_path_in(dir.path(), "homelab", FP), b"").unwrap();
        assert!(
            state_path_in(dir.path(), "homelab", FP).exists(),
            "file kept"
        );
        assert!(read_in(dir.path(), "homelab").is_none(), "flag cleared");
        assert!(read_in(dir.path(), "other").is_some(), "other untouched");
    }

    #[test]
    fn lock_is_exclusive_and_preserves_existing_flag() {
        let dir = tempfile::tempdir().unwrap();
        // A pre-existing flag must survive acquiring the lock (no truncation on open).
        write_in(dir.path(), "homelab", "node-abc");

        let first = acquire_lock_in(dir.path(), "homelab", FP).expect("first lock");
        assert!(
            read_in(dir.path(), "homelab").is_some(),
            "lock open preserves the flag body"
        );

        // A second acquisition (separate open file description) is refused while held.
        match acquire_lock_in(dir.path(), "homelab", FP) {
            Err(NameLockError::Held) => {}
            other => panic!("expected Held, got {other:?}"),
        }

        // A different name locks independently.
        let _other = acquire_lock_in(dir.path(), "laptop", FP).expect("different name locks");

        // Releasing the first lets it be re-acquired.
        drop(first);
        let _again = acquire_lock_in(dir.path(), "homelab", FP).expect("re-acquire after drop");
    }
}
