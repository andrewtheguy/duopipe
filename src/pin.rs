//! Short, human-typable PIN used by quick mode's nostr signaling.
//!
//! In quick mode a listener can share its ephemeral node id **and** auth token through
//! nostr without any copy-paste: it shows a short PIN that **rotates every 60 seconds**.
//! The PIN is the only secret the dialer types; both sides turn it into a nostr keypair
//! (via [`derive_key_material`]) that locates and decrypts a single relay record carrying
//! the `{node_id, token}` pair (see `crate::nostr_discovery`).
//!
//! The PIN alphabet is **Crockford base32** — unambiguous letters/numbers only (no
//! `I L O U`). It is always *displayed* uppercase and grouped (`XXXX-XXXX`); input is
//! case-insensitive, ignores dashes/spaces, and maps the look-alikes `I`/`L` → `1` and
//! `O` → `0` as a courtesy. The canonical form fed to the KDF is the de-grouped uppercase
//! string.
//!
//! Because the PIN is short (~40 bits) and the encrypted record sits on public relays,
//! the key derivation is deliberately slow and memory-hard (**Argon2id**): a captured
//! record resists offline brute-force, and the 60-second rotation plus a short record TTL
//! bound the exposure window.

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;

/// Crockford base32 alphabet: digits + uppercase letters minus the ambiguous `I L O U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Number of significant characters in a PIN (the canonical, de-grouped form). 8 Crockford
/// characters is ~40 bits.
pub const PIN_LEN: usize = 8;

/// Rotation period, in seconds. The displayed PIN (and the relay record under it) changes
/// every bucket; the dialer searches a small window of adjacent buckets.
pub const BUCKET_SECS: u64 = 60;

/// Argon2id memory cost, in KiB (64 MiB).
const ARGON2_MEM_KIB: u32 = 64 * 1024;
/// Argon2id time cost (passes).
const ARGON2_TIME: u32 = 3;
/// Argon2id parallelism.
const ARGON2_LANES: u32 = 1;

/// Domain-separating salt prefix for the PIN key derivation; the time bucket is appended
/// so each rotation derives an independent key.
const KDF_SALT_DOMAIN: &[u8] = b"duopipe:pin-rendezvous:v1";

/// Generate a fresh random PIN in canonical form (`PIN_LEN` uppercase Crockford chars, no
/// grouping). Uses rejection sampling so every character is uniform over the 32-symbol
/// alphabet.
pub fn generate_pin() -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(PIN_LEN);
    while out.len() < PIN_LEN {
        // 256 is a multiple of 32, so `byte % 32` is already unbiased; no rejection needed.
        let byte: u8 = rng.random();
        out.push(ALPHABET[(byte % 32) as usize] as char);
    }
    out
}

/// Normalize user-typed input to the canonical PIN form, or `None` if it is not a valid
/// PIN. Strips spaces/dashes, uppercases, maps the look-alikes `I`/`L` → `1` and `O` → `0`,
/// and requires exactly `PIN_LEN` Crockford characters.
pub fn normalize_pin(input: &str) -> Option<String> {
    let mut out = String::with_capacity(PIN_LEN);
    for ch in input.chars() {
        match ch {
            ' ' | '-' | '\t' => continue,
            _ => {}
        }
        let up = ch.to_ascii_uppercase();
        let mapped = match up {
            'I' | 'L' => '1',
            'O' => '0',
            other => other,
        };
        if !ALPHABET.contains(&(mapped as u8)) {
            return None;
        }
        out.push(mapped);
        if out.len() > PIN_LEN {
            return None;
        }
    }
    (out.len() == PIN_LEN).then_some(out)
}

/// Format a canonical PIN for display: uppercase, split into two dash-separated groups
/// (`XXXX-XXXX` for the default 8-char PIN). Non-canonical input is returned uppercased
/// as-is.
pub fn format_pin(canonical: &str) -> String {
    if canonical.len() != PIN_LEN {
        return canonical.to_ascii_uppercase();
    }
    let mid = PIN_LEN / 2;
    format!("{}-{}", &canonical[..mid], &canonical[mid..])
}

/// The current rotation bucket: whole 60-second windows since the Unix epoch. The listener
/// publishes under the current bucket; the dialer searches adjacent buckets.
pub fn current_bucket() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs / BUCKET_SECS
}

/// Seconds remaining until the current bucket rolls over (drives the countdown UI).
pub fn secs_until_next_bucket() -> u64 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    BUCKET_SECS - (secs % BUCKET_SECS)
}

/// Derive 32 bytes of key material from a canonical PIN and a rotation bucket via Argon2id.
/// Both peers run this on the same `(pin, bucket)` and get identical output, which
/// `crate::nostr_discovery` turns into the shared nostr keypair.
pub fn derive_key_material(canonical_pin: &str, bucket: u64) -> Result<[u8; 32]> {
    let mut salt = Vec::with_capacity(KDF_SALT_DOMAIN.len() + 8);
    salt.extend_from_slice(KDF_SALT_DOMAIN);
    salt.extend_from_slice(&bucket.to_be_bytes());

    let params = Params::new(ARGON2_MEM_KIB, ARGON2_TIME, ARGON2_LANES, Some(32))
        .map_err(|e| anyhow::anyhow!("invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(canonical_pin.as_bytes(), &salt, &mut out)
        .map_err(|e| anyhow::anyhow!("argon2 key derivation failed: {e}"))
        .context("deriving key material from PIN")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_pin_is_canonical_and_unambiguous() {
        for _ in 0..50 {
            let pin = generate_pin();
            assert_eq!(pin.len(), PIN_LEN);
            assert!(pin.chars().all(|c| ALPHABET.contains(&(c as u8))));
            // No ambiguous characters are ever emitted.
            assert!(!pin.contains(['I', 'L', 'O', 'U']));
            // Normalizing a generated PIN is the identity.
            assert_eq!(normalize_pin(&pin).as_deref(), Some(pin.as_str()));
        }
    }

    #[test]
    fn normalize_strips_grouping_and_maps_lookalikes() {
        // Dashes/spaces ignored, lowercase uppercased.
        assert_eq!(normalize_pin("k7p2-9qxm").as_deref(), Some("K7P29QXM"));
        assert_eq!(normalize_pin(" K7P2 9QXM ").as_deref(), Some("K7P29QXM"));
        // Look-alikes map to digits.
        assert_eq!(normalize_pin("iLoO0000").as_deref(), Some("11000000"));
    }

    #[test]
    fn normalize_rejects_wrong_length_and_bad_chars() {
        assert!(normalize_pin("K7P29QX").is_none()); // too short
        assert!(normalize_pin("K7P29QXMZ").is_none()); // too long
        assert!(normalize_pin("K7P29QX!").is_none()); // bad char
        assert!(normalize_pin("").is_none());
    }

    #[test]
    fn format_groups_into_two_halves() {
        assert_eq!(format_pin("K7P29QXM"), "K7P2-9QXM");
        // Round-trips back through normalize.
        assert_eq!(normalize_pin(&format_pin("K7P29QXM")).as_deref(), Some("K7P29QXM"));
    }

    #[test]
    fn key_material_is_deterministic_and_bucket_pin_specific() {
        let a = derive_key_material("K7P29QXM", 100).unwrap();
        let a_again = derive_key_material("K7P29QXM", 100).unwrap();
        assert_eq!(a, a_again, "same pin + bucket must derive the same key");

        let other_bucket = derive_key_material("K7P29QXM", 101).unwrap();
        assert_ne!(a, other_bucket, "a different bucket must derive a different key");

        let other_pin = derive_key_material("9QXMK7P2", 100).unwrap();
        assert_ne!(a, other_pin, "a different pin must derive a different key");
    }
}
