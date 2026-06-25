//! Token-based authentication for iroh tunnel connections.
//!
//! Provides pre-shared token authentication for the symmetric iroh peer runtime.
//!
//! ## Token Format
//! - Exactly 47 characters
//! - Starts with lowercase `d` (for duopipe)
//! - Remaining 46 characters are Base64URL (no padding)
//! - Decoded payload is exactly 34 bytes:
//!   - First 32 bytes: random entropy
//!   - Last 2 bytes: CRC16-CCITT-FALSE checksum (big-endian) of the 32 random bytes
//!
//! Generate tokens with: `duopipe generate-auth-token`

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use std::collections::HashSet;
use std::path::Path;

/// Required length for authentication tokens.
pub const TOKEN_LENGTH: usize = 47;

/// Required prefix character for tokens.
pub const TOKEN_PREFIX: char = 'd';

/// Number of random bytes in token payload.
const RANDOM_BYTES_LEN: usize = 32;

/// Number of checksum bytes in token payload.
const CHECKSUM_BYTES_LEN: usize = 2;

/// Number of decoded bytes in token payload.
const TOKEN_PAYLOAD_LEN: usize = RANDOM_BYTES_LEN + CHECKSUM_BYTES_LEN;

/// Compute CRC16-CCITT-FALSE.
///
/// Parameters:
/// - Poly: 0x1021
/// - Init: 0xFFFF
/// - RefIn: false
/// - RefOut: false
/// - XorOut: 0x0000
fn crc16_ccitt_false(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;

    for &byte in data {
        crc ^= (byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }

    crc
}

/// Generate a new authentication token.
///
/// Format: `d` + base64url_no_pad(32 random bytes + 2-byte CRC16) = 47 characters total.
pub fn generate_token() -> String {
    let mut random = [0u8; RANDOM_BYTES_LEN];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut random);

    let checksum = crc16_ccitt_false(&random).to_be_bytes();
    let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
    payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
    payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);

    format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload))
}

/// Short, stable fingerprint of a token for cross-device verification.
///
/// The token itself is shown only briefly (and never on the dialing side), so two
/// devices cannot easily confirm they share the same token. This 4-hex-digit
/// CRC16-CCITT-FALSE over the token string is displayed persistently in the UI: if it
/// matches on both devices the tokens match, without ever re-revealing the secret.
pub fn token_fingerprint(token: &str) -> String {
    format!("{:04X}", crc16_ccitt_false(token.as_bytes()))
}

/// Number of hex digits in a token fingerprint (see [`token_fingerprint`]).
pub const FINGERPRINT_LENGTH: usize = 4;

/// Validate that `fp` is a well-formed token fingerprint: exactly four hex digits, as
/// produced by [`token_fingerprint`]. Case-insensitive. Used to check the
/// `auth_token_fingerprint` declared in a nostr-mode config before it is compared
/// against a resolved token.
pub fn validate_fingerprint(fp: &str) -> Result<()> {
    let fp = fp.trim();
    if fp.len() != FINGERPRINT_LENGTH || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!(
            "Token fingerprint must be exactly {} hex digits (e.g. {}), got {:?}",
            FINGERPRINT_LENGTH,
            token_fingerprint("example"),
            fp
        );
    }
    Ok(())
}

/// Whether `token`'s fingerprint matches the `expected` one (case-insensitive). Used
/// to confirm a resolved token belongs to the pairing a config was written for.
pub fn fingerprint_matches(token: &str, expected: &str) -> bool {
    token_fingerprint(token).eq_ignore_ascii_case(expected.trim())
}

/// Validate token format.
///
/// Returns Ok(()) if valid, Err with description if invalid.
pub fn validate_token(token: &str) -> Result<()> {
    // Early ASCII check - all valid tokens are ASCII
    if !token.is_ascii() {
        anyhow::bail!("Token must contain only ASCII characters");
    }

    if token.len() != TOKEN_LENGTH {
        anyhow::bail!(
            "Token must be exactly {} characters, got {} characters",
            TOKEN_LENGTH,
            token.len()
        );
    }

    // Check prefix
    if !token.starts_with(TOKEN_PREFIX) {
        anyhow::bail!(
            "Token must start with '{}', got '{}'",
            TOKEN_PREFIX,
            token.chars().next().unwrap_or('?')
        );
    }

    let encoded_payload = &token[TOKEN_PREFIX.len_utf8()..];
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .context("Token payload is not valid base64url without padding")?;

    if payload.len() != TOKEN_PAYLOAD_LEN {
        anyhow::bail!(
            "Token payload must decode to exactly {} bytes, got {} bytes",
            TOKEN_PAYLOAD_LEN,
            payload.len()
        );
    }

    let random = &payload[..RANDOM_BYTES_LEN];
    let checksum = &payload[RANDOM_BYTES_LEN..];
    let expected_checksum = crc16_ccitt_false(random).to_be_bytes();

    if checksum != expected_checksum {
        anyhow::bail!("Token checksum is invalid");
    }

    Ok(())
}

/// Parse token entries from file content.
///
/// Yields `(line_number, token)` for each non-empty, non-comment token.
/// Handles comment lines (`#`), empty lines, inline comments, and whitespace trimming.
fn parse_token_lines(content: &str) -> impl Iterator<Item = (usize, &str)> {
    content.lines().enumerate().filter_map(|(i, line)| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let token = line.split('#').next().unwrap_or(line).trim();
        if token.is_empty() {
            return None;
        }
        Some((i + 1, token))
    })
}

/// Load a single auth token from a file.
///
/// # File Format
/// - First non-empty, non-comment line is the token (`d` + 46 Base64URL chars, no padding)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
pub fn load_auth_token_from_file(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth token file: {}", path.display()))?;

    if let Some((line_num, token)) = parse_token_lines(&content).next() {
        validate_token(token).with_context(|| {
            format!(
                "Invalid token at {}:{}: '{}'",
                path.display(),
                line_num,
                token
            )
        })?;
        return Ok(token.to_string());
    }

    anyhow::bail!("No valid token found in file: {}", path.display())
}

/// Check if a token is in the valid tokens set.
///
/// Returns true if the token is valid, false otherwise.
/// An empty valid_tokens set means no tokens are authorized.
#[inline]
pub fn is_token_valid(token: &str, valid_tokens: &HashSet<String>) -> bool {
    valid_tokens.contains(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_test_token(random: [u8; RANDOM_BYTES_LEN]) -> String {
        let checksum = crc16_ccitt_false(&random).to_be_bytes();
        let mut payload = [0u8; TOKEN_PAYLOAD_LEN];
        payload[..RANDOM_BYTES_LEN].copy_from_slice(&random);
        payload[RANDOM_BYTES_LEN..].copy_from_slice(&checksum);
        format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload))
    }

    fn decode_payload(token: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD
            .decode(&token[TOKEN_PREFIX.len_utf8()..])
            .unwrap()
    }

    #[test]
    fn test_crc16_ccitt_false_known_vector() {
        // Standard check value for CRC16-CCITT-FALSE with "123456789".
        assert_eq!(crc16_ccitt_false(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_token_fingerprint_stable_and_4_hex() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        let fp = token_fingerprint(&token);
        assert_eq!(fp.len(), 4);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        // Deterministic: same token always yields the same fingerprint.
        assert_eq!(fp, token_fingerprint(&token));
        // It is the CRC16 over the token string bytes.
        assert_eq!(fp, format!("{:04X}", crc16_ccitt_false(token.as_bytes())));
    }

    #[test]
    fn test_token_fingerprint_differs_for_different_tokens() {
        let a = make_test_token([0x01; RANDOM_BYTES_LEN]);
        let b = make_test_token([0x02; RANDOM_BYTES_LEN]);
        assert_ne!(token_fingerprint(&a), token_fingerprint(&b));
    }

    #[test]
    fn test_validate_fingerprint_accepts_four_hex_digits() {
        for fp in ["A1B2", "0000", "ffff", " abCD "] {
            assert!(validate_fingerprint(fp).is_ok(), "should accept {fp:?}");
        }
    }

    #[test]
    fn test_validate_fingerprint_rejects_malformed() {
        for fp in ["", "ABC", "ABCDE", "GHIJ", "12 4"] {
            assert!(validate_fingerprint(fp).is_err(), "should reject {fp:?}");
        }
    }

    #[test]
    fn test_fingerprint_matches_is_case_insensitive() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        let fp = token_fingerprint(&token);
        assert!(fingerprint_matches(&token, &fp));
        assert!(fingerprint_matches(&token, &fp.to_lowercase()));
        assert!(fingerprint_matches(&token, &format!("  {fp}  ")));

        let other = make_test_token([0x01; RANDOM_BYTES_LEN]);
        assert!(!fingerprint_matches(&token, &token_fingerprint(&other)));
    }

    #[test]
    fn test_generate_token_format() {
        let token = generate_token();
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_validate_token_valid() {
        let token = make_test_token([0xAB; RANDOM_BYTES_LEN]);
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_token("dshort");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 47 characters")
        );
    }

    #[test]
    fn test_validate_token_too_long() {
        let token = format!("{}{}", TOKEN_PREFIX, "A".repeat(TOKEN_LENGTH));
        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("exactly 47 characters")
        );
    }

    #[test]
    fn test_validate_token_wrong_prefix() {
        let mut token = generate_token().chars().collect::<Vec<_>>();
        token[0] = 'x';
        let token: String = token.into_iter().collect();

        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("must start with 'd'")
        );
    }

    #[test]
    fn test_validate_token_invalid_base64url_chars() {
        let token = format!("{}{}", TOKEN_PREFIX, "!".repeat(TOKEN_LENGTH - 1));
        let result = validate_token(&token);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("base64url"));
    }

    #[test]
    fn test_validate_token_non_ascii() {
        let result = validate_token("d🔐notascii");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASCII"));
    }

    #[test]
    fn test_validate_token_bad_checksum() {
        let mut payload = decode_payload(&generate_token());
        payload[RANDOM_BYTES_LEN] ^= 0x01;
        let bad = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_validate_token_rejects_mutated_random_byte() {
        let mut payload = decode_payload(&generate_token());
        payload[0] ^= 0x80;
        let bad = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_validate_token_rejects_mutated_checksum_byte() {
        let mut payload = decode_payload(&generate_token());
        payload[TOKEN_PAYLOAD_LEN - 1] ^= 0x01;
        let bad = format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(payload));

        let result = validate_token(&bad);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_load_single_token_from_file() {
        let token_a = generate_token();
        let token_b = generate_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# My auth token").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{}  # comment", token_a).unwrap();
        writeln!(file, "{}", token_b).unwrap(); // ignored

        let result = load_auth_token_from_file(file.path()).unwrap();
        assert_eq!(result, token_a);
    }

    #[test]
    fn test_load_single_token_invalid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bad").unwrap();

        let result = load_auth_token_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_token_valid_empty_set_rejects_all() {
        let token = generate_token();
        let valid_tokens = HashSet::new();
        assert!(!is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let token = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token.clone());

        assert!(is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let token_a = generate_token();
        let token_b = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token_a.clone());

        assert!(!is_token_valid(&token_b, &valid_tokens));
    }
}
