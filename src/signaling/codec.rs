//! Iroh signaling payload types and encoding/decoding.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Version 5: request-based protocol (single LocalForward stream kind, no remote forwards)
pub const IROH_MULTI_VERSION: u16 = 5;

/// Maximum length for rejection reason to prevent excessively large messages.
pub const MAX_REJECT_REASON_LENGTH: usize = 512;

/// Truncate a rejection reason to the maximum allowed length.
/// If truncation is needed, appends "..." suffix at a valid UTF-8 boundary.
fn truncate_reason(reason: String, max_len: usize) -> String {
    const TRUNCATION_SUFFIX: &str = "...";
    if reason.len() > max_len {
        let max_content_len = max_len.saturating_sub(TRUNCATION_SUFFIX.len());
        let truncated = &reason[..reason.floor_char_boundary(max_content_len)];
        format!("{}{}", truncated, TRUNCATION_SUFFIX)
    } else {
        reason
    }
}

// ============================================================================
// Iroh Multi-Source Handshake Protocol
// ============================================================================

/// Wrapper type for authentication tokens that redacts the value in Debug output.
///
/// This prevents accidental token exposure in logs or error messages.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthToken(String);

impl AuthToken {
    /// Create a new AuthToken from a string.
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    /// Get the token value as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthToken(***)")
    }
}

impl AsRef<str> for AuthToken {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for AuthToken {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// First frame on every non-auth bidirectional stream, written by the stream opener.
///
/// Makes each stream self-describing so a symmetric peer can route accepted streams
/// without positional assumptions. The auth stream (the very first stream) is the only
/// stream that does NOT carry a `StreamHello`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum StreamHello {
    /// Request data stream. The opener listens locally and wants the acceptor to
    /// connect out to `source` (e.g. "tcp://127.0.0.1:22"). The acceptor checks
    /// `source` against its `allowed_sources` allowlist, replies with a
    /// [`StreamAck`], and (if accepted) bridges traffic.
    LocalForward { version: u16, source: String },
}

impl StreamHello {
    pub fn local_forward(source: impl Into<String>) -> Self {
        StreamHello::LocalForward {
            version: IROH_MULTI_VERSION,
            source: source.into(),
        }
    }

    fn version(&self) -> u16 {
        match self {
            StreamHello::LocalForward { version, .. } => *version,
        }
    }
}

/// Acknowledgement sent by the acceptor of a data stream after attempting to set up
/// its end (connect to the destination). Surfaces connect success/failure to the opener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAck {
    pub version: u16,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl StreamAck {
    pub fn accepted() -> Self {
        Self {
            version: IROH_MULTI_VERSION,
            accepted: true,
            reason: None,
        }
    }

    /// Create a rejection ack with the given reason.
    /// The reason will be truncated if it exceeds [`MAX_REJECT_REASON_LENGTH`].
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: IROH_MULTI_VERSION,
            accepted: false,
            reason: Some(truncate_reason(reason.into(), MAX_REJECT_REASON_LENGTH)),
        }
    }
}

/// Authentication request sent by client immediately after iroh connection.
/// Must be sent on the first bidirectional stream opened by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub version: u16,
    /// Authentication token for server validation
    pub auth_token: AuthToken,
}

impl AuthRequest {
    pub fn new(auth_token: impl Into<String>) -> Self {
        Self {
            version: IROH_MULTI_VERSION,
            auth_token: AuthToken::new(auth_token),
        }
    }
}

/// Authentication response from server to client.
/// Sent in response to AuthRequest on the auth stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u16,
    /// Whether authentication was accepted
    pub accepted: bool,
    /// Reason for rejection (if rejected)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AuthResponse {
    pub fn accepted() -> Self {
        Self {
            version: IROH_MULTI_VERSION,
            accepted: true,
            reason: None,
        }
    }

    /// Create a rejection response with the given reason.
    /// The reason will be truncated if it exceeds [`MAX_REJECT_REASON_LENGTH`].
    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            version: IROH_MULTI_VERSION,
            accepted: false,
            reason: Some(truncate_reason(reason.into(), MAX_REJECT_REASON_LENGTH)),
        }
    }
}

// ============================================================================
// Stream-based Encoding/Decoding for Iroh Multi-Source
// ============================================================================

/// Maximum size for source request/response messages (16KB)
pub const MAX_SOURCE_MESSAGE_SIZE: usize = 16 * 1024;

// ============================================================================
// Length-Prefixed JSON Helpers
// ============================================================================

/// Encode a value as length-prefixed JSON bytes.
fn encode_length_prefixed<T: Serialize>(value: &T, type_name: &str) -> Result<Vec<u8>> {
    let json =
        serde_json::to_vec(value).with_context(|| format!("Failed to serialize {}", type_name))?;
    if json.len() > MAX_SOURCE_MESSAGE_SIZE {
        anyhow::bail!("{} too large: {} bytes", type_name, json.len());
    }
    let len = (json.len() as u32).to_be_bytes();
    let mut buf = Vec::with_capacity(4 + json.len());
    buf.extend_from_slice(&len);
    buf.extend_from_slice(&json);
    Ok(buf)
}

/// Decode a length-prefixed JSON value with version validation.
fn decode_length_prefixed<T: for<'de> Deserialize<'de>>(
    data: &[u8],
    expected_version: u16,
    get_version: impl FnOnce(&T) -> u16,
    type_name: &str,
) -> Result<T> {
    if data.len() < 4 {
        anyhow::bail!("{} too short: {} bytes", type_name, data.len());
    }
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if len > MAX_SOURCE_MESSAGE_SIZE {
        anyhow::bail!("{} length too large: {} bytes", type_name, len);
    }
    if data.len() < 4 + len {
        anyhow::bail!(
            "{} incomplete: expected {} bytes, got {}",
            type_name,
            4 + len,
            data.len()
        );
    }
    let value: T = serde_json::from_slice(&data[4..4 + len])
        .with_context(|| format!("Invalid {} JSON", type_name))?;
    let version = get_version(&value);
    if version != expected_version {
        anyhow::bail!(
            "{} version mismatch: expected {}, got {}",
            type_name,
            expected_version,
            version
        );
    }
    Ok(value)
}

/// Encode a StreamHello as length-prefixed JSON bytes.
pub fn encode_stream_hello(hello: &StreamHello) -> Result<Vec<u8>> {
    encode_length_prefixed(hello, "StreamHello")
}

/// Decode a StreamHello from length-prefixed JSON bytes.
pub fn decode_stream_hello(data: &[u8]) -> Result<StreamHello> {
    decode_length_prefixed(
        data,
        IROH_MULTI_VERSION,
        |h: &StreamHello| h.version(),
        "StreamHello",
    )
}

/// Encode a StreamAck as length-prefixed JSON bytes.
pub fn encode_stream_ack(ack: &StreamAck) -> Result<Vec<u8>> {
    encode_length_prefixed(ack, "StreamAck")
}

/// Decode a StreamAck from length-prefixed JSON bytes.
pub fn decode_stream_ack(data: &[u8]) -> Result<StreamAck> {
    decode_length_prefixed(
        data,
        IROH_MULTI_VERSION,
        |a: &StreamAck| a.version,
        "StreamAck",
    )
}

/// Encode an AuthRequest as length-prefixed JSON bytes.
pub fn encode_auth_request(req: &AuthRequest) -> Result<Vec<u8>> {
    encode_length_prefixed(req, "AuthRequest")
}

/// Decode an AuthRequest from length-prefixed JSON bytes.
pub fn decode_auth_request(data: &[u8]) -> Result<AuthRequest> {
    decode_length_prefixed(
        data,
        IROH_MULTI_VERSION,
        |r: &AuthRequest| r.version,
        "AuthRequest",
    )
}

/// Encode an AuthResponse as length-prefixed JSON bytes.
pub fn encode_auth_response(resp: &AuthResponse) -> Result<Vec<u8>> {
    encode_length_prefixed(resp, "AuthResponse")
}

/// Decode an AuthResponse from length-prefixed JSON bytes.
pub fn decode_auth_response(data: &[u8]) -> Result<AuthResponse> {
    decode_length_prefixed(
        data,
        IROH_MULTI_VERSION,
        |r: &AuthResponse| r.version,
        "AuthResponse",
    )
}

/// Read a length-prefixed message from a stream.
/// Returns the raw bytes including the length prefix.
pub async fn read_length_prefixed<R: tokio::io::AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("Failed to read message length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_SOURCE_MESSAGE_SIZE {
        anyhow::bail!("Message length too large: {} bytes", len);
    }
    let mut buf = Vec::with_capacity(4 + len);
    buf.extend_from_slice(&len_buf);
    buf.resize(4 + len, 0);
    reader
        .read_exact(&mut buf[4..])
        .await
        .context("Failed to read message body")?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_token_debug_redacts_value() {
        let token = AuthToken::new("super_secret_token");
        let debug_output = format!("{:?}", token);
        assert_eq!(debug_output, "AuthToken(***)");
        assert!(!debug_output.contains("super_secret"));
    }

    #[test]
    fn test_auth_token_accessors() {
        let token = AuthToken::new("my_token_value_");
        assert_eq!(token.as_str(), "my_token_value_");
        assert_eq!(token.as_ref(), "my_token_value_");
        assert_eq!(&*token, "my_token_value_"); // Deref
    }

    #[test]
    fn test_auth_token_serde_roundtrip() {
        let token = AuthToken::new("test_token_12345");
        let json = serde_json::to_string(&token).unwrap();
        // Should serialize as plain string (transparent)
        assert_eq!(json, "\"test_token_12345\"");

        let parsed: AuthToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_str(), "test_token_12345");
    }

    #[test]
    fn test_stream_hello_local_forward_roundtrip() {
        let hello = StreamHello::local_forward("tcp://127.0.0.1:22");
        let encoded = encode_stream_hello(&hello).unwrap();
        let decoded = decode_stream_hello(&encoded).unwrap();
        match decoded {
            StreamHello::LocalForward { version, source } => {
                assert_eq!(version, IROH_MULTI_VERSION);
                assert_eq!(source, "tcp://127.0.0.1:22");
            }
        }
    }

    #[test]
    fn test_stream_ack_roundtrip() {
        let ack = StreamAck::accepted();
        let decoded = decode_stream_ack(&encode_stream_ack(&ack).unwrap()).unwrap();
        assert!(decoded.accepted);
        assert!(decoded.reason.is_none());

        let rej = StreamAck::rejected("connect failed");
        let decoded = decode_stream_ack(&encode_stream_ack(&rej).unwrap()).unwrap();
        assert!(!decoded.accepted);
        assert_eq!(decoded.reason.as_deref(), Some("connect failed"));
    }

    #[test]
    fn test_auth_token_empty_string() {
        let token = AuthToken::new("");
        // Accessors should return empty string
        assert_eq!(token.as_str(), "");
        assert_eq!(token.as_ref(), "");
        assert_eq!(&*token, ""); // Deref
                                 // Debug should still be redacted
        let debug_output = format!("{:?}", token);
        assert_eq!(debug_output, "AuthToken(***)");
    }

    #[test]
    fn test_auth_token_special_characters_unicode() {
        // Test with special characters and unicode
        let special_token = "tök€n-with_spëcial.chars!@#$%^&*()🔐";
        let token = AuthToken::new(special_token);
        // Accessors should return original value unchanged
        assert_eq!(token.as_str(), special_token);
        assert_eq!(token.as_ref(), special_token);
        assert_eq!(&*token, special_token); // Deref
                                            // Debug should still be redacted (not expose unicode/special chars)
        let debug_output = format!("{:?}", token);
        assert_eq!(debug_output, "AuthToken(***)");
        assert!(!debug_output.contains("tök€n"));
        assert!(!debug_output.contains("🔐"));
    }

    #[test]
    fn test_auth_token_special_characters_serde_roundtrip() {
        let special_token = "tök€n-with_spëcial.chars!@#🔐";
        let token = AuthToken::new(special_token);
        let json = serde_json::to_string(&token).unwrap();
        let parsed: AuthToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_str(), special_token);
    }

    #[test]
    fn test_truncate_reason_no_truncation() {
        let reason = "short reason".to_string();
        let result = truncate_reason(reason.clone(), 100);
        assert_eq!(result, reason);
    }

    #[test]
    fn test_truncate_reason_exact_limit() {
        let reason = "x".repeat(10);
        let result = truncate_reason(reason.clone(), 10);
        assert_eq!(result, reason); // No truncation at exact limit
    }

    #[test]
    fn test_truncate_reason_ascii_truncation() {
        let reason = "a".repeat(20);
        let result = truncate_reason(reason, 10);
        assert_eq!(result, "aaaaaaa..."); // 7 chars + "..."
        assert_eq!(result.len(), 10);
    }

    #[test]
    fn test_truncate_reason_utf8_safe_truncation() {
        // "é" is 2 bytes in UTF-8
        let reason = "ééééé".to_string(); // 10 bytes
        let result = truncate_reason(reason, 8);
        // Should truncate at valid UTF-8 boundary
        // max_content_len = 8 - 3 = 5, floor_char_boundary(5) = 4 (2 chars)
        assert_eq!(result, "éé...");
        assert!(result.len() <= 8);
    }

    #[test]
    fn test_truncate_reason_emoji_safe_truncation() {
        // "🔐" is 4 bytes in UTF-8
        let reason = "🔐🔐🔐".to_string(); // 12 bytes
        let result = truncate_reason(reason, 10);
        // max_content_len = 10 - 3 = 7, floor_char_boundary(7) = 4 (1 emoji)
        assert_eq!(result, "🔐...");
        assert!(result.len() <= 10);
    }

    #[test]
    fn test_truncate_reason_suffix_only_edge_case() {
        let reason = "abcdef".to_string();
        let result = truncate_reason(reason, 3);
        // max_content_len = 3 - 3 = 0, so just suffix
        assert_eq!(result, "...");
    }

    // ========================================================================
    // Decode error path tests
    // ========================================================================

    #[test]
    fn test_decode_stream_hello_too_short() {
        assert!(decode_stream_hello(&[0, 0]).is_err());
    }

    #[test]
    fn test_decode_stream_hello_incomplete() {
        // Length prefix says 100 bytes but only 4 bytes of body follow
        let mut buf = vec![0, 0, 0, 100];
        buf.extend_from_slice(b"abcd");
        assert!(decode_stream_hello(&buf).is_err());
    }

    #[test]
    fn test_decode_stream_hello_invalid_json() {
        // Length prefix matches body length, but body is not valid JSON
        let body = b"not json";
        let len = (body.len() as u32).to_be_bytes();
        let mut buf = Vec::from(len);
        buf.extend_from_slice(body);
        assert!(decode_stream_hello(&buf).is_err());
    }

    #[test]
    fn test_decode_stream_hello_wrong_version() {
        let bad = StreamHello::LocalForward {
            version: IROH_MULTI_VERSION + 1,
            source: "tcp://127.0.0.1:22".into(),
        };
        let json = serde_json::to_vec(&bad).unwrap();
        let len = (json.len() as u32).to_be_bytes();
        let mut buf = Vec::from(len);
        buf.extend_from_slice(&json);
        let err = decode_stream_hello(&buf).unwrap_err();
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn test_decode_stream_hello_exceeds_max_size() {
        // Length prefix claims a size larger than MAX_SOURCE_MESSAGE_SIZE
        let len = ((MAX_SOURCE_MESSAGE_SIZE + 1) as u32).to_be_bytes();
        let buf = Vec::from(len);
        let err = decode_stream_hello(&buf).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    #[test]
    fn test_encode_stream_hello_exceeds_max_size() {
        let hello = StreamHello::local_forward("x".repeat(MAX_SOURCE_MESSAGE_SIZE));
        let err = encode_stream_hello(&hello).unwrap_err();
        assert!(err.to_string().contains("too large"));
    }

    // ========================================================================
    // AuthRequest / AuthResponse roundtrip tests
    // ========================================================================

    #[test]
    fn test_auth_request_roundtrip() {
        let req = AuthRequest::new("my_secret_token");
        let encoded = encode_auth_request(&req).unwrap();
        let decoded = decode_auth_request(&encoded).unwrap();
        assert_eq!(decoded.version, IROH_MULTI_VERSION);
        assert_eq!(decoded.auth_token.as_str(), "my_secret_token");
    }

    #[test]
    fn test_auth_response_accepted_roundtrip() {
        let resp = AuthResponse::accepted();
        let encoded = encode_auth_response(&resp).unwrap();
        let decoded = decode_auth_response(&encoded).unwrap();
        assert_eq!(decoded.version, IROH_MULTI_VERSION);
        assert!(decoded.accepted);
        assert!(decoded.reason.is_none());
    }

    #[test]
    fn test_auth_response_rejected_roundtrip() {
        let resp = AuthResponse::rejected("bad token");
        let encoded = encode_auth_response(&resp).unwrap();
        let decoded = decode_auth_response(&encoded).unwrap();
        assert_eq!(decoded.version, IROH_MULTI_VERSION);
        assert!(!decoded.accepted);
        assert_eq!(decoded.reason.as_deref(), Some("bad token"));
    }

}
