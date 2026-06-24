//! Nostr side channel for discovering a peer's current ephemeral iroh node id.
//!
//! duopipe keeps the iroh identity ephemeral (a fresh node id every run) and uses
//! nostr to publish & look it up. Both peers derive the *same* nostr keypair from
//! the shared `auth_token`, so the listener publishes a replaceable event whose
//! content is its current node id and the dialer derives the same key to look it up.
//! The node id is public — the `auth_token` still gates the actual connection — so
//! the value is not encrypted.
//!
//! Several peers may share one `auth_token`, so each is distinguished by a short
//! **identifier**: the kind-30078 `d` tag is `duopipe:nodeid:<sha256(auth||id)>`. A
//! listener publishes under its own identifier; a dialer hashes the identifier it was
//! given into the same `d` tag and fetches that one record. The hash is salted with
//! the `auth_token` so a short, low-entropy identifier cannot be guessed or
//! enumerated on relays without the shared token. Because the `d` tag is keyed on the
//! stable identifier (not the volatile node id), a listener restart replaces its own
//! record — no stale accumulation.
//!
//! The node id in the event content is **encrypted** (NIP-44) under the shared
//! auth-token-derived keypair — the listener encrypts to its own derived public key
//! and any peer with the same `auth_token` derives the same key to decrypt. This
//! keeps the node id off the relays in the clear (the `auth_token` still gates the
//! actual connection).
//!
//! Discovery therefore requires a *shared* `auth_token`: a listener that
//! autogenerates a token publishes under a key the dialer cannot derive until that
//! token reaches it (which it must anyway, for auth).

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::EndpointId;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};

/// Default public relays used when the config supplies none. Matches the set used
/// by the sibling nostr projects (beam-rs / xfer-webrtc).
pub const DEFAULT_NOSTR_RELAYS: &[&str] = &[
    "wss://nos.lol",
    "wss://relay.nostr.net",
    "wss://relay.primal.net",
    "wss://relay.snort.social",
];

/// Parameterized-replaceable event kind (NIP-78 application-specific data) used to
/// carry the node id. Replaceable, so the latest publish supersedes the previous.
const NODEID_KIND_U16: u16 = 30078;
/// Base of the `d` tag identifying duopipe node-id records; the per-peer identifier
/// hash is appended (see [`identifier_dtag`]).
const NODEID_DTAG_BASE: &str = "duopipe:nodeid";
/// Domain separation for deriving the nostr key from the auth token.
const KEY_DERIVATION_DOMAIN: &[u8] = b"duopipe:nostr-rendezvous:v1";
/// Domain separation for hashing a peer identifier into its `d` tag.
const IDENTIFIER_DOMAIN: &[u8] = b"duopipe:peer-id:v1";

/// Timeout for establishing relay connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a node-id lookup query.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn nodeid_kind() -> Kind {
    Kind::from_u16(NODEID_KIND_U16)
}

/// Build the `d` tag for a peer's node-id record: the base tag plus a hex
/// SHA-256 of the (trimmed) identifier, salted with the shared `auth_token`. The
/// salt means a short identifier cannot be guessed or enumerated on relays without
/// the token; both parties share the token, so both derive the same tag.
fn identifier_dtag(auth_token: &str, identifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(IDENTIFIER_DOMAIN);
    hasher.update(auth_token.as_bytes());
    hasher.update(identifier.trim().as_bytes());
    let digest = hasher.finalize();
    let mut tag = String::with_capacity(NODEID_DTAG_BASE.len() + 1 + digest.len() * 2);
    tag.push_str(NODEID_DTAG_BASE);
    tag.push(':');
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(tag, "{b:02x}");
    }
    tag
}

/// Derive the shared nostr identity from the `auth_token`. Both peers run this on
/// the same token and get the same keypair, so the listener publishes and the
/// dialer looks up under one author key with no extra identifier exchanged.
pub fn derive_keys(auth_token: &str) -> Result<Keys> {
    let mut hasher = Sha256::new();
    hasher.update(KEY_DERIVATION_DOMAIN);
    hasher.update(auth_token.as_bytes());
    let digest = hasher.finalize();
    let secret =
        SecretKey::from_slice(&digest).context("deriving nostr secret key from auth token")?;
    Ok(Keys::new(secret))
}

/// Connect a no-signer nostr client to the given relays. Events are signed by the
/// caller before sending, so no signer is configured here. Bails if none connect.
async fn connect_client(relays: &[String]) -> Result<Client> {
    let client = Client::default();
    let mut added = 0;
    for relay in relays {
        if client.add_relay(relay.clone()).await.is_ok() {
            added += 1;
        }
    }
    if added == 0 {
        anyhow::bail!(
            "no usable nostr relays among {} configured",
            relays.len().max(1)
        );
    }
    client.connect().await;
    client.wait_for_connection(CONNECT_TIMEOUT).await;
    Ok(client)
}

/// Publish this peer's current ephemeral node id under the auth-token-derived key,
/// tagged with this peer's `identifier` so peers sharing the token stay distinct.
pub async fn publish_node_id(
    auth_token: &str,
    identifier: &str,
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    let keys = derive_keys(auth_token)?;
    // Encrypt the node id under the shared (auth-token-derived) keypair so it does
    // not appear on relays in the clear. Self-encryption: encrypt to our own derived
    // public key — any peer with the same auth token derives the same key to decrypt.
    let content = nip44::encrypt(
        keys.secret_key(),
        &keys.public_key(),
        node_id.to_string(),
        nip44::Version::V2,
    )
    .context("encrypting node id for nostr")?;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(nodeid_kind(), content)
        .tags([Tag::identifier(identifier_dtag(auth_token, identifier))])
        .sign_with_keys(&keys)
        .context("signing node-id event")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing node-id event to relays")?;
    Ok(())
}

/// Look up the node id published under `identifier` by a peer sharing the auth token.
/// Returns the most recently published node id for that identifier.
pub async fn lookup_node_id(
    auth_token: &str,
    identifier: &str,
    relays: &[String],
) -> Result<EndpointId> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(nodeid_kind())
        .author(keys.public_key())
        .identifier(identifier_dtag(auth_token, identifier))
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the peer's node id")?;
    let latest = events.iter().max_by_key(|e| e.created_at).with_context(|| {
        format!(
            "no node-id record found on nostr for identifier '{}' (is that peer running and sharing the same auth token?)",
            identifier.trim()
        )
    })?;
    let node_id = nip44::decrypt(keys.secret_key(), &keys.public_key(), &latest.content)
        .context("decrypting nostr node-id record (wrong auth token?)")?;
    node_id
        .trim()
        .parse::<EndpointId>()
        .context("nostr node-id record is not a valid node id")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_keys_is_deterministic_and_token_specific() {
        let a = derive_keys("token-one").unwrap();
        let a_again = derive_keys("token-one").unwrap();
        let b = derive_keys("token-two").unwrap();
        assert_eq!(
            a.public_key(),
            a_again.public_key(),
            "same token must derive the same key"
        );
        assert_ne!(
            a.public_key(),
            b.public_key(),
            "different tokens must derive different keys"
        );
    }

    #[test]
    fn identifier_dtag_is_deterministic_identifier_and_token_specific() {
        let token = "the-auth-token";
        let a = identifier_dtag(token, "web1");
        let a_again = identifier_dtag(token, "web1");
        let b = identifier_dtag(token, "web2");
        assert_eq!(a, a_again, "same token + identifier must derive the same d tag");
        assert_ne!(a, b, "different identifiers must derive different d tags");
        // The d tag carries the base prefix.
        assert!(a.starts_with(NODEID_DTAG_BASE), "d tag was: {a}");

        // Trimming: surrounding whitespace must not change the tag.
        assert_eq!(a, identifier_dtag(token, "  web1  "));

        // Salt: the same identifier under a different token derives a different tag.
        let other_token = identifier_dtag("other-token", "web1");
        assert_ne!(a, other_token, "the auth token salts the identifier hash");
    }

    #[test]
    fn node_id_round_trips_through_encrypted_event_content() {
        let token = "round-trip-token";
        let keys = derive_keys(token).unwrap();
        let node_id = iroh::SecretKey::generate().public();
        // Mirror publish: encrypt the node id to our own derived key.
        let content = nip44::encrypt(
            keys.secret_key(),
            &keys.public_key(),
            node_id.to_string(),
            nip44::Version::V2,
        )
        .expect("encrypt node id");
        let event = EventBuilder::new(nodeid_kind(), content)
            .tags([Tag::identifier(identifier_dtag(token, "web1"))])
            .sign_with_keys(&keys)
            .expect("sign node-id event");
        // The ciphertext must not contain the cleartext node id.
        assert!(
            !event.content.contains(&node_id.to_string()),
            "node id leaked in cleartext"
        );
        // Mirror lookup: decrypt with the same shared key.
        let decrypted = nip44::decrypt(keys.secret_key(), &keys.public_key(), &event.content)
            .expect("decrypt node id");
        let parsed: EndpointId = decrypted.trim().parse().expect("decrypts to a node id");
        assert_eq!(parsed.to_string(), node_id.to_string());
    }

    #[test]
    fn wrong_auth_token_cannot_decrypt_node_id() {
        let node_id = iroh::SecretKey::generate().public();
        let publisher = derive_keys("the-real-token").unwrap();
        let content = nip44::encrypt(
            publisher.secret_key(),
            &publisher.public_key(),
            node_id.to_string(),
            nip44::Version::V2,
        )
        .expect("encrypt node id");
        // A peer with a different auth token derives a different key and cannot read it.
        let attacker = derive_keys("a-different-token").unwrap();
        assert!(
            nip44::decrypt(attacker.secret_key(), &attacker.public_key(), &content).is_err(),
            "decryption must fail under a different auth token"
        );
    }
}
