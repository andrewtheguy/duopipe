//! Nostr side channel for discovering a peer's current ephemeral iroh node id.
//!
//! duopipe keeps the iroh identity ephemeral (a fresh node id every run) and uses
//! nostr to publish & look it up. Both peers derive the *same* nostr keypair from
//! the shared `auth_token`, so no extra identifier is exchanged: the listener
//! publishes a replaceable event whose content is its current node id, and the
//! dialer derives the same key and looks it up. The node id is public — the
//! `auth_token` still gates the actual connection — so the value is not encrypted.
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
/// `d` tag identifying duopipe's node-id record under the derived author key.
const NODEID_DTAG: &str = "duopipe:nodeid";
/// Domain separation for deriving the nostr key from the auth token.
const KEY_DERIVATION_DOMAIN: &[u8] = b"duopipe:nostr-rendezvous:v1";

/// Timeout for establishing relay connections.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for a node-id lookup query.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(15);

fn nodeid_kind() -> Kind {
    Kind::from_u16(NODEID_KIND_U16)
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

/// Publish this peer's current ephemeral node id under the auth-token-derived key.
pub async fn publish_node_id(
    auth_token: &str,
    node_id: &EndpointId,
    relays: &[String],
) -> Result<()> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let event = EventBuilder::new(nodeid_kind(), node_id.to_string())
        .tags([Tag::identifier(NODEID_DTAG)])
        .sign_with_keys(&keys)
        .context("signing node-id event")?;
    let res = client.send_event(&event).await;
    client.disconnect().await;
    res.context("publishing node-id event to relays")?;
    Ok(())
}

/// Look up the peer's current node id from nostr, deriving the shared key from the
/// auth token. Returns the most recently published node id.
pub async fn lookup_node_id(auth_token: &str, relays: &[String]) -> Result<EndpointId> {
    let keys = derive_keys(auth_token)?;
    let client = connect_client(relays).await?;
    let filter = Filter::new()
        .kind(nodeid_kind())
        .author(keys.public_key())
        .identifier(NODEID_DTAG)
        .limit(1);
    let events = client.fetch_events(filter, LOOKUP_TIMEOUT).await;
    client.disconnect().await;
    let events = events.context("querying nostr relays for the peer's node id")?;
    let latest = events.iter().max_by_key(|e| e.created_at).context(
        "no node-id record found on nostr (is the peer running and sharing the same auth token?)",
    )?;
    latest
        .content
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
    fn node_id_round_trips_through_event_content() {
        let keys = derive_keys("round-trip-token").unwrap();
        let node_id = iroh::SecretKey::generate().public();
        let event = EventBuilder::new(nodeid_kind(), node_id.to_string())
            .tags([Tag::identifier(NODEID_DTAG)])
            .sign_with_keys(&keys)
            .expect("sign node-id event");
        let parsed: EndpointId = event
            .content
            .trim()
            .parse()
            .expect("event content parses as a node id");
        assert_eq!(parsed.to_string(), node_id.to_string());
    }
}
