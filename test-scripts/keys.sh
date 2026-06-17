#!/bin/bash
# Key management for tunnel testing
# Usage: source test-scripts/keys.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/.keys"
KEYS_FILE="$SCRIPT_DIR/.tunnel_keys"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/duopipe"

generate_keys() {
    echo "Generating new key pairs..."
    mkdir -p "$KEYS_DIR"

    # Generate the listening peer's identity key
    "$TUNNEL_BIN" generate-key --output "$KEYS_DIR/peer.key" --force 2>/dev/null
    PEER_KEY_FILE="$KEYS_DIR/peer.key"
    PEER_NODE_ID=$("$TUNNEL_BIN" show-id --secret-file "$PEER_KEY_FILE")

    # Generate auth token
    AUTH_TOKEN=$("$TUNNEL_BIN" generate-auth-token)

    # Generate ALPN token
    ALPN_TOKEN=$("$TUNNEL_BIN" generate-alpn-token)

    # Save to config file
    cat > "$KEYS_FILE" << EOF
# Tunnel test keys - generated $(date)
PEER_KEY_FILE=$PEER_KEY_FILE
PEER_NODE_ID=$PEER_NODE_ID
DUOPIPE_AUTH_TOKEN=$AUTH_TOKEN
DUOPIPE_AUTH_TOKENS=$AUTH_TOKEN
DUOPIPE_ALPN_TOKEN=$ALPN_TOKEN
EOF
    chmod 600 "$KEYS_FILE"

    echo "Keys saved to $KEYS_DIR/"
    echo "  Peer: $PEER_NODE_ID"
}

load_keys() {
    if [ ! -f "$KEYS_FILE" ]; then
        echo "No keys file found. Generating new keys..."
        generate_keys
    fi
    source "$KEYS_FILE"
    export PEER_KEY_FILE PEER_NODE_ID DUOPIPE_AUTH_TOKEN DUOPIPE_AUTH_TOKENS DUOPIPE_ALPN_TOKEN
}

show_keys() {
    load_keys
    echo "=== Tunnel Test Keys ==="
    echo "Peer Key:   $PEER_KEY_FILE"
    echo "Peer ID:    $PEER_NODE_ID"
    echo "Auth Token: $DUOPIPE_AUTH_TOKEN"
    echo "ALPN Token: $DUOPIPE_ALPN_TOKEN"
}

# Auto-load keys when sourced
load_keys
