#!/bin/bash
# Start a listening peer (accepts a connection from the dialing peer).
# Usage: ./test-scripts/peer-listen.sh [MAX_SESSIONS]
#
# This peer waits for the dialing peer to connect, then serves whatever
# forwards either side declares. In the simple test setup below it hosts no
# forwards of its own; the dialing peer drives the -L/-R tunnels.
#
# Note: start the echo server the dialing peer's -L targets first:
#   python3 test-scripts/echo_server.py 19999

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

MAX_SESSIONS="${1:-5}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/duopipe"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

echo "=== Listening peer ==="
echo "EndpointId: $PEER_NODE_ID"
echo "Max sessions: $MAX_SESSIONS"
echo ""

exec "$TUNNEL_BIN" peer \
    --connect listen \
    --secret-file "$PEER_KEY_FILE" \
    --max-sessions "$MAX_SESSIONS"
