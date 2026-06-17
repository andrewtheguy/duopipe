#!/bin/bash
# Start a dialing peer with local forwards (-L).
# Usage: ./test-scripts/peer-dial.sh [NUM_SESSIONS] [BASE_PORT] [SOURCE_PORT]
#
# Each -L exposes the listening peer's tcp://localhost:SOURCE_PORT service on a
# local port (BASE_PORT, BASE_PORT+1, ...). Add -R flags here to also have the
# listening peer forward its ports back to services on this machine.

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/keys.sh"

NUM_SESSIONS="${1:-1}"
BASE_PORT="${2:-17001}"
SOURCE_PORT="${3:-19999}"
TUNNEL_BIN="$SCRIPT_DIR/../target/release/duopipe"

[ ! -f "$TUNNEL_BIN" ] && cargo build --release --manifest-path="$SCRIPT_DIR/../Cargo.toml"

# Build repeated -L flags: 127.0.0.1:PORT=tcp://localhost:SOURCE_PORT
LOCAL_FORWARDS=()
for i in $(seq 1 "$NUM_SESSIONS"); do
    PORT=$((BASE_PORT + i - 1))
    LOCAL_FORWARDS+=(-L "127.0.0.1:$PORT=tcp://localhost:$SOURCE_PORT")
done

echo "=== Dialing peer ==="
echo "Peer: $PEER_NODE_ID"
echo "Local forwards: $NUM_SESSIONS (local ports $BASE_PORT-$((BASE_PORT + NUM_SESSIONS - 1)) -> tcp://localhost:$SOURCE_PORT)"
echo ""
echo "Test with: python3 test-scripts/test_tunnel.py -n $NUM_SESSIONS --port $BASE_PORT --loop"
echo "Press Ctrl+C to stop"
echo ""

exec "$TUNNEL_BIN" peer \
    --connect dial \
    --peer-node-id "$PEER_NODE_ID" \
    "${LOCAL_FORWARDS[@]}"
