# duopipe

**Cross-platform Secure Peer-to-Peer TCP/UDP port forwarding with NAT traversal.**

Duopipe enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

> [!IMPORTANT]
> **Project Goal:** This tool provides a convenient way to connect to different networks for **development or homelab purposes** without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** During initial development before version 1.0, no backward compatibility or migration path is provided between minor versions (e.g., 0.1.x to 0.2.x). Expect to regenerate peer keys and rebuild peer configurations when upgrading in between minor versions.

**Features:**
- **No account or registration required** — Just download and run
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
- **One connection, many tunnels in both directions** — A single P2P link carries any number of local (`-L`) and remote (`-R`) forwards at once
- **Full TCP and UDP support** — Seamlessly tunnel any TCP or UDP traffic
- **Cross-platform** — Works on Linux, macOS, and Windows
- **No root required** — Runs as unprivileged user
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with automatic NAT hole punching and relay fallback

**Use Cases:**
- **SSH access** to machines behind NAT/firewalls
- **UDP Tunneling** — A key advantage over AWS SSM and `kubectl port-forward` which typically lack UDP support. Ideal for:
  - WireGuard/OpenVPN over P2P
  - Game servers (Valheim, Minecraft Bedrock, etc.)
  - VoIP applications and WebRTC
  - Accessing UDP services in Kubernetes (bypassing the [7+ year old limitation in `kubectl`](https://github.com/kubernetes/kubernetes/issues/47862) without complex sidecar workarounds)
- **Simpler Alternative to SSM For Staging Environment Access Purposes** — Great for ad-hoc access without configuring AWS agents or IAM users. **Note:** Not intended for production; it is not battle-tested for enterprise use and lacks integration with cloud security policies (IAM, auditing).
- **Remote Desktop** access (RDP/VNC over TCP) without port forwarding
- **Secure Service Exposure** (HTTP servers, databases, etc.) without public infrastructure
- **Development and Testing** of TCP/UDP services across network boundaries
- **Homelab Networking** — Connecting distributed homelab nodes or accessing local services remotely without complex VPN setups or public IP requirements
- **Cross-platform Tunneling** for both TCP and UDP workflows (including Windows endpoints)

## Overview

duopipe runs as a single symmetric command: `duopipe peer`. Two peers establish **one** iroh P2P connection, and over that single connection they run **many tunnels in both directions at once** — combining SSH's `-L` (local forward) and `-R` (remote forward).

Setting up the connection is asymmetric only because QUIC needs a dialer and an acceptor:

- One peer **listens** — it carries a stable identity key so it can be dialed, and accepts auth tokens.
- One peer **dials** — it presents an auth token and may use an ephemeral identity.

Once the connection is established and authenticated, tunnels flow both ways: **either** peer may declare local and remote forwards. iroh provides NAT traversal with relay fallback and automatic discovery.

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### Forwards at a glance

| Type | SSH analog | CLI | Behavior |
|------|-----------|-----|----------|
| Local forward | `-L` | `-L LISTEN=DEST` | **This** peer listens locally; the **other** peer connects out to `DEST`. The `DEST` scheme (`tcp://` / `udp://`) selects the protocol. |
| Remote forward | `-R` | `-R BIND=DEST` | The **other** peer binds `BIND` and forwards connections back to **our** local `DEST`. The `BIND` scheme (`tcp://` / `udp://`) selects the protocol. |

Both TCP and UDP are supported in both directions and may be freely mixed on the same connection. Forward flags are repeatable.

> **Note:** UDP `-R` (remote forward) uses a single-peer-address reply model. This is fine for single-client UDP services.

## Installation

You only need the binary in your PATH; no runtime dependencies or package managers are required.

**Linux & macOS:**
```bash
curl -sSL https://andrewtheguy.github.io/duopipe/install.sh | bash
```

**Windows:**
```powershell
irm https://andrewtheguy.github.io/duopipe/install.ps1 | iex
```

This installs `duopipe`.

<details>
<summary>Advanced installation options</summary>

Install with custom release tag:
```bash
# Linux/macOS
curl -sSL https://andrewtheguy.github.io/duopipe/install.sh | bash -s <RELEASE_TAG>
```

```powershell
# Windows
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/duopipe/install.ps1))) <RELEASE_TAG>
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build:

```bash
# Linux/macOS - latest prerelease
curl -sSL https://andrewtheguy.github.io/duopipe/install.sh | bash -s -- --prerelease

# Linux/macOS - pin to specific tag
curl -sSL https://andrewtheguy.github.io/duopipe/install.sh | bash -s 20251210172710
```

```powershell
# Windows - latest prerelease
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/duopipe/install.ps1))) -PreRelease

# Windows - pin to specific tag
& ([scriptblock]::Create((irm https://andrewtheguy.github.io/duopipe/install.ps1))) 20251210172710
```

> **Note:** Prerelease artifacts may not include Windows binaries. If unavailable, use a stable release tag or build from source.

</details>

### From Source

```bash
cargo install --path .
```

### Feature Flags

Relay-only is a **CLI-only** flag that forces connections through relay servers instead of attempting direct connections. It is intended for testing or special scenarios and is **not supported in config files** to avoid accidental activation. See `duopipe --help` for usage.

### Supported Platforms

duopipe works on Linux, macOS, and Windows.

Official prebuilt release artifacts currently include:
- **Linux** (x86_64, ARM64)
- **macOS** (Apple Silicon)
- **Windows** (x86_64, stable releases)

Intel macOS is supported when building from source.

---

# Configuration

## Peer Identity

The **listening** peer needs a stable identity so the dialing peer can reach it. Generate a persistent key and reference it via `--secret-file`:

```bash
# Generate key and output EndpointId
duopipe generate-key --output ./peer.key

# Show EndpointId for existing key
duopipe show-id --secret-file ./peer.key
```

Then reference the key when listening:

**CLI** (tokens saved to files — recommended):
```bash
# Save tokens to files with restricted permissions
echo "$AUTH_TOKEN" > auth_tokens.txt && chmod 600 auth_tokens.txt
echo "$ALPN_TOKEN" > alpn_token.txt && chmod 600 alpn_token.txt

duopipe peer \
  --connect listen \
  --secret-file ./peer.key \
  --auth-tokens-file ./auth_tokens.txt \
  --alpn-token-file ./alpn_token.txt
```

> **Tip:** For containers and automation scripts, use environment variables (`DUOPIPE_AUTH_TOKENS`, `DUOPIPE_ALPN_TOKEN`) instead of files. See the environment variable table below.

**Config file** (`peer.toml`):
```toml
[iroh]
connect = "listen"
secret_file = "./peer.key"
```

> **Note:** The dialing peer may use an ephemeral identity. Only the listening peer needs a persistent key to maintain a stable EndpointId that the dialer can connect to.

> **Note:** The age encryption key (`config-encryption generate-key`) is different from the peer identity key (`generate-key`). The peer key establishes a stable EndpointId for P2P connections. The encryption key protects secrets stored in config files.

## Authentication

A peer connection is gated by two pre-shared secrets:

1. An **ALPN token**, shared by **both** peers, embedded in the QUIC ALPN identifier — a lightweight "port knock" rejected before any stream opens.
2. An **auth token** that the **dialing** peer presents; the **listening** peer accepts a configured set of tokens.

**Auth Token Format:**
- Exactly 47 characters
- Starts with `i` (for iroh)
- Remaining 46 characters are Base64URL-encoded (no padding)
- Decoded payload: 32 random bytes + 2-byte CRC16-CCITT-FALSE checksum

The CRC16 checksum detects all single-byte errors in the token payload.

Generate auth tokens with: `duopipe generate-auth-token`
Generate the ALPN token with: `duopipe generate-alpn-token`

> [!IMPORTANT]
> **Full trust after auth.** Once the ALPN token (QUIC handshake "port knock") and the connection-level auth token both pass, the peer is **fully trusted**. There are no per-destination allowlists — a trusted peer may declare forwards to any destination either side can reach. Only share tokens with peers you trust.

### Token Management

```bash
# Generate a valid auth token
AUTH_TOKEN=$(duopipe generate-auth-token)
echo $AUTH_TOKEN  # Share this with the dialing peer

# Generate multiple tokens
duopipe generate-auth-token -c 5
```

### Multiple Tokens (Listening Peer)

The listening peer can accept several tokens, one per authorized dialer:

```bash
# Use a file with one token per line (recommended)
duopipe peer --connect listen \
  --secret-file ./peer.key \
  --auth-tokens-file /etc/duopipe/auth_tokens.txt \
  --alpn-token-file ./alpn_token.txt

# Or comma-separated via environment variable (for containers/automation)
export DUOPIPE_AUTH_TOKENS="token-for-alice,token-for-bob"
duopipe peer --connect listen --secret-file ./peer.key
```

**Example `auth_tokens.txt`:**
```text
# Alice's token (generate with: duopipe generate-auth-token)
iXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Bob's token
iYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
```

### Configuration File

> **Security:** Plaintext tokens and secrets are **not allowed** in TOML config files. Use the `_file` variants (e.g., `auth_tokens_file`, `auth_token_file`, `alpn_token_file`, `secret_file`) in config files. For non-containerized deployments, `_file` variants are the recommended approach. Environment variables (`DUOPIPE_*`) are best suited for containers and automation scripts where secrets are injected dynamically. Plaintext values are also accepted via `--config-stdin` (JSON) for IPC.

**Listening peer** (`peer.toml`):
```toml
[iroh]
connect = "listen"
secret_file = "./peer.key"
auth_tokens_file = "/etc/duopipe/auth_tokens.txt"
alpn_token_file = "/etc/duopipe/alpn_token.txt"
```

**Dialing peer** (`peer.toml`):
```toml
[iroh]
connect = "dial"
peer_node_id = "<ENDPOINT_ID>"
auth_token_file = "~/.config/duopipe/token.txt"
alpn_token_file = "~/.config/duopipe/alpn_token.txt"
```

---

# Usage

## Architecture

A single iroh connection carries forwards in both directions. For example, an SSH local forward (`-L`) declared by the dialing peer:

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | dialing peer    |  iroh  | listening peer  |  TCP   | SSH Server      |
|                 |<------>| -L (local:2222) |<======>|                 |<------>| (peer connects) |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
```

The same connection may simultaneously carry a remote forward (`-R`) running the opposite direction, plus any number of additional TCP/UDP forwards declared by either side.

For deeper architecture diagrams and protocol flows, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

### 1. Setup (One-Time)

On the listening machine, generate an identity key. On either machine, create the shared tokens:

```bash
# On the listening machine - generate persistent identity
duopipe generate-key --output ./peer.key
# Output: EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga

# Create a shared authentication token (the dialing peer presents this)
AUTH_TOKEN=$(duopipe generate-auth-token)
echo $AUTH_TOKEN

# Create an ALPN token (shared between both peers)
ALPN_TOKEN=$(duopipe generate-alpn-token)
echo $ALPN_TOKEN
```

### 2. Complete Example (one `-L` and one `-R`)

**On the listening machine** (waits for the dialer to connect):
```bash
duopipe generate-key --output peer.key
duopipe show-id --secret-file peer.key        # prints <ENDPOINT_ID>

DUOPIPE_AUTH_TOKENS=<token> DUOPIPE_ALPN_TOKEN=<alpn> \
  duopipe peer --connect listen --secret-file peer.key
```

Output:
```
EndpointId: 2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga
Auth tokens: 1 token(s) configured
Waiting for a peer to connect...
```

**On the dialing machine** (declares the forwards):
```bash
DUOPIPE_AUTH_TOKEN=<token> DUOPIPE_ALPN_TOKEN=<alpn> \
  duopipe peer --connect dial --peer-node-id <ENDPOINT_ID> \
  -L 127.0.0.1:15678=tcp://127.0.0.1:5678 \
  -R tcp://0.0.0.0:6574=127.0.0.1:6574
```

In this example:
- `-L 127.0.0.1:15678=tcp://127.0.0.1:5678` — the dialing peer listens on `127.0.0.1:15678`; connections are forwarded to `tcp://127.0.0.1:5678` reached by the **listening** peer.
- `-R tcp://0.0.0.0:6574=127.0.0.1:6574` — the **listening** peer binds `tcp://0.0.0.0:6574`; connections there are forwarded back to `127.0.0.1:6574` on the **dialing** peer.

Either peer may declare its own `-L`/`-R` forwards; they all share the one connection.

> **Tip:** For containers and automation scripts, use environment variables (`DUOPIPE_AUTH_TOKEN`, `DUOPIPE_AUTH_TOKENS`, `DUOPIPE_ALPN_TOKEN`, etc.) instead of files. See the environment variable tables below.

### 3. SSH over a local forward

With the dialer's `-L 127.0.0.1:2222=tcp://127.0.0.1:22` (listening peer reaches the SSH server):

```bash
ssh -p 2222 user@127.0.0.1
```

### 4. UDP forward (e.g., WireGuard/Game/DNS)

UDP works in both directions; the scheme on the destination (`-L`) or bind (`-R`) selects the protocol:

```bash
# Local forward: dialer listens on UDP 51820, listening peer reaches the UDP service
duopipe peer --connect dial --peer-node-id <ENDPOINT_ID> \
  -L 0.0.0.0:51820=udp://127.0.0.1:51820

# Remote forward: listening peer binds UDP, forwards back to dialer's local service
duopipe peer --connect dial --peer-node-id <ENDPOINT_ID> \
  -R udp://0.0.0.0:51820=127.0.0.1:51820
```

> **Note:** UDP `-R` uses a single-peer-address reply model — suitable for single-client UDP services.

## CLI Options

### peer

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/duopipe/peer.toml` |
| `--config-stdin` | false | Read JSON config from stdin for automation/IPC (use `-c` for normal usage) |

### peer iroh

| Option | Default | Description |
|--------|---------|-------------|
| `--connect` | - | Connection role: `dial` (connect out) or `listen` (accept) |
| `--peer-node-id`, `-n` | - | EndpointId of the peer to dial (required when `--connect dial`) |
| `-L` | - | Local forward, repeatable: `LISTEN=DEST` (e.g. `127.0.0.1:15678=tcp://127.0.0.1:5678`). The `DEST` scheme selects TCP/UDP. |
| `-R` | - | Remote forward, repeatable: `BIND=DEST` (e.g. `tcp://0.0.0.0:6574=127.0.0.1:6574`). The `BIND` scheme selects TCP/UDP. |
| `--secret-file` | - | Path to secret key file for persistent identity (required when listening) |
| `--auth-token-file` | - | Path to file containing the auth token presented when dialing |
| `--auth-tokens-file` | - | Path to file containing accepted auth tokens when listening (one per line, # comments allowed) |
| `--alpn-token-file` | - | Path to file containing ALPN token (required for both roles) |
| `--max-sessions` | 100 | Maximum concurrent data streams per connection |
| `--relay-url` | public | Custom relay server URL(s), repeatable |
| `--relay-only` | false | Force all traffic through relay (CLI-only; not supported in config files) |
| `--dns-server` | public | Custom DNS server URL, or "none" to disable DNS discovery |
| `--encryption-key-file` | - | Path to age identity file for decrypting age-encrypted config values |

**Environment variables** (for containers and automation scripts):

> Environment variables are primarily intended for containerized deployments and automation scripts. For regular use, prefer the `_file` CLI flags or config file equivalents.

| Env Var | Role | Description |
|---------|------|-------------|
| `DUOPIPE_ALPN_TOKEN` | both | ALPN token for QUIC handshake-level filtering (14-char Base64URL with CRC16 checksum). Required for both peers and must match. Generate with `generate-alpn-token`. |
| `DUOPIPE_AUTH_TOKEN` | dial | Auth token presented to the listening peer (required when dialing unless provided via `--auth-token-file`) |
| `DUOPIPE_AUTH_TOKENS` | listen | Accepted auth tokens (comma-separated). Required when listening unless provided via `--auth-tokens-file`. |
| `DUOPIPE_SECRET` | listen | Base64-encoded secret key for persistent identity (use this or `--secret-file`) |
| `DUOPIPE_ENCRYPTION_KEY_FILE` | both | Path to age identity file for decrypting age-encrypted config values |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path (both TOML). For normal usage, prefer config files so your settings are saved and reusable. The `--config-stdin` flag is intended for automation and IPC — it accepts JSON (self-delimiting, so the caller does not need to close stdin). Only one of these may be used at a time. Configuration uses the `[iroh]` section.

> **Security:** TOML config files **reject plaintext sensitive fields** (`auth_token`, `auth_tokens`, `alpn_token`, `secret`). You have three options: use the corresponding `_file` variants (recommended), use environment variables (`DUOPIPE_*`) for containers/automation, or use [age-encrypted inline values](#encrypted-config-values). Plaintext values are also accepted via `--config-stdin` (JSON) for IPC.

**Default location:** `~/.config/duopipe/peer.toml`

> **Note:** `--relay-only` is intentionally **CLI-only** and is not supported in config files to avoid accidental activation.

### Overriding Config Values

CLI arguments take precedence over config file values. Use `--default-config` with CLI arguments to override or extend specific fields:

```bash
# Use config but add an extra local forward on the command line
duopipe peer --default-config \
  -L 127.0.0.1:3000=tcp://127.0.0.1:8080

# Use config but override the dial target
duopipe peer --default-config \
  --connect dial --peer-node-id <ENDPOINT_ID>
```

This lets you keep common settings (keys, relay URLs, ALPN token) in the config file while varying per-session options on the command line.

### Encrypted Config Values

Instead of separate `_file` variants, you can embed age-encrypted secrets directly in TOML config files. This is useful when managing configs for multiple peers — each config is self-contained with a single shared private key.

**Setup:**

```bash
# 1. Generate an age keypair (run again to add keys for rotation)
duopipe config-encryption generate-key --output ~/.config/duopipe/age.key
# Output: age1ql3z7hjy...  (this is your public key / recipient)

# 2. Encrypt a secret value
echo -n "$AUTH_TOKEN" | duopipe config-encryption encrypt-value --recipient age1ql3z7hjy...
```

**Use in config:**

```toml
[iroh]
connect = "dial"
peer_node_id = "<ENDPOINT_ID>"
encryption_key_file = "~/.config/duopipe/age.key"
encryption_recipient = "age1ql3z7hjy..."

auth_token = "ageenc:YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
alpn_token = "ageenc:YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
```

Each encrypted value is a single-line `ageenc:` prefixed string (base64-encoded age ciphertext). The `encryption_key_file` can also be specified via `--encryption-key-file` CLI flag or `DUOPIPE_ENCRYPTION_KEY_FILE` env var.

### Transport Tuning

QUIC transport parameters can be tuned via an optional `[iroh.transport]` section in the config file. These are **config-only** (no CLI flags) and all have sensible defaults — only set them if you need to.

```toml
[iroh.transport]
# Congestion controller: "cubic" (default), "bbr", or "newreno"
congestion_controller = "cubic"
# QUIC per-stream receive window in bytes (default: 67108864 = 64MB; range 1024-67108864)
receive_window = 67108864
# QUIC send window in bytes (default: 67108864 = 64MB; range 1024-67108864)
send_window = 67108864
```

The connection-level receive window uses iroh's default. If `send_window` is omitted but `receive_window` is set, the send window defaults to twice the stream receive window, capped at the 64MB default. See [`peer.toml.example`](peer.toml.example) for the annotated reference.

### Peer Config Example

```toml
# Example peer configuration (iroh mode)
mode = "iroh"

[iroh]
# Connection role: "dial" or "listen"
connect = "dial"

# --- when connect = "dial" ---
peer_node_id = "2xnbkpbc7izsilvewd7c62w7wnwziacmpfwvhcrya5nt76dqkpga"
auth_token_file = "~/.config/duopipe/token.txt"

# --- when connect = "listen" (comment out the dial fields above) ---
# secret_file = "./peer.key"
# auth_tokens_file = "/etc/duopipe/auth_tokens.txt"

# ALPN token (required for both roles)
alpn_token_file = "~/.config/duopipe/alpn_token.txt"

# relay_urls = ["https://relay.example.com"]
dns_server = "https://dns.example.com/pkarr"
max_sessions = 100

# Local forwards (-L): this peer listens locally, the peer connects to dest.
[[iroh.local_forward]]
listen = "127.0.0.1:15678"
dest = "tcp://127.0.0.1:5678"

# Remote forwards (-R): the peer binds, forwarding back to our local dest.
[[iroh.remote_forward]]
bind = "tcp://0.0.0.0:6574"
dest = "127.0.0.1:6574"
```

> [!NOTE]
> See [`peer.toml.example`](peer.toml.example) for the full annotated example.

```bash
# Load from default location (~/.config/duopipe/peer.toml)
duopipe peer --default-config

# Load from custom path
duopipe peer -c ./my-peer.toml
```

Example: spawning a dialing peer with `--config-stdin` from Python:

```python
import json, socket, subprocess, time

config = {
    "mode": "iroh",
    "iroh": {
        "connect": "dial",
        "peer_node_id": "<ENDPOINT_ID>",
        "auth_token": "<AUTH_TOKEN>",
        "alpn_token": "<ALPN_TOKEN>",
        "local_forward": [
            {"listen": "127.0.0.1:2222", "dest": "tcp://127.0.0.1:22"}
        ],
    }
}

proc = subprocess.Popen(
    ["duopipe", "peer", "--config-stdin"],
    stdin=subprocess.PIPE,
)
proc.stdin.write(json.dumps(config).encode())
proc.stdin.flush()  # config is parsed immediately, no need to close stdin

# wait for the forwarded port to be ready
for attempt in range(10):
    try:
        with socket.create_connection(("127.0.0.1", 2222), timeout=2):
            print("tunnel is up")
            break
    except OSError:
        time.sleep(1)
else:
    raise RuntimeError("tunnel failed to start")

input("press enter to quit..")
proc.terminate()
```

---

# Utility Commands

## generate-auth-token

Generate authentication tokens for the dialing peer to present:

```bash
# Generate a single auth token
duopipe generate-auth-token
# Output: i<base64url-encoded-payload>

# Generate multiple auth tokens
duopipe generate-auth-token -c 5
```

Auth token format: `i` + Base64URL-encoded(32 random bytes + CRC16 checksum) = 47 characters total.

## generate-alpn-token

Generate an ALPN token shared between both peers:

```bash
# Generate a single ALPN token
duopipe generate-alpn-token

# Generate multiple ALPN tokens
duopipe generate-alpn-token -c 5
```

ALPN token format: Base64URL-encoded(8 random bytes + 2-byte CRC16 checksum) = 14 characters total.

## generate-key

Generate a private key for a peer's persistent identity (used by the listening peer).

```bash
duopipe generate-key --output ./peer.key

# Write the key to stdout instead of a file (e.g. to capture it in a script)
duopipe generate-key --output -

# Overwrite an existing key file
duopipe generate-key --output ./peer.key --force
```

The secret key is written to the `--output` target (created with `0600` permissions on Unix), and the EndpointId is printed to stdout. Use `-` as the output to write the key to stdout instead — in that case the EndpointId is printed to stderr so it stays off the key stream. Existing files are not overwritten unless `--force` is passed.

## show-id

Show the public EndpointId derived from a private key. The dialing peer uses this with `--peer-node-id`.

```bash
duopipe show-id --secret-file ./peer.key
```

## config-encryption

Age encryption commands for config file secrets.

### generate-key

Generate an age keypair for encrypting config file secrets:

```bash
duopipe config-encryption generate-key --output ~/.config/duopipe/age.key
# Prints the public key (recipient) to stdout
```

Running again with the same `--output` appends a new keypair to the file, enabling key rotation. Use `--force` to overwrite the file and start fresh.

### encrypt-value

Encrypt a value for embedding in config files (reads plaintext from stdin):

```bash
echo -n "$AUTH_TOKEN" | duopipe config-encryption encrypt-value --recipient age1...

# Or read recipient from a config file
echo -n "$AUTH_TOKEN" | duopipe config-encryption encrypt-value --config peer.toml
```

Output is a single-line `ageenc:` string ready to paste into TOML config values.

---

## Security

- All traffic is encrypted using QUIC/TLS 1.3
- The EndpointId is a public key that identifies the listening peer
- **ALPN-level filtering:** A pre-shared ALPN token is embedded in the QUIC protocol identifier (`mf/2/<token>`). Connections from peers without the correct token are rejected at the QUIC handshake level — before any application streams are opened — acting as a lightweight "port knock".
- **Token Authentication:** The dialing peer authenticates immediately after the QUIC connection via a dedicated auth stream. Invalid tokens are rejected with an `AuthResponse` and the connection is closed with an error code. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- **Full trust after auth:** Once both the ALPN token and the auth token pass, the peer is fully trusted and there are no per-destination allowlists. Only share tokens with peers you trust.
- Secret key files are created with `0600` permissions (Unix) and appropriate permissions on Windows
- Treat secret key files, auth tokens, and ALPN tokens like passwords

## Exit Codes

The peer process uses categorized exit codes so wrapper scripts can distinguish transient failures (retry) from permanent errors (stop).

| Exit Code | Meaning | Retry? |
|-----------|---------|--------|
| 0 | Success | N/A |
| 1 | General/unexpected error | Use judgment |
| 2 | Configuration error (invalid arguments, bad token format, missing fields) | No — fix configuration |
| 3 | Authentication failure (token rejected, auth timeout) | No — fix credentials |
| 10 | Connection establishment failed (timeout, relay failure, peer unreachable) | Only if it worked before |
| 11 | Connection lost after tunnels were established | Yes — always retry |

Example retry wrapper script (useful for the dialing peer):

```bash
#!/bin/bash
succeeded_before=false
while true; do
    duopipe peer --default-config
    code=$?
    case $code in
        0)   echo "Clean exit"; break ;;
        2|3) echo "Unrecoverable error (exit $code), not retrying"; exit $code ;;
        10)
            if [ "$succeeded_before" = true ]; then
                echo "Connection failed (previously connected), retrying in 5s..."
                sleep 5
            else
                echo "Never connected successfully (exit 10), not retrying"
                exit $code
            fi
            ;;
        11)  succeeded_before=true
             echo "Connection lost, retrying in 5s..."
             sleep 5 ;;
        *)   echo "Unexpected error (exit $code), retrying in 10s..."; sleep 10 ;;
    esac
done
```

## How It Works

### iroh Mode
1. The listening peer creates an iroh endpoint with discovery services
2. The listening peer publishes its address via Pkarr/DNS
3. The dialing peer resolves the listening peer via discovery
4. **ALPN handshake:** the QUIC connection requires a matching ALPN token (`mf/2/<token>`) — peers without the token are rejected at the handshake level
5. **Authentication phase:** the dialing peer opens a dedicated auth stream and sends `AuthRequest` with its token
6. **The listening peer validates the token** (10s timeout) — invalid tokens are rejected with an error response
   - *If authentication fails, the connection is closed and the following steps do not occur*
7. **Full trust:** once authenticated, the peer is fully trusted; either side may declare local (`-L`) and remote (`-R`) forwards
8. Forwards are negotiated over the single connection and traffic flows in both directions
