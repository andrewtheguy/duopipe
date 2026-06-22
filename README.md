# duopipe

**Cross-platform Secure Peer-to-Peer TCP/UDP port forwarding with NAT traversal.**

Duopipe enables you to forward TCP and UDP traffic between machines without requiring public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted connections between peers using modern P2P networking techniques.

> [!IMPORTANT]
> **Project Goal:** This tool provides a convenient way to connect to different networks for **development or homelab purposes** without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale. It is meant for **interactive use** (`duopipe start` and its TUI); the non-interactive env-var override is a **test-mode-only** workaround (`DUOPIPE_TEST_MODE=1`), not a supported automation interface.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** During initial development before version 1.0, no backward compatibility or migration path is provided between minor versions (e.g., 0.1.x to 0.2.x). Expect to regenerate tokens and rebuild peer configurations when upgrading in between minor versions.

**Features:**
- **No account or registration required** — Just download and run
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
- **One connection, many tunnels in both directions** — A single P2P link carries any number of requested tunnels at once, in either direction
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

duopipe runs as a single symmetric command: `duopipe start`, which launches an interactive terminal UI. Two peers establish **one** iroh P2P connection, and over that single connection they run **many tunnels in both directions at once**. Each tunnel is *requested* — SSH `-L`–style local forwarding: a peer binds a local listener and asks the other side to connect out to a remote source.

On startup, the TUI asks **"Connect to an existing instance?"**. Setting up the connection is asymmetric only because QUIC needs a dialer and an acceptor:

- Answer **No** → this peer **listens**. If no auth token is configured, it generates one; the TUI header shows the listener's **node id** and the **auth token** so you can copy them to the other side. Generated tokens hide automatically after 10 minutes, or immediately when you press `h`.
- Answer **Yes** → this peer **dials**. The TUI prompts for the existing instance's node id, and for the auth token if one isn't already in config or the environment. Both are validated (node id parse, auth-token CRC16) before connecting.

> **Note:** The iroh identity is **ephemeral** — a fresh identity is generated on every run. This means the listener's node id **changes every run** and must be re-copied to the dialer each time. (This avoids same-machine locking that could otherwise produce duplicate node ids.)

Once the connection is established and authenticated, tunnels flow both ways: **either** peer may request tunnels of the other. iroh provides NAT traversal with relay fallback and automatic discovery.

> [!IMPORTANT]
> **Intended use — a coordinated link between two trusted endpoints.** duopipe assumes the two peers are operated by **two parties who trust each other**, or by **one person across their own devices** (e.g. laptop ↔ homelab box). It is *not* a public service or a multi-tenant gateway. The design leans on this throughout:
> - **Out-of-band coordination.** The ephemeral node id changes every run, and any generated auth token is per-run too. Share the current node id and the shared token over a side channel you already have (chat, SSH session, password manager, a second device you control) before connecting.
> - **Live, interactive operation.** Both ends run the TUI and watch shared status — connection state, the active peer, and each tunnel's health — and **start/stop tunnels by hand**. Nothing forwards on its own; the two ends coordinate *what* to expose and *when*.
> - **Mutual trust, narrowly scoped.** Either peer may *request* tunnels of the other, so only pair with someone (or a device) you trust, and keep each side's `[allowed_sources]` allowlist as tight as the task needs.

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### Tunnel requests at a glance

Every tunnel is a **request** (SSH `-L`–style, pull direction): a peer declares `[[request]]` entries in config, and activating one binds a local listener and asks the other peer to connect out to a remote source.

| Field | Meaning |
|-------|---------|
| `remote_source` | Origin on the **other** peer to connect out to (`tcp://host:port` or `udp://host:port`; the scheme selects the protocol). |
| `local_listen` | Local address on **this** peer where the tunnel is exposed (`host:port`). |

To expose one of **your** services, the **other** peer requests it from you — there is no separate "remote forward". The serving side gates every incoming request against its `[allowed_sources]` CIDR allowlist (separate `tcp` / `udp` lists). Empty or absent TCP or UDP lists default to dual-stack localhost (`127.0.0.0/8`, `::1/128`). Both TCP and UDP are supported and may be mixed on one connection. Nothing forwards until you start a request in the TUI.

> **Note:** UDP requests use a single-peer-address reply model. This is fine for single-client UDP services.

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

Relay-only (`relay_only`) is a **config bool** that forces connections through relay servers instead of attempting direct connections. It is intended for testing or special scenarios and requires at least one `relay_urls` entry. Set it in the config file (see [Configuration Files](#configuration-files)).

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

The iroh identity is **ephemeral** — duopipe generates a fresh identity on every run, so there is no key file to create or manage. The consequence is that the **listening** peer's **node id changes every run**: the TUI displays the current node id in its header, and you must copy it to the dialing peer each time you start a session.

> **Note:** There is no `config-encryption` overlap to worry about here. The age encryption key (`config-encryption generate-key`) only protects secrets stored in config files; it has nothing to do with the peer's network identity.

## Authentication

A peer connection is gated by a single pre-shared **auth token**, shared by **both** peers. The dialing peer presents it; the listening peer accepts exactly that one token. Sharing it presumes a coordinated link between two trusted endpoints (or your own devices) with an out-of-band channel to pass it over — see [Intended use](#overview).

> **Note:** The QUIC ALPN identifier is a fixed constant (`mf/2`). It is no longer used for access control — authentication is solely via the shared auth token.

**Auth Token Format:**
- Exactly 47 characters
- Starts with `i` (for iroh)
- Remaining 46 characters are Base64URL-encoded (no padding)
- Decoded payload: 32 random bytes + 2-byte CRC16-CCITT-FALSE checksum

The CRC16 checksum detects all single-byte errors in the token payload.

Generate auth tokens with: `duopipe generate-auth-token`

> [!IMPORTANT]
> **Trust after auth, gated by the source allowlist.** Once the connection-level auth token passes, the peer may *request* tunnels, but when it asks us to connect out to one of our sources we only honor addresses inside our `[allowed_sources]` CIDR lists. Empty or absent TCP or UDP defaults to dual-stack localhost. Requests are also activated interactively — nothing forwards until you start it. Only share the token with peers you trust, and keep `[allowed_sources]` as narrow as possible.

### Token Management

When the listening peer starts without a configured auth token, it **generates one automatically** and displays it in the TUI header alongside the node id for 10 minutes, or until you press `h` to hide it. You can also mint tokens ahead of time:

```bash
# Generate a valid auth token
AUTH_TOKEN=$(duopipe generate-auth-token)
echo $AUTH_TOKEN  # The shared token — both peers use this one value

# Generate multiple tokens
duopipe generate-auth-token -c 5
```

The same token is used by **both** sides: the listener accepts it, and the dialer presents it.

### Configuration File

> **Security:** A plaintext `auth_token` is **not allowed** in TOML config files. Use `auth_token_file`, set the `DUOPIPE_AUTH_TOKEN` environment variable, or embed the token directly with an [age-encrypted inline value](#encrypted-config-values).

A minimal config is essentially the requests you can make, the sources you'll expose, plus an optional shared token (`peer.toml`):
```toml
auth_token_file = "/etc/duopipe/auth_token.txt"

# A tunnel we can request: bind locally, ask the peer to reach its source.
[[request]]
name = "db"
remote_source = "tcp://127.0.0.1:5678"
local_listen = "127.0.0.1:15678"

# What the peer is allowed to request of us (defaults to localhost if omitted).
[allowed_sources]
tcp = ["127.0.0.0/8"]
```

The connection role (listen vs dial) and the dialer's target node id are chosen **interactively** in the TUI, not in the config file. Requests are started/stopped from the TUI too — nothing forwards automatically.

---

# Usage

## Architecture

A single iroh connection carries requested tunnels. Each side *requests* a tunnel: it binds a local listener and asks the peer to connect out to a remote source. For example, a request for the peer's SSH server:

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | requesting peer |  iroh  | serving peer    |  TCP   | SSH Server      |
|                 |<------>| listen :2222    |<======>| (allowlist gate)|<------>| source :22      |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
```

The same connection may simultaneously carry requests in the opposite direction (the peer requesting our sources, gated by our `[allowed_sources]`), plus any number of additional TCP/UDP requests from either side.

For deeper architecture diagrams and protocol flows, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

duopipe is **interactive-first**: you run `duopipe start` on both machines and answer a prompt in the TUI. Tunnel requests, relays, and the auth token come from a config file (and/or env vars); only the role and the dial target are chosen interactively.

### 1. Start the listening instance

On the first machine, point at a config that declares the requests (see [Configuration Files](#configuration-files)) and run:

```bash
duopipe start -c ./peer.toml
```

When the TUI asks **"Connect to an existing instance?"**, answer **No**. This instance becomes the listener. If no auth token is configured, it generates one. The TUI header shows the **node id** and the **auth token** — copy both for the next step. The token hides automatically after 10 minutes, or immediately when you press `h`.

> **Important:** The node id is regenerated on every run (the identity is ephemeral), so re-copy it each time you start the listener.

### 2. Start the dialing instance

On the second machine (also pointed at a config that declares its requests):

```bash
duopipe start -c ./peer.toml
```

When the TUI asks **"Connect to an existing instance?"**, answer **Yes**. It prompts for the listener's **node id**, and for the **auth token** if one isn't already in config or the `DUOPIPE_AUTH_TOKEN` env var. Both are validated before connecting.

Once connected, the requests you start in the TUI flow over the single connection. For example, a config with:

```toml
[[request]]
name = "db"
remote_source = "tcp://127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
```

- This request makes **this** peer listen on `127.0.0.1:15678`; connections are forwarded to `tcp://127.0.0.1:5678`, which the **other** peer connects out to (subject to its `[allowed_sources]`).
- To expose a service running on **this** peer instead, the **other** peer adds the matching `[[request]]` and you list that source in **your** `[allowed_sources]`.

Either peer may declare its own requests; they all share the one connection and are started/stopped independently in the TUI.

### 3. SSH over a requested tunnel

With a `[[request]]` of `remote_source = "tcp://127.0.0.1:22"`, `local_listen = "127.0.0.1:2222"` (the other peer reaches the SSH server, and allows `127.0.0.0/8` in `[allowed_sources]`):

```bash
ssh -p 2222 user@127.0.0.1
```

### 4. UDP request (e.g., WireGuard/Game/DNS)

UDP works too; the `remote_source` scheme selects the protocol, and the address is gated by the peer's `allowed_sources.udp` list:

```toml
# This peer listens on UDP 51820; the other peer connects out to the UDP service.
[[request]]
name = "wg"
remote_source = "udp://127.0.0.1:51820"
local_listen = "0.0.0.0:51820"
```

> **Note:** UDP requests use a single-peer-address reply model — suitable for single-client UDP services.

### Test mode (testing only)

duopipe is meant for interactive use. For automated tests, `DUOPIPE_TEST_MODE=1` runs the peer **headless** (no TUI, logs to stderr, needs no terminal) and is the single gate that enables all test-only env vars:

| Env Var | Purpose |
|---------|---------|
| `DUOPIPE_TEST_MODE=1` | Run headless (no TUI). Gates the env vars below. |
| `DUOPIPE_PEER_NODE_ID=<id>` | When **set** ⇒ dial that node id; when **unset** ⇒ listen. |
| `DUOPIPE_AUTOSTART_REQUESTS=1` | Start every configured `[[request]]` once connected (nothing auto-starts otherwise). |
| `DUOPIPE_AUTH_TOKEN=<token>` | The shared auth token (also valid outside test mode; see env table below). |

In test mode the listener prints `node_id: <id>` and `auth_token: <token>` to **stderr**, so a test harness can capture them and wire up the dialer.

## CLI Options

### start

`duopipe start` launches the interactive TUI. It takes only config-selection flags; everything else (requests, relays, DNS, max-streams, relay-only, auth token, encryption key) comes from the config file and/or environment variables.

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | - | Path to TOML config file |
| `--default-config` | false | Load config from `~/.config/duopipe/peer.toml` |

The connection role (listen/dial) and the dialer's target node id are chosen interactively in the TUI (or via env vars for tests — see [Test mode (testing only)](#test-mode-testing-only)).

**Environment variables:**

| Env Var | Description |
|---------|-------------|
| `DUOPIPE_AUTH_TOKEN` | The shared auth token (highest precedence over config `auth_token` / `auth_token_file`). |
| `DUOPIPE_ENCRYPTION_KEY_FILE` | Path to age identity file for decrypting age-encrypted config values. |
| `DUOPIPE_TEST_MODE` | Testing only: set to `1` to run headless (no TUI) and enable the test-only env vars below. |
| `DUOPIPE_PEER_NODE_ID` | Testing only (requires `DUOPIPE_TEST_MODE=1`): when set ⇒ dial that node id; when unset ⇒ listen. |
| `DUOPIPE_AUTOSTART_REQUESTS` | Testing only (requires `DUOPIPE_TEST_MODE=1`): set to `1` to start all requests on connect. |

## Configuration Files

Use `--default-config` to load from the default location, or `-c <path>` for a custom path (both TOML). Prefer config files so your settings are saved and reusable. Only one of these may be used at a time. All config keys live at the top level.

> **Security:** TOML config files **reject a plaintext `auth_token`**. You have three options: use `auth_token_file` (recommended), set the `DUOPIPE_AUTH_TOKEN` environment variable, or use an [age-encrypted inline value](#encrypted-config-values).

**Default location:** `~/.config/duopipe/peer.toml`

> **Note:** `relay_only` is a config bool and requires at least one `relay_urls` entry.

The config file holds the tunnel requests, auth token, relays, DNS, and transport tuning. The connection **role** and the dialer's **target node id** are chosen interactively in the TUI, not in the config.

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
encryption_key_file = "~/.config/duopipe/age.key"
encryption_recipient = "age1ql3z7hjy..."

auth_token = "ageenc:YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."
```

Each encrypted value is a single-line `ageenc:` prefixed string (base64-encoded age ciphertext). Age encryption applies only to `auth_token`. The `encryption_key_file` can also be specified via the `DUOPIPE_ENCRYPTION_KEY_FILE` env var.

### Transport Tuning

QUIC transport parameters can be tuned via an optional `[transport]` section in the config file. These are **config-only** (no CLI flags) and all have sensible defaults — only set them if you need to.

```toml
[transport]
# Congestion controller: "cubic" (default), "bbr", or "newreno"
congestion_controller = "cubic"
# QUIC per-stream receive window in bytes (default: 67108864 = 64MB; range 1024-67108864)
receive_window = 67108864
# QUIC send window in bytes (default: 67108864 = 64MB; range 1024-67108864)
send_window = 67108864
```

The connection-level receive window uses iroh's default. If `send_window` is omitted but `receive_window` is set, the send window defaults to twice the stream receive window, capped at the 64MB default. See [`peer.toml.example`](peer.toml.example) for the annotated reference.

### Peer Config Example

The same config shape is used by both peers; the role is chosen interactively at startup.

```toml
# Example peer configuration.
# The connection role and dial target node id are chosen interactively in the TUI.

# Shared auth token (plaintext not allowed — use a file, env var, or ageenc: value)
auth_token_file = "~/.config/duopipe/auth_token.txt"

# relay_urls = ["https://relay.example.com"]
# relay_only = false           # requires at least one relay_urls entry
dns_server = "https://dns.example.com/pkarr"
max_streams = 100   # max concurrent forwarded connections across all tunnels

# Tunnel requests: bind locally, ask the peer to connect out to source.
[[request]]
name = "db"
remote_source = "tcp://127.0.0.1:5678"
local_listen = "127.0.0.1:15678"

# Sources the peer may request of us (defaults to localhost if omitted).
[allowed_sources]
tcp = ["127.0.0.0/8"]
```

> [!NOTE]
> See [`peer.toml.example`](peer.toml.example) for the full annotated example.

```bash
# Load from default location (~/.config/duopipe/peer.toml)
duopipe start --default-config

# Load from custom path
duopipe start -c ./my-peer.toml
```

---

# Utility Commands

## generate-auth-token

Generate the shared authentication token used by both peers:

```bash
# Generate a single auth token
duopipe generate-auth-token
# Output: i<base64url-encoded-payload>

# Generate multiple auth tokens
duopipe generate-auth-token -c 5
```

Auth token format: `i` + Base64URL-encoded(32 random bytes + CRC16 checksum) = 47 characters total.

> **Note:** A listening instance that starts without a configured token generates one automatically and shows it in the TUI header, so generating one ahead of time is optional.

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
- The node id is a public key that identifies the listening peer. Because the identity is ephemeral, it changes every run.
- **Fixed ALPN:** The QUIC protocol identifier is a fixed constant (`mf/2`). It is not used for access control.
- **Token Authentication:** The dialing peer authenticates immediately after the QUIC connection via a dedicated auth stream, presenting the shared auth token. An invalid token is rejected with an `AuthResponse` and the connection is closed with an error code. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- **Source allowlist:** After auth the peer may *request* tunnels, but each requested source is checked against our `[allowed_sources]` CIDR lists before we connect out. Empty or absent TCP or UDP defaults to dual-stack localhost (`127.0.0.0/8`, `::1/128`). Requests are also activated interactively — nothing forwards until started. Only share the token with peers you trust, and keep the allowlist narrow.
- Treat the auth token like a password

## Exit Codes

The peer process uses categorized exit codes so wrapper scripts can distinguish transient failures (retry) from permanent errors (stop).

| Exit Code | Meaning | Retry? |
|-----------|---------|--------|
| 0 | Success | N/A |
| 1 | General/unexpected error | Use judgment |
| 2 | Configuration error (invalid arguments, bad token format, missing fields) | No — fix configuration |
| 3 | Authentication failure (token rejected, auth timeout) | No — fix credentials |
| 4 | Rejected: the listener's session is bound to a different node id | No — unbind/restart the listener, or dial from the bound node |
| 10 | Connection establishment failed (timeout, relay failure, peer unreachable) | Only if it worked before |
| 11 | Connection lost after tunnels were established | Yes — always retry |

## How It Works

### iroh Mode
1. On startup the TUI asks "Connect to an existing instance?", selecting the listen or dial role (the identity is freshly generated either way)
2. The listening peer creates an iroh endpoint with discovery services and publishes its address via Pkarr/DNS; its node id is shown in the TUI header
3. The dialing peer (given the listener's node id) resolves the listening peer via discovery
4. **QUIC handshake:** the connection uses the fixed ALPN constant (`mf/2`); there is no token in the ALPN
5. **Authentication phase:** the dialing peer opens a dedicated auth stream and sends `AuthRequest` with the shared auth token
6. **The listening peer validates the token** (10s timeout) against its single accepted token — an invalid token is rejected with an error response
   - *If authentication fails, the connection is closed and the following steps do not occur*
7. **Auth, then a source allowlist:** once authenticated, either side may *request* tunnels of the other; each requested source is checked against the serving peer's `[allowed_sources]` CIDR lists before it connects out. Empty or absent TCP or UDP defaults to dual-stack localhost.
8. Requested tunnels are negotiated over the single connection and traffic flows in both directions
