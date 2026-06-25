# duopipe

**Cross-platform secure P2P TCP/UDP port forwarding with NAT traversal, for linking your own devices — driven by an interactive TUI.**

Duopipe is for **one person connecting their own devices** — laptop, homelab box, work machine, VPS — so they can reach services on each other without public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted P2P connections between two endpoints **you control**. It is driven through an interactive terminal UI (TUI) launched with `duopipe quick` (configless) or `duopipe nostr` (config-driven, with node-id discovery), which walks you through connecting your devices and managing tunnels.

> [!IMPORTANT]
> **Project Goal:** This tool lets a **single user link their own devices** to reach services across them — for **development or homelab purposes** — without the hassle and security risk of opening a port. Both ends are expected to be machines you own (or otherwise fully trust). It is **not** meant for production setups, multi-user/multi-tenant access, or to be performant at scale. It is meant for **interactive use** (`duopipe quick` / `duopipe nostr` and the TUI); the non-interactive env-var override is a **test-mode-only** workaround (`DUOPIPE_TEST_MODE=1`), not a supported automation interface.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** During initial development before version 1.0, no backward compatibility or migration path is provided between minor versions (e.g., 0.1.x to 0.2.x). Expect to regenerate tokens and rebuild peer configurations when upgrading in between minor versions.

**Features:**
- **No account or registration required** — Just download and run
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
- **Many peers, many tunnels** — A listener serves several dialers at once over one endpoint; each dialer requests any number of tunnels, each carrying bidirectional traffic
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

duopipe runs as a peer launched in one of two modes — `duopipe quick` (configless) or `duopipe nostr` (config-driven) — each of which opens an interactive terminal UI. Every instance is **always listening**: it accepts **many inbound peers at once** over one iroh endpoint and serves their tunnel requests, each gated by its `[allowed_sources]` allowlist. Alongside that, each instance can hold **one outbound dial session** that *it* drives — SSH `-L`–style local forwarding: it binds a local listener and asks the connected peer to connect out to a remote source. Each individual connection is one-directional (one requester, one server); your process is just both at once.

There is **no listen/dial choice at startup**. Setup only collects the serving allowlist (when config supplies none) and the auth token (supplied, or generated with a confirm), then the dashboard opens — already listening. To dial a peer, press **`c`** and type the target (its `name` in nostr mode, or its node id in quick mode); press **`D`** to disconnect. You can disconnect and dial a different peer at any time — one outbound session at a time.

- The TUI header shows this instance's **node id** and (when freshly generated) the **auth token**, so you can copy them to your other device. Generated tokens hide automatically after 10 minutes, or immediately when you press `h`.
- The connect prompt validates its input (node id parse, or own-name/own-id rejection) before dialing; the auth token comes from config/env or is generated.

> **Note:** The iroh identity is **ephemeral** — a fresh identity is generated on every run, so a node id **changes every run**. In nostr mode peers find each other by `name` regardless; in quick mode re-copy the node id each run.

A peer can serve **many inbound peers at once** — laptop + phone + VPS all dialing one homelab box — each shown in its peer list, while also dialing out itself. iroh provides NAT traversal with relay fallback and automatic discovery.

> [!IMPORTANT]
> **Intended use — one person linking their own devices.** duopipe assumes both peers are **devices you own** (e.g. laptop ↔ homelab box ↔ VPS); the same auth token lives on each of your machines. (Two parties who fully trust each other can use it too, but that is not the primary design point.) It is *not* a public service or a multi-tenant gateway. The design leans on this throughout:
> - **Out-of-band coordination.** The ephemeral node id changes every run, and any generated auth token is per-run too. Move the auth token between your own devices over a side channel you already have (a password manager, an SSH session, a synced notes/secrets store) before connecting; in nostr mode the node id is then discovered automatically.
> - **Live, interactive operation.** Each device runs the TUI and watches shared status — connection state, connected peers, and each tunnel's health — and **start/stop tunnels by hand**. Nothing forwards on its own; you decide *what* to expose and *when*.
> - **Trust assumed, exposure narrowly scoped.** The dialer *requests* tunnels; the listener serves only what its `[allowed_sources]` allowlist permits — keep it as tight as the task needs.

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### Tunnel requests at a glance

Every tunnel is a **request** (SSH `-L`–style, pull direction): the **dialer** declares `[[tunnel]]` entries in config, and activating one binds a local listener and asks the **listener** peer to connect out to a remote source.

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

The iroh identity is **ephemeral** — duopipe generates a fresh identity on every run, so there is no key file to create or manage. The **listening** peer's **node id therefore changes every run**. In **nostr mode** (when a config file is loaded), duopipe avoids copying it by hand each time by using **nostr** as a side channel: both peers derive a shared nostr key from the auth token, each listener publishes its current node id under its `name`, and a dialer looks it up by typing the target peer's `name` (see [Node-id discovery](#node-id-discovery)). In **configless mode** (`duopipe quick`) nostr is off and the dialer enters the node id manually. The node id is always shown in the TUI header.

## Authentication

A peer connection is gated by a single pre-shared **auth token**, shared by **both** peers. The dialing peer presents it; the listening peer accepts exactly that one token. The expected setup is the **same token on your own devices**, copied between them over an out-of-band channel you already have (a password manager, an SSH session) — see [Intended use](#overview).

> **Note:** The QUIC ALPN identifier is a fixed constant (`mf/2`). It is no longer used for access control — authentication is solely via the shared auth token.

**Auth Token Format:**
- Exactly 47 characters
- Starts with `d` (for duopipe)
- Remaining 46 characters are Base64URL-encoded (no padding)
- Decoded payload: 32 random bytes + 2-byte CRC16-CCITT-FALSE checksum

The CRC16 checksum detects all single-byte errors in the token payload.

Generate auth tokens with: `duopipe generate-auth-token`

> [!IMPORTANT]
> **Trust after auth, gated by the source allowlist.** Once the connection-level auth token passes, the peer may *request* tunnels, but when it asks us to connect out to one of our sources we only honor addresses inside our `[allowed_sources]` CIDR lists. Empty or absent TCP or UDP defaults to dual-stack localhost. Requests are also activated interactively — nothing forwards until you start it. Keep the token only on devices you own (or otherwise fully trust), and keep `[allowed_sources]` as narrow as possible.

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

> **Security:** Supply the auth token with `auth_token_file` or the `DUOPIPE_AUTH_TOKEN` environment variable. The token is never written inline in the config file.

A minimal config is essentially the requests you can make, the sources you'll expose, plus an optional shared token (`peer.toml`):
```toml
auth_token_file = "/etc/duopipe/auth_token.txt"

# A tunnel we can request: bind locally, ask the peer to reach its source.
[[tunnel]]
name = "db"
remote_source = "tcp://127.0.0.1:5678"
local_listen = "127.0.0.1:15678"

# What the peer is allowed to request of us (defaults to localhost if omitted).
[allowed_sources]
tcp = ["127.0.0.0/8"]
```

The instance always listens; the dial target is chosen **interactively** at runtime (press `c`), not in the config file. `[[tunnel]]` entries are templates for that dial session, started/stopped from the TUI — nothing forwards automatically.

---

# Usage

## Architecture

Each iroh connection carries requested tunnels. The **dialer** *requests* a tunnel: it binds a local listener and asks the **listener** to connect out to a remote source. For example, a request for the listener's SSH server:

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | dialer (request)|  iroh  | listener (serve)|  TCP   | SSH Server      |
|                 |<------>| listen :2222    |<======>| (allowlist gate)|<------>| source :22      |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
```

One connection can carry any number of TCP/UDP requests from the dialer at once, and one listener serves many dialers concurrently. The listener is a pure server — to reach a service that lives near the listener box, run that box as the dialer instead.

For deeper architecture diagrams and protocol flows, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

duopipe is **interactive-first**: you run `duopipe nostr` (config-driven, with node-id discovery) on both machines. Each instance is always listening; you dial the other on demand from the TUI. Tunnel requests, relays, and the auth token come from a config file (and/or env vars); the dial target is chosen interactively. For a one-off session with no config, use `duopipe quick` instead (see [CLI Options](#cli-options)).

### 1. Start both instances

On each machine, point at a config that declares its requests (see [Configuration Files](#configuration-files)) and run:

```bash
duopipe nostr -c ./peer.toml
```

There is no role prompt — setup just confirms the allowlist/token and the dashboard opens, already listening. Each config must set a `name` and supply the auth token (config `auth_token_file` or `DUOPIPE_AUTH_TOKEN`); each instance publishes its current node id to nostr under its `name` so peers can find it. The TUI header shows this instance's **node id** and indicates that the auth token was loaded.

> **Important:** The node id is regenerated on every run (the identity is ephemeral), but in nostr mode you don't copy it by hand — peers find each other by `name`.

### 2. Dial a peer

In the TUI on either machine, press **`c`** and type the **`name`** of the peer you want (e.g. `web1`, which must differ from this instance's own `name`); duopipe resolves it via nostr and connects. Press **`D`** to disconnect, then `c` again to dial a different peer. The **auth token** comes from config or `DUOPIPE_AUTH_TOKEN` and is shared by both sides.

Once connected, the requests you start in the TUI flow over that session. For example, a config with:

```toml
[[tunnel]]
name = "db"
remote_source = "tcp://127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
```

- This makes the **dialing** side listen on `127.0.0.1:15678`; connections are forwarded to `tcp://127.0.0.1:5678`, which the **connected peer** connects out to (subject to *its* `[allowed_sources]`).
- The direction is per-connection: whoever pressed `c` is the requester. To pull a service the *other* way, dial from the other box (or both dial each other — each instance serves and dials at once).

Requests are started/stopped independently in the TUI. A single instance serves several inbound peers at once while holding one outbound dial session.

### 3. SSH over a requested tunnel

With a `[[tunnel]]` of `remote_source = "tcp://127.0.0.1:22"`, `local_listen = "127.0.0.1:2222"` (the other peer reaches the SSH server, and allows `127.0.0.0/8` in `[allowed_sources]`):

```bash
ssh -p 2222 user@127.0.0.1
```

### 4. UDP request (e.g., WireGuard/Game/DNS)

UDP works too; the `remote_source` scheme selects the protocol, and the address is gated by the peer's `allowed_sources.udp` list:

```toml
# This peer listens on UDP 51820; the other peer connects out to the UDP service.
[[tunnel]]
name = "wg"
remote_source = "udp://127.0.0.1:51820"
local_listen = "0.0.0.0:51820"
```

> **Note:** UDP requests use a single-peer-address reply model — suitable for single-client UDP services.

### Bidirectional tunnels — both directions on demand

Each individual connection is one-directional: **whoever dialed is the requester, the
other side serves.** But every instance both serves and dials, so you get both
directions naturally — just dial from whichever side needs to pull:

- `homelab` wants a service on `laptop`: on `homelab` press `c`, dial `laptop`, and
  start its `[[tunnel]]` for that service.
- `laptop` wants a service on `homelab`: on `laptop` press `c`, dial `homelab`, and
  start its request.

Both can be connected at the same time — each instance's serve half accepts the
other's inbound dial while its own dial session pulls the other way. Each box's
`[[tunnel]]` list is what *it* pulls when dialing; its `[allowed_sources]` gates what
a connected peer may reach when serving — one config carries both halves.

**This does not conflict on nostr.** Each instance publishes its node id under its own
`name`'s `d` tag (salted with the auth token); dialing only *reads* the target's
record. Two machines with distinct names (`homelab`, `laptop`) publish two independent
records. The only requirement is a **unique `name` per machine** — already true for
distinct peers. (See [docs/ROADMAP.md](docs/ROADMAP.md) for what happens if two
machines accidentally share a name.)

### Test mode (testing only)

duopipe is meant for interactive use. For automated tests, `DUOPIPE_TEST_MODE=1` runs the peer **headless** (no TUI, logs to stderr, needs no terminal) and is the single gate that enables all test-only env vars:

| Env Var | Purpose |
|---------|---------|
| `DUOPIPE_TEST_MODE=1` | Run headless (no TUI). Gates the env vars below. |
| `DUOPIPE_PEER_NODE_ID=<id>` | When **set** ⇒ dial that node id; when **unset** ⇒ listen. |
| `DUOPIPE_AUTOSTART_TUNNELS=1` | Start every configured `[[tunnel]]` (dial role) once connected (nothing auto-starts otherwise). |
| `DUOPIPE_AUTH_TOKEN=<token>` | The shared auth token (also valid outside test mode; see env table below). |

In test mode the listener prints `node_id: <id>` and `auth_token: <token>` to **stderr**, so a test harness can capture them and wire up the dialer.

## CLI Options

Both interactive subcommands launch the same always-listening TUI; they differ only in how the connect prompt names a target. In `quick`, press `c` and enter the peer's node id. In `nostr`, press `c` and enter the peer's `name`. Headless test mode is the only path with a fixed listen/dial role (see [Test mode (testing only)](#test-mode-testing-only)).

### quick (configless mode)

`duopipe quick` runs everything ephemeral with **no config file** and **no nostr**: the node id changes every run, and to dial you enter the peer's node id by hand in the connect prompt (`c`).

| Option | Default | Description |
|--------|---------|-------------|
| `--auth-token-file` | - | Path to a file holding the shared auth token. Precedence: this flag > `DUOPIPE_AUTH_TOKEN`. Without either, a fresh ephemeral token is generated each run. |

### nostr (config-driven mode)

`duopipe nostr` reads a config file and uses **nostr** for node-id discovery. It **requires a provided auth token** (the nostr rendezvous secret) and a **`name`** (this peer's short identifier); it fails fast if either is missing. Requests, relays, DNS, max-streams, relay-only, and the optional nostr relay override all come from the config. A dialer reaches a peer by typing that peer's `name`, so several peers can share one auth token and be reached individually.

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `~/.config/duopipe/peer.toml` | Path to TOML config file |

**Environment variables:**

| Env Var | Description |
|---------|-------------|
| `DUOPIPE_AUTH_TOKEN` | The shared auth token (precedence: below `--auth-token-file`, above config `auth_token_file`). |
| `DUOPIPE_TEST_MODE` | Testing only: set to `1` to run headless (no TUI) and enable the test-only env vars below. |
| `DUOPIPE_PEER_NODE_ID` | Testing only (requires `DUOPIPE_TEST_MODE=1`): when set ⇒ dial that node id; when unset ⇒ listen. |
| `DUOPIPE_AUTOSTART_TUNNELS` | Testing only (requires `DUOPIPE_TEST_MODE=1`): set to `1` to start all dial-role requests on connect. |

## Configuration Files

Config files are used by `duopipe nostr`: run it with no flag to load the default location, or `-c <path>` for a custom path (TOML). Prefer config files so your settings are saved and reusable. All config keys live at the top level.

> **Security:** Supply the auth token with `auth_token_file` or the `DUOPIPE_AUTH_TOKEN` environment variable — it is never written inline in the config file.

**Default location:** `~/.config/duopipe/peer.toml`

> **Note:** `relay_only` is a config bool and requires at least one `relay_urls` entry.

`duopipe nostr` requires a provided auth token and a `name`. The config holds the tunnel requests, the path to the auth token, the peer's `name`, relays, DNS, the optional nostr relay override, and transport tuning. The instance always listens; the **dial target** is chosen interactively at runtime (press `c`), not in the config.

### Node-id discovery

Nostr discovery is active in `duopipe nostr`. The iroh node id is ephemeral, so each listener publishes its current node id to **nostr** under its `name`, and a dialer looks it up by typing the target peer's `name` — no manual copy needed. Both peers derive the same nostr *author* key from the shared auth token; each peer's record is then placed under a `d` tag of `duopipe:nodeid:<sha256(auth_token || name)>`, so several peers can share one auth token yet stay individually addressable (duplicate names just mean newest-wins). The name hash is **salted with the auth token**, so a short name can't be guessed or enumerated on relays. The node id in the event content is **encrypted** (NIP-44) under the shared auth-token-derived keypair, so it never appears on relays in the clear — and the auth token still gates the actual connection. Because the `d` tag is keyed on the stable `name`, a listener restart replaces its own record (no stale entries) and the dialer re-resolves by name on each reconnect. To dial a raw node id without nostr, use `duopipe quick`.

```toml
# Relays default to a built-in public set; override if desired:
# nostr_relay_urls = ["wss://nos.lol", "wss://relay.nostr.net"]
```

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

The same config shape is used by both peers. Every interactive run serves from launch; the outbound dial target is chosen later from the dashboard.

```toml
# Example peer configuration.
# The outbound dial target is chosen interactively from the dashboard.

# This peer's short identifier (required in nostr mode). A dialer types it to find
# this peer; the listener publishes its node id under this name.
name = "web1"

# Shared auth token — supply via a file (here) or the DUOPIPE_AUTH_TOKEN env var.
auth_token_file = "~/.config/duopipe/auth_token.txt"

# relay_urls = ["https://relay.example.com"]
# relay_only = false           # requires at least one relay_urls entry
dns_server = "https://dns.example.com/pkarr"
max_streams = 100   # max concurrent forwarded connections across all tunnels and peers

# Tunnel requests (dial role): bind locally, ask the listener to connect out to source.
[[tunnel]]
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
duopipe nostr

# Load from custom path
duopipe nostr -c ./my-peer.toml
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

Auth token format: `d` + Base64URL-encoded(32 random bytes + CRC16 checksum) = 47 characters total.

> **Note:** A listening instance that starts without a configured token generates one automatically and shows it in the TUI header, so generating one ahead of time is optional.

---

## Security

- All traffic is encrypted using QUIC/TLS 1.3
- The node id is a public key that identifies the listening peer. Because the identity is ephemeral, it changes every run.
- **Fixed ALPN:** The QUIC protocol identifier is a fixed constant (`mf/2`). It is not used for access control.
- **Token Authentication:** The dialing peer authenticates immediately after the QUIC connection via a dedicated auth stream, presenting the shared auth token. An invalid token is rejected with an `AuthResponse` and the connection is closed with an error code. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- **Source allowlist:** After auth the peer may *request* tunnels, but each requested source is checked against our `[allowed_sources]` CIDR lists before we connect out. Empty or absent TCP or UDP defaults to dual-stack localhost (`127.0.0.0/8`, `::1/128`). Requests are also activated interactively — nothing forwards until started. Keep the token only on devices you own (or otherwise fully trust), and keep the allowlist narrow.
- Treat the auth token like a password

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

## How It Works

### iroh Mode
1. On startup the instance begins listening immediately (no role prompt); the identity is freshly generated. A dial session is started later from the TUI (`c`)
2. The instance creates an iroh endpoint with discovery services and publishes its address via Pkarr/DNS; its node id is shown in the TUI header
3. When dialing, the dial session (given the target's node id, directly or resolved via nostr) reaches the target via discovery
4. **QUIC handshake:** the connection uses the fixed ALPN constant (`mf/2`); there is no token in the ALPN
5. **Authentication phase:** the dialing peer opens a dedicated auth stream and sends `AuthRequest` with the shared auth token
6. **The listening peer validates the token** (10s timeout) against its single accepted token — an invalid token is rejected with an error response
   - *If authentication fails, the connection is closed and the following steps do not occur*
7. **Auth, then a source allowlist:** once authenticated, the **dialer** *requests* tunnels; the **listener serves** them, checking each requested source against its `[allowed_sources]` CIDR lists before it connects out. Empty or absent TCP or UDP defaults to dual-stack localhost. A listener admits many dialers concurrently (no single-peer binding).
8. Requested tunnels are negotiated over the connection; within each tunnel, traffic flows in both directions
