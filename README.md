# duopipe

**Cross-platform secure P2P TCP port forwarding with NAT traversal, for linking your own devices — driven by an interactive TUI.**

Duopipe is for **one person connecting their own devices** — laptop, homelab box, work machine, VPS — so they can reach services on each other without public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted P2P connections between two endpoints **you control**. It is driven through an interactive terminal UI (TUI) launched with `duopipe quick` (configless) or `duopipe connect` (config-driven, with node-id discovery), which walks you through connecting your devices and managing tunnels.

> [!IMPORTANT]
> **Project Goal:** This tool lets a **single user link their own devices** to reach services across them — for **development or homelab purposes** — without the hassle and security risk of opening a port. Both ends are expected to be machines you own (or otherwise fully trust). It is **not** meant for production setups, multi-user/multi-tenant access, or to be performant at scale. It is meant for **interactive use** (`duopipe quick` / `duopipe connect` and the TUI); the non-interactive env-var override is a **test-mode-only** workaround (`DUOPIPE_TEST_MODE=1`), not a supported automation interface.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** During initial development before version 1.0, no backward compatibility or migration path is provided between minor versions (e.g., 0.1.x to 0.2.x). Expect to regenerate tokens and rebuild peer configurations when upgrading in between minor versions.

**Features:**
- **No account or registration required** — Just download and run
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
- **Many peers, one forward each** — A listener serves several dialers at once over one endpoint; each dial session carries a single TCP forward, with bidirectional traffic
- **TCP forwarding** — Seamlessly tunnel a single TCP stream per session (UDP is intentionally out of scope — see [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs))
- **Cross-platform** — Works on Linux, macOS, and Windows
- **No root required** — Runs as unprivileged user
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with automatic NAT hole punching and relay fallback

**Use Cases:**
- **SSH access** to machines behind NAT/firewalls
- **Simpler Alternative to SSM For Staging Environment Access Purposes** — Great for ad-hoc access without configuring AWS agents or IAM users. **Note:** Not intended for production; it is not battle-tested for enterprise use and lacks integration with cloud security policies (IAM, auditing).
- **Remote Desktop** access (RDP/VNC over TCP) without port forwarding
- **Secure Service Exposure** (HTTP servers, databases, etc.) without public infrastructure
- **Development and Testing** of TCP services across network boundaries
- **Homelab Networking** — Connecting distributed homelab nodes or accessing local services remotely without complex VPN setups or public IP requirements
- **Cross-platform Tunneling** for TCP workflows (including Windows endpoints)

## Overview

duopipe runs as a peer launched in one of two modes — `duopipe quick` (configless) or `duopipe connect` (config-driven) — each of which opens an interactive terminal UI. Every instance is **always listening**: it accepts **many inbound peers at once** over one iroh endpoint and serves their tunnel request. Alongside that, each instance can hold **one outbound dial session** that *it* drives — SSH `-L`–style local forwarding: it binds a local listener and asks the connected peer to connect out to a remote source. Each individual connection is one-directional (one requester, one server); your process is just both at once.

> **Note:** v1 forwards a **single TCP stream** per dial session — one `remote_source` reached through one `local_listen`. A single SOCKS5 listener (so one tunnel can reach many destinations) is the planned future direction, modeled on [flextunnel](https://github.com/andrewtheguy/flextunnel). UDP is intentionally out of scope; that role belongs to [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs).

There is **no listen/dial choice at startup**. Quick mode always generates a fresh ephemeral token and at setup you pick how to share this device: **PIN** (the dashboard shows a short code that refreshes every 60s and carries this peer's node id + token over nostr — the dialer just types the PIN) or **Manual** (no nostr/internet — the node id + token are shown to copy by hand). Connect mode uses a pre-shared token you generated with `duopipe generate-auth-token`, supplied via config/env or pasted at setup. Then the dashboard opens, already listening. To dial a peer, press **`Shift-C`** and type the target — its `name` in connect mode, a **PIN** in quick PIN mode, or its **node id** in quick manual mode; press **`Shift-D`** to disconnect. You can disconnect and dial a different peer at any time — one outbound session at a time.

- The TUI header shows this instance's **node id** and a short **token fingerprint** (the first 8 hex digits of the token's SHA-256, shown in every mode so you can confirm both devices match). In quick **PIN** mode it also shows the **current PIN with a live countdown** (always visible, refreshing every 60s). In quick **manual** mode it shows the full **auth token** to copy (hidden automatically after 10 minutes, or immediately when you press `h`).
- The connect prompt validates its input (node id parse, or own-name/own-id rejection) before dialing; the auth token comes from config/env or is generated/entered at setup.
- The dashboard shows a **single tunnel row** (there is no list to navigate). Press **`s`** to start the listener and **`x`** to stop it — starting is its own deliberate key, never `Enter`, so a stray press can't begin forwarding; press **`e`** to open the **set-tunnel** form — two fields only, the remote source (`host:port`) and the local listen (`host:port`), with no protocol picker and no name field (saving only *sets* the spec — it does not start it); press **`d`** (or **`Del`**) to clear the tunnel. (`Shift` is reserved for the dial session: **`Shift-C`** connect, **`Shift-D`** disconnect.)

> **Note:** The iroh identity is **ephemeral** — a fresh identity is generated on every run, so a node id **changes every run**. In connect mode peers find each other by `name` regardless; in quick mode re-copy the node id each run.

A peer can serve **many inbound peers at once** — laptop + phone + VPS all dialing one homelab box — each shown in its peer list, while also dialing out itself. Each dial session carries one TCP forward. iroh provides NAT traversal with relay fallback and automatic discovery.

> [!IMPORTANT]
> **Intended use — one person linking their own devices.** duopipe assumes both peers are **devices you own** (e.g. laptop ↔ homelab box ↔ VPS); the same auth token lives on each of your machines. (Two parties who fully trust each other can use it too, but that is not the primary design point.) It is *not* a public service or a multi-tenant gateway. The design leans on this throughout:
> - **Out-of-band coordination.** The ephemeral node id changes every run, and any generated auth token is per-run too. Move the auth token between your own devices over a side channel you already have (a password manager, an SSH session, a synced notes/secrets store) before connecting; in connect mode the node id is then discovered automatically.
> - **Live, interactive operation.** Each device runs the TUI and watches shared status — connection state, connected peers, and the tunnel's health — and **starts/stops the tunnel by hand**. Nothing forwards on its own; you decide *what* to expose and *when*.
> - **Trust rests on the shared token.** Once the shared auth token passes, the connected peer is fully trusted — it may ask the serving peer to connect out to **any `host:port`** it requests. Keep the token only on devices you own (or fully trust).

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### Tunnel requests at a glance

The tunnel is a **request** (SSH `-L`–style, pull direction): the **dialer** declares a single `[tunnel]` in config, and activating it binds a local listener and asks the **listener** peer to connect out to a remote source.

| Field | Meaning |
|-------|---------|
| `remote_source` | Origin on the **other** peer to connect out to (a bare `host:port`, TCP only). |
| `local_listen` | Local address on **this** peer where the tunnel is exposed (`host:port`). |

To expose one of **your** services, the **other** peer requests it from you — there is no separate "remote forward". Once the shared auth token passes, the connected peer is fully trusted: it may ask the serving side to connect out to **any `host:port`** it names. Nothing forwards until you start the request in the TUI.

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

The iroh identity is **ephemeral** — duopipe generates a fresh identity on every run, so there is no key file to create or manage. The **listening** peer's **node id therefore changes every run**. In **connect mode** (when a config file is loaded), duopipe avoids copying it by hand each time by using **nostr** as a side channel: both peers derive a shared nostr key from the auth token, each listener publishes its current node id under its `name`, and a dialer looks it up by typing the target peer's `name` (see [Node-id discovery](#node-id-discovery)). In **configless mode** (`duopipe quick`) you pick at setup between two ways to share the node id: a rotating **PIN** over nostr (which also carries the token; see [Quick-mode PIN](#quick-mode-pin)) or **manual** copy-paste with nostr off. The node id is always shown in the TUI header.

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
> **The token is the sole gate.** Once the connection-level auth token passes, the connected peer is **fully trusted** — when it asks us to connect out to a `host:port`, we honor **any** address it names. Security rests **solely** on the shared token (and on the fact that the tunnel is activated interactively — nothing forwards until you start it). Keep the token only on devices you own (or otherwise fully trust).

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

A minimal config is essentially the request you can make plus an optional shared token (`peer.toml`):
```toml
auth_token_file = "/etc/duopipe/auth_token.txt"

# The tunnel we can request: bind locally, ask the peer to reach its source.
[tunnel]
remote_source = "127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
```

The instance always listens; the dial target is chosen **interactively** at runtime (press `Shift-C`), not in the config file. The `[tunnel]` entry is the template for that dial session, started/stopped from the TUI — nothing forwards automatically.

---

# Usage

## Architecture

Each iroh connection carries one requested tunnel. The **dialer** *requests* the tunnel: it binds a local listener and asks the **listener** to connect out to a remote source. For example, a request for the listener's SSH server:

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SSH Client      |  TCP   | dialer (request)|  iroh  | listener (serve)|  TCP   | SSH Server      |
|                 |<------>| listen :2222    |<======>| (trusted peer)  |<------>| source :22      |
|                 |        |                 |  QUIC  |                 |        |                 |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
```

One connection carries a single TCP request from the dialer, and one serving peer handles many dialers concurrently. For any single connection the serving side is a pure server — so to reach a service that lives near the *other* box, dial *from* the box that wants to reach it (every node can dial on demand).

For deeper architecture diagrams and protocol flows, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

duopipe is **interactive-first**: you run `duopipe connect` (config-driven, with node-id discovery) on both machines. Each instance is always listening; you dial the other on demand from the TUI. Tunnel requests, relays, and the auth token come from a config file (and/or env vars); the dial target is chosen interactively. For a one-off session with no config, use `duopipe quick` instead (see [CLI Options](#cli-options)).

### 1. Start both instances

On each machine, point at a config that declares its requests (see [Configuration Files](#configuration-files)) and run:

```bash
duopipe connect -c ./peer.toml
```

There is no role prompt — setup just confirms the token and the dashboard opens, already listening. Each config must set a `name`. The auth token may come from config `auth_token_file` or `DUOPIPE_AUTH_TOKEN`; if neither is set, setup prompts you to **paste it** — so `auth_token_file` is optional. The token is a pre-shared secret: generate it once with `duopipe generate-auth-token` and use the same value on every peer (connect setup does not generate one for you). Each instance publishes its current node id to nostr under its `name` so peers can find it. The TUI header shows this instance's **node id** and a short **token fingerprint** (the first 8 hex digits of the token's SHA-256) so you can confirm both devices share the same token even after the full token is hidden.

> **Important:** The node id is regenerated on every run (the identity is ephemeral), but in connect mode you don't copy it by hand — peers find each other by `name`.

### 2. Dial a peer

In the TUI on either machine, press **`Shift-C`** and type the **`name`** of the peer you want (e.g. `web1`, which must differ from this instance's own `name`); duopipe resolves it via nostr and connects. Press **`Shift-D`** to disconnect, then `Shift-C` again to dial a different peer. The **auth token** comes from config, `DUOPIPE_AUTH_TOKEN`, or the interactive setup prompt, and is shared by both sides — compare the **token fingerprint** in each header to confirm they match.

Once connected, the request you start in the TUI flows over that session. For example, a config with:

```toml
[tunnel]
remote_source = "127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
```

- This makes the **dialing** side listen on `127.0.0.1:15678`; connections are forwarded to `127.0.0.1:5678`, which the **connected peer** connects out to (it is fully trusted once the shared token passes).
- The direction is per-connection: whoever pressed `c` is the requester. To pull a service the *other* way, dial from the other box (or both dial each other — each instance serves and dials at once).

The request is started/stopped from the TUI. A single instance serves several inbound peers at once while holding one outbound dial session.

### 3. SSH over a requested tunnel

With a `[tunnel]` of `remote_source = "127.0.0.1:22"`, `local_listen = "127.0.0.1:2222"` (the other peer reaches the SSH server):

```bash
ssh -p 2222 user@127.0.0.1
```

### Bidirectional tunnels — both directions on demand

Each individual connection is one-directional: **whoever dialed is the requester, the
other side serves.** But every instance both serves and dials, so you get both
directions naturally — just dial from whichever side needs to pull:

- `homelab` wants a service on `laptop`: on `homelab` press `Shift-C`, dial `laptop`, and
  start its `[tunnel]` for that service.
- `laptop` wants a service on `homelab`: on `laptop` press `Shift-C`, dial `homelab`, and
  start its request.

Both can be connected at the same time — each instance's serve half accepts the
other's inbound dial while its own dial session pulls the other way. Each box's
`[tunnel]` is what *it* pulls when dialing; when serving, a connected peer that
passed the shared token may reach any `host:port` it requests — one config carries
both halves.

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
| `DUOPIPE_AUTOSTART_TUNNELS=1` | Start the configured `[tunnel]` (dial side) once connected (nothing auto-starts otherwise). |
| `DUOPIPE_AUTH_TOKEN=<token>` | The shared auth token. In **quick mode** it is honored **only** in test mode (interactive quick mode always generates its own token); in **connect mode** it is also valid outside test mode (see env table below). |

In test mode the listener prints `node_id: <id>` and `auth_token: <token>` to **stderr**, so a test harness can capture them and wire up the dialer.

## CLI Options

Both interactive subcommands launch the same always-listening TUI; they differ only in how the connect prompt names a target. In `quick`, press `Shift-C` and enter the peer's **PIN** (PIN signaling) or its **node id** (manual signaling). In `connect`, press `Shift-C` and enter the peer's `name`. Headless test mode is the only path with a fixed listen/dial role (see [Test mode (testing only)](#test-mode-testing-only)).

### quick (configless mode)

`duopipe quick` runs everything ephemeral with **no config file**: the node id and auth token are generated fresh on every run, and there is no way to supply an existing token. (`DUOPIPE_AUTH_TOKEN` is honored only under `DUOPIPE_TEST_MODE=1`; see [Test mode](#test-mode-testing-only).) It takes **no options** — instead, the setup screen offers two ways to share this device with the dialer:

- **Start with PIN** — uses **nostr** (needs internet). The dashboard shows a short, easy-to-type code that **refreshes every 60s with a countdown**; it carries this peer's node id *and* token, so to connect the other device just presses `Shift-C` and types the **PIN**. See [Quick-mode PIN](#quick-mode-pin).
- **Start manual** — **no nostr/internet**. The node id and auth token are shown in the dashboard header to copy by hand; to connect, the other device presses `Shift-C` and enters the **node id** (the token must be moved out of band).

<a name="quick-mode-pin"></a>
#### Quick-mode PIN

The PIN is **8 Crockford-base32 characters** drawn from unambiguous letters/numbers only (no `I L O U`), shown UPPERCASE and grouped like `K7P2-9QXM`. Input is case-insensitive and ignores dashes/spaces. A fresh random PIN is minted every 60 seconds.

How it works: both sides turn `(PIN, 60-second time bucket)` into the same nostr keypair via **Argon2id** (memory-hard, to slow brute-force). The listener publishes a single relay record under that key whose content is the **NIP-44 encrypted** `{node_id, token}`; a dialer holding the PIN derives the same key, finds the record by author, and decrypts it. The record carries a short expiration and the dialer also searches the adjacent buckets, so typing a PIN right across a rotation boundary still works.

> **Security:** the PIN is short and the encrypted record sits on public relays, so the slow Argon2id derivation plus the 60-second rotation and short record lifetime are what bound an attacker's window. Anyone who reads the current PIN during its window can connect (it conveys the token) — share it only with your own device, and prefer manual mode when you don't need the convenience.

### connect (config-driven mode)

`duopipe connect` reads a config file and uses **nostr** for node-id discovery. It requires a **`name`** (this peer's short identifier — ASCII letters, digits, and underscores only) and fails fast if it is missing or malformed. It also requires **`auth_token_fingerprint`** — the 8-hex-digit prefix of the shared token's SHA-256 — whether or not the token itself is in the config; whatever token is finally resolved (file, `DUOPIPE_AUTH_TOKEN`, or pasted at setup) must match it, or duopipe refuses to start. This pins each config to one pairing, so a config pointed at the wrong token file or a token meant for a different pair of devices is caught up front instead of failing as an auth error later. The auth token (the nostr rendezvous secret) may come from config `auth_token_file` or `DUOPIPE_AUTH_TOKEN`; if neither is set, setup prompts you to paste it, so `auth_token_file` is optional. The token is pre-shared, so generate it once (`duopipe generate-auth-token`, which prints its fingerprint) and use the same value on every peer — connect setup does not generate one for you. Requests, relays, DNS, max-streams, relay-only, and the optional nostr relay override all come from the config. A dialer reaches a peer by typing that peer's `name`, so several peers can share one auth token and be reached individually.

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `~/.config/duopipe/peer.toml` | Path to TOML config file |

**Environment variables:**

| Env Var | Description |
|---------|-------------|
| `DUOPIPE_AUTH_TOKEN` | The shared auth token (precedence: above config `auth_token_file`). |
| `DUOPIPE_TEST_MODE` | Testing only: set to `1` to run headless (no TUI) and enable the test-only env vars below. |
| `DUOPIPE_PEER_NODE_ID` | Testing only (requires `DUOPIPE_TEST_MODE=1`): when set ⇒ dial that node id; when unset ⇒ listen. |
| `DUOPIPE_AUTOSTART_TUNNELS` | Testing only (requires `DUOPIPE_TEST_MODE=1`): set to `1` to start the dial-side tunnel on connect. |

## Configuration Files

Config files are used by `duopipe connect`: run it with no flag to load the default location, or `-c <path>` for a custom path (TOML). Prefer config files so your settings are saved and reusable. All config keys live at the top level.

> **Security:** Supply the auth token with `auth_token_file` or the `DUOPIPE_AUTH_TOKEN` environment variable — it is never written inline in the config file.

**Default location:** `~/.config/duopipe/peer.toml`

> **Note:** `relay_only` is a config bool and requires at least one `relay_urls` entry.

`duopipe connect` requires a `name` and an `auth_token_fingerprint`; the auth token itself is optional in the config (supply it via `auth_token_file`/`DUOPIPE_AUTH_TOKEN`, or paste it at setup — generate it first with `duopipe generate-auth-token` and pre-share it). The resolved token must match `auth_token_fingerprint`, which pins the config to one pairing. The config holds the tunnel request, the token fingerprint, the optional path to the auth token, the peer's `name`, relays, DNS, the optional nostr relay override, and transport tuning. The instance always listens; the **dial target** is chosen interactively at runtime (press `Shift-C`), not in the config.

### Node-id discovery

Nostr discovery is active in `duopipe connect`. The iroh node id is ephemeral, so each listener publishes its current node id to **nostr** under its `name`, and a dialer looks it up by typing the target peer's `name` — no manual copy needed. Both peers derive the same nostr *author* key from the shared auth token; each peer's record is then placed under a `d` tag of `duopipe:nodeid:<sha256(auth_token || name)>`, so several peers can share one auth token yet stay individually addressable (duplicate names just mean newest-wins). The name hash is **salted with the auth token**, so a short name can't be guessed or enumerated on relays. The node id in the event content is **encrypted** (NIP-44) under the shared auth-token-derived keypair, so it never appears on relays in the clear — and the auth token still gates the actual connection. Because the `d` tag is keyed on the stable `name`, a listener restart replaces its own record (no stale entries) and the dialer re-resolves by name on each reconnect. To dial a raw node id without nostr, use `duopipe quick`.

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

# This peer's short identifier (required in connect mode). A dialer types it to find
# this peer; the listener publishes its node id under this name. ASCII letters,
# digits, and underscores only (used verbatim in the local state-file name).
name = "web1"

# Shared auth token (optional) — supply via a file (here) or the DUOPIPE_AUTH_TOKEN
# env var. If you omit both, setup prompts to generate a fresh token or paste an
# existing one.
auth_token_file = "~/.config/duopipe/auth_token.txt"

# Expected token fingerprint (required in connect mode) — the first 8 hex digits of the
# shared token's SHA-256, printed by `duopipe generate-auth-token`. Whatever token is
# resolved must match it, pinning this config to one pairing. Case-insensitive.
auth_token_fingerprint = "a1b2c3d4"

# relay_urls = ["https://relay.example.com"]
# relay_only = false           # requires at least one relay_urls entry
dns_server = "https://dns.example.com/pkarr"
max_streams = 100   # max concurrent forwarded connections across all peers

# Seed tunnel (dial side): bind locally, ask the connected peer to connect out to source.
[tunnel]
remote_source = "127.0.0.1:5678"
local_listen = "127.0.0.1:15678"
```

> [!NOTE]
> See [`peer.toml.example`](peer.toml.example) for the full annotated example.

```bash
# Load from default location (~/.config/duopipe/peer.toml)
duopipe connect

# Load from custom path
duopipe connect -c ./my-peer.toml
```

---

# Utility Commands

## generate-auth-token

Generate the shared authentication token used by both peers:

```bash
# Generate a single auth token (the fingerprint trails as an inline `#` comment, so
# the output is still a valid auth_token_file)
duopipe generate-auth-token
# Output: d<base64url-encoded-payload>  # fp: a1b2c3d4

# Generate multiple auth tokens
duopipe generate-auth-token -c 5

# JSON output for scripting/automation: a [{"token","fingerprint"}] array
duopipe generate-auth-token --json
duopipe generate-auth-token -c 5 --json
```

Auth token format: `d` + Base64URL-encoded(32 random bytes + CRC16 checksum) = 47 characters total. The 8-hex-digit `fingerprint` (the prefix of the token's SHA-256) is what goes in a connect-mode config's `auth_token_fingerprint`.

> **Note:** A listening instance that starts without a configured token generates one automatically and shows it in the TUI header, so generating one ahead of time is optional.

---

## Security

- All traffic is encrypted using QUIC/TLS 1.3
- The node id is a public key that identifies the listening peer. Because the identity is ephemeral, it changes every run.
- **Fixed ALPN:** The QUIC protocol identifier is a fixed constant (`mf/2`). It is not used for access control.
- **Token Authentication:** The dialing peer authenticates immediately after the QUIC connection via a dedicated auth stream, presenting the shared auth token. An invalid token is rejected with an `AuthResponse` and the connection is closed with an error code. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- **Token is the sole gate:** After auth the connected peer is **fully trusted** — when it requests a tunnel we connect out to **any `host:port`** it names. Security rests solely on the shared token; the request is also activated interactively, so nothing forwards until started. Keep the token only on devices you own (or otherwise fully trust).
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
7. **After auth, the tunnel request:** once authenticated, the **dialer** *requests* the tunnel and the **listener serves** it — connecting out to whatever `host:port` the now-trusted dialer names. A listener admits many dialers concurrently (no single-peer binding).
8. The requested tunnel is negotiated over the connection; within the tunnel, TCP traffic flows in both directions
