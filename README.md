# duopipe

**Cross-platform secure P2P access to services on your own devices via a per-device loopback SOCKS5 proxy over NAT-traversing P2P — driven by an interactive TUI.**

Duopipe is for **one person connecting their own devices** — laptop, homelab box, work machine, VPS — so they can reach services on each other without public IP addresses, open ports, or VPN infrastructure. It establishes direct encrypted P2P connections between two endpoints **you control**. Once two devices are paired, each can run a small **loopback-only SOCKS5 proxy** whose connections tunnel over the P2P link and egress on the *other* device's network. It is driven through an interactive terminal UI (TUI) launched with `duopipe quick` (configless) or `duopipe run` (config-driven, with node-id discovery), which walks you through connecting your devices and starting the proxy.

> [!IMPORTANT]
> **Project Goal:** This tool lets a **single user link their own devices** to reach services across them — for **development or homelab purposes** — without the hassle and security risk of opening a port. Both ends are expected to be machines you own (or otherwise fully trust). It is **not** meant for production setups, multi-user/multi-tenant access, or to be performant at scale. It is meant for **interactive use** (`duopipe quick` / `duopipe run` and the TUI); the non-interactive env-var override is a **test-mode-only** workaround (`DUOPIPE_TEST_MODE=1`), not a supported automation interface.

> [!WARNING]
> **No Backward Compatibility (Pre-1.0):** During initial development before version 1.0, no backward compatibility or migration path is provided between minor versions (e.g., 0.1.x to 0.2.x). Expect to regenerate tokens and rebuild peer configurations when upgrading in between minor versions.

**Features:**
- **No account or registration required** — Just download and run
- **No publicly accessible IPs or port forwarding required** — Automatic NAT hole punching
- **One pairing per run (listen XOR dial)** — A run is *either* the listening side *or* the dialing side of a single pairing, never both. A listener pairs with a single dialer (all modes); the first peer to authenticate claims the endpoint and others are refused until you stop listening
- **Symmetric SOCKS5 proxy** — Once paired, each device can bind a loopback-only SOCKS5 proxy that tunnels its CONNECTs over the P2P link to egress on the *other* device's network (CONNECT-only, TCP-only; UDP is intentionally out of scope — see [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs))
- **Cross-platform** — Works on Linux, macOS, and Windows
- **No root required** — Runs as unprivileged user
- **End-to-end encryption** via QUIC/TLS 1.3
- **NAT traversal** with automatic NAT hole punching and relay fallback

**Use Cases:**
- **SSH access** to machines behind NAT/firewalls
- **Simpler Alternative to SSM For Staging Environment Access Purposes** — Great for ad-hoc access without configuring AWS agents or IAM users. **Note:** Not intended for production; it is not battle-tested for enterprise use and lacks integration with cloud security policies (IAM, auditing).
- **Remote Desktop** access (RDP/VNC over TCP) via the SOCKS5 proxy without port forwarding
- **Secure Service Exposure** (HTTP servers, databases, etc.) without public infrastructure
- **Development and Testing** of TCP services across network boundaries
- **Homelab Networking** — Connecting distributed homelab nodes or accessing local services remotely without complex VPN setups or public IP requirements
- **Cross-platform proxying** for TCP workflows (including Windows endpoints)

## Overview

duopipe runs as a peer launched in one of two modes — `duopipe quick` (configless) or `duopipe run` (config-driven) — each of which opens an interactive terminal UI. The dashboard opens **idle**, and a run then becomes **either** the listening side **or** the dialing side of a single pairing — never both. Press **`Shift-L`** to start listening, and it pairs with **one inbound peer** over one iroh endpoint (press `Shift-L` again to stop; the first peer to authenticate claims the endpoint for that session, and other peers are refused until you stop). Alternatively, press **`Shift-C`** to **dial** a peer. These are **mutually exclusive**: while you are listening, `Shift-C` is refused; while an outbound dial session exists, `Shift-L` is refused. Whichever way the pairing is formed, once it is live **both** paired devices can each run their own loopback SOCKS5 proxy.

Once two devices are paired, the tunnel is a **symmetric loopback-only SOCKS5 proxy**: each side can bind a SOCKS5 proxy on `127.0.0.1` (+ `::1`) at a port it chooses, and each proxy's `CONNECT`s tunnel over the existing iroh connection and **egress on the other device's network**. Domains resolve on the remote (exit) side. It is CONNECT-only, no-auth-method, TCP-only ([RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)) — no BIND, no UDP. UDP is intentionally out of scope; that role belongs to [tunnel-rs](https://github.com/andrewtheguy/tunnel-rs).

There is **no listen/dial choice at startup**. Quick mode runs fully ephemeral (a fresh node id every run) and at setup you pick how to share this device: **PIN** (once listening, the dashboard shows a short code that refreshes every 60s and carries this peer's node id over nostr — the dialer types the PIN, which both fetches the node id and authenticates the connection in-band; **no token exists in this mode**) or **Manual** (no nostr/internet — a fresh ephemeral token is generated and the node id + token are shown to copy by hand). Config mode uses a pre-shared token you generated with `duopipe generate-auth-token`, supplied via config/env or pasted at setup. Then the dashboard opens **idle** — press **`Shift-L`** to start listening (which brings up the node id, the PIN/token, and the nostr/PIN publishers), and `Shift-L` again to stop. Because the iroh identity is ephemeral, a stop→start cycle mints a **new** node id (and, in quick PIN mode, a **new** PIN). To dial a peer instead, press **`Shift-C`** and type the target — its `name` in config mode, a **PIN** in quick PIN mode, or its **node id** in quick manual mode; press **`Shift-D`** to disconnect. You can disconnect and dial a different peer at any time — one outbound session at a time — but you cannot dial while listening (or listen while dialing).

- Press **`Shift-L`** to start listening (only available when you are not dialing); until you do, the node-id line reads *not listening — press Shift+L to start* and no PIN or token banner is shown. Once listening, the TUI header shows this instance's **node id**. In config and quick **manual** modes it also shows a short **token fingerprint** (the first 8 hex digits of the token's SHA-256) so you can confirm both devices share the same token. In quick **PIN** mode it instead shows the **current PIN** (which refreshes every 60s, with a small countdown to the next refresh) — there is no token to match, since the PIN authenticates the connection and no token is shared; in quick **manual** mode it shows the full **auth token** to copy. Either secret **auto-hides after 10 minutes** — the line also shows the absolute clock time it will hide at — and **`h` toggles it off/on at any time** (re-showing re-arms the 10-minute timer). Pressing `Shift-L` again stops listening (and, because the identity is ephemeral, a later restart mints a new node id — and, in quick PIN mode, a new PIN).
- The connect prompt validates its input (node id parse, or own-name/own-id rejection) before dialing; the auth token comes from config/env or is generated/entered at setup. Dialing is only available when you are not listening.
- The dashboard shows a **single SOCKS5 proxy row** (there is no list to navigate). Press **`e`** to open the **set SOCKS5 port** form — a single field, the port `1..=65535`; press **`s`** to start the proxy (bind the loopback-only SOCKS5 listener on that port and route its CONNECTs over the live pairing) and **`x`** to stop it (freeing the bound port) — starting is its own deliberate key, never `Enter`, so a stray press can't open a proxy; press **`d`** (or **`Del`**) to clear the port. The row title reads ` SOCKS5 Proxy  [s start · x stop · e set · d clear] ` once paired, or ` SOCKS5 Proxy  [e set · d clear — pair first] ` before a pairing is live. The proxy is symmetric, so it is available on **both** the listener and the dialer once a connection is live. (`Shift` drives the pairing: **`Shift-L`** start/stop listening, **`Shift-C`** connect, **`Shift-D`** disconnect.)

> **Note:** The iroh identity is **ephemeral** — a fresh identity is generated on every run, so a node id **changes every run**. In config mode peers find each other by `name` regardless; in quick mode re-copy the node id each run.

A peer serves **one inbound peer per listen session** — the first device to authenticate (laptop *or* phone *or* VPS) claims the homelab box until it stops listening — shown inline in its header. iroh provides NAT traversal with relay fallback and automatic discovery.

> [!IMPORTANT]
> **Intended use — one person linking their own devices.** duopipe assumes both peers are **devices you own** (e.g. laptop ↔ homelab box ↔ VPS), authenticated by the same **shared auth secret** — a pre-shared **auth token** in config and quick manual modes, or a **rotating PIN** in quick PIN mode. (Two parties who fully trust each other can use it too, but that is not the primary design point.) It is *not* a public service or a multi-tenant gateway. The design leans on this throughout:
> - **Out-of-band coordination.** The ephemeral node id changes every run, and any generated auth secret is per-run too. In config and quick manual modes, move the **auth token** between your own devices over a side channel you already have (a password manager, an SSH session, a synced notes/secrets store) before connecting; in config mode the node id is then discovered automatically. In quick **PIN** mode there is nothing to pre-share — the listener shows a rotating PIN that you type on the dialer, which both finds the node id and authenticates the connection in-band.
> - **Live, interactive operation.** Each device runs the TUI and watches shared status — connection state, the paired peer, and the proxy's health — and **starts/stops its SOCKS5 proxy by hand**. Nothing tunnels on its own; you decide *whether* to open a proxy and *when*.
> - **Trust rests on the shared token.** Once the shared auth token passes, the connected peer is fully trusted — its SOCKS5 proxy may ask this device to connect out to **any `host:port`** it names (there is no destination allowlist). Keep the token only on devices you own (or fully trust).

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed diagrams and technical deep-dives.

### The SOCKS5 proxy at a glance

The tunnel is a **loopback-only SOCKS5 proxy**. Once two devices are paired, each side can bind a SOCKS5 listener on a chosen port; each `CONNECT` it receives is tunneled over the pairing and connected out on the **other** device's network, with domains resolved remotely.

| Setting | Meaning |
|---------|---------|
| `socks_port` | Local loopback port (`1..=65535`) where **this** device binds its SOCKS5 proxy (`127.0.0.1` + `::1`). Optional; set/started interactively in the TUI. |

The proxy is **symmetric** — both paired devices can each run their own proxy, and each one reaches the *other* device's network. Once the shared auth token passes, the connected peer is fully trusted: its proxy may ask this side to connect out to **any `host:port`** it names (no destination allowlist). The bind is loopback-only, so only local apps on the proxying device can use it. Nothing tunnels until you start the proxy in the TUI.

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

The iroh identity is **ephemeral** — duopipe generates a fresh identity on every run, so there is no key file to create or manage. The **listening** peer's **node id therefore changes every run**. In **config mode** (when a config file is loaded), duopipe avoids copying it by hand each time by using **nostr** as a side channel: both peers derive a shared nostr key from the auth token, each listener publishes its current node id under its `name`, and a dialer looks it up by typing the target peer's `name` (see [Node-id discovery](#node-id-discovery)). In **configless mode** (`duopipe quick`) you pick at setup between two ways to share the node id: a rotating **PIN** over nostr (which carries only the node id — the PIN itself authenticates the connection, so no token is sent; see [Quick-mode PIN](#quick-mode-pin)) or **manual** copy-paste with nostr off. The node id is shown in the TUI header once you start listening (`Shift-L`).

## Authentication

Most connections are gated by a single pre-shared **auth token**, shared by **both** peers: the dialing peer presents it and the listening peer accepts exactly that one token. This covers **config mode** (a token you generated ahead of time and pre-shared) and quick **manual** mode (a fresh ephemeral token shown to copy by hand). The expected setup is the **same token on your own devices**, copied between them over an out-of-band channel you already have (a password manager, an SSH session) — see [Intended use](#overview).

The exception is quick **PIN** mode, which uses **no token at all**: the rotating PIN both locates the node id and authenticates the connection in-band (see [Quick-mode PIN](#quick-mode-pin)). Everything below about tokens applies to config and quick manual modes.

> **Note:** The QUIC ALPN identifier is a fixed constant (`mf/2`). It is no longer used for access control — authentication is solely via the shared auth token.

**Auth Token Format:**
- Exactly 47 characters
- Starts with `d` (for duopipe)
- Remaining 46 characters are Base64URL-encoded (no padding)
- Decoded payload: 32 random bytes + 2-byte CRC16-CCITT-FALSE checksum

The CRC16 checksum detects all single-byte errors in the token payload.

Generate auth tokens with: `duopipe generate-auth-token`

> [!IMPORTANT]
> **The token is the sole gate.** Once the connection-level auth token passes, the connected peer is **fully trusted** — when its SOCKS5 proxy asks us to connect out to a `host:port`, we honor **any** address it names (no allowlist). Security rests **solely** on the shared token (and on the fact that the proxy is loopback-only and activated interactively — nothing tunnels until you start it). Keep the token only on devices you own (or otherwise fully trust).

### Token Management

In configless quick **manual** mode, the listening peer has no configured token, so it **generates one automatically** and — once you start listening (`Shift-L`) — displays it in the TUI header alongside the node id. The banner auto-hides after 10 minutes (and once a peer connects); press `h` to hide it sooner or to toggle it back on. (Quick **PIN** mode generates no token — it shows a rotating PIN instead; see [Quick-mode PIN](#quick-mode-pin).) You can also mint tokens ahead of time:

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

A minimal config is essentially an optional shared token plus an optional SOCKS5 port (`peer.toml`):
```toml
auth_token_file = "/etc/duopipe/auth_token.txt"

# Loopback-only SOCKS5 proxy port for this device (optional).
socks_port = 1080
```

Listening is started on demand from the TUI (press `Shift-L`), or you dial a peer instead (press `Shift-C`) — the two are mutually exclusive, and the dial target is chosen **interactively** at runtime, not in the config file. The `socks_port` seeds the proxy's port; it is started/stopped from the TUI (`s`/`x`) once a pairing is live — nothing tunnels automatically.

---

# Usage

## Architecture

Once two devices are paired, each side can run a loopback-only SOCKS5 proxy whose CONNECTs tunnel over the iroh connection and egress on the *other* device's network. For example, a local SOCKS5 client reaching the peer's SSH server:

```
+-----------------+        +-----------------+        +-----------------+        +-----------------+
| SOCKS5 client   |  TCP   | this device     |  iroh  | peer (exit side)|  TCP   | SSH Server      |
| (curl/ssh/…)    |<------>| SOCKS5 :1080    |<======>| (trusted peer)  |<------>| host :22        |
|                 |        | 127.0.0.1 only  |  QUIC  |                 |        | (resolved here) |
+-----------------+        +-----------------+        +-----------------+        +-----------------+
```

The proxy is symmetric — the paired peer can equally run its own proxy back the other way — and a serving peer is paired with one dialer per listen session. Domains resolve on the exit (peer) side, so use a remote-DNS SOCKS client (`socks5h://`). Each connection is bounded by the shared stream limit (`max_streams`).

For deeper architecture diagrams and protocol flows, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

duopipe is **interactive-first**: you run `duopipe run` (config-driven, with node-id discovery) on both machines. On one, press `Shift-L` to start listening; on the other, press `Shift-C` to dial it (a run does one or the other, not both). Once paired, either side can start its loopback SOCKS5 proxy. The SOCKS5 port, relays, and the auth token come from a config file (and/or env vars); the dial target is chosen interactively. For a one-off session with no config, use `duopipe quick` instead (see [CLI Options](#cli-options)).

### 1. Start both instances

On each machine, point at a config (see [Configuration Files](#configuration-files)) and run:

```bash
duopipe run -c ./peer.toml
```

There is no role prompt — setup just confirms the token and the dashboard opens **idle**; press `Shift-L` to start listening (or `Shift-C` to dial — a run is one or the other). Each config must set a `name`. The auth token may come from config `auth_token_file` or `DUOPIPE_AUTH_TOKEN`; if neither is set, setup prompts you to **paste it** — so `auth_token_file` is optional. The token is a pre-shared secret: generate it once with `duopipe generate-auth-token` and use the same value on every peer (config setup does not generate one for you). Once listening, each instance publishes its current node id to nostr under its `name` so peers can find it. The TUI header then shows this instance's **node id** and a short **token fingerprint** (the first 8 hex digits of the token's SHA-256) so you can confirm both devices share the same token even after the full token is hidden.

> **Important:** The node id is regenerated on every run (the identity is ephemeral), but in config mode you don't copy it by hand — peers find each other by `name`.

### 2. Dial a peer

On the machine that is **not** listening, press **`Shift-C`** and type the **`name`** of the peer you want (e.g. `web1`, which must differ from this instance's own `name`); duopipe resolves it via nostr and connects. Press **`Shift-D`** to disconnect, then `Shift-C` again to dial a different peer. The **auth token** comes from config, `DUOPIPE_AUTH_TOKEN`, or the interactive setup prompt, and is shared by both sides — compare the **token fingerprint** in each header to confirm they match. (You cannot dial while listening; a run is one or the other.)

Once connected, either side can start its loopback SOCKS5 proxy from the TUI (`s`) on its `socks_port`. For example, a config with:

```toml
socks_port = 1080
```

- This makes the device bind a SOCKS5 proxy on `127.0.0.1:1080` (loopback only); its CONNECTs tunnel over the pairing and the **connected peer** connects out to whatever host you ask for (it is fully trusted once the shared token passes).
- The proxy is symmetric: the peer can run its own proxy reaching *this* device's network at the same time — one config carries both halves, since either side may listen-or-dial and each may run a proxy.

The proxy is started/stopped from the TUI (`s`/`x`). A single instance is either the listening or the dialing side of one pairing.

### 3. SSH via the SOCKS5 proxy

With `socks_port = 1080` and a proxy running, reach the peer's SSH server through the proxy (use a remote-DNS-capable client):

```bash
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:1080 %h %p' user@<host-on-peer-network>
```

Or an HTTP service on the peer (`socks5h://` resolves the hostname on the exit side):

```bash
curl -x socks5h://127.0.0.1:1080 http://<service-on-peer>/
```

### Both directions on demand

The SOCKS5 proxy is **symmetric**: once paired, each side can run its own loopback proxy
reaching the *other* device's network. A run is either the listener or the dialer of a
pairing, but both roles get a proxy:

- `homelab` wants services on `laptop`: pair the two, then on `homelab` start its SOCKS5
  proxy — its CONNECTs egress on `laptop`.
- `laptop` wants services on `homelab`: over the *same* pairing, `laptop` starts its own
  proxy — its CONNECTs egress on `homelab`.

Both proxies can run at the same time over one pairing, each reaching the other side's
network. Each box's `socks_port` is where *its* local apps connect; when acting as the
exit side, a connected peer that passed the shared token may reach any `host:port` it
names — one config carries both halves.

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
| `DUOPIPE_AUTOSTART_SOCKS=1` | Start the local SOCKS5 proxy once connected (nothing auto-starts otherwise). |
| `DUOPIPE_SOCKS_PORT=<port>` | Seed the SOCKS5 proxy port for config-free headless runs (`0` = OS-assigned). |
| `DUOPIPE_AUTH_TOKEN=<token>` | The shared auth token. In **quick mode** it is honored **only** in test mode (interactive quick mode always generates its own token); in **config mode** it is also valid outside test mode (see env table below). |

In test mode the listener prints `node_id: <id>` and `auth_token: <token>` to **stderr**, so a test harness can capture them and wire up the dialer.

## CLI Options

Both interactive subcommands launch the same TUI — idle at startup, with listening started on demand by `Shift-L`; they differ only in how the connect prompt names a target. In `quick`, press `Shift-C` and enter the peer's **PIN** (PIN signaling) or its **node id** (manual signaling). In `run`, press `Shift-C` and enter the peer's `name`. Headless test mode is the only path with a fixed listen/dial role (see [Test mode (testing only)](#test-mode-testing-only)).

### quick (configless mode)

`duopipe quick` runs everything ephemeral with **no config file**: the node id is generated fresh on every run, and there is no way to supply an existing token. **PIN** signaling uses no token at all (the PIN authenticates the connection); **manual** signaling generates a fresh ephemeral token to copy by hand. (`DUOPIPE_AUTH_TOKEN` is honored only under `DUOPIPE_TEST_MODE=1`; see [Test mode](#test-mode-testing-only).) It takes **no options** — instead, the setup screen offers two ways to share this device with the dialer:

- **Start with PIN** — uses **nostr** (needs internet). Once you start listening (`Shift-L`), the dashboard shows a short, easy-to-type code that **refreshes every 60s with a countdown**; it carries only this peer's node id (never the token). To connect, the other device presses `Shift-C` and types the **PIN** — the same PIN both locates the node id on nostr and authenticates the connection in-band. See [Quick-mode PIN](#quick-mode-pin).
- **Start manual** — **no nostr/internet**. Once you start listening (`Shift-L`), the node id and auth token are shown in the dashboard header to copy by hand; to connect, the other device presses `Shift-C` and enters the **node id** (the token must be moved out of band).

<a name="quick-mode-pin"></a>
#### Quick-mode PIN

The PIN is **8 Crockford-base32 characters** drawn from unambiguous letters/numbers only (no `I L O U`), shown UPPERCASE and grouped like `K7P2-9QXM`. The last character is a **check digit** (7 random data characters + 1 checksum, ~35 bits), so a mistyped PIN is rejected up front instead of failing later as an empty lookup. Input is case-insensitive and ignores dashes/spaces. A fresh random PIN is minted every 60 seconds.

How it works, in two steps that both use the PIN but no token on the wire:

1. **Find the node id.** Both sides turn `(PIN, 60-second time bucket)` into the same nostr keypair via **Argon2id** (memory-hard, to slow brute-force). The listener publishes a single relay record under that key whose content is the **NIP-44 encrypted** `{node_id}` — the node id only, never the token. A dialer holding the PIN derives the same key, finds the record by author, and decrypts it. The record carries a short expiration and the dialer also searches the adjacent buckets, so typing a PIN right across a rotation boundary still works.
2. **Authenticate the connection.** After dialing that node id, both peers prove they hold the same PIN with a short **challenge-response over the connection itself** (iroh's QUIC channel is encrypted and bound to the peer's node id). A separate Argon2id key derived from the PIN string seals each side's proof (NIP-44); a wrong PIN fails the exchange. The listener remembers the last few buckets' PINs so a code read just before a rotation still authenticates.

> **Security:** the only thing on public relays is the ephemeral node id, encrypted under a PIN-derived key; the auth token is **never** put on a relay. So even if the record is captured and the short (~35-bit) PIN is later brute-forced past the slow Argon2id derivation, it yields only a node id — not a reusable credential — and by the time that slow crack finishes the PIN has long since rotated, so it can no longer authenticate a connection. Anyone who reads the current PIN *during its window* can still connect, so share it only with your own device.

### run (config-driven mode)

`duopipe run` reads a config file and uses **nostr** for node-id discovery. It requires a **`name`** (this peer's short identifier — ASCII letters, digits, and underscores only) and fails fast if it is missing or malformed. It also requires **`auth_token_fingerprint`** — the 8-hex-digit prefix of the shared token's SHA-256 — whether or not the token itself is in the config; whatever token is finally resolved (file, `DUOPIPE_AUTH_TOKEN`, or pasted at setup) must match it, or duopipe refuses to start. This pins each config to one pairing, so a config pointed at the wrong token file or a token meant for a different pair of devices is caught up front instead of failing as an auth error later. The auth token (the nostr rendezvous secret) may come from config `auth_token_file` or `DUOPIPE_AUTH_TOKEN`; if neither is set, setup prompts you to paste it, so `auth_token_file` is optional. The token is pre-shared, so generate it once (`duopipe generate-auth-token`, which prints its fingerprint) and use the same value on every peer — config setup does not generate one for you. The SOCKS5 port, relays, DNS, max-streams, relay-only, and the optional nostr relay override all come from the config. A dialer reaches a peer by typing that peer's `name`, so several peers can share one auth token and be reached individually.

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-c` | `~/.config/duopipe/peer.toml` | Path to TOML config file |

**Environment variables:**

| Env Var | Description |
|---------|-------------|
| `DUOPIPE_AUTH_TOKEN` | The shared auth token (precedence: above config `auth_token_file`). |
| `DUOPIPE_TEST_MODE` | Testing only: set to `1` to run headless (no TUI) and enable the test-only env vars below. |
| `DUOPIPE_PEER_NODE_ID` | Testing only (requires `DUOPIPE_TEST_MODE=1`): when set ⇒ dial that node id; when unset ⇒ listen. |
| `DUOPIPE_AUTOSTART_SOCKS` | Testing only (requires `DUOPIPE_TEST_MODE=1`): set to `1` to start the local SOCKS5 proxy on connect. |
| `DUOPIPE_SOCKS_PORT` | Testing only (requires `DUOPIPE_TEST_MODE=1`): seed the SOCKS5 proxy port for config-free headless runs (`0` = OS-assigned). |

## Configuration Files

Config files are used by `duopipe run`: run it with no flag to load the default location, or `-c <path>` for a custom path (TOML). Prefer config files so your settings are saved and reusable. All config keys live at the top level.

> **Security:** Supply the auth token with `auth_token_file` or the `DUOPIPE_AUTH_TOKEN` environment variable — it is never written inline in the config file.

**Default location:** `~/.config/duopipe/peer.toml`

> **Note:** `relay_only` is a config bool and requires at least one `relay_urls` entry.

`duopipe run` requires a `name` and an `auth_token_fingerprint`; the auth token itself is optional in the config (supply it via `auth_token_file`/`DUOPIPE_AUTH_TOKEN`, or paste it at setup — generate it first with `duopipe generate-auth-token` and pre-share it). The resolved token must match `auth_token_fingerprint`, which pins the config to one pairing. The config holds the optional `socks_port`, the token fingerprint, the optional path to the auth token, the peer's `name`, relays, DNS, the optional nostr relay override, and transport tuning. Listening is started on demand from the TUI (press `Shift-L`), or you dial a peer instead (press `Shift-C`) — the two are mutually exclusive, and the **dial target** is chosen interactively at runtime, not in the config.

### Node-id discovery

Nostr discovery is active in `duopipe run`. The iroh node id is ephemeral, so each listener publishes its current node id to **nostr** under its `name`, and a dialer looks it up by typing the target peer's `name` — no manual copy needed. Both peers derive the same nostr *author* key from the shared auth token; each peer's record is then placed under a `d` tag of `duopipe:nodeid:<sha256(auth_token || name)>`, so several peers can share one auth token yet stay individually addressable (duplicate names just mean newest-wins). The name hash is **salted with the auth token**, so a short name can't be guessed or enumerated on relays. The node id in the event content is **encrypted** (NIP-44) under the shared auth-token-derived keypair, so it never appears on relays in the clear — and the auth token still gates the actual connection. Because the `d` tag is keyed on the stable `name`, a listener restart replaces its own record (no stale entries) and the dialer re-resolves by name on each reconnect. To dial a raw node id without nostr, use `duopipe quick`.

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

The same config shape is used by both peers. Each interactive run either starts listening on demand (`Shift-L`) or dials a peer (`Shift-C`) — never both; the outbound dial target is chosen from the dashboard.

```toml
# Example peer configuration.
# The outbound dial target is chosen interactively from the dashboard.

# This peer's short identifier (required in config mode). A dialer types it to find
# this peer; the listener publishes its node id under this name. ASCII letters,
# digits, and underscores only (used verbatim in the local state-file name).
name = "web1"

# Shared auth token (optional) — supply via a file (here) or the DUOPIPE_AUTH_TOKEN
# env var. If you omit both, setup prompts to generate a fresh token or paste an
# existing one.
auth_token_file = "~/.config/duopipe/auth_token.txt"

# Expected token fingerprint (required in config mode) — the first 8 hex digits of the
# shared token's SHA-256, printed by `duopipe generate-auth-token`. Whatever token is
# resolved must match it, pinning this config to one pairing. Case-insensitive.
auth_token_fingerprint = "a1b2c3d4"

# relay_urls = ["https://relay.example.com"]
# relay_only = false           # requires at least one relay_urls entry
dns_server = "https://dns.example.com/pkarr"
max_streams = 100   # max concurrent forwarded connections across all peers

# Loopback-only SOCKS5 proxy port for this device (optional). Once paired, start it
# from the TUI (`s`); its CONNECTs egress on the peer's network. Symmetric — the
# peer can run its own proxy back the other way.
socks_port = 1080
```

> [!NOTE]
> See [`peer.toml.example`](peer.toml.example) for the full annotated example.

```bash
# Load from default location (~/.config/duopipe/peer.toml)
duopipe run

# Load from custom path
duopipe run -c ./my-peer.toml
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

Auth token format: `d` + Base64URL-encoded(32 random bytes + CRC16 checksum) = 47 characters total. The 8-hex-digit `fingerprint` (the prefix of the token's SHA-256) is what goes in a config-mode config's `auth_token_fingerprint`.

> **Note:** A quick-mode instance that starts without a configured token generates one automatically and shows it in the TUI header once you start listening (`Shift-L`), so generating one ahead of time is optional.

---

## Security

- All traffic is encrypted using QUIC/TLS 1.3
- The node id is a public key that identifies the listening peer. Because the identity is ephemeral, it changes every run.
- **Fixed ALPN:** The QUIC protocol identifier is a fixed constant (`mf/2`). It is not used for access control.
- **Token Authentication:** The dialing peer authenticates immediately after the QUIC connection via a dedicated auth stream, presenting the shared auth token. An invalid token is rejected with an `AuthResponse` and the connection is closed with an error code. See [Architecture: Token Authentication](docs/ARCHITECTURE.md#token-authentication-iroh-mode).
- **Token is the sole gate:** After auth the connected peer is **fully trusted** — its SOCKS5 proxy may ask us to connect out to **any `host:port`** it names (no destination allowlist). Security rests solely on the shared token; the proxy is also loopback-only and activated interactively, so nothing tunnels until you start it and only local apps on the proxying device can use it. Keep the token only on devices you own (or otherwise fully trust).
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
| 11 | Connection lost after the pairing was established | Yes — always retry |

## How It Works

### iroh Mode
1. On startup the dashboard opens idle (no role prompt); the user presses `Shift-L` to start listening (a fresh identity is generated then) **or** `Shift-C` to dial a peer — the two are mutually exclusive, a run is one or the other
2. On `Shift-L`, the instance creates an iroh endpoint with discovery services and publishes its address via Pkarr/DNS; its node id is then shown in the TUI header
3. When dialing, the dial session (given the target's node id, directly or resolved via nostr) reaches the target via discovery
4. **QUIC handshake:** the connection uses the fixed ALPN constant (`mf/2`); there is no token in the ALPN
5. **Authentication phase:** the dialing peer opens a dedicated auth stream and sends `AuthRequest` with the shared auth token
6. **The listening peer validates the token** (10s timeout) against its single accepted token — an invalid token is rejected with an error response
   - *If authentication fails, the connection is closed and the following steps do not occur*
7. **After auth, the pairing is live:** a listener pairs with a single dialer per listen session — the first peer to authenticate claims the endpoint (by its node id) and other peers are refused until the session is stopped, but the paired peer may reconnect without re-authenticating.
8. **SOCKS5 proxy (symmetric):** either paired device can start a loopback-only SOCKS5 proxy. Each CONNECT it accepts opens a stream tagged `SocksConnect { host, port }`; the trusted peer resolves the host on *its* network, connects out, and bridges — so traffic flows both ways over the tunnel.
