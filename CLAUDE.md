no backward compatibility is needed since it is still pre-release.
run cargo clippy and cargo test -q after making rust code changes.
no cargo fmt

# Purpose
duopipe is for a **single user connecting their own devices** (laptop ↔ homelab box
↔ VPS, …) to reach services across them — the same auth token lives on each of the
user's machines. Both ends are assumed to be owned (or otherwise fully trusted) by
that one person; it is not a public service or a multi-tenant gateway. Two mutually
trusting parties *can* use it, but that is not the primary design point.

# Usage model
This project is meant for interactive usage: a TUI asks, on startup, whether to
connect to an existing instance. There are two interactive subcommands, one per
mode:
- Configless mode — `duopipe quick [--auth-token-file <path>]`: ephemeral node id,
  no nostr, no config file. The auth token is generated fresh each run (shown in
  the TUI), or loaded from `--auth-token-file` / `DUOPIPE_AUTH_TOKEN`. A dialer
  enters the peer's node id manually (there is no nostr side channel to discover it).
- Nostr mode — `duopipe nostr [-c <file>]`: reads a config file (the `-c` path, or
  the default `~/.config/duopipe/peer.toml`) and requires both a *provided* auth
  token (it is the nostr rendezvous secret — a generated one couldn't be discovered
  by the peer) and a `name` (this peer's short identifier). Startup fails fast if
  either is missing. Nostr publishes/looks up the node id by name (see below): when
  connecting, the dialer types the *target peer's* identifier (its `name`) — setup
  rejects entering this peer's own `name`, which would resolve to itself. There is
  no raw node-id entry in nostr mode — use quick mode for that.

Token precedence is `--auth-token-file` (quick only) > `DUOPIPE_AUTH_TOKEN` > config
`auth_token_file` (nostr only).

Test usage is supported only for testing purposes, driven by env vars.
`DUOPIPE_TEST_MODE=1` is the single gate: it runs the peer headless (no TUI, logs
to stderr, needs no terminal) and is required for the other test-only vars to take
effect.
- `DUOPIPE_TEST_MODE=1` enables headless test mode and gates the vars below.
- `DUOPIPE_PEER_NODE_ID=<id>` present ⇒ dial that node id; absent ⇒ listen.
- `DUOPIPE_AUTOSTART_REQUESTS=1` starts every template `[[request]]` for a peer once
  its connection is up. Test-only: in the interactive TUI tunnels are always started
  manually, so this is the sole way to exercise tunnels headlessly.
- `DUOPIPE_AUTH_TOKEN=<token>` is the shared auth token (required to dial; for
  listen it is used if set, otherwise one is generated). Also honored outside test
  mode as a way to supply the token.
In test mode the listener prints `node_id:` and `auth_token:` to stderr so a test
harness can wire up the dialing side. The iroh identity key is always ephemeral
(regenerated every run), so the node id changes between runs.

Tests stay hermetic: when `DUOPIPE_PEER_NODE_ID` is set the dialer dials that id
directly and never touches nostr, so `cargo test -q` needs no live relays.

# Node-id discovery (nostr)
The iroh identity is always ephemeral — there is no stable-node-id mode. In nostr
mode (a config file is loaded) nostr is used as a side channel to publish & look up
a peer's *current* ephemeral node id, so a restart (new node id) doesn't require
re-exchanging it. Configless mode does not use nostr at all.

Both peers derive the same nostr *author* keypair from the shared `auth_token`
(`sha256("duopipe:nostr-rendezvous:v1" || auth_token)`). Each peer is then
distinguished by its `name`: the kind-30078 (NIP-78) `d` tag is
`duopipe:nodeid:<sha256("duopipe:peer-id:v1" || auth_token || name)>`. The listener
publishes a replaceable event under its own name's `d` tag whose content is its
current node id; the dialer hashes the *target* name into the same `d` tag and looks
it up, then dials. The `d`-tag hash is salted with the `auth_token` so a short,
low-entropy name can't be guessed or enumerated on relays without the token. Several
peers can share one `auth_token` and be reached individually by name; duplicate names
just clobber (replaceable, newest wins), which is acceptable for this convenience
layer. The node id in the event content is **encrypted** (NIP-44) under the shared
auth-token-derived keypair (self-encryption: the listener encrypts to its own derived
public key; any peer with the same `auth_token` derives the same key to decrypt), so
it does not appear on relays in the clear — and the `auth_token` still gates the
actual connection.

Because the `d` tag is keyed on the *stable* name (not the volatile node id), a
listener restart replaces its own record — no stale accumulation. The dialer
re-looks-up by name on every connect attempt, so a listener that restarted with a
fresh node id self-heals on the next attempt (no persistent subscription). As a
safety net, `run_dial` refuses to connect to a resolved node id equal to its own
(a self-dial) — whether a quick-mode node id pasted by mistake or a nostr name that
maps back to this peer. Relays
default to a built-in public set (`nostr_discovery::DEFAULT_NOSTR_RELAYS`); override
with `nostr_relay_urls`. To dial a raw node id without nostr, use quick mode.

Tunnel model: a peer *requests* tunnels from a connected party. A request binds a
local `local_listen` address and asks that peer to connect out to a `remote_source`,
bridging the two. The serving side gates incoming requests with `[allowed_sources]`
CIDR lists (`tcp`/`udp`); an empty/absent `tcp` list defaults to dual-stack localhost
(`127.0.0.0/8`, `::1/128`), and an empty/absent `udp` list uses the same default.

`[[request]]` is a **prefilled template**: it seeds the tunnel list of every
connection to save manual typing, but tunnels are **started manually** in the TUI
(nothing auto-connects; the only autostart is the test-mode
`DUOPIPE_AUTOSTART_REQUESTS` gate). It is not config to "open these tunnels."

Multiple peers: a listener accepts **many concurrent dialers** at once (one iroh
endpoint serves all of them — there is no single-peer session binding). Tunnel state
is **per peer**: each connection (`PeerSession` in `app_state.rs`) has its own tunnel
table seeded from the template, its own command channel, and its own observed path.
Because a tunnel is always directed at one connection, the TUI carries a peer
selector: `Tab` switches focus between the peer list and the selected peer's tunnels,
so starting a tunnel targets exactly that peer. A dialer holds at most one peer; a
listener holds one per connected device. The single global stream cap (`max_streams`)
is shared across all peers. The only admission guard left is transient: a second
*concurrent* connection from a node id that already has a live session is refused as
`peer_busy` (so a reconnect race can't bind the same local ports twice); the dialer
retries. Runtime-added tunnels are per-connection and do not survive that peer
disconnecting (it re-seeds from the template on reconnect).
