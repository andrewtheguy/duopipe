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
This project is meant for interactive usage. Every interactive run is **always
listening** (serving inbound peers) from launch; there is **no listen/dial role
choice at startup**. The single outbound **dial session is started on demand from
the dashboard** (press `c`, type the target), can be disconnected (`D`), and
re-pointed at a different peer — one outbound session at a time. Setup only collects
the serving `[allowed_sources]` (when config supplies none) and the auth token
(supplied, or generated with a confirm). There are two interactive subcommands, one
per mode — they differ only in how a dial target is named:
- Configless mode — `duopipe quick [--auth-token-file <path>]`: ephemeral node id,
  no nostr, no config file. The auth token is generated fresh each run (shown in
  the TUI), or loaded from `--auth-token-file` / `DUOPIPE_AUTH_TOKEN`. To dial, the
  user types the *peer's node id* in the connect prompt (no nostr side channel to
  discover it).
- Nostr mode — `duopipe nostr [-c <file>]`: reads a config file (the `-c` path, or
  the default `~/.config/duopipe/peer.toml`) and requires both a *provided* auth
  token (it is the nostr rendezvous secret — a generated one couldn't be discovered
  by the peer) and a `name` (this peer's short identifier, published so peers can
  reach it). Startup fails fast if either is missing. To dial, the user types the
  *target peer's* `name` in the connect prompt — it rejects entering this peer's own
  `name` (which would resolve to itself). For a raw node id, use quick mode.

Internally the interactive process runs as one dual role (`Role::Both`): an
always-on serve half plus a dial manager that drives the on-demand session over a
separate endpoint. Each *connection* is still strictly one-directional (one
requester, one server). Single-role `Role::Listen`/`Role::Dial` exist only for the
headless test path below.

Token precedence is `--auth-token-file` (quick only) > `DUOPIPE_AUTH_TOKEN` > config
`auth_token_file` (nostr only).

Test usage is supported only for testing purposes, driven by env vars.
`DUOPIPE_TEST_MODE=1` is the single gate: it runs the peer headless (no TUI, logs
to stderr, needs no terminal) and is required for the other test-only vars to take
effect.
- `DUOPIPE_TEST_MODE=1` enables headless test mode and gates the vars below.
- `DUOPIPE_PEER_NODE_ID=<id>` present ⇒ dial that node id; absent ⇒ listen.
- `DUOPIPE_AUTOSTART_TUNNELS=1` starts every configured `[[tunnel]]` (dial role)
  once the connection is up. Required to exercise tunnels in tests, since tunnels are
  otherwise activated interactively in the TUI and nothing forwards automatically.
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
listener restart replaces its own record — no stale accumulation. The dial session
re-looks-up by name on every connect attempt, so a peer that restarted with a fresh
node id self-heals on the next attempt (no persistent subscription). As a safety net,
the connect prompt rejects a target equal to this peer's own name / published node id,
and the dial session refuses to connect to a resolved node id equal to its own (a
self-dial) — ending that session rather than the process. Relays default to a built-in
public set (`nostr_discovery::DEFAULT_NOSTR_RELAYS`); override with `nostr_relay_urls`.
To dial a raw node id without nostr, use quick mode.

Tunnel model: within any one connection the **dialer requests** tunnels and the
**server side is pure** (initiates none). An interactive process is both at once: its
always-on serve half gates each incoming request against its `[allowed_sources]` CIDR
lists (`tcp`/`udp`; an empty/absent list defaults to dual-stack localhost
`127.0.0.0/8`, `::1/128`), while its dial session requests tunnels from whatever peer
it is connected to. The `[[tunnel]]` entries are a seed list of tunnels (dial side):
each binds a local `local_listen` address and asks the connected peer to connect out
to a `remote_source`, bridging the two — SSH `-L`-style local forwarding. Names must
be unique. Tunnels are started interactively (`Enter`), added at runtime (`a`), or
edited in place while not running (`e`).

Multiple peers: the serve half accepts **many concurrent inbound peers** over its iroh
endpoint — there is no single-peer session binding (authentication is the only gate).
The dial side holds **one** outbound session at a time (re-pointable on demand). The
TUI lists connected inbound peers and the outbound dial session + its tunnels. One
global `max_streams` semaphore caps concurrent forwarded streams across both halves.
