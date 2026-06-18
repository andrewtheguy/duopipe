no backward compatibility is needed since it is still pre-release.
run cargo clippy and cargo test -q after making changes.
no cargo fmt

# Usage model
This project is meant for interactive usage: `duopipe peer` runs a TUI that asks,
on startup, whether to connect to an existing instance, then prompts for the node
id and (if not configured) the auth token.

Test usage is supported only for testing purposes, driven by env vars.
`DUOPIPE_TEST_MODE=1` is the single gate: it runs the peer headless (no TUI, logs
to stderr, needs no terminal) and is required for the other test-only vars to take
effect.
- `DUOPIPE_TEST_MODE=1` enables headless test mode and gates the vars below.
- `DUOPIPE_PEER_NODE_ID=<id>` present ⇒ dial that node id; absent ⇒ listen.
- `DUOPIPE_AUTOSTART_REQUESTS=1` starts every configured `[[request]]` once the
  connection is up. Required to exercise tunnels in tests, since requests are
  otherwise activated interactively in the TUI and nothing forwards automatically.
- `DUOPIPE_AUTH_TOKEN=<token>` is the shared auth token (required to dial; for
  listen it is used if set, otherwise one is generated). Also honored outside test
  mode as a way to supply the token.
In test mode the listener prints `node_id:` and `auth_token:` to stderr so a test
harness can wire up the dialing side. The iroh identity key is always ephemeral
(regenerated every run), so the node id changes between runs.

Tunnel model: a peer always *requests* tunnels from the other party. Each
`[[request]]` binds a local `local_listen` address and asks the peer to connect out
to a `remote_source`. The serving side gates incoming requests with `[allowed_sources]`
CIDR lists (`tcp`/`udp`); an empty/absent `tcp` list defaults to dual-stack localhost
(`127.0.0.0/8`, `::1/128`), while an empty/absent `udp` list rejects everything
(fail-closed).