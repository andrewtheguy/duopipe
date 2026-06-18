no backward compatibility is needed since it is still pre-release.
run cargo clippy and cargo test -q after making changes.
no cargo fmt

# Usage model
This project is meant for interactive usage: `duopipe peer` runs a TUI that asks,
on startup, whether to connect to an existing instance, then prompts for the node
id and (if not configured) the auth token.

Non-interactive usage is supported only for testing purposes, driven by env vars:
- `DUOPIPE_NONINTERACTIVE=1` skips the interactive prompts.
- `DUOPIPE_PEER_NODE_ID=<id>` present ⇒ dial that node id; absent ⇒ listen.
- `DUOPIPE_AUTH_TOKEN=<token>` is the shared auth token (required to dial; for
  listen it is used if set, otherwise one is generated).
In non-interactive mode the listener prints `node_id:` and `auth_token:` to stderr
so a test harness can wire up the dialing side. The iroh identity key is always
ephemeral (regenerated every run), so the node id changes between runs.