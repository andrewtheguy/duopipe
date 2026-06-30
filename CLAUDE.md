# Working in this repo
- No backward compatibility is needed since it is still pre-release.
- Run `cargo clippy` and `cargo test -q` after making Rust code changes.
- No `cargo fmt`.
- Keep tests hermetic — they must never depend on live relays or network
  rendezvous. With `DUOPIPE_PEER_NODE_ID` set the dialer dials that id directly and
  never touches nostr, so `cargo test -q` runs offline; preserve that.

# What this is
duopipe is for a **single user connecting their own devices** (laptop ↔ homelab box
↔ VPS, …) to reach services across them — the same auth token lives on each of the
user's machines. It is not a public service or a multi-tenant gateway.

It is interactive: every run is **always listening** and holds **one** on-demand
outbound dial session. Two interactive subcommands — `duopipe quick` (configless,
dial by node id) and `duopipe nostr` (config-driven, dial by `name`). Headless test
mode is gated by `DUOPIPE_TEST_MODE=1`.

**Scope (v1):** a dial session forwards exactly **one TCP** stream — the single
`[tunnel]` (`remote_source` / `local_listen`, both bare `host:port`). This is the
groundwork for a single SOCKS5 listener per host (cf. `../flextunnel`). **UDP is not
supported** — that role lives in `../tunnel-rs`. There is no multi-tunnel/multi-port
support; don't reintroduce it.

# Automation / AI agents
The interactive `quick`/`nostr` subcommands need a TTY and are not scriptable, but
`duopipe generate-auth-token` is. For programmatic use pass `--json` to get a
`[{"token","fingerprint"}]` array (use `--count N` for several) instead of the
human-readable `<token>  # fp: <fp>` lines — parse that rather than scraping stdout.
The `fingerprint` is what goes in a nostr config's `auth_token_fingerprint`; the
`token` goes in the `auth_token_file` (or `DUOPIPE_AUTH_TOKEN`) on every paired device.

# Where the details live
Don't duplicate these here — read and update the source docs:
- **README.md** — usage model, CLI options, config file format, test-mode env vars
  (`DUOPIPE_TEST_MODE`, `DUOPIPE_*`), quick-start examples.
- **docs/ARCHITECTURE.md** — runtime roles (`Role::Both`/`Listen`/`Dial`), tunnel
  model, security/threat model, protocol details, component map.
- **src/nostr_discovery.rs** — exact nostr key derivation and tag construction for
  node-id discovery.
