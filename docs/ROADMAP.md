# Roadmap

Planned work, with enough design detail to start implementation. Items here are
not yet built; the current behavior is described in [README.md](../README.md) and
[ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Option B — single dual-role process (serve + dial on demand)

> **Status: implemented.** Selectable in the setup screen as *"Serve and dial (both
> directions, one process)"* (`Role::Both`). One process runs a listen half and a dial
> half over separate iroh endpoints sharing one `AppState` and one stream semaphore
> (`run_dual` / `split_dual_config` in `src/iroh_mode/peer.rs`). The notes below are
> kept for context; the *Open items* still apply.

### Motivation

The tunnel model is one-directional per connection: **the dialer requests, the
listener only serves** (see `run_listen` / `run_dial` in `src/iroh_mode/peer.rs`,
dispatched by `run_peer` on `PeerConfig.role`). To get tunnels in *both*
directions between two machines today you run **two processes per machine** — one
listening, one dialing — as documented under
[*Bidirectional tunnels*](../README.md#bidirectional-tunnels--both-directions-on-demand)
(this is "Option A").

Option A works and is conflict-free on nostr (only listeners publish, each under
its own `name`'s `d` tag; dialers only read). Its cost is **operational**: two
processes, two TUIs, and two iroh endpoints to manage per box.

Option B folds both roles into **one process per machine** with a split TUI: a
pane for *peers I'm serving* and a pane for *my outbound tunnels*. The listener
half is always active; the dial half connects on demand.

### Key principle: this is NOT a return to the symmetric model

The `symmetric-listener-dialer` branch made each **single connection**
bidirectional — both ends could request tunnels over the same connection, which
required per-connection role negotiation and is the complexity the pure-server
model deliberately removed.

Option B keeps the pure-server rule **per connection**: a connection still has
exactly one requester and one server. We simply **co-locate two independent
roles in one process** — an inbound serve endpoint and an outbound dial
connection — that never interact at the connection layer. The symmetric branch is
useful only as plumbing reference (running both directions in one process), not
for its per-connection negotiation.

### Design sketch

**Concurrency.** Run `run_listen` and `run_dial` concurrently from one process,
e.g. a new `run_peer_dual` that `tokio::select!`/joins both, sharing one
`Arc<AppState>` and one `CancellationToken` (`AppState.shutdown`). Both halves use
the **one global stream `Semaphore`** already created once per process
(`new_stream_semaphore`), so the existing global `max_streams` cap naturally spans
both roles — no change to the limiter.

**Endpoints.** Start with **two iroh endpoints** (one per half). It's the simplest
correct option and avoids any ambiguity around a single endpoint being both the
QUIC initiator and acceptor between the same two peers. A later optimization could
collapse to a single shared endpoint if the relay/hole-punch overhead matters.

**nostr.** Unchanged and already safe: the listen half publishes its node id under
this machine's `name`; the dial half only looks up the *target's* `name`. No new
records, no clobbering. (Confirmed: `publish_node_id` is called only from
`run_listen`; `run_dial` only calls `lookup_node_id`.)

**State (`src/app_state.rs`).** `AppState.role` is currently a single `Role`. For a
dual-role process this needs to express "both":
- The listen half populates the peer list (`add_peer` / `peers`).
- The dial half owns the outbound tunnel table and `conn_status`.
- Cleanest is to make the *snapshot* carry both views (a serving-peers list and an
  outbound-connection/tunnels view) rather than overloading one `Role`. Options:
  introduce `Role::Both`, or split `AppState` status into independent
  `serve` / `dial` sub-states. Decide during implementation; prefer the smallest
  change that lets the TUI render both panes unambiguously.

**TUI (`src/tui/`).** Today `render_peers` and `render_tunnels` branch on
`snap.role` (`ui.rs:299`, `319`, `351`). For dual-role:
- Always render the **serving-peers** pane (today's `Role::Listen` peer list).
- Always render the **outbound-tunnels** pane (today's `Role::Dial` tunnel table,
  with `a` add / `Enter` start-stop / `x` delete) bound to the single outbound
  connection.
- Keep a focus toggle between the two panes (a `Pane` focus enum, as the earlier
  multi-peer TUI prototyped).
- The dial half's target `name` is entered once (interactively or from config),
  the same way `run_dial` resolves it now.

**Entry point (`src/main.rs`).** Add a way to select dual-role: a TUI setup choice
("Serve and dial") and/or a config/flag. `run_peer_headless` (test mode) can keep
single-role only — dual-role is an interactive convenience and need not complicate
the hermetic test path.

### What stays unchanged

- The per-connection pure-server rule (one requester, one server per connection).
- `[[request]]` semantics (dial-role template) and `[allowed_sources]` gating
  (serve-role allowlist) — a single config already carries both halves.
- nostr discovery, the global `max_streams` cap, and the auth handshake.

### Phasing

1. **Plumbing:** `run_peer_dual` running both halves over a shared `AppState` +
   global semaphore, two endpoints, headless-verifiable (extend test mode minimally
   or cover with a unit/integration test that both a served tunnel and a requested
   tunnel work from one process).
2. **State:** represent dual-role in `AppState`/snapshot without overloading a
   single `Role`.
3. **TUI:** split view with both panes always present + focus toggle; wire the
   add/start/stop/delete actions to the outbound connection.
4. **Entry/setup:** interactive "serve and dial" selection; docs update (move the
   relevant bits from this roadmap into README/ARCHITECTURE once shipped).

### Open questions

- One shared endpoint vs. two — measure relay/hole-punch overhead before
  collapsing.
- How to represent "both roles" in `AppState` with the least churn (`Role::Both`
  vs. split sub-states).
- Whether the dial half should support **multiple** outbound targets from one
  process (N dial connections) or stay single-target for v1. Single-target is the
  smaller step and matches today's `run_dial`.

---

## nostr name collision between listeners (preexisting)

### The problem

nostr discovery keys a listener's published node id by `name`, not by device: the
NIP-78 (kind-30078) `d` tag is `duopipe:nodeid:<sha256("duopipe:peer-id:v1" ||
auth_token || name)>` (`identifier_dtag` in `src/nostr_discovery.rs`). NIP-78 events
are **replaceable** — a relay keeps only the newest event per `(author, d-tag)`. Since
all of a user's devices derive the **same author keypair** from the shared
`auth_token`, two listeners that publish under the **same `name`** map to the same
`(author, d-tag)` and **clobber each other**: the most recent `publish_node_id` wins,
and the republish loop (`spawn_node_id_publisher`, ~every 5 min) makes them fight
indefinitely, each overwriting the other.

A dialer looking up that `name` then resolves to **whichever device published last** —
effectively non-deterministic. CLAUDE.md already calls this out as accepted
("duplicate names just clobber (replaceable, newest wins)"), but it is **silent**: no
warning is shown on either the publishing or the dialing side, so a
copy-paste-the-config-to-a-second-box mistake looks like a flaky/cross-wired tunnel
rather than a name conflict.

Option B does not introduce this — each dual-role process still publishes under its own
single `name` — but it makes a unique name per machine more load-bearing (every box now
also serves), so it is worth resolving.

### Resolution options (sketch)

1. **Detect and warn before/while publishing (lowest cost, recommended first).**
   Before the first `publish_node_id`, look up the `d` tag. If a *recent* event exists
   whose decrypted content is a **different** node id than ours, log a prominent warning
   ("another device appears to be publishing under name `<name>` — names must be unique
   per auth token") and surface it in the TUI header. Re-check on each republish; a
   value that keeps flipping between two node ids is the tell-tale of a live collision.
   Cheap, no protocol change, no false sense of safety — just stops the silent failure.

2. **Embed a device fingerprint in the event content.** Extend the (encrypted) content
   from a bare node id to `{ node_id, instance_id }` where `instance_id` is a random
   per-process value. A listener that sees its own `d` tag carrying a *different*
   `instance_id` knows another device is clobbering it and can warn (as in #1) — more
   robust than comparing node ids, which legitimately change on every restart of the
   *same* device.

3. **Make the record per-device, discovery still by name.** Publish under a `d` tag that
   includes a stable per-device suffix, and have the dialer query the name *prefix* and
   pick among results. This removes the clobber but turns "dial a name" into "dial one
   of N devices under a name" — i.e. it needs a selection/most-recent-wins policy and a
   prefix query. Bigger change; only worth it if multi-device-same-name becomes a
   supported feature rather than a misconfiguration to detect.

4. **Document-only fallback.** Keep the clobber but make the "names must be unique per
   `auth_token`" rule loud in README/`peer.toml.example` and validate that a single
   config file doesn't reuse a name. Weakest option — does nothing for the
   two-separate-configs case, which is the common mistake.

### Recommendation

Start with **#1 (detect + warn)**, optionally backed by **#2**'s `instance_id` so the
detection is reliable across the same device's own restarts. Defer **#3** unless
"several devices reachable under one name" becomes a real product goal.
