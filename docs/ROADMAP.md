# Roadmap

Planned work, with enough design detail to start implementation. Items here are
not yet built; the current behavior is described in [README.md](../README.md) and
[ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Option B — single dual-role process (serve + dial on demand)

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
