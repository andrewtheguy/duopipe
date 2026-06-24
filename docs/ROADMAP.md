# Roadmap

Planned work, with enough design detail to start implementation. Items here are
not yet built; the current behavior is described in [README.md](../README.md) and
[ARCHITECTURE.md](./ARCHITECTURE.md).

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

The dual-role mode (serve + dial in one process) does not introduce this — each process
still publishes under its own single `name` — but it makes a unique name per machine more
load-bearing (every box now also serves), so it is worth resolving.

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
