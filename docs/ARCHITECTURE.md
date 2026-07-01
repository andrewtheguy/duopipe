# duopipe Architecture

This document provides a comprehensive overview of the duopipe architecture, including detailed diagrams of component interactions, data flows, and security considerations.

## Table of Contents

- [System Overview](#system-overview)
- [Features](#features)
- [iroh Mode Architecture](#iroh-mode-architecture)
- [Configuration System](#configuration-system)
- [Security Model](#security-model)
- [Protocol Support](#protocol-support)
- [Component Details](#component-details)
- [Performance Considerations](#performance-considerations)
- [Error Handling](#error-handling)
- [Capabilities](#capabilities)
- [References](#references)

---

## System Overview

duopipe is a P2P single-TCP-forward tool using iroh for peer discovery, relay fallback, and encrypted QUIC transport. Each dial session carries one TCP forward — groundwork for a future single SOCKS5 listener (modeled on flextunnel). UDP is intentionally out of scope and lives in a separate project (`../tunnel-rs`).

Binary: `duopipe`

> **Design Goal:** The project's primary goal is to let a **single user link their own devices** (laptop, homelab box, VPS, …) to reach services across them — for development or homelab purposes — without the hassle and security risk of opening a port. Both ends are expected to be machines the same person owns (or otherwise fully trusts). It is **not** meant for production setups, multi-user/multi-tenant access, or to be performant at scale. It is meant for **interactive use** (`duopipe quick` / `duopipe run` and the TUI); the non-interactive env-var override is a **test-mode-only** workaround (`DUOPIPE_TEST_MODE=1`), not a supported automation interface.

duopipe runs as a single peer binary, launched in one of two interactive modes — `duopipe quick` (configless) or `duopipe run` (config-driven) — each opening a ratatui TUI. There is no separate "server" and "client" binary mode. Interactively, the dashboard opens **idle**; the user presses **`Shift-L`** to start the **on-demand serve half** (and `Shift-L` again to stop it), and the instance also holds one **on-demand outbound dial session**. Within any one connection the **dialer requests** its single TCP tunnel and the **server side serves** it; once listening, an instance serves many inbound peers at once while dialing out itself. Within a tunnel, traffic flows in both directions.

There is **no role prompt at startup**: the dashboard opens idle and the serve half is started on demand with `Shift-L` (a toggle — `Shift-L` again stops it), while the dial session is driven independently from the TUI (`Shift-C` to connect, `Shift-D` to disconnect, re-pointable on demand) and works even before listening begins. For tests, the role is single and derived from environment variables (see [Non-interactive mode](#non-interactive-mode-testing)). The iroh identity is **ephemeral** — a fresh identity is generated each time the serve half starts, so a stop→start cycle (and every run) mints a new node id.

Internally the interactive runtime is `Role::Both`: a `run_serve_and_dial` that joins a `run_listen_supervisor` (the serve half, started on-demand when the user presses Shift+L — it idles until then) with a `run_dial_manager` (the dial session manager) over a shared `AppState` and stream semaphore. The supervisor brings up `run_listen` under a child cancellation token on a `ListenCommand::Start` and tears it down on `Stop`. The serve half and the dial session use separate iroh endpoints; the listen endpoint owns the displayed/published node id. Single-role `Role::Listen`/`Role::Dial` exist only for the headless test path (and still auto-listen).

Config declares the single **tunnel request** (the dial target is chosen interactively at runtime, not here):

- **`[tunnel]`** (`remote_source`, `local_listen`): the template for the dial session. The dialing side binds a local listener at `local_listen`; each accepted local connection asks the **connected peer** to connect out to `remote_source` (a bare `host:port`), then bridges the two. Activated on demand (TUI `s`, or `DUOPIPE_AUTOSTART_TUNNELS=1` in test mode) — nothing forwards automatically.

#### Non-interactive mode (testing)

The project is meant for interactive use, but for automated tests `DUOPIPE_TEST_MODE=1` runs the peer headless (no TUI) and gates all other test-only env vars:

- `DUOPIPE_TEST_MODE=1` — run headless; required to enable the vars below.
- `DUOPIPE_PEER_NODE_ID=<id>` — when set ⇒ dial that node id; when unset ⇒ listen.
- `DUOPIPE_AUTOSTART_TUNNELS=1` — start the configured `[tunnel]` (dial side) on connect.
- `DUOPIPE_AUTH_TOKEN=<token>` — the shared auth token (in quick mode honored only here in test mode; also valid outside test mode in config mode).

In this mode the listener prints `node_id: <id>` and `auth_token: <token>` to **stderr** so a test harness can capture them and wire up the dialer.

```mermaid
graph TB
    subgraph "duopipe"
        A[iroh]
    end

    subgraph "Use Cases"
        D[Best NAT Traversal<br/>Relay Fallback]
    end

    subgraph "Infrastructure"
        G[Pkarr/DNS<br/>Relay Servers]
    end

    A --> D
    A --> G

    style A fill:#4CAF50
```

Relay-only (`relay_only`) is a config bool that forces connections through relay servers instead of attempting direct connections. It is intended for testing or special scenarios and requires at least one `relay_urls` entry.

### Core Components

```mermaid
graph LR
    subgraph "Core Modules"
        A[main.rs<br/>CLI & orchestration]
        T[tui/<br/>Interactive setup + status]
        B[config.rs<br/>Config loading & validation]
        C[iroh_mode/peer.rs<br/>Symmetric peer runtime]
        C2[net.rs<br/>Address parsing & resolution]
        C3[iroh_mode/helpers.rs<br/>TCP bridging]
        D[iroh_mode/endpoint.rs<br/>iroh endpoint setup]
        E2[auth.rs<br/>Auth token]
        F[signaling/codec.rs<br/>Stream framing & messages]
    end

    A --> T
    A --> B
    A --> C
    A --> E2
    T --> C
    C --> C2
    C --> C3
    C --> D
    C --> E2
    C --> F

    style A fill:#E3F2FD
    style C fill:#E8F5E9
    style E2 fill:#FFCCBC
```

---

## Features

### Feature Summary

```mermaid
graph TD
    subgraph "iroh"
        A1[Discovery: Automatic]
        A2[NAT: Relay Fallback]
        A3[Setup: Minimal - node id required]
        A4[Infrastructure: Required]
    end

    style A1 fill:#C8E6C9
    style A2 fill:#C8E6C9
    style A3 fill:#C8E6C9
    style A4 fill:#FFCCBC
```

### NAT Traversal Capabilities

```mermaid
graph LR
    subgraph "NAT Types"
        A[Full Cone]
        B[Restricted Cone]
        C[Port Restricted]
        D[Symmetric]
    end

    subgraph "iroh"
        E1[✓ Direct/Relay]
        E2[✓ Direct/Relay]
        E3[✓ Direct/Relay]
        E4[✓ Relay]
    end

    A --> E1
    B --> E2
    C --> E3
    D --> E4

    style E1 fill:#C8E6C9
    style E2 fill:#C8E6C9
    style E3 fill:#C8E6C9
    style E4 fill:#C8E6C9
```

---

## iroh Mode Architecture

### Architecture Overview

Both ends run the same interactive peer runtime (`duopipe quick` or `duopipe run`): an on-demand serve half (started with `Shift-L`) plus one on-demand outbound dial session. Within any one connection, the dial session establishes the QUIC connection and **requests** its single tunnel (`[tunnel]`), running the request listener; the connected peer's serve half is a **pure server** for that connection and can serve many inbound dialers at once.

```mermaid
graph TB
    subgraph "Server Side of One Connection"
        A[on-demand serve half]
        B[iroh Endpoint<br/>ephemeral node id]
        C[Accept Loop]
        D[Discovery<br/>Pkarr/DNS]
        E[Relay Server]
    end

    subgraph "Requester Side of One Connection"
        F[on-demand dial session]
        G[iroh Endpoint<br/>ephemeral node id]
        H[Request Listener<br/>for the active tunnel]
        I[Discovery<br/>Pkarr/DNS]
        J[Relay Server]
    end

    A --> B
    B --> C
    B --> D
    B --> E

    F --> G
    G --> H
    G --> I
    G --> J

    B <-.QUIC/TLS, bidirectional streams.-> G
    D <-.Publish/Resolve.-> I
    E <-.Fallback.-> J

    style A fill:#E8F5E9
    style F fill:#E8F5E9
    style B fill:#BBDEFB
    style G fill:#BBDEFB
```

### Connection Establishment Flow

Connection setup is asymmetric (dialer + acceptor), and the tunnel model remains asymmetric for that connection: after auth, the dialer opens request streams for its single tunnel and the listener accepts and bridges them. An interactive process gets bidirectional use by also having its own independent dial session.

```mermaid
sequenceDiagram
    participant L as Listen Peer
    participant SD as Discovery Service
    participant D as Dial Peer
    participant RS as Relay Server

    Note over L: User presses Shift-L; serve half creates ephemeral identity
    L->>L: Create iroh Endpoint
    L->>SD: Publish node id + Addresses
    Note over L: Display node id + token banner/hint in TUI
    L->>RS: Connect to relay
    L->>L: endpoint.accept() loop

    Note over D: User presses Shift-C and enters node id or peer name
    D->>D: Create iroh Endpoint (ephemeral identity)
    D->>SD: Resolve node id or current name record
    SD-->>D: Return addresses
    D->>RS: Connect to relay

    alt Direct Connection Possible
        D->>L: Direct QUIC connection (ALPN: mf/2)
        L-->>D: Accept connection
    else NAT Traversal Failed
        D->>RS: Connect via relay
        RS->>L: Forward connection
        L-->>RS: Accept via relay
        RS-->>D: Relay established
    end

    Note over L,D: Encrypted QUIC tunnel established

    Note over D,L: Authentication Phase (first bi-stream, positional)
    D->>L: open_bi() + AuthRequest {token}
    alt Token Valid
        L-->>D: AuthResponse {accepted: true}
    else Token Invalid
        L-->>D: AuthResponse {accepted: false, reason}
        L->>L: Close connection (error code 1)
    else Auth Timeout
        L->>L: Close connection (error code 2)
    end

    Note over D,L: After auth, the dialer requests its single tunnel
    D->>L: open_bi() + StreamHello::LocalForward{source}
    L-->>D: StreamAck + bridged traffic, or rejection
```

### Stream Dispatch (StreamHello)

The **auth stream is the only stream that does not carry a hello** — it is positional (the first bi-stream the dialer opens). Every *other* bidirectional stream begins with a self-describing [`StreamHello`] frame written by the stream **opener**, so the **acceptor** can route it without positional assumptions. There is now a single non-auth stream kind: `StreamHello::LocalForward { source }`, a tunnel request.

```mermaid
graph TB
    A[accept_bi: new stream] --> B[Read StreamHello<br/>HELLO_TIMEOUT 10s]
    B --> C{LocalForward source}

    C --> D[Acquire session permit]
    D --> E[Connect out to source over TCP<br/>bare host:port]
    E --> F[Reply StreamAck, bridge]

    style B fill:#FFF9C4
    style F fill:#C8E6C9
```

A single global `Semaphore` (default `max_streams = 100`), shared across all connected peers, bounds concurrent forwarded **data** streams in both directions (surfaced in the TUI as the `streams` gauge). The auth stream does not consume a permit. A timeout (`HELLO_TIMEOUT`) guards the `StreamHello` read so a stalled opener cannot pin a permit. If the limit is reached the acceptor replies with a rejecting `StreamAck` instead of bridging.

### Request Data Flow

A peer activates its request: it binds the local `local_listen` address and, per incoming connection, opens a stream tagged `StreamHello::LocalForward { source }`. The acceptor connects out over TCP to `source` (a bare `host:port`), replies `StreamAck`, then bridges. The request starts/stops on demand (TUI `s`/`x`, or `DUOPIPE_AUTOSTART_TUNNELS=1` in test mode); stopping it cancels its task and frees the bound port.

```mermaid
sequenceDiagram
    participant App as Local App
    participant O as Requester (binds listen)
    participant P as Peer (acceptor)
    participant T as Source Service

    App->>O: connect to local listener
    O->>P: open_bi() + StreamHello::LocalForward{source}
    alt connect ok
        P->>T: connect out to source
        P-->>O: StreamAck{accepted: true}
        Note over O,P: bridge_streams() copies both directions
    else connect failed
        P-->>O: StreamAck{accepted: false, reason}
    end
```

The request's listener is owned by a task with its own `CancellationToken`; a `Stop` command (or the connection closing) cancels it, dropping the `TcpListener` and aborting in-flight bridged connections, which frees the bound port.

### TCP Tunnel Data Flow

TCP bridging uses `bridge_streams()` (`iroh_mode/helpers.rs`). The "opener" is the requesting peer that accepted the local connection; the "connect side" is the peer that dials the source.

```mermaid
graph LR
    subgraph "Opener Side"
        A[TCP Client] -->|connect| B[Listen Socket]
        B -->|accept| C[TCP Stream]
        C -->|StreamHello + read| E[iroh SendStream]
    end

    subgraph "QUIC Transport"
        E <-->|encrypted| F[iroh RecvStream]
    end

    subgraph "Connect Side"
        F -->|read StreamHello| G[Route + connect]
        G -->|connect| I[Target Service]
        I -->|response| H[TCP Stream]
        H -->|write| K[iroh SendStream]
    end

    subgraph "Return Path"
        K <-->|encrypted| L[iroh RecvStream]
        L -->|write| C
        C -->|send| A
    end

    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style K fill:#BBDEFB
    style L fill:#BBDEFB
```

### Endpoint Management

Both the listen peer (`create_server_endpoint`) and the dial peer (`create_client_endpoint`) build their `iroh::Endpoint` through the same `create_endpoint_builder`, which configures QUIC transport tuning, relay mode, and discovery. Neither role provides a secret key — iroh generates a fresh ephemeral identity on every run, so the node id changes each run.

```mermaid
graph TB
    subgraph "Endpoint Creation"
        A[Generate ephemeral identity] --> B[Create Endpoint Builder]
        B --> B2[QUIC transport config:<br/>idle timeout 300s,<br/>keep-alive 15s,<br/>cc + window sizes]
        B2 --> C{Relay URLs?}
        C -->|Yes| D[Add Custom Relays]
        C -->|No| E[Use Default Relays]
        D --> F{Relay Only? (config bool)}
        E --> F
        F -->|Yes| G[clear_ip_transports]
        F -->|No| H[Keep IP + relay transports]
        G --> I{DNS Server?}
        H --> I
        I -->|none| J2[Disable DNS discovery]
        I -->|custom| J[Add Pkarr publisher/resolver]
        I -->|default| K[n0 Pkarr + DNS]
        J --> L[Add mDNS + Build]
        J2 --> L
        K --> L
    end

    subgraph "Discovery"
        L --> M[Publish to Pkarr/DNS]
        M --> N[Wait for endpoint online]
        N --> O[Endpoint Ready]
    end

    style A fill:#C8E6C9
    style L fill:#C8E6C9
    style O fill:#C8E6C9
```

---

## Configuration System

A single, symmetric `PeerConfig` drives both halves of an interactive peer. There is no `role` key and no `connect` key: interactive runs always use the single combined serve+dial runtime, and the outbound dial target is chosen later from the dashboard. Only headless test mode derives a single listen/dial role from environment variables.

### Configuration File Structure

```mermaid
graph TB
    subgraph "Config File"
        A[peer.toml]
    end

    subgraph "Options"
        E[auth_token_file — path to the single shared token<br/>auth_token_fingerprint — required in config mode]
        G[tunnel {remote_source, local_listen}]
        H[max_streams]
        I[relay_urls / relay_only / dns_server]
        J[transport<br/>cc + window sizes]
        K[name — peer identifier for nostr<br/>nostr_relay_urls]
    end

    A --> S[Validation]
    S --> E
    S --> G
    S --> H
    S --> I
    S --> J
    S --> K

    style S fill:#FFF9C4
```

The outbound dial target is not a config field. In interactive mode it is entered at runtime from the connect prompt (`Shift-C`): a node id in quick mode or a peer `name` in config mode. In headless test mode only, `DUOPIPE_PEER_NODE_ID` under `DUOPIPE_TEST_MODE=1` selects the single role (set ⇒ dial, unset ⇒ listen).

### iroh Credential Mapping

`iroh` mode uses a **single** shared credential, the auth token — except quick **PIN** mode, which has no token and instead authenticates each connection with an in-band PIN challenge-response (see [Quick-mode PIN rendezvous](#quick-mode-pin-rendezvous)). The ALPN is a fixed constant (`mf/2`) and carries no credential.

| Credential | Env Var | Config Key | Expected Usage |
|------------|---------|-------------|----------------|
| **Auth Token** | `DUOPIPE_AUTH_TOKEN` | `auth_token_file` | Connection-level credential validated on the first bi-stream. Both peers use the **same** token: the dial peer **presents** it, the listen peer **accepts** exactly that one value. Also the rendezvous secret for nostr node-id discovery. |

Token precedence is `DUOPIPE_AUTH_TOKEN` (env) > config `auth_token_file`. A file token is never written inline in the config. **Quick mode** takes no existing-token input (`DUOPIPE_AUTH_TOKEN` is honored only in test mode, where the headless dial side needs it): its **manual** signaling generates a fresh ephemeral token in the setup screen, while its **PIN** signaling uses **no token at all** (the PIN authenticates the connection in-band). The generated token is surfaced in the dashboard header for copying in quick **manual** mode once the user starts listening (`Shift-L`); in quick **PIN** mode the token is never shown or shared — the PIN authenticates the connection in-band instead (see [Quick-mode PIN rendezvous](#quick-mode-pin-rendezvous)). **Config mode** accepts a token from config/env or pasted at setup (validated against its CRC before acceptance), since it is the pre-shared rendezvous secret both peers derive their key from and must be generated ahead of time (`duopipe generate-auth-token`); `auth_token_file` is therefore optional there too — only a `name` and `auth_token_fingerprint` are mandatory.

The TUI displays a short **token fingerprint** — `auth::token_fingerprint`, the first 4 bytes of the token string's SHA-256 rendered as 8 lowercase hex digits — in the header once the serve half is listening (gated on `snap.listening`) and in the `w`-dump. Because the full token is shown only briefly (and never on the dial side), the fingerprint lets the user confirm two devices share the same token without re-revealing the secret. The same canonical form also namespaces the per-name local state/lock file (`peer_state`): its path is `state-<fingerprint>-<name>.json`, with the `name` used verbatim (safe because `config::validate_name` restricts it to ASCII letters, digits, and `_`), so different pairings (tokens) that share a `name` get distinct, human-readable state files.

**Fingerprint pinning (config mode):** a config-mode config must declare `auth_token_fingerprint` (the same 8-hex-digit value) regardless of whether the token itself is in the config. The resolved token — from config, env, or pasted at setup — is checked against it (`auth::fingerprint_matches`): a file/env token is verified in `main::resolve_expected_fingerprint` before the TUI launches (a mismatch is a plain config error), and a pasted token is verified in the setup screen (`submit_token`). This disambiguates configs meant for different pairings, so pointing a config at the wrong token file is caught up front instead of failing as an auth error on connect. Quick mode declares no fingerprint.

```toml
# peer.toml
auth_token_file = "/etc/duopipe/auth_token.txt"
auth_token_fingerprint = "a1b2c3d4"   # required in config mode; must match the token above

[tunnel]
remote_source = "127.0.0.1:22"
local_listen = "127.0.0.1:2222"
```

### Configuration Loading Flow

Config files are read by `duopipe run` and use TOML — settings are saved and reusable. The default path is `~/.config/duopipe/peer.toml`; `-c <path>` overrides it. `duopipe quick` reads no config and takes no options: it always generates its own token, and the dial target is entered interactively.

```mermaid
sequenceDiagram
    participant CLI as CLI Parser
    participant Main as Main
    participant Config as Config Module
    participant Source as Config Source (file)

    CLI->>Main: Parse arguments

    alt duopipe run (no -c)
        Main->>Config: Load from default path
        Config->>Source: Read ~/.config/duopipe/peer.toml
        Source-->>Config: TOML content
    else duopipe run -c <path>
        Main->>Config: Load from specified path
        Config->>Source: Read file
        Source-->>Config: TOML content
    else duopipe quick
        Main->>Main: Setup screen (no config/options); manual mode generates a token, PIN mode uses none
    end

    alt Config loaded
        Config->>Config: Parse TOML
        Config->>Config: Validate structure and address formats
        Config-->>Main: Validated config
        Main->>Main: Apply env overrides (DUOPIPE_AUTH_TOKEN wins)
    end

    Main->>Main: Launch idle TUI; listen starts on Shift-L, dial target entered later
```

### Config Validation

```mermaid
graph TB
    A[Load Config] --> F{Check fields}

    F --> I{Request address valid?}

    I -->|No| J[Error: bad request address]
    I -->|Yes| K[Validation Success]

    style J fill:#FFCCBC
    style K fill:#C8E6C9
```

---

## Security Model

### Encryption Stack

```mermaid
graph TB
    subgraph "Application Data"
        A[TCP Payload]
    end
    
    subgraph "QUIC Layer"
        B[QUIC Stream Encryption]
        C[TLS 1.3]
        D[Per-Stream Keys]
    end
    
    subgraph "Transport"
        E[QUIC Packets]
        F[Authenticated Encryption]
    end
    
    subgraph "Network"
        G[UDP Datagrams]
    end
    
    A --> B
    B --> C
    C --> D
    D --> E
    E --> F
    F --> G
    
    style C fill:#C8E6C9
    style D fill:#C8E6C9
    style F fill:#C8E6C9
```

### Identity and Authentication

```mermaid
graph TB
    subgraph "iroh Mode"
        A[Ephemeral Ed25519 identity<br/>regenerated each run] --> C[node id - Public Key]
        C --> D[Dial Peer Connects<br/>fixed ALPN mf/2]
        D --> E[Auth Token Validation]
        E --> F{Valid Token?}
        F -->|Yes| G[Authenticated<br/>requests served (peer trusted)]
        F -->|No| H[Rejected]
    end

    style A fill:#FFE0B2
    style C fill:#C8E6C9
    style G fill:#C8E6C9
    style H fill:#FFCCBC
```

### Trust Model

**Your own devices, coordinated out-of-band.** duopipe is built for **one person linking devices they own** (laptop ↔ homelab box ↔ VPS) — not a public service or multi-tenant gateway. (Two parties who fully trust each other can use it too, but that is not the primary design point.) Several design choices follow directly from this assumption:

- **Out-of-band credential exchange.** The shared auth token is the same value placed on each of your devices, moved over a side channel you already have (a password manager, an existing SSH session, a synced secrets store). The ephemeral node id changes every run, but it no longer needs hand-copying: it is published to and looked up from nostr, keyed off that same shared token (see [Node-id discovery](#node-id-discovery-nostr)).
- **Interactive, operator-driven runtime.** Each device runs the TUI and watches shared status — connection state, connected peers, and tunnel health — and starts/stops its tunnel manually. Coordination of *what* to expose and *when* is done by you (one person across your screens), not automatically.
- **Trust assumed between your devices.** Because the dialer can *request* a tunnel of the listener once authenticated, the token should only ever live on endpoints you control. Once the shared auth token passes, the connected peer is **fully trusted**: the acceptor will connect out to **any `host:port`** it requests. Security rests **solely** on the shared token plus the interactive activation.

**Multiple peers, no session binding (serve half).** The serve half accepts **many concurrent dialers** over its one iroh endpoint; authentication is the only gate. Each authenticated connection is served independently and shown as a row in the TUI peer list (`AppState::add_peer` / `remove_peer`). There is no sticky single-peer binding and no fatal "wrong peer" rejection — different node ids are all admitted. Because each dialer is a separate process binding its own local ports, N dialers can request the same listener source at once with no conflict; the listener simply makes N independent outbound connects. A brief duplicate connection from the same node id (a reconnect overlap) is de-duplicated in the peer list rather than rejected.

**Dialer requests, listener serves.** Connection setup is asymmetric, and so is the tunnel model: the **dialer** initiates its single tunnel, while the **listener is a pure server** — it runs only the acceptor loop and initiates none of its own (with many peers there would be no single connection a request could bind to). A request asks the listener to connect out to a `source`; once the connection has authenticated, the listener connects out to whatever `host:port` the peer requests — the authenticated peer is fully trusted. The tunnel is activated on demand from the dialer's TUI; nothing forwards until started. To reach a service that lives near the *other* box, dial *from* the box that wants to reach it — every node can dial on demand. Only grant a peer the token if you trust it to reach any host this machine can route to.

### Token Authentication (iroh Mode)

Access control rests on a single shared auth token. The ALPN is a fixed constant (`mf/2`) and carries no credential. After the QUIC/TLS handshake, the dialing peer must present a valid auth token on the **first bidirectional stream** (positional — this auth stream is the only stream that carries no `StreamHello`) within a 10-second timeout.

#### Auth Token

- **Auth Token** (`DUOPIPE_AUTH_TOKEN` env var / `auth_token_file`): A single shared connection-level token, validated on the first bi-stream. Both peers use the **same** value. In code it is a 47-char `i...` token.

1. **Listen Peer Configuration**: The listen peer is configured with the shared auth token (or, in configless manual mode, generates an ephemeral one and displays it in the TUI; configless **PIN** mode uses no token — the PIN authenticates the connection in-band).
2. **Dial Peer Configuration**: The dial peer is configured with — or interactively prompted for — the same shared token.
3. **Protocol Flow**: The dialer opens the first bidirectional stream and sends an `AuthRequest` positionally (no hello). **No tunnel streams are processed until authentication succeeds.**
4. **Validation**: The listen peer validates the presented token against its single accepted token within a 10-second timeout (`auth_as_listener`).
5. **Rejection**: An invalid token is rejected with an `AuthResponse` containing the rejection reason, and the connection is closed with an error code.

This validation prevents unauthorized peers from holding open connections or opening tunnel streams.

```mermaid
sequenceDiagram
    participant D as Dial Peer
    participant L as Listen Peer
    participant A as Auth Module

    D->>L: Connect (QUIC TLS handshake, ALPN: mf/2 fixed)
    L->>D: Accept connection

    Note over D,L: Auth Phase (10s timeout, first bi-stream)
    D->>L: open_bi() + AuthRequest {version, auth_token}
    L->>A: validate against shared auth token
    alt Token is valid
        A-->>L: true
        L->>D: AuthResponse {accepted: true}
        Note over L,D: Connection authenticated — requests served (peer trusted)
    else Token is invalid
        A-->>L: false
        L->>D: AuthResponse {accepted: false, reason}
        L->>L: Close connection (error code 1)
        Note over L,D: Connection closed with rejection
    else Timeout (no auth within 10s)
        L->>L: Close connection (error code 2)
        Note over L,D: Connection closed (auth timeout)
    end

    Note over D,L: After auth, dialer opens StreamHello-tagged request streams
```

### Token Security Notes (iroh Mode)

- The token is a **bearer credential**: possession is sufficient for access. Rotate it if exposure is suspected.
- Token strength comes from **randomness, not format**: 32 random bytes (256 bits of entropy). Treat the token like a high‑entropy secret.
- The token is sent only **after** the QUIC/TLS 1.3 handshake, so the auth stream is encrypted in transit.
- The CRC16-CCITT-FALSE checksum is **for typo detection only**, not cryptographic security.
- The token is Base64URL-encoded and validated as ASCII.
- Avoid logging or sharing the token; the `AuthToken` wrapper redacts values in Debug output, but treat it like a password.
- Prefer a token file with restricted permissions (e.g., `0600`).

### Threat Model

```mermaid
graph TB
    subgraph "Protected Against"
        A[Eavesdropping<br/>TLS 1.3 encryption]
        B[MITM<br/>Peer authentication]
        C[Replay Attacks<br/>QUIC nonces]
        D[Tampering<br/>Authenticated encryption]
        E2[Unauthorized Access<br/>Shared Token Authentication]
    end

    subgraph "User Responsibility"
        G[node id Verification<br/>Trust on first use]
        H[Auth Token Security<br/>Treat the token like a password]
    end

    style A fill:#C8E6C9
    style B fill:#C8E6C9
    style C fill:#C8E6C9
    style D fill:#C8E6C9
    style E2 fill:#C8E6C9

    style G fill:#FFF9C4
    style H fill:#FFF9C4
```

### Identity Management

The iroh identity is **ephemeral**: iroh generates a fresh Ed25519 keypair each time the serve half starts (the user presses `Shift-L`), so there is no key file to store or protect. The consequence is that the **listen peer's node id changes on every run — and on every stop→start cycle** (the TUI displays the current node id once listening). This avoids same-machine locking that could otherwise produce duplicate node ids. Instead of re-copying the node id by hand, peers discover it via nostr (below).

```mermaid
sequenceDiagram
    participant User as User
    participant TUI as TUI
    participant EP as iroh Endpoint

    Note over EP: No key file — fresh identity each time listening starts
    User->>TUI: duopipe quick/connect, then press Shift-L to listen
    TUI->>EP: Create endpoint (ephemeral identity)
    EP->>EP: Derive node id from fresh keypair
    EP-->>TUI: node id
    TUI->>User: Display node id + generated-token banner or loaded-token hint
```

### Node-id discovery (nostr)

Because the node id is ephemeral, **config mode** (active whenever a config file is loaded) uses **nostr** as a side channel so the dialer can find the listener's *current* node id without a manual exchange. Configless **quick** mode offers two signaling choices at setup: a rotating **PIN** over nostr (see [Quick-mode PIN rendezvous](#quick-mode-pin-rendezvous) below) or **manual** copy-paste with nostr off (the dialer enters the node id by hand). The name-based discovery here is config mode's; it is implemented in `nostr_discovery.rs`:

- **Shared author key from the auth token.** Both peers derive the same nostr *author* keypair via `sha256("duopipe:nostr-rendezvous:v1" || auth_token)`. The token both sides share *is* the rendezvous, so discovery only works when it's shared (which the dialer needs anyway, for auth).
- **Per-peer `d` tag from the `name`.** Each peer is distinguished by its `name`: the `d` tag is `duopipe:nodeid:<sha256("duopipe:peer-id:v1" || auth_token || name)>` (`identifier_dtag`). Salting the hash with the auth token stops a short, low-entropy name from being guessed or enumerated on relays. Several peers can share one auth token and stay individually addressable; duplicate names just clobber (replaceable, newest wins).
- **Publish (listener).** `run_listen` spawns a background task that publishes a replaceable event (NIP-78 kind 30078, `d` tag = this peer's name tag, content = the current node id string) at startup and refreshes it every ~5 minutes. Relay failures are logged but non-fatal. Because the `d` tag is keyed on the stable name, a restart replaces the peer's own record — no stale accumulation.
- **Lookup on demand (dialer).** A nostr-mode dialer types the *target's* `name`; `run_dial` resolves it (filter by author = derived pubkey + kind + name's `d` tag, newest wins) at the top of *every* connect attempt, so a listener that restarted with a fresh node id self-heals on the next attempt. No persistent subscription.
- **Encrypted content.** The node id is encrypted (NIP-44) under the shared auth-token-derived keypair — self-encryption to the listener's own derived public key, so any peer with the same auth token derives the same key to decrypt — keeping it off relays in the clear. The auth token still gates the actual connection. Relays default to `DEFAULT_NOSTR_RELAYS`, overridable via `nostr_relay_urls`. To dial a raw node id without nostr, use quick mode.

Hermetic tests bypass nostr entirely: when `DUOPIPE_PEER_NODE_ID` is set the dialer dials that id directly, so the test suite needs no live relays.

### Quick-mode PIN rendezvous

Quick mode shares its **ephemeral node id** through nostr with no copy-paste, via a short rotating **PIN** — and the PIN then **authenticates the connection in-band**, so the auth token never touches a relay. Unlike config-mode discovery (keyed off the shared auth token), here the dialer starts with nothing but the PIN. PIN format/KDFs live in `pin.rs`; the relay record in `nostr_discovery.rs`; the in-band challenge-response in `pin_auth.rs`.

There are two independent PIN-derived keys, both Argon2id (64 MiB, t=3) over the canonical PIN but domain-separated by salt (`pin::derive_key_material` vs `pin::derive_auth_key_material`): a **rendezvous** key (salt includes the bucket) that locates & decrypts the relay record, and an **auth** key (`"duopipe:pin-auth:v1"`, **no** bucket) that seals the in-band proofs. The auth key is bucket-independent so the dialer derives it from the typed PIN without knowing the listener's bucket.

- **PIN format.** 8 Crockford-base32 characters (alphabet `0-9A-Z` minus the ambiguous `I L O U`), displayed UPPERCASE and grouped `XXXX-XXXX`. Input is normalized case-insensitively and ignores dashes/spaces (mapping the look-alikes `I`/`L`→`1`, `O`→`0`). The trailing character is a **check digit** — a position-weighted sum of the preceding chars mod 32 (mirroring `../secure-send-web`) — verified in `normalize_pin` so a typo is rejected before any KDF/lookup; the check digit adds no secrecy, leaving 7 random data characters (~35 bits). A fresh random PIN is minted per 60-second bucket.
- **Publish (listener).** When quick PIN mode is selected, `run_listen` spawns `run_pin_publisher`: each 60-second bucket it generates a PIN, sets it (plus the rollover deadline) on `AppState` for the header's refresh countdown, derives that PIN's auth key into a small **recent-PIN cache** (last `RECENT_PIN_CACHE = 3` buckets, shared with the listener auth path), and publishes a **regular (stored, non-replaceable) event** — kind `9421`, NIP-44-encrypted `{node_id}` content (node id only, **no token**), with a NIP-40 `expiration` a few buckets out so per-bucket records coexist for boundary look-back then self-clean. The lookup key is the **author pubkey** (only a holder of the PIN can derive it); no extra tag is needed. A different kind from config mode's replaceable 30078 is used deliberately so each bucket's record persists.
- **Display.** The PIN banner is shown like the manual-mode token banner: it **auto-hides after 10 minutes** (the header shows the absolute clock time it will hide), `h` toggles it off/on (re-showing re-arms the timer), and it hides once on the first inbound peer connect. The publisher keeps rotating in the background while hidden, so toggling back on shows the *current* PIN.
- **Lookup on demand (dialer).** A `DialTarget::Pin` resolves in the dial session: `lookup_pin_record` derives the rendezvous keypair for the current bucket and its two neighbors (covering the rotation boundary and small clock skew), queries all of them by author in one round-trip, then NIP-44-decrypts the newest matching record to the **node id** (no token).
- **In-band auth (`pin_auth.rs`).** After dialing that node id, both peers prove PIN possession on the first bi stream, using the same framing as token auth but a `AuthRequest::Pin` method: `D→L nonce_d`, `L→D nonce_l`, `D→L proof_d`, `L→D {accepted, proof_l}`. Each `proof` is a NIP-44 self-seal, under the PIN auth key, of `domain | direction | nonce_d | nonce_l`; a wrong PIN yields a wrong key and the seal fails to open (verified constant-time). The listener tries each recent-bucket key (so a code read just before a rotation still authenticates); the dialer verifies the listener's proof, giving **mutual** authentication. `auth_as_dialer_pin` / the `AuthRequest::Pin` arm of `auth_as_listener` wire this into `handle_connection` via the `AuthMode` enum; failures are `ErrorCategory::Auth` (fatal for the target, like a bad token). Nothing offline-crackable crosses the wire — the proofs are AEAD over random nonces on a channel iroh already encrypts and binds to the node id, so no PAKE is needed.
- **Trust.** The only thing on relays is the ephemeral node id (encrypted under the rendezvous key); the token is **never** published. Cracking a captured record's short (~35-bit) PIN past Argon2id yields only an already-rotated node id, not a reusable credential. Anyone who reads the current PIN *within its window* can still connect, so share it only with your own device. The 60-second rotation, short record TTL, and Argon2id cost bound the window; raising PIN length or KDF parameters tightens it further.

#### Future work (Option A): in-band token / device pairing

The in-band handshake above yields a channel that is both confidential (QUIC/TLS) and mutually PIN-authenticated — the natural place to *pair* devices. A future extension could, once that handshake succeeds, transmit the user's long-lived cross-device auth token (or other bootstrap material) over this same stream so the dialer can persist it — analogous to how `../secure-send-web` sends **file content** over its PIN/ECDH-established channel. Critically the token would travel only over the authenticated in-band channel and **never** touch a relay. Not implemented today: quick mode authenticates the session with the PIN and persists no token.

The PIN crypto round-trips and the full challenge-response handshake are unit-tested offline (`pin.rs`, `pin_auth.rs`, `nostr_discovery.rs`); no live-relay tests.

---

## Protocol Support

### Signaling Protocol (signaling/codec.rs)

The signaling protocol is `IROH_MULTI_VERSION = 6`. All control messages are **length-prefixed JSON**: a `u32` big-endian length followed by the JSON body (capped at 16 KB). Each message embeds a `version` field that is validated on decode.

| Message | Direction | Carried On | Purpose |
|---------|-----------|------------|---------|
| `AuthRequest` / `AuthResponse` | dialer → listener / reply | first bi-stream (positional, no hello) | Connection-level token auth. |
| `StreamHello::LocalForward { source }` | requester → acceptor | first frame of a request data stream | Asks the acceptor to connect out over TCP to `source` (a bare `host:port`) and bridge. |
| `StreamAck { accepted, reason }` | acceptor → requester | per data stream | Acceptance reply once the acceptor connects out (or fails). |

### TCP Tunneling Architecture

```mermaid
graph TB
    subgraph "Opener Side (accepts local conn)"
        A[Listen Socket] --> B[Accept Connection]
        B --> C[TCP Stream]
        C --> D[Open bi-stream + StreamHello]
    end

    subgraph "QUIC Tunnel"
        E[Bi-Stream]
        F[Send Stream]
        G[Recv Stream]
    end

    subgraph "Connect Side (dials target)"
        H[Read StreamHello]
        I[Connect out to source]
        J[StreamAck + Async Read/Write]
    end
    
    D --> E
    E --> F
    E --> G
    
    F --> H
    H --> I
    I --> J
    G --> D
    
    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style G fill:#BBDEFB
```

---

## Component Details

### Endpoint (iroh)

The `iroh::Endpoint` provides:

- **Discovery**: Automatic peer discovery via Pkarr/DNS/mDNS
- **Relay**: Fallback relay servers for NAT traversal
- **QUIC**: Built-in QUIC transport with hole punching
- **Identity**: Ephemeral Ed25519 peer identity, regenerated each run

### Peer Runtime (iroh_mode/peer.rs)

`run_peer(crate::iroh_mode::PeerConfig)` is the single runtime entry point. The TOML `crate::config::PeerConfig` has no serialized role; runtime `Role` is synthesized before this point by `ResolvedPeer`: interactive setup always builds `Role::Both`, while headless test mode infers `Role::Dial` when `DUOPIPE_PEER_NODE_ID` is present and `Role::Listen` otherwise. `build_peer_config` / `run_peer_headless` copy that synthesized role into the runtime config. Inside `run_peer`, that runtime role selects `run_serve_and_dial`, `run_listen`, or `run_dial`. The ALPN is the fixed `ALPN` constant.

- `run_listen` — `create_server_endpoint`, then an `endpoint.accept()` loop spawning `handle_connection(.., is_dialer = false)`. When `announce_endpoint` is set (non-interactive mode) it prints `node_id:` and `auth_token:` to stderr.
- `run_dial_manager` — interactive-only manager for the single outbound session. It reuses one client endpoint, idles until a `DialCommand::Connect`, and replaces or disconnects the active session on dashboard commands.
- `run_dial` — headless test path for a fixed target: `create_client_endpoint` + `connect_to_server`, wrapped in a reconnect loop with exponential backoff (capped at 30s). Auth failures are fatal and stop the loop.

`handle_connection` authenticates (`auth_as_dialer` / `auth_as_listener`), then runs an `accept_loop` (incoming requests from the peer, each then connects out over TCP — the peer is trusted post-auth — capped by the global semaphore). The **dialer** additionally drives its single tunnel (`run_tunnel`), starting/stopping it on `TunnelCommand`s from the TUI under a `CancellationToken`; the **listener** runs only the acceptor (it is a pure server). In test mode, `DUOPIPE_AUTOSTART_TUNNELS=1` starts the dial-side tunnel on connect. Everything is torn down when `conn.closed()` resolves; the listener also drops the peer from its list.

---

## Performance Considerations

### Connection Establishment Times

> **Note:** These are illustrative, environment-dependent ranges (network conditions, NAT type, relay availability, and DNS). Treat as rough guidance, not guarantees.

```mermaid
graph LR
    subgraph "iroh"
        A[Discovery: 1-3s]
        B[Connection: 0.5-2s]
        C[Total: 1.5-5s]
    end

    style C fill:#FFF9C4
```

### Throughput Characteristics

- **TCP Tunneling**: Limited by QUIC stream flow control and congestion control
- **Relay Mode**: Higher latency, potentially lower throughput
- **Direct Mode**: Near-native performance with encryption overhead
- **Concurrency**: A single global semaphore caps concurrent forwarded data streams (`max_streams`, default 100) across both directions and all connected peers.

---

## Error Handling

### Connection Failures

```mermaid
graph TB
    A[Connection Attempt] --> B{Success?}
    B -->|Yes| C[Established]
    B -->|No| E{Relay available?}

    E -->|Yes| F[Fallback to relay]
    E -->|No| G[Connection failed]

    F --> C

    style C fill:#C8E6C9
    style F fill:#FFF9C4
    style G fill:#FFCCBC
```

### Exit Codes

The peer process uses categorized exit codes so wrapper scripts can distinguish
transient failures (retry) from permanent errors (stop). Note that the dial peer
has its own internal reconnect loop; the process only exits on fatal errors.

| Code | Category | Examples |
|------|----------|---------|
| 0 | Success | Normal termination |
| 1 | General error | Unexpected/uncategorized failures |
| 2 | Configuration | Missing/invalid node id, invalid token format, bad request address |
| 3 | Authentication | Token rejected by peer, auth response timeout |
| 10 | Connection failed | Relay timeout, endpoint offline, peer unreachable |
| 11 | Connection lost | QUIC connection closed after tunnel was established |

Retry guidance:

- **Code 1** — Ambiguous. Retry a limited number of times with backoff; escalate if the error persists.
- **Codes 2, 3** — Do not retry. These require human intervention (fix config or credentials).
- **Code 10** — Connection establishment failed. Retry only if the tunnel has previously connected successfully.
- **Code 11** — Connection lost after the tunnel was working. Always safe to retry.

### Stream Errors

- **TCP**: Connection reset, timeout → close QUIC stream
- **QUIC**: Stream reset → close local TCP connection
- **Session limit reached**: acceptor replies with a rejecting `StreamAck`; opener-side TCP connections are dropped.

---

## Capabilities

| Feature | Support |
|---------|---------|
| Bidirectional tunnel | **Yes** — the dialer requests its single TCP tunnel; the listener serves it, and the tunnel carries traffic both ways |
| Multi-Stream | **Yes** — many concurrent forwarded data streams per connection (`max_streams`) |
| Single TCP forward | **Yes** — one `[tunnel]` (`remote_source` / `local_listen`) per dial session; groundwork for a future single SOCKS5 listener |
| UDP forwarding | **No** — intentionally out of scope; lives in a separate project (`../tunnel-rs`) |
| Encryption | QUIC/TLS 1.3 |
| Platform | Linux, macOS, Windows |

---

## References

- [iroh Documentation](https://iroh.computer/)
- [RFC 9000 - QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
</content>
</invoke>
