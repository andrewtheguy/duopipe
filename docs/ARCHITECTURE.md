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

duopipe is a P2P TCP/UDP port forwarding tool using iroh for peer discovery, relay fallback, and encrypted QUIC transport.

Binary: `duopipe`

> **Design Goal:** The project's primary goal is to provide a convenient way to connect to different networks for development or homelab purposes without the hassle and security risk of opening a port. It is **not** meant for production setups or designed to be performant at scale.

duopipe runs as a single, **symmetric peer**: `duopipe peer`, which launches an interactive ratatui TUI. There is no separate "server" and "client" binary mode. Connection *setup* is asymmetric — QUIC needs one side to dial and the other to accept — but once a connection exists, **either side can open streams**, so tunnels flow in **both directions** over the one connection.

The role is chosen **at startup**: the TUI asks "Connect to an existing instance?" (or, for tests, the role is derived from environment variables — see [Non-interactive mode](#non-interactive-mode-testing)). The iroh identity is **ephemeral** — a fresh identity is generated on every run, so the listener's node id changes each run.

- The **listen peer** (answers "no") generates an ephemeral identity and calls `endpoint.accept()` in a loop. The TUI shows its node id and the shared auth token.
- The **dial peer** (answers "yes") is given the listener's node id and connects to it, with an automatic reconnect loop (exponential backoff, capped).

Each peer can declare:

- **Local forwards** (`-L LISTEN=DEST`): this peer binds a local listener; each accepted connection is forwarded to a destination the *other* peer connects out to.
- **Remote forwards** (`-R BIND=DEST`): this peer asks the *other* peer to bind a listener and forward connections back to a destination *this* peer connects out to.

#### Non-interactive mode (testing)

The project is meant for interactive use, but the TUI prompts can be bypassed for automated tests:

- `DUOPIPE_NONINTERACTIVE=1` — skip the interactive prompts.
- `DUOPIPE_PEER_NODE_ID=<id>` — when set ⇒ dial that node id; when unset ⇒ listen.
- `DUOPIPE_AUTH_TOKEN=<token>` — the shared auth token.

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
        C3[iroh_mode/helpers.rs<br/>TCP/UDP bridging]
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

Both ends run the same `duopipe peer` runtime. The only asymmetry is who establishes the QUIC connection. Once authenticated, each peer runs **both** an accept-streams loop *and* its own outbound listeners, so local forwards (`-L`) and remote forwards (`-R`) declared on either side all multiplex over the single connection.

```mermaid
graph TB
    subgraph "Listen Peer"
        A[duopipe peer<br/>answered no]
        B[iroh Endpoint<br/>ephemeral node id]
        C[Accept Loop +<br/>Local/Remote Forwards]
        D[Discovery<br/>Pkarr/DNS]
        E[Relay Server]
    end

    subgraph "Dial Peer"
        F[duopipe peer<br/>answered yes]
        G[iroh Endpoint<br/>ephemeral node id]
        H[Accept Loop +<br/>Local/Remote Forwards]
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

Connection setup is asymmetric (dialer + acceptor), but authentication is the *only* phase that distinguishes the two roles. After auth, the roles converge: both peers open and accept streams.

```mermaid
sequenceDiagram
    participant L as Listen Peer
    participant SD as Discovery Service
    participant D as Dial Peer
    participant RS as Relay Server

    Note over L: Generate ephemeral identity (TUI: answered "no")
    L->>L: Create iroh Endpoint
    L->>SD: Publish node id + Addresses
    Note over L: Display node id + auth token in TUI
    L->>RS: Connect to relay
    L->>L: endpoint.accept() loop

    Note over D: User provides node id (TUI prompt, answered "yes")
    D->>D: Create iroh Endpoint (ephemeral identity)
    D->>SD: Resolve node id
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

    Note over D,L: After auth, BOTH sides run symmetrically
    par Dial peer's tunnels
        D->>L: open_bi() + StreamHello (-L / -R)
    and Listen peer's tunnels
        L->>D: open_bi() + StreamHello (-L / -R)
    end
    Note over D,L: Tunnels flow in both directions
```

### Stream Dispatch (StreamHello)

The **auth stream is the only stream that does not carry a hello** — it is positional (the first bi-stream the dialer opens). Every *other* bidirectional stream begins with a self-describing [`StreamHello`] frame written by the stream **opener**, so the **acceptor** can route it without positional assumptions. This is what makes a symmetric peer possible: the side that accepts a stream doesn't need to know in advance whether it is a local-forward data stream, a remote-forward data stream, or a remote-forward control stream.

```mermaid
graph TB
    A[accept_bi: new stream] --> B[Read StreamHello<br/>HELLO_TIMEOUT 10s]
    B --> C{kind?}

    C -->|LocalForward dest| D[Acquire session permit]
    D --> E[Connect out to dest<br/>tcp:// or udp://]
    E --> F[Reply StreamAck, bridge]

    C -->|RemoteForwardData tunnel_id| G[Look up tunnel_id -> local dest]
    G --> H[Acquire session permit]
    H --> I[Connect out to local dest]
    I --> F

    C -->|RemoteForwardControl| J[Read RemoteForwardRequest per -R]
    J --> K[Bind requested listener<br/>full trust]
    K --> L[Reply RemoteForwardResponse<br/>with bound_addr]

    style B fill:#FFF9C4
    style F fill:#C8E6C9
    style L fill:#C8E6C9
```

A per-connection `Semaphore` (default `max_sessions = 100`) bounds concurrent **data** streams in both directions. Auth and remote-forward *control* streams do not consume permits. A timeout (`HELLO_TIMEOUT`) guards the `StreamHello` read so a stalled opener cannot pin a permit; if the limit is reached the acceptor replies with a rejecting `StreamAck` instead of bridging.

### Local Forward (-L) Data Flow

The declaring peer binds a local listener. Per connection it opens a stream tagged `StreamHello::LocalForward { dest }`; the peer connects out to `dest` (`tcp://host:port` or `udp://host:port`), replies `StreamAck`, then bridges. This is the generalization of the old "one side opens a stream, the other connects out" path.

```mermaid
sequenceDiagram
    participant App as Local App
    participant O as Opener (declares -L)
    participant P as Peer (acceptor)
    participant T as Target Service

    App->>O: connect to local listener
    O->>P: open_bi() + StreamHello::LocalForward{dest}
    P->>T: connect out to dest
    alt connect ok
        P-->>O: StreamAck{accepted: true}
        Note over O,P: bridge_streams() copies both directions
    else connect failed
        P-->>O: StreamAck{accepted: false, reason}
    end
```

### Remote Forward (-R) Data Flow

The requester opens **one** control stream (`StreamHello::RemoteForwardControl`) and sends a `RemoteForwardRequest { tunnel_id, bind }` per `-R`. The host binds the requested listener (**full trust — no allowlist**), then replies `RemoteForwardResponse { accepted, bound_addr, ... }`. On each accepted connection, the host opens a fresh `StreamHello::RemoteForwardData { tunnel_id }` stream back; the requester maps `tunnel_id` to its own local `dest` and connects out.

```mermaid
sequenceDiagram
    participant R as Requester (declares -R)
    participant H as Host (peer)
    participant App as External Client
    participant Local as Requester's local dest

    R->>H: open_bi() + StreamHello::RemoteForwardControl
    loop per -R forward
        R->>H: RemoteForwardRequest{tunnel_id, bind}
        H->>H: bind listener (full trust)
        H-->>R: RemoteForwardResponse{accepted, bound_addr}
    end

    App->>H: connect to hosted listener (bound_addr)
    H->>R: open_bi() + StreamHello::RemoteForwardData{tunnel_id}
    R->>R: map tunnel_id -> local dest
    R->>Local: connect out
    R-->>H: StreamAck{accepted: true}
    Note over R,H: bridge_streams() copies both directions
```

Tunnel ids are allocated by the requester via an `AtomicU64`. Hosted `-R` listeners self-terminate when the connection closes (a `tokio::select!` on `conn.closed()`), freeing the bound port.

### TCP Tunnel Data Flow

TCP bridging uses `bridge_streams()` (`iroh_mode/helpers.rs`) regardless of forward direction. The "opener" is whichever peer accepted the local connection; the "connect side" is whichever peer dials the target.

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

### UDP Tunnel Data Flow

UDP forwarding reuses `forward_stream_to_udp_server` / `forward_stream_to_udp_client` / `forward_udp_to_stream` (`iroh_mode/helpers.rs`) and works in both directions. Each UDP forward uses a single bidirectional stream; packets are length-prefixed (see [UDP Packet Framing](#udp-packet-framing)).

> **Note:** A hosted `-R` UDP forward inherits a single-peer-address reply limitation — the host tracks one external peer address per stream for return packets.

```mermaid
graph TB
    subgraph "Opener Side"
        A[UDP Client] -->|sendto| B[UDP Socket]
        B -->|recvfrom| C[Track Peer Address]
        C -->|encode length + data| D[iroh SendStream]
    end

    subgraph "QUIC Transport"
        D <-->|encrypted| E[iroh RecvStream]
    end

    subgraph "Connect Side"
        E -->|decode| F[Packet Buffer]
        F -->|sendto| G[UDP Socket]
        G -->|forward| H[Target Service]
        H -->|response| G
        G -->|recvfrom| I[Response Buffer]
        I -->|encode| J[iroh SendStream]
    end

    subgraph "Return Path"
        J <-->|encrypted| K[iroh RecvStream]
        K -->|decode| L[Packet Buffer]
        L -->|sendto| B
        B -->|deliver| A
    end

    style D fill:#BBDEFB
    style E fill:#BBDEFB
    style J fill:#BBDEFB
    style K fill:#BBDEFB
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

A single, symmetric `PeerConfig` drives the peer. There is no `role` enum and no `connect` key; the connection role is chosen **at startup** (interactively in the TUI, or via env vars for tests), not in config.

### Configuration File Structure

```mermaid
graph TB
    subgraph "Config File"
        A[peer.toml]
    end

    subgraph "Options"
        E[auth_token* — single shared token<br/>both peers]
        G[local_forward[] {listen, dest} -L<br/>remote_forward[] {bind, dest} -R]
        H[max_sessions]
        I[relay_urls / relay_only / dns_server]
        J[transport<br/>cc + window sizes]
        K[encryption_key_file / encryption_recipient]
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

The role (listen vs dial) and the dialer's target node id are not config fields. They are resolved at startup from the TUI prompts, or — for tests — from `DUOPIPE_PEER_NODE_ID` (set ⇒ dial, unset ⇒ listen) under `DUOPIPE_NONINTERACTIVE=1`.

### iroh Credential Mapping

`iroh` mode uses a **single** shared credential, the auth token. The ALPN is a fixed constant (`mf/2`) and carries no credential.

| Credential | Env Var | Config Key (TOML: use `_file` variant or age-encrypted inline) | Expected Usage |
|------------|---------|-------------|----------------|
| **Auth Token** | `DUOPIPE_AUTH_TOKEN` | `auth_token_file` or age-encrypted `auth_token` | Connection-level credential validated on the first bi-stream. Both peers use the **same** token: the dial peer **presents** it, the listen peer **accepts** exactly that one value. |

`DUOPIPE_AUTH_TOKEN` takes precedence over the config `auth_token` / `auth_token_file`.

Example config usage (a plaintext `auth_token` is not allowed in TOML config files — use `auth_token_file`, the `DUOPIPE_AUTH_TOKEN` env var, or an age-encrypted inline value):

```toml
# peer.toml — using the _file variant
auth_token_file = "/etc/duopipe/auth_token.txt"

[[local_forward]]
listen = "127.0.0.1:2222"
dest = "tcp://127.0.0.1:22"
```

```toml
# peer.toml — using an age-encrypted inline value
encryption_key_file = "~/.config/duopipe/age.key"

auth_token = "ageenc:YWdlLWVuY3J5cHRpb24ub3JnL3Yx..."

[[remote_forward]]
bind = "tcp://0.0.0.0:6574"
dest = "127.0.0.1:6574"
```

### Configuration Loading Flow

Configs are file-based (`-c`, `--default-config`) and use TOML — settings are saved and reusable. The default path is `~/.config/duopipe/peer.toml`. Without a config flag, configuration comes from environment variables and interactive prompts only.

```mermaid
sequenceDiagram
    participant CLI as CLI Parser
    participant Main as Main
    participant Config as Config Module
    participant Source as Config Source (file)

    CLI->>Main: Parse arguments
    Main->>Main: Check config flags (only one allowed)

    alt --default-config
        Main->>Config: Load from default path
        Config->>Source: Read ~/.config/duopipe/peer.toml
        Source-->>Config: TOML content
    else -c <path>
        Main->>Config: Load from specified path
        Config->>Source: Read file
        Source-->>Config: TOML content
    else No config flag
        Main->>Main: Use env vars + interactive prompts only
    end

    alt Config loaded
        Config->>Config: Parse TOML
        Config->>Config: Validate address formats + auth token
        Config-->>Main: Validated config
        Main->>Main: Apply env overrides (DUOPIPE_AUTH_TOKEN wins)
    end

    Main->>Main: Launch TUI: resolve role + dial target
```

### Config Validation

```mermaid
graph TB
    A[Load Config] --> F{Check fields}

    F --> G{Plaintext auth_token in file?}
    G -->|Yes| H[Error: use auth_token_file, env, or ageenc:]
    G -->|No| I{Forward addresses valid?}

    I -->|No| J[Error: bad -L/-R address]
    I -->|Yes| K[Validation Success]

    style H fill:#FFCCBC
    style J fill:#FFCCBC
    style K fill:#C8E6C9
```

---

## Security Model

### Encryption Stack

```mermaid
graph TB
    subgraph "Application Data"
        A[TCP/UDP Payload]
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
        F -->|Yes| G[Authenticated - FULL TRUST]
        F -->|No| H[Rejected]
    end

    style A fill:#FFE0B2
    style C fill:#C8E6C9
    style G fill:#C8E6C9
    style H fill:#FFCCBC
```

### Trust Model

**Full trust after authentication.** Connection setup is asymmetric, but trust is symmetric: once the shared auth token passes, the peer is fully trusted. There are **no per-destination allowlists** and no CIDR gating. A `-L` forward connects out to whatever `dest` the opener names, and a `-R` forward binds whatever listener the requester asks for. Only grant a peer access via a token you would trust with that level of network reach.

### Token Authentication (iroh Mode)

Access control rests on a single shared auth token. The ALPN is a fixed constant (`mf/2`) and carries no credential. After the QUIC/TLS handshake, the dialing peer must present a valid auth token on the **first bidirectional stream** (positional — this auth stream is the only stream that carries no `StreamHello`) within a 10-second timeout.

#### Auth Token

- **Auth Token** (`DUOPIPE_AUTH_TOKEN` env var / `auth_token_file` / age-encrypted `auth_token`): A single shared connection-level token, validated on the first bi-stream. Both peers use the **same** value. In code it is a 47-char `i...` token.

1. **Listen Peer Configuration**: The listen peer is configured with the shared auth token (or generates one if none is set, displaying it in the TUI).
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
        Note over L,D: Connection authenticated — full trust
    else Token is invalid
        A-->>L: false
        L->>D: AuthResponse {accepted: false, reason}
        L->>L: Close connection (error code 1)
        Note over L,D: Connection closed with rejection
    else Timeout (no auth within 10s)
        L->>L: Close connection (error code 2)
        Note over L,D: Connection closed (auth timeout)
    end

    Note over D,L: After auth, both sides open StreamHello-tagged tunnels
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
        I[Full Trust After Auth<br/>peers can reach any dest/bind]
    end

    style A fill:#C8E6C9
    style B fill:#C8E6C9
    style C fill:#C8E6C9
    style D fill:#C8E6C9
    style E2 fill:#C8E6C9

    style G fill:#FFF9C4
    style H fill:#FFF9C4
    style I fill:#FFF9C4
```

### Identity Management

The iroh identity is **ephemeral**: iroh generates a fresh Ed25519 keypair on every run, so there is no key file to store or protect. The consequence is that the **listen peer's node id changes every run** and must be re-copied to the dial peer (the TUI displays the current node id). This avoids same-machine locking that could otherwise produce duplicate node ids.

```mermaid
sequenceDiagram
    participant User as User
    participant TUI as TUI
    participant EP as iroh Endpoint

    Note over EP: No key file — fresh identity each run
    User->>TUI: duopipe peer  (answer "no" → listen)
    TUI->>EP: Create endpoint (ephemeral identity)
    EP->>EP: Derive node id from fresh keypair
    EP-->>TUI: node id
    TUI->>User: Display node id + auth token (copy to dial peer)
```

---

## Protocol Support

### Signaling Protocol (signaling/codec.rs)

The signaling protocol is `IROH_MULTI_VERSION = 4`. All control messages are **length-prefixed JSON**: a `u32` big-endian length followed by the JSON body (capped at 16 KB). Each message embeds a `version` field that is validated on decode.

| Message | Direction | Carried On | Purpose |
|---------|-----------|------------|---------|
| `AuthRequest` / `AuthResponse` | dialer → listener / reply | first bi-stream (positional, no hello) | Connection-level token auth. |
| `StreamHello::LocalForward { dest }` | opener → acceptor | first frame of a `-L` data stream | Asks the acceptor to connect out to `dest` and bridge. |
| `StreamHello::RemoteForwardData { tunnel_id }` | host → requester | first frame of a `-R` data stream | A connection arrived on a hosted listener; requester maps `tunnel_id` to its local dest. |
| `StreamHello::RemoteForwardControl` | requester → host | first frame of the `-R` control stream | Opens remote-forward negotiation. |
| `RemoteForwardRequest { tunnel_id, bind }` | requester → host | `-R` control stream | One per `-R`: asks the host to bind `bind`. |
| `RemoteForwardResponse { tunnel_id, accepted, reason, bound_addr }` | host → requester | `-R` control stream | Result of a bind, including the actual `bound_addr`. |
| `StreamAck { accepted, reason }` | acceptor → opener | per data stream | Acceptance reply once the acceptor has connected out (or failed). |

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
        H[Read StreamHello + route]
        I[Connect to dest / local dest]
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

### UDP Tunneling Architecture

```mermaid
graph TB
    subgraph "Opener Side"
        A[UDP Socket] --> B[Receive Packet]
        B --> C[Track Peer Address]
        C --> D[Encode: u16 len + data]
    end

    subgraph "QUIC Tunnel"
        E[Single Bidirectional Stream]
        F[Send Stream]
        G[Recv Stream]
    end

    subgraph "Connect Side"
        H[Decode Packet]
        I[Send to Target]
        J[Receive Response]
        K[Encode Response]
    end
    
    subgraph "Return Path"
        L[Send via QUIC]
        M[Decode at Opener]
        N[Send to Peer Address]
    end
    
    D --> E
    E --> F
    F --> H
    H --> I
    I --> J
    J --> K
    K --> L
    L --> G
    G --> M
    M --> N
    N --> C
    
    style E fill:#BBDEFB
    style F fill:#BBDEFB
    style G fill:#BBDEFB
    style L fill:#BBDEFB
```

### UDP Packet Framing

```mermaid
graph LR
    subgraph "UDP Packet"
        A[Payload<br/>variable length]
    end
    
    subgraph "QUIC Stream Frame"
        B[Length<br/>u16 BE]
        C[Payload<br/>bytes]
    end
    
    subgraph "Decoding"
        D[Read 2 bytes]
        E[Parse length]
        F[Read N bytes]
        G[Reconstruct packet]
    end
    
    A --> B
    A --> C
    
    B --> D
    D --> E
    E --> F
    C --> F
    F --> G
    
    style B fill:#FFF9C4
    style C fill:#C8E6C9
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

`run_peer(PeerConfig)` is the single entry point. It validates relay-only usage and dispatches on `config.role` (resolved at startup from the TUI or env vars). The ALPN is the fixed `ALPN` constant.

- `run_listen` — `create_server_endpoint`, then an `endpoint.accept()` loop spawning `handle_connection(.., is_dialer = false)`. When `announce_endpoint` is set (non-interactive mode) it prints `node_id:` and `auth_token:` to stderr.
- `run_dial` — `create_client_endpoint` + `connect_to_server`, wrapped in a reconnect loop with exponential backoff (capped at 30s). Auth failures are fatal and stop the loop.

`handle_connection` authenticates (`auth_as_dialer` / `auth_as_listener`), then runs three concurrent halves over the one connection: an `accept_loop` (incoming streams), one task per local-forward listener (`run_local_forward`), and a remote-forward requester task (`request_remote_forwards`). Everything is torn down when `conn.closed()` resolves.

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
- **UDP Tunneling**: Additional framing overhead (2 bytes per packet)
- **Relay Mode**: Higher latency, potentially lower throughput
- **Direct Mode**: Near-native performance with encryption overhead
- **Concurrency**: A per-connection semaphore caps concurrent data streams (`max_sessions`, default 100) across both directions.

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
| 2 | Configuration | Missing/invalid node id, invalid token format, bad `-L`/`-R` address |
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
- **UDP**: Packet loss → no retry (UDP semantics preserved)
- **QUIC**: Stream reset → close local TCP connection or stop UDP forwarding
- **Session limit reached**: acceptor replies with a rejecting `StreamAck`; opener-side TCP connections are dropped.

---

## Capabilities

| Feature | Support |
|---------|---------|
| Bidirectional tunnels | **Yes** — `-L` and `-R` on either peer over one connection |
| Multi-Session | **Yes** — many concurrent data streams per connection (`max_sessions`) |
| Dynamic destinations | **Yes** — each `-L`/`-R` names its own `dest`/`bind` |
| Encryption | QUIC/TLS 1.3 |
| Platform | Linux, macOS, Windows |

---

## References

- [iroh Documentation](https://iroh.computer/)
- [RFC 9000 - QUIC](https://datatracker.ietf.org/doc/html/rfc9000)
</content>
</invoke>
