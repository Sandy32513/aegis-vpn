# Aegis VPN

`aegis-vpn` is a Rust monorepo for an OS-level VPN client and Linux tunnel server. It captures traffic from a TUN/Wintun interface, encrypts packets with `X25519 + HKDF-SHA256 + AES-256-GCM`, sends them over a framed UDP transport, and forwards decrypted packets through a Linux server using kernel IP forwarding and NAT.

---

> **Designed & Engineered by Santhosh**
> **Approved & Reviewed by Sandy**

---

**Current version:** v0.2.0 (audit release)
**Production target:** v1.0.0
**License:** Apache-2.0

---

## 1. Project Overview

Aegis VPN provides full-system traffic protection by intercepting packets at the OS network stack level. The project is modular, with separate Rust crates for crypto, routing, transport, platform integration, and a React frontend for control and diagnostics.

| Dimension | Current State |
|---|---|
| Client platforms | Linux, Windows |
| Server platform | Linux (TUN + NAT forwarding) |
| Encryption | X25519 ECDH + HKDF-SHA256 + AES-256-GCM |
| Tunnel mode | Single-hop (client -> server -> Internet) |
| Kill switch | Linux (nftables), Windows (firewall fallback) |
| IPC | TCP JSON-line over loopback |
| UI | React 19 + Vite 6 with Node.js bridge |
| Tests | 43 automated tests across 8 files |
| Audit score | 72/100 (see docs/AUDIT.md) |

---

## 2. Architecture

### 2.1 System Architecture Diagram

```text
+-------------------------------------------------------------------+
|  UI Layer                                                          |
|  React 19 (App.tsx)  <-->  Node.js Bridge (index.mjs)            |
|  - Tunnel control           - Daemon IPC proxy                    |
|  - MCP health monitor       - MCP REST proxy (bearer auth)        |
|  - Stitch asset status      - Log SSE streaming                   |
|  - Developer log viewer     - CORS (localhost only)               |
+-------------------------------------------------------------------+
         | HTTP (Vite proxy)        | TCP JSON-line
         v                          v
+-------------------------------------------------------------------+
|  vpn-daemon (Rust)                                                 |
|  controller.rs (mock)  |  service.rs (real client)                |
|  - Simulated mode       |  - TUN/Wintun setup                     |
|  - IPC server           |  - 4-way crypto handshake               |
|  - Mock metrics         |  - Packet loop (inbound/outbound)       |
|                         |  - Rotation state machine                |
|                         |  - Kill switch activation                |
+-------------------------------------------------------------------+
         |                    |                    |
         v                    v                    v
+------------------+  +------------------+  +------------------+
| vpn-crypto       |  | vpn-routing      |  | vpn-transport    |
| X25519 + HKDF    |  | IPv4/IPv6 parse  |  | UDP socket       |
| AES-256-GCM      |  | Policy classify  |  | bincode frames   |
| Replay window    |  | Flow table       |  | 16KB max         |
+------------------+  +------------------+  +------------------+
         |
         v
+-------------------------------------------------------------------+
|  Platform Layer                                                    |
|  Linux: /dev/net/tun + nftables + NAT                             |
|  Windows: Wintun DLL + firewall rules + WFP stub                  |
+-------------------------------------------------------------------+
         |
         v
+-------------------------------------------------------------------+
|  Linux VPN Server (vpn_server binary)                              |
|  decrypt -> TUN -> kernel NAT -> Internet -> TUN -> encrypt       |
+-------------------------------------------------------------------+
```

### 2.2 VPN Packet Pipeline

**Outbound:**
```text
TUN/Wintun -> vpn-routing (classify) -> vpn-crypto (seal) -> vpn-transport (UDP) -> server
```

**Inbound:**
```text
server UDP -> vpn-transport (recv) -> vpn-crypto (open) -> TUN/Wintun inject -> app
```

**Server forwarding:**
```text
client UDP -> server TUN decrypt -> kernel route/NAT -> Internet
Internet -> server TUN -> session lookup -> encrypt -> client UDP
```

### 2.3 UI -> Backend Interaction Flow

```text
Browser (React)                     Node.js Bridge                  vpn-daemon
     |                                   |                              |
     |-- GET /api/daemon/status -------->|                              |
     |                                   |-- TCP {"Status":null} ------>|
     |                                   |<-- {"Status":{...}} ---------|
     |<-- JSON DaemonStatus -------------|                              |
     |                                   |                              |
     |-- POST /api/daemon/connect ------>|                              |
     |                                   |-- TCP {"Connect":null} ----->|
     |                                   |<-- {"Ok":{...}} -------------|
     |<-- JSON ActionResponse -----------|                              |
     |                                   |                              |
     |-- GET /api/mcp/health ----------->|                              |
     |                                   |-- HTTP GET MCP_BASE_URL ---->|
     |                                   |   + Bearer MCP_API_KEY       |
     |                                   |<-- MCP health response -----|
     |<-- JSON McpHealthResponse --------|                              |
     |                                   |                              |
     |-- GET /api/logs/stream (SSE) ---->|                              |
     |                                   |-- file watch daemon.log ---->|
     |<-- SSE: log lines (ongoing) ------|                              |
```

### 2.4 State Machine (Connect/Disconnect)

```text
                     +------------------+
                     |  DISCONNECTED    |
                     +--------+---------+
                              |
                     [User clicks Connect]
                              |
                              v
                     +------------------+
                     |   CONNECTING     |
                     | (4-way handshake)|
                     +--------+---------+
                              |
                 +------------+------------+
                 |                         |
          [Success]                  [Failure/Timeout]
                 |                         |
                 v                         v
        +--------+---------+     +---------+--------+
        |    CONNECTED      |     |  DISCONNECTED   |
        | (packet loop      |     | (error logged)  |
        |  rotation active) |     +-----------------+
        +--------+---------+
                 |
        [Rotation triggered]
                 |
                 v
        +--------+---------+
        |    ROTATING       |
        | Prepare->Migrate  |
        | ->Verify->Stable  |
        +--------+---------+
                 |
          [Rotation complete]
                 |
                 v
        +--------+---------+
        |    CONNECTED      |
        +--------+---------+
                 |
        [User clicks Disconnect]
                 |
                 v
        +--------+---------+
        |  DISCONNECTING   |
        | (admin auth?)    |
        +--------+---------+
                 |
                 v
        +------------------+
        |  DISCONNECTED    |
        +------------------+
```

### 2.5 Entity-Relationship Diagram

```text
+------------------+       +-------------------+       +------------------+
|    SESSIONS      |       |      NODES        |       |    DEVICES       |
+------------------+       +-------------------+       +------------------+
| session_id (PK)  |       | node_id (PK)      |       | device_id (PK)   |
| device_id (FK)   |<----->| hostname          |       | name             |
| entry_node (FK)  |  N:1  | role              |       | public_key       |
| exit_node (FK)   |  N:1  | jurisdiction      |       | platform         |
| start_time       |       | ip_address        |       | created_at       |
| end_time         |       | port              |       | last_seen        |
| bytes_tx         |       | public_key        |       +--------+---------+
| bytes_rx         |       | health_score      |                |
| status           |       | load_pct          |                |
| circuit_id       |       | uptime_secs       |                |
+--------+---------+       | supported_profiles|                |
         |                 | last_health_check |                |
         |                 +-------------------+                |
         |                                                      |
         v                                                      |
+------------------+       +-------------------+                |
|    LOGS          |       |   ADMIN_ACTIONS   |                |
+------------------+       +-------------------+                |
| log_id (PK)      |       | action_id (PK)    |                |
| session_id (FK)  |<------| session_id (FK)   |                |
| device_id (FK)   |------>| actor             |<---------------+
| category         |       | action_type       |
| event            |       | result            |
| level            |       | source_ip_hash    |
| fields (JSON)    |       | auth_success      |
| prev_hmac        |       | lockout_triggered |
| row_hmac         |       | timestamp         |
| timestamp        |       | prev_hmac         |
+------------------+       | row_hmac          |
                           +-------------------+

Relationships:
  DEVICES 1:N SESSIONS        (one device has many sessions)
  NODES 1:N SESSIONS          (one node serves many sessions as entry/exit)
  SESSIONS 1:N LOGS           (one session produces many log entries)
  SESSIONS 1:N ADMIN_ACTIONS  (one session can have many admin actions)
  DEVICES 1:N ADMIN_ACTIONS   (one device can trigger many actions)
```

### 2.6 Data Flow Diagram

```text
    App/Browser
        |
        v (IP packet)
    OS Kernel Route Table
        |
        v
    TUN/Wintun Device  <-- vpn-platform-*
        |
        v
    Packet Classifier  <-- vpn-routing
    (5-tuple extraction)
        |
   +----+----+
   |         |
[EXCLUDE]  [INCLUDE]
   |         |
   v         v
Native    FlowTable  <-- vpn-routing
Stack     (pin to circuit)
(bypass)     |
             v
        AES-256-GCM seal  <-- vpn-crypto
        nonce = iv XOR counter
        AAD = type + len + epoch
             |
             v
        WireFrame::Data  <-- vpn-transport
        bincode serialize
        16KB max
             |
             v
        UDP Socket (send)
             |
             v (encrypted UDP)
        Linux VPN Server
        TUN decrypt -> kernel NAT
             |
             v
        Internet
```

---

## 3. Platform-Specific Sections

### 3.1 Windows

| Feature | File | Status | Known Issues |
|---|---|---|---|
| Wintun integration | `vpn-platform-windows/src/lib.rs` | **Implemented** | Requires wintun.dll in PATH |
| Firewall kill switch | `enable_kill_switch()` | **Implemented** | PowerShell cmdlet fallback only |
| WFP native kill switch | `wfp_native.rs` | **Stub** | install_kill_switch() returns Err |
| Interface configuration | `configure_interface()` | **Implemented** | PowerShell New-NetIPAddress |
| Route management | `route_*` functions | **Implemented** | PowerShell route add |
| Service installer | `service_installer.rs` | **Implemented** | sc.exe create/delete |
| Service host | `service_host.rs` | **Implemented** | Windows SCM lifecycle |
| Key storage | File-based | **Implemented** | No DPAPI/TPM (planned v0.3.0) |

**Requirements:** Windows 10+ x86_64, Admin, wintun.dll, PowerShell 5.1+

**Pending:**
- [ ] Native WFP kernel kill switch (v0.3.0)
- [ ] DPAPI/TPM key storage (v0.3.0)
- [ ] Full lifecycle validation on real host (v0.3.0)

### 3.2 Linux

| Feature | File | Status | Known Issues |
|---|---|---|---|
| TUN device | `vpn-platform-linux/src/lib.rs` | **Implemented** | Uses ip commands (not netlink) |
| Interface configuration | `configure_interface()` | **Implemented** | Shell exec, not programmatic |
| Kill switch | `enable_kill_switch()` | **Implemented** | nftables inet aegis_vpn table |
| NAT forwarding | `server_nat.rs` | **Implemented** | Cleanup before reapply |
| Server binary | `server/mod.rs` | **Implemented** | Single-client only (no IP pool) |
| Key storage | File-based (0o600) | **Implemented** | No keyring (planned v0.4.0) |

**Requirements:** Root, ip, nft or iptables, TUN kernel support

**Pending:**
- [ ] netlink-based route management (v0.4.0)
- [ ] systemd service hardening (v0.4.0)
- [ ] Multi-client IP pool allocation (v0.3.0)

### 3.3 macOS

**Status: PLANNED (v0.6.0)**

| Feature | Status | Notes |
|---|---|---|
| NEPacketTunnelProvider | Planned | Network Extension framework |
| Keychain storage | Planned | Secure Enclave when available |
| App group IPC | Planned | Config handoff between components |
| Notarized distribution | Planned | Outside Mac App Store |

**Pending:**
- [ ] Create `vpn-platform-macos` crate
- [ ] NEPacketTunnelProvider implementation
- [ ] PF-assisted kill switch
- [ ] Keychain integration

### 3.4 Android

**Status: PLANNED (v0.6.0)**

| Feature | Status | Notes |
|---|---|---|
| VpnService | Planned | Full tunnel via addRoute("0.0.0.0", 0) |
| Per-app split tunnel | Planned | addDisallowedApplication() |
| JNI bridge | Planned | Rust core via jni crate |
| Foreground service | Planned | Mandatory notification |
| Android Keystore | Planned | StrongBox when available |

**Pending:**
- [ ] Create `vpn-platform-android` crate
- [ ] VpnService JNI bridge
- [ ] Always-on VPN integration
- [ ] Keystore / StrongBox integration

---

## 4. Features

### 4.1 Implemented (v0.2.0)

| Feature | Crate/Component | Description |
|---|---|---|
| X25519 ECDH key exchange | vpn-crypto | Ephemeral keypair, shared secret derivation |
| AES-256-GCM encryption | vpn-crypto | Per-packet seal/open, nonce=iv XOR counter |
| HKDF-SHA256 key derivation | vpn-crypto | Directional key + IV derivation |
| 4-way handshake | vpn-daemon | HandshakeInit -> Response -> Confirm -> Ack |
| Server static proof | vpn-crypto | HMAC binding for trust pinning |
| Replay protection | vpn-crypto | 2048-bit sliding window |
| TOML config loading | vpn-config | Client/server/dns/logging sections |
| Identity persistence | vpn-config | X25519 keypair, 0o600 permissions |
| UDP transport | vpn-transport | Bincode WireFrame, 16KB max |
| IPv4/IPv6 parsing | vpn-routing | Extension header skipping |
| Split-tunnel classification | vpn-routing | Process/domain/IP/port rules |
| Flow table | vpn-routing | Circuit pinning, draining, reaping |
| Circuit rotation | vpn-rotation | Stable -> Prepare -> Migrate -> Verify -> Stable |
| TCP JSON-line IPC | vpn-ipc | Connect/Disconnect/Status/Metrics |
| HMAC-chained logging | vpn-logger | JSON lines + optional MySQL |
| Linux TUN + kill switch + NAT | vpn-platform-linux | Full server + client support |
| Windows Wintun + kill switch | vpn-platform-windows | Firewall fallback, WFP stub |
| Windows service | vpn-daemon | SCM lifecycle |
| React web UI | ui/ | Dashboard, MCP health, logs |
| Node.js bridge | ui/server/ | IPC proxy, MCP proxy, log SSE |
| Mock controller | vpn-daemon | Simulated daemon for UI dev |
| 43 automated tests | All crates | Crypto, config, routing, rotation, transport |

### 4.2 Planned (Not Yet Implemented)

| Feature | Target | Module |
|---|---|---|
| Multi-hop onion routing (2-5 hops) | v0.4.0 | vpn-multi-hop |
| Node scoring and path selection | v0.4.0 | vpn-multi-hop |
| Anti-DPI TLS mimicry | v0.5.0 | vpn-obfuscation |
| WebSocket tunnel | v0.5.0 | vpn-obfuscation |
| HTTP/2 tunnel | v0.5.0 | vpn-obfuscation |
| Traffic shaping / jitter | v0.5.0 | vpn-obfuscation |
| Packet fragmentation | v0.5.0 | vpn-obfuscation |
| Domain fronting | v0.5.0 | vpn-obfuscation |
| QUIC/HTTP/3 transport | v0.7.0 | vpn-transport |
| Adaptive protocol selection | v0.7.0 | vpn-transport |
| macOS platform | v0.6.0 | vpn-platform-macos |
| Android platform | v0.6.0 | vpn-platform-android |
| Native WFP kill switch | v0.3.0 | vpn-platform-windows |
| bcrypt admin auth | v0.3.0 | vpn-daemon |
| Batched MySQL writes | v0.3.0 | vpn-logger |
| Full MySQL schema (4 tables) | v0.3.0 | vpn-logger |
| TCP session migration | v0.7.0 | vpn-rotation |
| netlink route management | v0.4.0 | vpn-platform-linux |
| gRPC IPC | v0.4.0 | vpn-ipc |
| Health monitoring | v0.4.0 | vpn-daemon |
| External IP verification | v0.3.0 | vpn-rotation |
| Split-tunnel EXCLUDE | v0.3.0 | vpn-routing |
| Automatic rekey | v0.4.0 | vpn-crypto |

---

## 5. File/Folder Structure

```
aegis-vpn/
├── Cargo.toml                      Workspace root (11 crate members)
├── Cargo.lock
├── rust-toolchain.toml             stable + clippy + rustfmt
├── .env.example                    MCP + daemon environment vars
├── .gitignore
├── .github/workflows/ci.yml        Linux (fmt+clippy+test), Windows (build)
├── .vscode/                        Editor config
├── config/
│   └── control-plane.example.toml  Full example config
├── crates/
│   ├── vpn-crypto/                 X25519, AES-256-GCM, HKDF (530 lines)
│   │   ├── src/lib.rs
│   │   └── tests/                  11 integration tests
│   ├── vpn-config/                 TOML loading, identity (272 lines)
│   │   ├── src/lib.rs
│   │   └── tests/                  5 tests
│   ├── vpn-transport/              UDP, bincode WireFrame (122 lines)
│   │   ├── src/lib.rs
│   │   └── tests/                  1 test
│   ├── vpn-routing/                IPv4/IPv6, policy, flow table (326 lines)
│   │   ├── src/lib.rs
│   │   └── tests/                  9 tests
│   ├── vpn-rotation/               State machine (147 lines)
│   │   ├── src/lib.rs
│   │   └── tests/                  8 tests
│   ├── vpn-tun/                    TunDevice trait (15 lines)
│   ├── vpn-ipc/                    TCP JSON-line IPC (113 lines)
│   ├── vpn-logger/                 HMAC logging (292 lines)
│   │   ├── src/lib.rs
│   │   └── src/events.rs
│   ├── vpn-daemon/                 CLI, client, server, controller (2015 lines)
│   │   ├── src/main.rs             CLI dispatch
│   │   ├── src/config.rs           CLI args
│   │   ├── src/control_plane.rs    Settings resolution
│   │   ├── src/controller.rs       Mock simulator
│   │   ├── src/service.rs          Real client runtime
│   │   ├── src/service_host.rs     Windows SCM
│   │   ├── src/server/mod.rs       Linux VPN server
│   │   ├── src/bin/vpn_server.rs   Server binary
│   │   ├── src/bin/echo_server.rs  Echo binary
│   │   └── tests/                  1 test
│   ├── vpn-platform-linux/         TUN, nftables, NAT (598 lines)
│   │   ├── src/lib.rs
│   │   └── src/server_nat.rs
│   └── vpn-platform-windows/       Wintun, firewall, WFP (533 lines)
│       ├── src/lib.rs
│       ├── src/wfp_native.rs       (stub)
│       └── src/service_installer.rs
├── ui/
│   ├── src/App.tsx                 Dashboard (378 lines)
│   ├── src/types.ts                Interfaces (107 lines)
│   ├── src/api/client.ts           API client (48 lines)
│   ├── src/main.tsx                React entry
│   ├── src/styles.css              Dark theme (376 lines)
│   ├── server/index.mjs            Express bridge (598 lines)
│   ├── package.json                React 19, Vite 6, Express
│   ├── vite.config.ts
│   ├── stitch-manifest.json        8 UI screens
│   └── scripts/download-stitch-assets.mjs
├── docs/
│   ├── AUDIT.md                    v0.2.0 audit (72/100)
│   ├── TESTING.md                  Test strategy
│   ├── UI_DEV_SETUP.md             VS Code + MCP setup
│   ├── mysql-schema.sql            event_log DDL
│   └── server-nat.md              NAT docs
├── scripts/
│   ├── mock-mcp.mjs                Mock MCP server
│   ├── linux/setup-server-nat.sh   NAT setup
│   ├── linux/cleanup-server-nat.sh NAT cleanup
│   ├── windows/install-service.ps1 Service install
│   └── windows/uninstall-service.ps1 Service uninstall
├── server/README.md
├── CONTRIBUTING.md
├── LICENSE                         Apache-2.0
└── README.md
```

---

## 6. Data Pipelines

### 6.1 Crypto Pipeline

```text
X25519 keypair -> shared_secret -> HKDF-SHA256 -> send_key, recv_key, send_iv, recv_iv, confirm_key
                                                                    |
                                                          AES-256-GCM seal/open
                                                          nonce = static_iv XOR counter
                                                          AAD = type || len || epoch || path_id
```

### 6.2 Logging Pipeline

```text
Event -> LogRecord { service, category, event, fields, timestamp, level }
     -> compute_hmac(chain_key, prev_hmac || row_bytes)
     -> JSON line write to file
     -> (optional) MySQL INSERT into event_log
```

### 6.3 Config Pipeline

```text
control-plane.toml -> load_config() -> Config struct
     -> validate_config() (checks required fields)
     -> get_identity() (load or generate X25519 keypair)
     -> resolve_run_settings() (merge with CLI args)
     -> DaemonRuntime
```

---

## 7. Bug Tracking

### CRITICAL

| ID | Status | Module | Issue |
|---|---|---|---|
| C-01 | **Fixed** | vpn-crypto | Handshake lacked authenticated server identity |
| C-02 | **Fixed** | vpn-ipc | IPC could be exposed off-host |
| C-03 | **Fixed** | vpn-daemon | Default-route activation before tunnel establishment |
| C-04 | **Pending** | vpn-platform-windows | Native WFP kill switch not authored |

### HIGH

| ID | Status | Module | Issue |
|---|---|---|---|
| H-01 | **Fixed** | vpn-daemon/server | Server accepted traffic from unexpected UDP peers |
| H-02 | **Pending** | vpn-daemon/server | Server doesn't allocate unique client tunnel IPs |
| H-03 | **Pending** | vpn-daemon | Disconnect auth optional when no admin secret set |

### MEDIUM

| ID | Status | Module | Issue |
|---|---|---|---|
| M-01 | **Fixed** | vpn-logger | MySQL sink wrote placeholder IDs |
| M-02 | **Fixed** | vpn-platform-linux | NAT setup duplicated firewall rules |
| M-03 | **Fixed** | vpn-daemon | CLI required --server flag redundantly |
| M-04 | **Fixed** | vpn-routing | IPv4 parser accepted malformed headers |
| M-05 | **Pending** | vpn-platform-windows | Windows route/WFP cleanup needs lifecycle validation |
| M-06 | **Pending** | vpn-routing | Split-tunnel EXCLUDE action not functional |

### LOW

| ID | Status | Module | Issue |
|---|---|---|---|
| L-01 | **Fixed** | README | Documentation was stale |
| L-02 | **Fixed** | scripts/ | Empty helper dirs had no guidance |
| L-03 | **Pending** | vpn-daemon | echo_server binary identical to vpn_server |

---

## 8. Fix Summary

**v0.2.0 audit pass repaired:**
- Authenticated server trust path (C-01)
- Loopback-only IPC enforcement (C-02)
- Safe tunnel activation order (C-03)
- Server peer validation (H-01)
- MySQL schema alignment (M-01)
- NAT idempotency (M-02)
- Config-only CLI startup (M-03)
- IPv4 parser hardening (M-04)
- 12 new integration tests
- Complete documentation rewrite

**v1.0.0 blockers:**
1. Native WFP kernel kill switch (C-04)
2. Enforced admin disconnect (H-03)
3. Multi-client IP allocation (H-02)
4. Cross-platform integration testing
5. Multi-hop routing
6. Anti-DPI obfuscation

---

## 9. Setup & Run Instructions

### 9.1 Prerequisites

| Platform | Requirements |
|---|---|
| All | Rust stable (cargo + rustc), Git |
| Linux | Root, `ip`, `nft` or `iptables`, TUN support |
| Windows | Admin, `wintun.dll`, PowerShell 5.1+ |

### 9.2 Build

```bash
git clone <repo-url> && cd aegis-vpn
cargo build --workspace
```

### 9.3 Configuration

Copy `config/control-plane.example.toml` to `config/control-plane.toml` and edit:

| Field | Section | Description |
|---|---|---|
| `server_endpoint` | [client] | Server IP:port |
| `trusted_server_public_key` | [client] | Hex public key for trust pinning |
| `listen_address` | [server] | Server bind address |
| `tun_cidr` | [server] | Server TUN CIDR |
| `egress_interface` | [server] | Outbound interface |
| `admin_secret_env` | [client] | Env var for admin secret |

### 9.4 Run Linux Server

```bash
sudo bash scripts/linux/setup-server-nat.sh
sudo cargo run -p vpn-daemon --bin vpn_server -- config/control-plane.toml
```

### 9.5 Run Linux Client

```bash
sudo cargo run -p vpn-daemon -- run --config-path config/control-plane.toml
```

### 9.6 Run Windows Client

```powershell
# As service
cargo run -p vpn-daemon -- service-install --daemon-path target\debug\vpn-daemon.exe --config-path config\control-plane.toml

# Or direct (admin)
cargo run -p vpn-daemon -- run --config-path config\control-plane.toml
```

### 9.7 Start UI

```bash
cd ui
npm install
npm run dev
```

### 9.8 MCP Configuration

Set in `.env`:
- `MCP_BASE_URL` — MCP server URL
- `MCP_API_KEY` — Bearer token
- `MCP_HEALTH_PATH` — Health endpoint (default: `/health`)

---

## 10. Deployment Guide

### Linux Server Deployment

1. Provision Ubuntu/Debian server with root access.
2. Install Rust toolchain.
3. Clone repo and build: `cargo build --release`.
4. Configure `config/control-plane.toml`.
5. Run `scripts/linux/setup-server-nat.sh`.
6. Run `vpn_server` binary as systemd service or directly.
7. Open UDP port (default 51820).

### Windows Client Deployment

1. Build on Windows or cross-compile.
2. Bundle `wintun.dll` alongside `vpn-daemon.exe`.
3. Install as service: `vpn-daemon service-install`.
4. Configure `config/control-plane.toml` with server endpoint.

### CI/CD

- GitHub Actions: Linux (fmt + clippy + test), Windows (build).
- Planned: integration tests with network namespaces (v0.3.0).

---

## 11. Future Roadmap

### v0.3.0 — Hardening
- Native WFP kill switch
- bcrypt admin auth with brute-force lockout
- Batched MySQL writes, full schema
- CI integration tests
- External IP verification
- Split-tunnel EXCLUDE action

### v0.4.0 — Multi-Hop
- Onion routing (2-5 hops)
- Node scoring, path selection, health monitoring
- gRPC IPC, netlink routes
- Automatic rekey

### v0.5.0 — Anti-DPI
- TLS mimicry, WebSocket, HTTP/2 tunnels
- Traffic shaping, domain fronting
- Packet fragmentation

### v0.6.0 — Mobile
- macOS (NEPacketTunnelProvider)
- Android (VpnService + JNI)
- Per-app split tunneling

### v0.7.0 — Transport
- QUIC / HTTP/3
- TCP session migration
- Adaptive protocol selection

### v1.0.0 — Production
- Security audit / penetration test
- Enterprise packaging, signed updates
- Multi-platform validation
- Full documentation

---

## Task Management

All project tasks are tracked in [`TASK_MANAGER.md`](TASK_MANAGER.md). This includes platform-specific breakdowns, bug tracking, progress metrics, and GitHub Issue mappings.

### Progress Summary

| Category | Count |
|---|---|
| Completed features | 26 |
| Bug fixes applied | 10 |
| Pending bugs (Critical) | 2 |
| Pending bugs (Medium) | 4 |
| Planned features | 24 |

### Bug Summary (Pending)

| ID | Severity | Module | Issue | Target |
|---|---|---|---|---|
| C-04 | **CRITICAL** | vpn-platform-windows | Native WFP kill switch not authored | v0.3.0 |
| H-02 | **HIGH** | vpn-daemon/server | Server doesn't allocate unique client IPs | v0.3.0 |
| M-05 | **MEDIUM** | vpn-platform-windows | Windows route/WFP cleanup unvalidated | v0.3.0 |
| M-06 | **MEDIUM** | vpn-platform-windows | WFP filter application stubbed | v0.3.0 |
| M-07 | **MEDIUM** | vpn-routing | Split-tunnel EXCLUDE not functional | v0.3.0 |
| L-03 | **LOW** | vpn-daemon | echo_server identical to vpn_server | v0.3.0 |

### Auto-Tracking

Run the task tracker to scan for new TODOs/FIXMEs:
```bash
node scripts/task-tracker.mjs              # Full scan + update TASK_MANAGER.md
node scripts/task-tracker.mjs --scan-only  # Print findings to stdout
node scripts/task-tracker.mjs --json       # Machine-readable output
```

### CI/CD Pipeline

The CI pipeline (`.github/workflows/ci.yml`) runs:
- **Linux**: fmt check + clippy + build + test
- **Windows**: build (debug + release)
- **UI**: lint + TypeScript typecheck
- **Coverage**: cargo-tarpaulin (pushes only)
- **Security**: cargo-deny audit
- **Task scan**: TODO/FIXME detection

---

## Versioning

| Version | Date | Scope |
|---|---|---|
| v0.1.0 | Pre-audit | Initial implementation |
| **v0.2.0** | **2026-03-29** | **Audit release: fixes, server, tests** |
| v0.3.0 | Planned | Hardening: WFP, admin auth, tests, CI |
| v0.4.0 | Planned | Multi-hop, health monitoring, gRPC |
| v0.5.0 | Planned | Anti-DPI obfuscation |
| v0.6.0 | Planned | macOS + Android |
| v0.7.0 | Planned | QUIC, TCP migration |
| v1.0.0 | Planned | Production: audit, packaging |

---

## License

Apache-2.0. See [LICENSE](LICENSE).

## Blueprint

Engineering blueprint: [`Aegis_Style_VPN_Blueprint.md`](../Aegis_Style_VPN_Blueprint.md)

---

> **Designed & Engineered by Santhosh**
> **Approved & Reviewed by Sandy**
