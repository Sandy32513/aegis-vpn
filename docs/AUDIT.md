# Aegis VPN Audit Report

Date: `2026-03-29`

Scope:

- full monorepo static audit
- targeted code fixes
- repository cleanup for public release

Environment note:

- `cargo` and `rustc` were not installed in the working environment used for this audit pass
- compile/test execution could not be performed locally
- all results below are based on source inspection plus code changes applied in-tree

## Verdict

- Release recommendation: `v0.2.0`
- Production recommendation: `not ready for v1.0.0`

## Findings

### Critical

| ID | Status | Area | Issue | Fix / Outcome |
|---|---|---|---|---|
| C-01 | Fixed | Crypto | Client handshake accepted unauthenticated server ephemeral keys, enabling MITM against unpinned deployments. | Added control-plane trust pin plumbing, server static proof fields, and client-side verification logic when a trusted server public key is configured. |
| C-02 | Fixed | Control plane | IPC listener could be configured on a non-loopback address, exposing privileged daemon commands remotely. | Added loopback-only validation before daemon startup. |
| C-03 | Fixed | Client routing | Default-route activation happened before circuit establishment, risking self-inflicted outage and unsafe error handling during startup. | Split TUN creation from route activation and move tunnel activation after successful circuit creation. |
| C-04 | Pending | Windows networking | Native WFP kill switch is still only a wrapper boundary and not a validated production filter implementation. | Repository now documents fallback behavior clearly; full WFP authoring remains required before `v1.0.0`. |

### Medium

| ID | Status | Area | Issue | Fix / Outcome |
|---|---|---|---|---|
| M-01 | Fixed | Server | Server accepted `HandshakeConfirm`, `Data`, and `Keepalive` from unexpected peers if the session ID was known. | Added peer-address checks before session promotion and data acceptance. |
| M-02 | Fixed | Logging | MySQL sink wrote placeholder identifiers into `connection_events`, which did not match the actual event model. | Changed sink to a generic `event_log` table model and added schema docs. |
| M-03 | Fixed | NAT | Repeated Linux NAT setup could duplicate rules across restarts. | NAT enable path now attempts cleanup first; client pool CIDR is validated. |
| M-04 | Fixed | CLI/control plane | Client still required `--server` even when `--config-path` already provided the endpoint. | CLI now supports config-only startup cleanly. |
| M-05 | Fixed | Parsing | IPv4 parser accepted invalid IHL values and could derive nonsense flow metadata. | Added minimum-IHL validation and test coverage. |
| M-06 | Pending | Multi-client routing | Server does not yet allocate or enforce unique inner client tunnel IPs, so large multi-client deployments still depend on external coordination. | Needs control-plane lease assignment or per-client pool management. |
| M-07 | Pending | Admin control | If no admin secret is configured, any local loopback IPC client can request disconnect. | Still open; production deployments must set `admin_secret_env` until a stronger local authorization model is implemented. |
| M-08 | Pending | Lifecycle | Windows service, route cleanup, and WFP cleanup have not been end-to-end validated on a Windows build host. | Requires platform test pass and likely additional teardown handling. |

### Low

| ID | Status | Area | Issue | Fix / Outcome |
|---|---|---|---|---|
| L-01 | Fixed | Docs | README and project metadata did not reflect the routed server, control plane, or real risk status. | Rewrote README and added release docs. |
| L-02 | Fixed | Repo hygiene | Empty helper directories provided no operator guidance. | Added server docs plus Linux/Windows helper scripts. |
| L-03 | Fixed | Testing | Some important behaviors were untested. | Added config persistence and control-plane tests, plus routing coverage improvements. |

## Files Changed During Audit

- `crates/vpn-daemon/src/control_plane.rs`
- `crates/vpn-daemon/src/config.rs`
- `crates/vpn-daemon/src/service.rs`
- `crates/vpn-daemon/src/server/mod.rs`
- `crates/vpn-logger/src/lib.rs`
- `crates/vpn-platform-linux/src/server_nat.rs`
- `crates/vpn-rotation/src/lib.rs`
- `crates/vpn-routing/src/lib.rs`
- `crates/vpn-transport/tests/frame_limits.rs`
- `crates/vpn-config/tests/identity_persistence.rs`
- `crates/vpn-daemon/tests/control_plane.rs`
- `README.md`
- repository support files under `docs/`, `scripts/`, and root metadata files

## Security Score

| Category | Score | Notes |
|---|---|---|
| Security | 68/100 | Major handshake and IPC issues were fixed, but WFP hardening and disconnect authorization still block a production-grade score. |
| Stability | 64/100 | Rotation, routing activation, and NAT idempotency improved, but no compile/runtime validation was possible here. |
| Performance | 72/100 | Data path remains simple and efficient enough for a skeleton, but batching, zero-copy tuning, and scale testing are still limited. |
| Code Quality | 76/100 | Module boundaries are solid and cleaner than before; a few platform abstractions still need polish. |
| Maintainability | 78/100 | Repo structure, docs, and tests improved meaningfully; CI and platform validation are still missing. |

Overall score: `72/100`

## What Was Fixed

- authenticated server trust path wired through config, client, and server
- loopback-only IPC enforcement
- safer tunnel activation order during startup
- server peer validation on established sessions
- MySQL event sink schema alignment
- Linux NAT idempotency and client-pool validation
- config-only client startup
- malformed IPv4 packet handling
- additional unit and integration tests
- release-facing documentation and helper scripts

## What Remains

- complete and validate native Windows WFP filters
- require or otherwise harden admin disconnect authorization
- add compile/test CI and execute cross-platform validation
- add integration tests for real forwarded traffic and kill switch behavior
- validate route teardown on Windows service stop/crash paths

## Semantic Version Recommendation

- `v0.2.0`: current audited cleanup and stabilization release
- `v0.3.0`: Windows hardening, integration tests, CI, admin-control hardening
- `v1.0.0`: only after native Windows enforcement, platform validation, and operational testing are complete
