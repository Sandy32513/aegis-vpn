# Testing Strategy

## Automated Tests Present

### Unit tests

- `vpn-crypto`
  - session key derivation round-trip
  - replay window rejection
  - server static proof verification
- `vpn-config`
  - config parsing
  - identity persistence and reload
- `vpn-routing`
  - CIDR rule classification
  - circuit reap behavior
  - IPv6 extension-header parsing
- `vpn-rotation`
  - migrate state transition
- `vpn-transport`
  - frame size encoding sanity

### Integration tests

- `vpn-daemon/tests/control_plane.rs`
  - config-backed runtime resolution
  - trusted server key decode path

## Manual and Scenario Testing Required

### Basic functional path

1. Start Linux routed server.
2. Start client with pinned `trusted_server_public_key`.
3. Verify:
   - client handshake succeeds
   - default route moves to tunnel only after connection
   - public egress IP becomes server egress IP

### Negative trust test

1. Configure an incorrect `client.trusted_server_public_key`.
2. Start client.
3. Expect:
   - handshake failure
   - no default-route activation
   - no kill switch lockout left behind

### Rotation test

1. Lower `rotation_interval_secs` to `15`.
2. Start long-lived and short-lived flows.
3. Verify:
   - new flows migrate to the new circuit
   - draining flows keep using the old circuit until timeout
   - no session-table corruption occurs on server

### Linux kill switch test

1. Start client with `kill_switch = true`.
2. Confirm only loopback, tunnel interface, and server endpoint are allowed.
3. Kill daemon process abruptly.
4. Verify cleanup behavior and whether manual recovery is required.

### Windows client test

1. Install and start Windows service.
2. Verify Wintun adapter configuration and routing.
3. Confirm firewall-backed kill switch behavior.
4. Confirm service stop/uninstall paths restore policy.

## Stress and Failure Scenarios

- high packet-rate UDP bursts with batch size pressure
- packet loss and reordering across the UDP transport
- server restart while client is connected
- circuit rotation during active downloads
- duplicate NAT setup calls
- invalid/malformed IPv4 and IPv6 packets from TUN
- replayed encrypted frames
- IPC requests from non-loopback bind targets

## Not Yet Automated

- end-to-end forwarded traffic in isolated Linux namespaces
- route cleanup after crash on Windows
- native WFP filter installation/removal
- multi-client saturation and memory growth tracking
- continuous rotation under sustained throughput

## Recommended Next CI Additions

1. `cargo fmt --check`
2. `cargo clippy --workspace --all-targets --all-features -D warnings`
3. `cargo test --workspace`
4. Linux integration harness using network namespaces
5. Windows hosted runner build plus service smoke test
