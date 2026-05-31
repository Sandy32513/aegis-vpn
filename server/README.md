# Server Notes

The current server implementation is Linux-only and uses a routed forwarding model:

1. receive encrypted UDP frame
2. decrypt into an IP packet
3. inject into a server TUN device
4. rely on Linux IP forwarding and NAT for Internet egress
5. read return traffic from TUN
6. map destination IP back to an active client session
7. encrypt and return the frame to the correct client

Important operational notes:

- enable `net.ipv4.ip_forward=1`
- configure either `iptables` or `nftables`
- use a dedicated private client pool CIDR
- validate that the `egress_interface` in config matches the real outbound NIC

See [server-nat.md](../docs/server-nat.md) and [setup-server-nat.sh](../scripts/linux/setup-server-nat.sh).
