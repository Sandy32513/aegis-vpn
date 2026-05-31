# Linux NAT Integration

The Phase 2 server path uses a Linux TUN interface plus kernel forwarding/NAT.

Required kernel setting:

```bash
sysctl -w net.ipv4.ip_forward=1
```

Iptables mode:

```bash
iptables -t nat -A POSTROUTING -s 10.20.0.0/24 -o eth0 -j MASQUERADE
iptables -A FORWARD -i aegis-srv0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o aegis-srv0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

Nftables mode:

```bash
nft add table inet aegis_vpn_srv
nft add chain inet aegis_vpn_srv forward { type filter hook forward priority 0 \; policy drop \; }
nft add chain ip aegis_vpn_srv postrouting { type nat hook postrouting priority 100 \; }
nft add rule inet aegis_vpn_srv forward iifname "aegis-srv0" oifname "eth0" accept
nft add rule inet aegis_vpn_srv forward iifname "eth0" oifname "aegis-srv0" ct state established,related accept
nft add rule ip aegis_vpn_srv postrouting ip saddr 10.20.0.0/24 oifname "eth0" masquerade
```

The Rust server module uses the same model programmatically:

1. Decrypt client packet.
2. Inject it into the server TUN.
3. Let kernel routing + NAT forward it.
4. Read return packet from TUN.
5. Encrypt and send back to the correct client session.

Helper scripts:

- [setup-server-nat.sh](../scripts/linux/setup-server-nat.sh)
- [cleanup-server-nat.sh](../scripts/linux/cleanup-server-nat.sh)
