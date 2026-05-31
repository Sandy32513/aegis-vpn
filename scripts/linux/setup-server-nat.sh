#!/usr/bin/env bash
set -euo pipefail

CLIENT_POOL_CIDR="${CLIENT_POOL_CIDR:-10.20.0.0/24}"
EGRESS_IFACE="${EGRESS_IFACE:-eth0}"
TUN_NAME="${TUN_NAME:-aegis-srv0}"
NAT_MODE="${NAT_MODE:-iptables}"

sysctl -w net.ipv4.ip_forward=1

if [[ "${NAT_MODE}" == "iptables" ]]; then
  iptables -t nat -D POSTROUTING -s "${CLIENT_POOL_CIDR}" -o "${EGRESS_IFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "${TUN_NAME}" -o "${EGRESS_IFACE}" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${EGRESS_IFACE}" -o "${TUN_NAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true

  iptables -t nat -A POSTROUTING -s "${CLIENT_POOL_CIDR}" -o "${EGRESS_IFACE}" -j MASQUERADE
  iptables -A FORWARD -i "${TUN_NAME}" -o "${EGRESS_IFACE}" -j ACCEPT
  iptables -A FORWARD -i "${EGRESS_IFACE}" -o "${TUN_NAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT
else
  nft delete table inet aegis_vpn_srv 2>/dev/null || true
  nft delete table ip aegis_vpn_srv_ip 2>/dev/null || true

  nft add table inet aegis_vpn_srv
  nft add chain inet aegis_vpn_srv forward "{ type filter hook forward priority 0 ; policy drop ; }"
  nft add table ip aegis_vpn_srv_ip
  nft add chain ip aegis_vpn_srv_ip postrouting "{ type nat hook postrouting priority 100 ; }"
  nft add rule inet aegis_vpn_srv forward iifname "${TUN_NAME}" oifname "${EGRESS_IFACE}" accept
  nft add rule inet aegis_vpn_srv forward iifname "${EGRESS_IFACE}" oifname "${TUN_NAME}" ct state established,related accept
  nft add rule ip aegis_vpn_srv_ip postrouting ip saddr "${CLIENT_POOL_CIDR}" oifname "${EGRESS_IFACE}" masquerade
fi
