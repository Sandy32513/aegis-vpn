#!/usr/bin/env bash
set -euo pipefail

CLIENT_POOL_CIDR="${CLIENT_POOL_CIDR:-10.20.0.0/24}"
EGRESS_IFACE="${EGRESS_IFACE:-eth0}"
TUN_NAME="${TUN_NAME:-aegis-srv0}"
NAT_MODE="${NAT_MODE:-iptables}"

if [[ "${NAT_MODE}" == "iptables" ]]; then
  iptables -t nat -D POSTROUTING -s "${CLIENT_POOL_CIDR}" -o "${EGRESS_IFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -D FORWARD -i "${TUN_NAME}" -o "${EGRESS_IFACE}" -j ACCEPT 2>/dev/null || true
  iptables -D FORWARD -i "${EGRESS_IFACE}" -o "${TUN_NAME}" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
else
  nft delete table inet aegis_vpn_srv 2>/dev/null || true
  nft delete table ip aegis_vpn_srv_ip 2>/dev/null || true
fi
