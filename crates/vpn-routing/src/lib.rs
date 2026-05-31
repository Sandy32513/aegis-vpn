use ipnet::IpNet;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Instant,
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowContext {
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    pub domain: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    Tunnel,
    Bypass,
    Drop,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRule {
    pub process_name: String,
    pub action: RuleAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DomainRule {
    pub suffix: String,
    pub action: RuleAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpRule {
    pub cidr: IpNet,
    pub action: RuleAction,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortRule {
    pub port: u16,
    pub action: RuleAction,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicySet {
    pub process_rules: Vec<ProcessRule>,
    pub domain_rules: Vec<DomainRule>,
    pub ip_rules: Vec<IpRule>,
    pub port_rules: Vec<PortRule>,
}

impl PolicySet {
    pub fn classify(&self, packet: &[u8], context: Option<&FlowContext>) -> RuleAction {
        if let Some(ctx) = context {
            if let Some(name) = &ctx.process_name {
                if let Some(rule) = self
                    .process_rules
                    .iter()
                    .find(|r| r.process_name.eq_ignore_ascii_case(name))
                {
                    return rule.action.clone();
                }
            }

            if let Some(domain) = &ctx.domain {
                if let Some(rule) = self
                    .domain_rules
                    .iter()
                    .find(|r| domain.ends_with(&r.suffix))
                {
                    return rule.action.clone();
                }
            }
        }

        if let Some(flow) = FlowKey::from_packet(packet) {
            if let Some(rule) = self.ip_rules.iter().find(|r| r.cidr.contains(&flow.dst_ip)) {
                return rule.action.clone();
            }

            if let Some(rule) = self.port_rules.iter().find(|r| r.port == flow.dst_port) {
                return rule.action.clone();
            }
        }

        RuleAction::Tunnel
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub src_port: u16,
    pub dst_port: u16,
}

impl PartialEq for FlowKey {
    fn eq(&self, other: &Self) -> bool {
        self.src_ip == other.src_ip
            && self.dst_ip == other.dst_ip
            && self.protocol == other.protocol
            && self.src_port == other.src_port
            && self.dst_port == other.dst_port
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.protocol.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
    }
}

impl FlowKey {
    pub fn from_packet(packet: &[u8]) -> Option<Self> {
        let version = packet.first().map(|v| v >> 4)?;
        match version {
            4 => parse_ipv4(packet),
            6 => parse_ipv6(packet),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlowRecord {
    pub flow: FlowKey,
    pub circuit_id: Uuid,
    pub created_at: Instant,
    pub last_seen: Instant,
    pub bytes_up: u64,
    pub draining: bool,
}

#[derive(Default)]
pub struct FlowTable {
    inner: RwLock<HashMap<FlowKey, FlowRecord>>,
}

impl FlowTable {
    pub fn assign_or_get(&self, flow: FlowKey, active_circuit: Uuid, bytes: usize) -> Uuid {
        let now = Instant::now();
        let mut guard = self.inner.write();
        let entry = guard.entry(flow.clone()).or_insert_with(|| FlowRecord {
            flow,
            circuit_id: active_circuit,
            created_at: now,
            last_seen: now,
            bytes_up: 0,
            draining: false,
        });

        entry.last_seen = now;
        entry.bytes_up = entry.bytes_up.saturating_add(bytes as u64);
        entry.circuit_id
    }

    pub fn mark_circuit_draining(&self, circuit_id: Uuid) {
        for record in self.inner.write().values_mut() {
            if record.circuit_id == circuit_id {
                record.draining = true;
            }
        }
    }

    pub fn reap_circuit(&self, circuit_id: Uuid) {
        self.inner
            .write()
            .retain(|_, record| record.circuit_id != circuit_id);
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 20 {
        return None;
    }

    let ihl = usize::from((packet[0] & 0x0f) * 4);
    if ihl < 20 {
        return None;
    }
    if packet.len() < ihl + 4 {
        return None;
    }

    let protocol = packet[9];
    let src_ip = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    let (src_port, dst_port) = parse_ports(protocol, &packet[ihl..])?;

    Some(FlowKey {
        src_ip,
        dst_ip,
        protocol,
        src_port,
        dst_port,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<FlowKey> {
    if packet.len() < 40 {
        return None;
    }

    let mut next_header = packet[6];
    let mut offset = 40usize;

    // Skip IPv6 extension headers to find the transport header
    loop {
        match next_header {
            // TCP, UDP, ICMPv6 — these are the final headers
            6 | 17 | 58 => break,
            // Hop-by-Hop (0), Routing (43), Destination Options (60), Mobility (135)
            // Fragment header (44) has a fixed 8-byte size
            0 | 43 | 44 | 60 | 135 => {
                let hdr_len = if next_header == 44 {
                    8
                } else {
                    if offset + 2 > packet.len() {
                        return None;
                    }
                    let ext_len = usize::from(packet[offset + 1]);
                    8 + ext_len * 8
                };
                if offset + hdr_len > packet.len() {
                    return None;
                }
                next_header = packet[offset];
                offset += hdr_len;
            }
            // Unknown next header — cannot extract ports
            _ => {
                return Some(FlowKey {
                    src_ip: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
                    dst_ip: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
                    protocol: next_header,
                    src_port: 0,
                    dst_port: 0,
                })
            }
        }
    }

    let src_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let dst_ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    let (src_port, dst_port) = parse_ports(next_header, &packet[offset..])?;

    Some(FlowKey {
        src_ip,
        dst_ip,
        protocol: next_header,
        src_port,
        dst_port,
    })
}

fn parse_ports(protocol: u8, payload: &[u8]) -> Option<(u16, u16)> {
    match protocol {
        6 | 17 => {
            if payload.len() < 4 {
                return None;
            }

            Some((
                u16::from_be_bytes([payload[0], payload[1]]),
                u16::from_be_bytes([payload[2], payload[3]]),
            ))
        }
        _ => Some((0, 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn classify_ip_rule() {
        let policy = PolicySet {
            ip_rules: vec![IpRule {
                cidr: "10.0.0.0/8".parse().expect("parse cidr"),
                action: RuleAction::Bypass,
            }],
            ..PolicySet::default()
        };

        let packet = [
            0x45, 0x00, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0, 192, 0, 2, 1, 10, 1, 2, 3, 0x12, 0x34,
            0x00, 0x50,
        ];
        assert_eq!(policy.classify(&packet, None), RuleAction::Bypass);
    }

    #[test]
    fn flow_table_reaps_old_circuit() {
        let table = FlowTable::default();
        let flow = FlowKey {
            src_ip: "192.0.2.1".parse().expect("parse src ip"),
            dst_ip: "198.51.100.8".parse().expect("parse dst ip"),
            protocol: 6,
            src_port: 12345,
            dst_port: 443,
        };
        let circuit = Uuid::new_v4();
        let assigned = table.assign_or_get(flow, circuit, 128);
        assert_eq!(assigned, circuit);
        table.reap_circuit(circuit);
    }

    #[test]
    fn parse_ipv6_with_hop_by_hop_extension() {
        let packet = [
            0x60, 0, 0, 0, 0, 16, 0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 17, 0, 0, 0, 0, 0, 0, 0,
            0x12, 0x34, 0x00, 0x35, 0, 8, 0, 0,
        ];

        let flow = FlowKey::from_packet(&packet).expect("parse ipv6 flow");
        assert_eq!(flow.protocol, 17);
        assert_eq!(flow.src_port, 0x1234);
        assert_eq!(flow.dst_port, 53);
    }
}
