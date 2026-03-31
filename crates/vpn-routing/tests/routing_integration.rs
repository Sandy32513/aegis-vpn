use vpn_routing::*;

#[test]
fn classify_default_action_is_tunnel() {
    let policy = PolicySet::default();
    let packet = make_ipv4_tcp_packet("10.0.0.1", "8.8.8.8", 12345, 443);
    assert_eq!(policy.classify(&packet, None), RuleAction::Tunnel);
}

#[test]
fn classify_ip_rule() {
    let mut policy = PolicySet::default();
    policy.ip_rules.push(IpRule {
        cidr: "192.168.0.0/16".parse().unwrap(),
        action: RuleAction::Bypass,
    });

    let packet = make_ipv4_tcp_packet("10.0.0.1", "192.168.1.1", 12345, 80);
    assert_eq!(policy.classify(&packet, None), RuleAction::Bypass);

    let packet2 = make_ipv4_tcp_packet("10.0.0.1", "8.8.8.8", 12345, 443);
    assert_eq!(policy.classify(&packet2, None), RuleAction::Tunnel);
}

#[test]
fn classify_port_rule() {
    let mut policy = PolicySet::default();
    policy.port_rules.push(PortRule {
        port: 53,
        action: RuleAction::Drop,
    });

    let packet = make_ipv4_udp_packet("10.0.0.1", "8.8.8.8", 5353, 53);
    assert_eq!(policy.classify(&packet, None), RuleAction::Drop);
}

#[test]
fn flow_key_from_ipv4_packet() {
    let packet = make_ipv4_tcp_packet("10.0.0.1", "8.8.8.8", 12345, 443);
    let flow = FlowKey::from_packet(&packet).expect("should parse");
    assert_eq!(flow.src_ip, "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(flow.dst_ip, "8.8.8.8".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(flow.protocol, 6); // TCP
    assert_eq!(flow.src_port, 12345);
    assert_eq!(flow.dst_port, 443);
}

#[test]
fn flow_key_from_ipv4_udp() {
    let packet = make_ipv4_udp_packet("10.0.0.1", "1.1.1.1", 5353, 53);
    let flow = FlowKey::from_packet(&packet).expect("should parse");
    assert_eq!(flow.protocol, 17); // UDP
    assert_eq!(flow.dst_port, 53);
}

#[test]
fn flow_key_short_packet() {
    assert!(FlowKey::from_packet(&[0x45]).is_none());
    assert!(FlowKey::from_packet(&[]).is_none());
}

#[test]
fn flow_key_invalid_version() {
    assert!(FlowKey::from_packet(&[0x00]).is_none());
}

#[test]
fn flow_table_assign_or_get() {
    let table = FlowTable::default();
    let flow = make_flow("10.0.0.1", "8.8.8.8", 6, 12345, 443);
    let circuit = uuid::Uuid::new_v4();

    let id1 = table.assign_or_get(flow.clone(), circuit, 100);
    let id2 = table.assign_or_get(flow, circuit, 200);
    assert_eq!(id1, id2);
    assert_eq!(id1, circuit);
}

#[test]
fn flow_table_draining() {
    let table = FlowTable::default();
    let c1 = uuid::Uuid::new_v4();
    let c2 = uuid::Uuid::new_v4();

    table.assign_or_get(make_flow("10.0.0.1", "1.1.1.1", 6, 1000, 80), c1, 50);
    table.assign_or_get(make_flow("10.0.0.1", "2.2.2.2", 6, 1001, 443), c1, 50);
    table.assign_or_get(make_flow("10.0.0.1", "3.3.3.3", 6, 1002, 22), c2, 50);

    table.mark_circuit_draining(c1);
    table.reap_circuit(c1);

    // c2 flows should still be present
    let flow3 = make_flow("10.0.0.1", "3.3.3.3", 6, 1002, 22);
    assert_eq!(table.assign_or_get(flow3, c2, 50), c2);
}

#[test]
fn flow_key_ipv6_basic() {
    let mut packet = vec![0u8; 60];
    packet[0] = 0x60; // IPv6 version
    packet[6] = 6; // TCP next header
                   // src: 2001:db8::1
    packet[8..24].copy_from_slice(&hex::decode("20010db8000000000000000000000001").unwrap());
    // dst: 2001:db8::2
    packet[24..40].copy_from_slice(&hex::decode("20010db8000000000000000000000002").unwrap());
    // TCP header
    packet[40] = 0x04; // src port high
    packet[41] = 0xD2; // src port low = 1234
    packet[42] = 0x01; // dst port high
    packet[43] = 0xBB; // dst port low = 443

    let flow = FlowKey::from_packet(&packet).expect("should parse IPv6");
    assert_eq!(flow.dst_port, 443);
    assert_eq!(flow.protocol, 6);
}

// --- helpers ---

fn make_ipv4_tcp_packet(src: &str, dst: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[9] = 6; // TCP
    let s: std::net::Ipv4Addr = src.parse().unwrap();
    let d: std::net::Ipv4Addr = dst.parse().unwrap();
    pkt[12..16].copy_from_slice(&s.octets());
    pkt[16..20].copy_from_slice(&d.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt
}

fn make_ipv4_udp_packet(src: &str, dst: &str, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[9] = 17; // UDP
    let s: std::net::Ipv4Addr = src.parse().unwrap();
    let d: std::net::Ipv4Addr = dst.parse().unwrap();
    pkt[12..16].copy_from_slice(&s.octets());
    pkt[16..20].copy_from_slice(&d.octets());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt
}

fn make_flow(src: &str, dst: &str, proto: u8, src_port: u16, dst_port: u16) -> FlowKey {
    FlowKey {
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        protocol: proto,
        src_port,
        dst_port,
    }
}
