use bincode::Options;
use vpn_transport::WireFrame;

#[test]
fn keepalive_frame_is_small() {
    let frame = WireFrame::Keepalive { session_id: 7 };
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&frame)
        .expect("serialize frame");
    assert!(bytes.len() < 128);
}
