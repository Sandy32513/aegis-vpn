use vpn_crypto::{
    build_server_static_proof, random_nonce, verify_server_static_proof, EphemeralKeyPair,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[test]
fn server_static_proof_verifies_against_pinned_key() {
    let client_eph = EphemeralKeyPair::generate();
    let server_eph = EphemeralKeyPair::generate();
    let server_static = StaticSecret::random_from_rng(rand_core::OsRng);
    let server_static_public = PublicKey::from(&server_static).to_bytes();
    let client_nonce = random_nonce();
    let server_nonce = random_nonce();

    let proof = build_server_static_proof(
        server_static.to_bytes(),
        client_eph.public_bytes(),
        server_eph.public_bytes(),
        server_static_public,
        42,
        client_nonce,
        server_nonce,
    )
    .expect("build server proof");

    verify_server_static_proof(
        &client_eph,
        server_eph.public_bytes(),
        server_static_public,
        42,
        client_nonce,
        server_nonce,
        proof,
    )
    .expect("verify server proof");
}
