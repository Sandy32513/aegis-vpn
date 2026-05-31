use vpn_crypto::*;

#[test]
fn keypair_shared_secret_symmetric() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    assert_eq!(
        a.shared_secret(b.public_bytes()),
        b.shared_secret(a.public_bytes())
    );
}

#[test]
fn key_derivation_separates_directions() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let init = derive_session_keys(shared, cn, sn, Role::Initiator).unwrap();
    let resp = derive_session_keys(shared, cn, sn, Role::Responder).unwrap();

    assert_eq!(init.send_key, resp.recv_key);
    assert_eq!(init.recv_key, resp.send_key);
    assert_ne!(init.send_key, init.recv_key);
    assert_ne!(init.send_iv, init.recv_iv);
}

#[test]
fn nonce_uniqueness() {
    let iv = [0xAB; 12];
    let mut seen = std::collections::HashSet::new();
    for c in 0..10000u64 {
        let nonce = compute_nonce(&iv, c);
        assert!(seen.insert(nonce), "collision at counter {c}");
    }
}

#[test]
fn seal_open_roundtrip() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let tx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Initiator).unwrap());
    let rx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Responder).unwrap());

    for i in 0..50 {
        let msg = format!("packet {i}");
        let sealed = tx.seal(1, 1, 1, msg.as_bytes()).unwrap();
        let opened = rx
            .open(
                1,
                1,
                1,
                sealed.counter,
                sealed.plaintext_len,
                &sealed.ciphertext,
            )
            .unwrap();
        assert_eq!(opened, msg.as_bytes());
    }
}

#[test]
fn replay_rejected() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let tx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Initiator).unwrap());
    let rx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Responder).unwrap());

    let sealed = tx.seal(1, 1, 1, b"x").unwrap();
    rx.open(
        1,
        1,
        1,
        sealed.counter,
        sealed.plaintext_len,
        &sealed.ciphertext,
    )
    .unwrap();
    assert!(rx
        .open(
            1,
            1,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext
        )
        .is_err());
}

#[test]
fn tampered_ciphertext_fails() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let tx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Initiator).unwrap());
    let rx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Responder).unwrap());

    let mut sealed = tx.seal(1, 1, 1, b"hello").unwrap();
    sealed.ciphertext[0] ^= 0xFF;
    assert!(rx
        .open(
            1,
            1,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext
        )
        .is_err());
}

#[test]
fn wrong_aad_fails() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let tx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Initiator).unwrap());
    let rx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Responder).unwrap());

    let sealed = tx.seal(1, 1, 1, b"hello").unwrap();
    // Different epoch
    assert!(rx
        .open(
            1,
            2,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext
        )
        .is_err());
    // Different packet type
    assert!(rx
        .open(
            2,
            1,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext
        )
        .is_err());
}

#[test]
fn confirm_proof_roundtrip() {
    let key = [0x42; 32];
    let proof = confirm_proof(&key, b"label", 42, [1; 32], [2; 32]).unwrap();
    let confirm = HandshakeConfirm {
        session_id: 42,
        proof,
    };
    assert!(verify_confirm(&key, b"label", &confirm, [1; 32], [2; 32]).is_ok());
    assert!(verify_confirm(&key, b"wrong", &confirm, [1; 32], [2; 32]).is_err());
}

#[test]
fn aad_is_11_bytes() {
    assert_eq!(build_aad(1, 2, 3, 1400).len(), 11);
}

#[test]
fn empty_plaintext_roundtrip() {
    let a = EphemeralKeyPair::generate();
    let b = EphemeralKeyPair::generate();
    let shared = a.shared_secret(b.public_bytes());
    let cn = random_nonce();
    let sn = random_nonce();

    let tx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Initiator).unwrap());
    let rx = SessionCrypto::new(derive_session_keys(shared, cn, sn, Role::Responder).unwrap());

    let sealed = tx.seal(1, 1, 1, b"").unwrap();
    let opened = rx
        .open(
            1,
            1,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext,
        )
        .unwrap();
    assert_eq!(opened, b"");
}

#[test]
fn session_clone_independent_counters() {
    let keys = derive_session_keys([0x11; 32], [0x22; 32], [0x33; 32], Role::Initiator).unwrap();
    let original = SessionCrypto::new(keys.clone());
    let clone = SessionCrypto::new(keys);

    // Both start at counter 0, but increment independently
    let s1 = original.seal(1, 1, 1, b"a").unwrap();
    let s2 = clone.seal(1, 1, 1, b"b").unwrap();
    assert_eq!(s1.counter, 0);
    assert_eq!(s2.counter, 0);
}
