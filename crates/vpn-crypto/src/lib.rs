use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use anyhow::{anyhow, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeInit {
    pub client_public: [u8; 32],
    pub client_nonce: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub server_public: [u8; 32],
    pub server_static_public: [u8; 32],
    pub server_static_proof: [u8; 32],
    pub server_nonce: [u8; 32],
    pub session_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HandshakeConfirm {
    pub session_id: u64,
    pub proof: [u8; 32],
}

#[derive(Clone)]
pub struct EphemeralKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn shared_secret(&self, peer_public: [u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(peer_public);
        self.secret.diffie_hellman(&peer).to_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct SessionKeys {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub send_iv: [u8; 12],
    pub recv_iv: [u8; 12],
    pub confirm_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedPayload {
    pub counter: u64,
    pub ciphertext: Vec<u8>,
    pub plaintext_len: u16,
}

const REPLAY_WINDOW_SIZE: usize = 2048;

/// Sliding window replay detector. Tracks which counter values have been
/// accepted and rejects duplicates or out-of-window packets.
#[derive(Debug)]
struct ReplayWindow {
    window: [u64; REPLAY_WINDOW_SIZE / 64],
    highest: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            window: [0u64; REPLAY_WINDOW_SIZE / 64],
            highest: 0,
        }
    }

    /// Returns true if the counter is acceptable (not a replay).
    fn check_and_update(&mut self, counter: u64) -> bool {
        if counter == 0 && self.highest == 0 && !self.get_bit(0) {
            // First packet ever
            self.highest = counter;
            self.set_bit(0);
            return true;
        }

        if counter > self.highest {
            // New highest — shift window
            let shift = (counter - self.highest) as usize;
            if shift >= REPLAY_WINDOW_SIZE {
                // Large jump: clear entire window
                self.window.fill(0);
            } else {
                // Shift window bits right by `shift`
                for _ in 0..shift {
                    // Shift all words right by 1 bit
                    for i in (1..self.window.len()).rev() {
                        self.window[i] = (self.window[i] >> 1) | (self.window[i - 1] << 63);
                    }
                    self.window[0] >>= 1;
                }
            }
            self.highest = counter;
            self.set_bit(0);
            true
        } else {
            // Within window
            let diff = (self.highest - counter) as usize;
            if diff >= REPLAY_WINDOW_SIZE {
                return false; // Too old
            }
            if self.get_bit(diff) {
                return false; // Already seen — replay
            }
            self.set_bit(diff);
            true
        }
    }

    fn set_bit(&mut self, index: usize) {
        let word = index / 64;
        let bit = index % 64;
        if word < self.window.len() {
            self.window[word] |= 1u64 << bit;
        }
    }

    fn get_bit(&self, index: usize) -> bool {
        let word = index / 64;
        let bit = index % 64;
        if word < self.window.len() {
            self.window[word] & (1u64 << bit) != 0
        } else {
            false
        }
    }
}

impl Clone for ReplayWindow {
    fn clone(&self) -> Self {
        Self {
            window: self.window,
            highest: self.highest,
        }
    }
}

#[derive(Debug)]
pub struct SessionCrypto {
    keys: SessionKeys,
    send_counter: AtomicU64,
    recv_window: Mutex<ReplayWindow>,
}

impl Clone for SessionCrypto {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            send_counter: AtomicU64::new(self.send_counter.load(Ordering::Relaxed)),
            recv_window: Mutex::new(self.recv_window.lock().clone()),
        }
    }
}

impl SessionCrypto {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            send_counter: AtomicU64::new(0),
            recv_window: Mutex::new(ReplayWindow::new()),
        }
    }

    pub fn seal(
        &self,
        packet_type: u8,
        epoch: u32,
        path_id: u32,
        plaintext: &[u8],
    ) -> Result<SealedPayload> {
        let counter = self.send_counter.fetch_add(1, Ordering::Relaxed);
        let aad = build_aad(packet_type, epoch, path_id, plaintext.len() as u16);
        let ciphertext = seal_with_key(
            &self.keys.send_key,
            &self.keys.send_iv,
            counter,
            &aad,
            plaintext,
        )?;
        Ok(SealedPayload {
            counter,
            ciphertext,
            plaintext_len: plaintext.len() as u16,
        })
    }

    pub fn open(
        &self,
        packet_type: u8,
        epoch: u32,
        path_id: u32,
        counter: u64,
        plaintext_len: u16,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        if !self.recv_window.lock().check_and_update(counter) {
            return Err(anyhow!(
                "replay detected: counter {counter} already seen or too old"
            ));
        }
        let aad = build_aad(packet_type, epoch, path_id, plaintext_len);
        open_with_key(
            &self.keys.recv_key,
            &self.keys.recv_iv,
            counter,
            &aad,
            ciphertext,
        )
    }

    pub fn confirm_key(&self) -> &[u8; 32] {
        &self.keys.confirm_key
    }
}

pub fn random_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

pub fn derive_session_keys(
    shared_secret: [u8; 32],
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    role: Role,
) -> Result<SessionKeys> {
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(client_nonce);
    salt_hasher.update(server_nonce);
    let salt = salt_hasher.finalize();

    let hk = Hkdf::<Sha256>::new(Some(salt.as_ref()), &shared_secret);
    let c2s_key = expand_32(&hk, b"aegis:c2s:key")?;
    let s2c_key = expand_32(&hk, b"aegis:s2c:key")?;
    let c2s_iv = expand_12(&hk, b"aegis:c2s:iv")?;
    let s2c_iv = expand_12(&hk, b"aegis:s2c:iv")?;
    let confirm_key = expand_32(&hk, b"aegis:confirm:key")?;

    let (send_key, recv_key, send_iv, recv_iv) = match role {
        Role::Initiator => (c2s_key, s2c_key, c2s_iv, s2c_iv),
        Role::Responder => (s2c_key, c2s_key, s2c_iv, c2s_iv),
    };

    Ok(SessionKeys {
        send_key,
        recv_key,
        send_iv,
        recv_iv,
        confirm_key,
    })
}

pub fn build_confirm(
    confirm_key: &[u8; 32],
    label: &[u8],
    session_id: u64,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<HandshakeConfirm> {
    Ok(HandshakeConfirm {
        session_id,
        proof: confirm_proof(confirm_key, label, session_id, client_nonce, server_nonce)?,
    })
}

pub fn confirm_proof(
    confirm_key: &[u8; 32],
    label: &[u8],
    session_id: u64,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<[u8; 32]> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(confirm_key)
        .map_err(|e| anyhow!("invalid confirm key: {e}"))?;
    mac.update(label);
    mac.update(&session_id.to_be_bytes());
    mac.update(&client_nonce);
    mac.update(&server_nonce);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn verify_confirm(
    confirm_key: &[u8; 32],
    label: &[u8],
    confirm: &HandshakeConfirm,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<()> {
    let expected = confirm_proof(
        confirm_key,
        label,
        confirm.session_id,
        client_nonce,
        server_nonce,
    )?;
    if constant_time_eq(&expected, &confirm.proof) {
        Ok(())
    } else {
        Err(anyhow!("handshake confirm verification failed"))
    }
}

pub fn build_server_static_proof(
    server_static_private: [u8; 32],
    client_public: [u8; 32],
    server_public: [u8; 32],
    server_static_public: [u8; 32],
    session_id: u64,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<[u8; 32]> {
    let auth_shared = StaticSecret::from(server_static_private)
        .diffie_hellman(&PublicKey::from(client_public))
        .to_bytes();
    build_server_static_proof_from_shared(
        auth_shared,
        server_public,
        server_static_public,
        session_id,
        client_nonce,
        server_nonce,
    )
}

pub fn verify_server_static_proof(
    client_ephemeral: &EphemeralKeyPair,
    server_public: [u8; 32],
    server_static_public: [u8; 32],
    session_id: u64,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    proof: [u8; 32],
) -> Result<()> {
    let auth_shared = client_ephemeral.shared_secret(server_static_public);
    let expected = build_server_static_proof_from_shared(
        auth_shared,
        server_public,
        server_static_public,
        session_id,
        client_nonce,
        server_nonce,
    )?;

    if constant_time_eq(&expected, &proof) {
        Ok(())
    } else {
        Err(anyhow!("server static proof verification failed"))
    }
}

pub fn compute_nonce(static_iv: &[u8; 12], counter: u64) -> [u8; 12] {
    let mut nonce = *static_iv;
    for (dst, src) in nonce[4..].iter_mut().zip(counter.to_be_bytes()) {
        *dst ^= src;
    }
    nonce
}

pub fn build_aad(packet_type: u8, epoch: u32, path_id: u32, plaintext_len: u16) -> [u8; 11] {
    let mut aad = [0u8; 11];
    aad[0] = packet_type;
    aad[1..3].copy_from_slice(&plaintext_len.to_be_bytes());
    aad[3..7].copy_from_slice(&epoch.to_be_bytes());
    aad[7..11].copy_from_slice(&path_id.to_be_bytes());
    aad
}

pub fn seal_with_key(
    key: &[u8; 32],
    iv: &[u8; 12],
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("cipher init failed: {e}"))?;
    let nonce = compute_nonce(iv, counter);
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| anyhow!("encryption failed: {e}"))
}

pub fn open_with_key(
    key: &[u8; 32],
    iv: &[u8; 12],
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("cipher init failed: {e}"))?;
    let nonce = compute_nonce(iv, counter);
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| anyhow!("decryption failed: {e}"))
}

fn expand_32(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow!("hkdf expand failed for {}", hex::encode(info)))?;
    Ok(out)
}

fn expand_12(hk: &Hkdf<Sha256>, info: &[u8]) -> Result<[u8; 12]> {
    let mut out = [0u8; 12];
    hk.expand(info, &mut out)
        .map_err(|_| anyhow!("hkdf expand failed for {}", hex::encode(info)))?;
    Ok(out)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn build_server_static_proof_from_shared(
    auth_shared: [u8; 32],
    server_public: [u8; 32],
    server_static_public: [u8; 32],
    session_id: u64,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), &auth_shared);
    let proof_key = expand_32(&hk, b"aegis:server-static:proof")?;

    let mut mac = <HmacSha256 as Mac>::new_from_slice(&proof_key)
        .map_err(|e| anyhow!("invalid server proof key: {e}"))?;
    mac.update(b"server-static");
    mac.update(&session_id.to_be_bytes());
    mac.update(&server_public);
    mac.update(&server_static_public);
    mac.update(&client_nonce);
    mac.update(&server_nonce);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let initiator = EphemeralKeyPair::generate();
        let responder = EphemeralKeyPair::generate();
        let client_nonce = random_nonce();
        let server_nonce = random_nonce();

        let initiator_keys = derive_session_keys(
            initiator.shared_secret(responder.public_bytes()),
            client_nonce,
            server_nonce,
            Role::Initiator,
        )
        .expect("derive initiator keys");
        let responder_keys = derive_session_keys(
            responder.shared_secret(initiator.public_bytes()),
            client_nonce,
            server_nonce,
            Role::Responder,
        )
        .expect("derive responder keys");

        let tx = SessionCrypto::new(initiator_keys);
        let rx = SessionCrypto::new(responder_keys);
        let sealed = tx.seal(1, 1, 1, b"hello world").expect("seal");
        let opened = rx
            .open(
                1,
                1,
                1,
                sealed.counter,
                sealed.plaintext_len,
                &sealed.ciphertext,
            )
            .expect("open");
        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn replay_is_rejected() {
        let initiator = EphemeralKeyPair::generate();
        let responder = EphemeralKeyPair::generate();
        let client_nonce = random_nonce();
        let server_nonce = random_nonce();

        let initiator_keys = derive_session_keys(
            initiator.shared_secret(responder.public_bytes()),
            client_nonce,
            server_nonce,
            Role::Initiator,
        )
        .expect("derive initiator keys");
        let responder_keys = derive_session_keys(
            responder.shared_secret(initiator.public_bytes()),
            client_nonce,
            server_nonce,
            Role::Responder,
        )
        .expect("derive responder keys");

        let tx = SessionCrypto::new(initiator_keys);
        let rx = SessionCrypto::new(responder_keys);
        let sealed = tx.seal(1, 1, 1, b"hello world").expect("seal");
        rx.open(
            1,
            1,
            1,
            sealed.counter,
            sealed.plaintext_len,
            &sealed.ciphertext,
        )
        .expect("first receive");
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
}
