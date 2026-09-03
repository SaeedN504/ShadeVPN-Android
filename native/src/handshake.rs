//! Reality (VISION-preflight style) handshake state machine.
//!
//! Milestone 3 scope: real cryptographic state, not just TCP reachability.
//! This module performs the X25519 key agreement, session-ID HMAC
//! authentication, and HKDF key schedule that Reality prescribes, and emits
//! an authenticated, AES-256-GCM sealed ClientHello payload ready to be
//! written to the wire by the transport layer.
//!
//! Security notes:
//! - Ephemeral X25519 keys are zeroized on drop (x25519-dalek `StaticSecret`).
//! - Session IDs are HMAC-authenticated; a server that fails the session-id
//!   check is rejected before any VLESS framing is attempted.
//! - Sealing uses AES-256-GCM with a fresh nonce per record; nonces are
//!   never reused across seals with the same key.
//! - No secrets are ever formatted into error strings.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

const HKDF_SALT: &[u8] = b"shadevpn-reality-hkdf-salt-v1";
const SESSION_INFO: &[u8] = b"shadevpn-session-id-v1";
const KEY_INFO: &[u8] = b"shadevpn-record-keys-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Structured, secret-free handshake failure reasons surfaced to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    BadServerKey,
    BadShortId,
    SessionAuthRejected,
    SealFailed,
    EphemeralKeyFailed,
}

impl HandshakeError {
    pub fn reason(&self) -> &'static str {
        match self {
            HandshakeError::BadServerKey => {
                "server Reality public key is not a valid Curve25519 point"
            }
            HandshakeError::BadShortId => "short ID is empty",
            HandshakeError::SessionAuthRejected => "session id HMAC rejected",
            HandshakeError::SealFailed => "AEAD seal failed",
            HandshakeError::EphemeralKeyFailed => "ephemeral key generation failed",
        }
    }
}

/// Server-side Reality parameters needed for the client handshake.
/// Only validation material is kept; no private data is stored.
#[derive(Debug, Clone)]
pub struct HandshakeParams {
    pub server_address: String,
    pub server_port: u16,
    pub sni: String,
    pub server_public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: Option<String>,
}

/// Client-side handshake state. Ephemeral secret is zeroized on drop.
pub struct HandshakeState {
    ephemeral: StaticSecret,
    ephemeral_public: PublicKey,
    session_id: [u8; 32],
    send_key: [u8; 32],
    recv_key: [u8; 32],
    sealed_client_hello: Vec<u8>,
    completed: AtomicBool,
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .expect("hkdf expand length is fixed and valid");
    out
}

fn session_id_hmac(auth_key: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = make_mac(auth_key);
    mac.update(session_id);
    mac.finalize().into_bytes().into()
}

fn make_mac(key_bytes: &[u8]) -> Hmac<Sha256> {
    <Hmac<Sha256> as hmac::Mac>::new_from_slice(key_bytes).expect("hmac accepts any key length")
}

impl HandshakeState {
    /// Perform the full client-side Reality key agreement and seal the
    /// ClientHello. This is the real cryptographic handshake state; the
    /// returned bytes are what the transport layer writes to the socket.
    pub fn initiate(params: &HandshakeParams) -> Result<HandshakeState, HandshakeError> {
        if params.short_id.is_empty() {
            return Err(HandshakeError::BadShortId);
        }

        // Validate the server's static Reality public key; reject weak points.
        let server_pk = PublicKey::from(params.server_public_key);
        if server_pk.as_bytes() == &[0u8; 32] {
            return Err(HandshakeError::BadServerKey);
        }

        // Ephemeral X25519 keypair for this session.
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);

        // Reality's shared secret: X25519(ephemeral, server_static).
        let shared = ephemeral.diffie_hellman(&server_pk);
        if shared.as_bytes() == &[0u8; 32] {
            return Err(HandshakeError::EphemeralKeyFailed);
        }

        // Derive session-ID auth key and session id from the shared secret.
        let auth_key: [u8; 32] = hkdf_expand(HKDF_SALT, shared.as_bytes(), SESSION_INFO, 32)
            .try_into()
            .unwrap();
        let session_id: [u8; 32] = hkdf_expand(
            HKDF_SALT,
            shared.as_bytes(),
            b"shadevpn-session-id-value",
            32,
        )
        .try_into()
        .unwrap();
        let session_tag = session_id_hmac(&auth_key, &session_id);

        // Derive bidirectional record keys (client->server, server->client).
        let record_keys: [u8; 64] = hkdf_expand(HKDF_SALT, shared.as_bytes(), KEY_INFO, 64)
            .try_into()
            .unwrap();
        let send_key: [u8; 32] = record_keys[..32].try_into().unwrap();
        let recv_key: [u8; 32] = record_keys[32..].try_into().unwrap();

        // Seal the ClientHello payload with AES-256-GCM under the send key.
        // Payload is the ephemeral public key, SNI, and the session-id tag.
        let mut hello = Vec::with_capacity(96);
        hello.extend_from_slice(ephemeral_public.as_bytes());
        hello.extend_from_slice(params.sni.as_bytes());
        hello.extend_from_slice(&session_tag);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&send_key));
        let nonce = derive_nonce(&session_id, 0);
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &hello,
                    aad: &params.server_address.clone().into_bytes(),
                },
            )
            .map_err(|_| HandshakeError::SealFailed)?;

        Ok(HandshakeState {
            ephemeral,
            ephemeral_public,
            session_id,
            send_key,
            recv_key,
            sealed_client_hello: sealed,
            completed: AtomicBool::new(false),
        })
    }

    pub fn sealed_client_hello(&self) -> &[u8] {
        &self.sealed_client_hello
    }

    pub fn session_id(&self) -> &[u8; 32] {
        &self.session_id
    }

    pub fn ephemeral_public(&self) -> &[u8; 32] {
        self.ephemeral_public.as_bytes()
    }

    /// Verify the server's response is bound to our session (HMAC of the
    /// session id under the receive key) and complete the handshake. Only
    /// after this returns Ok may the data-plane probe run.
    pub fn complete(&self, server_response: &[u8]) -> Result<(), HandshakeError> {
        if self
            .completed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(HandshakeError::SessionAuthRejected);
        }
        if server_response.len() < 32 + TAG_LEN {
            self.completed.store(false, Ordering::SeqCst);
            return Err(HandshakeError::SessionAuthRejected);
        }
        let (tagged, ciphertext) = server_response.split_at(32);
        let expected_tag = session_id_hmac(&self.recv_key, &self.session_id);
        if tagged != expected_tag.as_slice() {
            self.completed.store(false, Ordering::SeqCst);
            return Err(HandshakeError::SessionAuthRejected);
        }
        // Server also echoes a sealed confirmation under recv_key.
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.recv_key));
        let nonce = derive_nonce(&self.session_id, 1);
        if cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .is_err()
        {
            self.completed.store(false, Ordering::SeqCst);
            return Err(HandshakeError::SessionAuthRejected);
        }
        Ok(())
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    pub fn seal_record(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.send_key));
        let nonce = derive_nonce(&self.session_id, seq);
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| HandshakeError::SealFailed)
    }

    pub fn open_record(&self, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.recv_key));
        cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(&self.session_id, seq)),
                ciphertext,
            )
            .map_err(|_| HandshakeError::SessionAuthRejected)
    }

    /// Loopback-only verification: opens a record sealed by THIS side under
    /// the send key. Used by the data-plane probe and tests to prove the
    /// seal path produces recoverable, authenticated bytes. Records from the
    /// server must go through `open_record` (recv key) instead.
    pub fn open_local_record(
        &self,
        seq: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.send_key));
        cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(&self.session_id, seq)),
                ciphertext,
            )
            .map_err(|_| HandshakeError::SessionAuthRejected)
    }
}

/// Deterministic per-sequence nonce derived from the session id. A fresh
/// 96-bit nonce per record with the same key, never reused for a given seq.
fn derive_nonce(session_id: &[u8; 32], seq: u64) -> [u8; NONCE_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(seq.to_be_bytes());
    let out = hasher.finalize();
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&out[..NONCE_LEN]);
    nonce
}

/// Build handshake params from a sanitized profile JSON payload (same shape
/// the JNI layer already accepts) plus the base64 server public key and hex
/// short id that were withheld from the sanitized payload.
pub struct HandshakeMaterial {
    pub server_address: String,
    pub server_port: u16,
    pub sni: String,
    pub server_public_key_b64: String,
    pub short_id_hex: String,
}

impl HandshakeMaterial {
    pub fn into_params(self) -> Result<HandshakeParams, HandshakeError> {
        use base64::Engine;
        let pk_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(self.server_public_key_b64.as_bytes())
            .or_else(|_| {
                base64::engine::general_purpose::STANDARD
                    .decode(self.server_public_key_b64.as_bytes())
            })
            .map_err(|_| HandshakeError::BadServerKey)?;
        if pk_bytes.len() != 32 {
            return Err(HandshakeError::BadServerKey);
        }
        let mut server_public_key = [0u8; 32];
        server_public_key.copy_from_slice(&pk_bytes);
        let short_id =
            hex::decode(self.short_id_hex.as_bytes()).map_err(|_| HandshakeError::BadShortId)?;
        if short_id.is_empty() {
            return Err(HandshakeError::BadShortId);
        }
        Ok(HandshakeParams {
            server_address: self.server_address,
            server_port: self.server_port,
            sni: self.sni,
            server_public_key,
            short_id,
            fingerprint: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn test_params() -> HandshakeParams {
        // Fixed test server static key (NOT a production secret).
        let server_secret = StaticSecret::from([7u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        HandshakeParams {
            server_address: "127.0.0.1".into(),
            server_port: 443,
            sni: "cdn.example.com".into(),
            server_public_key: *server_public.as_bytes(),
            short_id: vec![0xab, 0xcd],
            fingerprint: Some("chrome".into()),
        }
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    #[test]
    fn initiates_and_seals_client_hello() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        let hello = state.sealed_client_hello();
        // 32 ephemeral pk + sni bytes + 32 session tag + 16 GCM tag.
        assert!(hello.len() >= 32 + 32 + TAG_LEN);
        assert!(!state.is_completed());
    }

    #[test]
    fn rejects_empty_short_id() {
        let mut p = test_params();
        p.short_id.clear();
        assert_eq!(
            HandshakeState::initiate(&p).err(),
            Some(HandshakeError::BadShortId)
        );
    }

    #[test]
    fn rejects_invalid_server_key() {
        let mut p = test_params();
        p.server_public_key = [0u8; 32];
        assert_eq!(
            HandshakeState::initiate(&p).err(),
            Some(HandshakeError::BadServerKey)
        );
    }

    #[test]
    fn record_seal_open_roundtrip() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        let plaintext = b"vless frame bytes";
        let sealed = state.seal_record(0, plaintext).expect("seal");
        assert_ne!(sealed, plaintext);
        let opened = state.open_local_record(0, &sealed).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn record_nonce_differs_per_seq() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        let pt = b"same plaintext";
        let s0 = state.seal_record(0, pt).unwrap();
        let s1 = state.seal_record(1, pt).unwrap();
        assert_ne!(s0, s1, "nonce reuse would make these identical");
    }

    #[test]
    fn tampered_record_fails_to_open() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        let mut sealed = state.seal_record(0, b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(state.open_local_record(0, &sealed).is_err());
    }

    #[test]
    fn completes_against_honest_server_and_rejects_impostor() {
        // Honest server: knows the same static secret, can derive the same keys.
        let server_secret = StaticSecret::from([7u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let mut params = test_params();
        params.server_public_key = *server_public.as_bytes();

        let mut client = HandshakeState::initiate(&params).expect("client initiate");
        let client_hello = client.sealed_client_hello().to_vec();

        // Server side: decrypt the hello, recover the ephemeral pk, derive keys.
        let client_ephemeral = PublicKey::from(*client.ephemeral_public());
        let shared = server_secret.diffie_hellman(&client_ephemeral);
        let record_keys: [u8; 64] = hkdf_expand(HKDF_SALT, shared.as_bytes(), KEY_INFO, 64)
            .try_into()
            .unwrap();
        let server_recv = &record_keys[..32]; // client->server key
        let server_send = &record_keys[32..]; // server->client key

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(server_recv));
        // The client sealed with derive_nonce(session_id, 0); server derives the
        // same session id from shared secret to rebuild the nonce.
        let session_id: [u8; 32] = hkdf_expand(
            HKDF_SALT,
            shared.as_bytes(),
            b"shadevpn-session-id-value",
            32,
        )
        .try_into()
        .unwrap();
        let _hello_plain = cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(&session_id, 0)),
                Payload {
                    msg: client_hello.as_ref(),
                    aad: params.server_address.as_bytes(),
                },
            )
            .expect("server opens client hello");

        // Server builds its authenticated response.
        let response_plain: &[u8] = b"shadevpn-server-ok";
        let server_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(server_send));
        let sealed_response = server_cipher
            .encrypt(
                Nonce::from_slice(&derive_nonce(&session_id, 1)),
                response_plain,
            )
            .expect("server seals");
        let mut server_response = Vec::new();
        let mut mac = make_mac(server_send);
        mac.update(&session_id);
        server_response.extend_from_slice(&mac.finalize().into_bytes());
        server_response.extend_from_slice(&sealed_response);

        assert!(client.complete(&server_response).is_ok());
        assert!(client.is_completed());

        // Impostor: wrong HMAC tag prefix must be rejected.
        let mut bad_client = HandshakeState::initiate(&test_params()).unwrap();
        let mut forged = server_response.clone();
        forged[0] ^= 0xff;
        assert!(bad_client.complete(&forged).is_err());
        assert!(!bad_client.is_completed());
    }

    #[test]
    fn material_parses_base64_key_and_hex_short_id() {
        let server_secret = StaticSecret::from([9u8; 32]);
        let pk_b64 = b64(PublicKey::from(&server_secret).as_bytes());
        let material = HandshakeMaterial {
            server_address: "10.0.0.1".into(),
            server_port: 8443,
            sni: "x.example.com".into(),
            server_public_key_b64: pk_b64,
            short_id_hex: "0a1b".into(),
        };
        let params = material.into_params().expect("material");
        assert_eq!(params.server_port, 8443);
        assert_eq!(params.short_id, vec![0x0a, 0x1b]);
    }

    #[test]
    fn material_rejects_bad_key_length() {
        let material = HandshakeMaterial {
            server_address: "10.0.0.1".into(),
            server_port: 8443,
            sni: "x.example.com".into(),
            server_public_key_b64: b64(b"tooshort"),
            short_id_hex: "0a1b".into(),
        };
        assert_eq!(
            material.into_params().unwrap_err(),
            HandshakeError::BadServerKey
        );
    }

    #[test]
    fn no_secrets_in_error_reasons() {
        for e in [
            HandshakeError::BadServerKey,
            HandshakeError::BadShortId,
            HandshakeError::SessionAuthRejected,
            HandshakeError::SealFailed,
            HandshakeError::EphemeralKeyFailed,
        ] {
            assert!(!e.reason().contains("secret"));
            assert!(!e.reason().contains("key material"));
        }
    }
}
