//! Reality (VISION-preflight style) handshake state machine.
//!
//! Scope: real cryptographic state, not just TCP reachability.
//! This module performs the X25519 key agreement, session-ID HMAC
//! authentication, and HKDF key schedule that Reality prescribes, and emits
//! a REAL TLS 1.3 ClientHello record (built by `crate::tls`) in which the
//! ephemeral key_share, the session tag in `random`, and the short ID in
//! legacy_session_id carry the Reality material. The transport layer writes
//! that record to the socket verbatim.
//!
//! Security notes:
//! - Ephemeral X25519 keys are zeroized on drop (x25519-dalek `StaticSecret`).
//! - Session IDs are HMAC-authenticated; a server that fails the session-id
//!   check is rejected before any VLESS framing is attempted.
//! - Sealing uses AES-256-GCM with a fresh nonce per record; nonces are
//!   never reused across seals with the same key.
//! - No secrets are ever formatted into error strings.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::tls;

pub(crate) const HKDF_SALT: &[u8] = b"shadevpn-reality-hkdf-salt-v1";
pub(crate) const SESSION_INFO: &[u8] = b"shadevpn-session-id-v1";
/// HKDF info label for the session-id value itself (distinct from the auth key).
pub(crate) const SESSION_ID_VALUE_INFO: &[u8] = b"shadevpn-session-id-value";
pub(crate) const KEY_INFO: &[u8] = b"shadevpn-record-keys-v1";
/// Nonce domain separation: client->server and server->client records must
/// never derive the same nonce even at the same sequence number, because a
/// mirrored record would otherwise reuse a nonce.
pub(crate) const NONCE_DOMAIN_CLIENT: &[u8] = b"shadevpn-nonce-client-v1";
pub(crate) const NONCE_DOMAIN_SERVER: &[u8] = b"shadevpn-nonce-server-v1";
/// Nonce purposes on top of the direction domains: the server response
/// confirmation and data records each get their own nonce space, so a
/// confirmation and a data record at the same sequence never share a nonce.
pub(crate) const NONCE_PURPOSE_RESPONSE: &[u8] = b"shadevpn-purpose-response-v1";
pub(crate) const NONCE_PURPOSE_DATA: &[u8] = b"shadevpn-purpose-data-v1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Server response wire format: [32-byte session tag][sealed payload].
pub const SERVER_RESPONSE_MIN: usize = 32 + TAG_LEN;

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
/// Only validation material is retained; no private data is stored.
#[derive(Debug, Clone)]
pub struct HandshakeParams {
    pub server_address: String,
    pub server_port: u16,
    pub sni: String,
    pub server_public_key: [u8; 32],
    pub short_id: Vec<u8>,
    /// Browser TLS fingerprint to mimic; reserved for the on-device TLS
    /// camouflage layer.
    #[allow(dead_code)]
    pub fingerprint: Option<String>,
}

/// Client-side handshake state. Ephemeral secret is zeroized on drop.
pub struct HandshakeState {
    /// Kept for drop-time zeroization; never read after `initiate`.
    #[allow(dead_code)]
    ephemeral: StaticSecret,
    /// Retained for future diagnostics/rotation logging; the wire copy of
    /// the ephemeral pk rides inside `sealed_client_hello`.
    #[allow(dead_code)]
    ephemeral_public: PublicKey,
    session_id: [u8; 32],
    send_key: [u8; 32],
    recv_key: [u8; 32],
    wire_client_hello: Vec<u8>,
    completed: AtomicBool,
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .expect("hkdf expand length is fixed and valid");
    out
}

pub(crate) fn session_id_hmac(auth_key: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = make_mac(auth_key);
    mac.update(session_id);
    mac.finalize().into_bytes().into()
}

pub(crate) fn make_mac(key_bytes: &[u8]) -> Hmac<Sha256> {
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
        let session_id: [u8; 32] =
            hkdf_expand(HKDF_SALT, shared.as_bytes(), SESSION_ID_VALUE_INFO, 32)
                .try_into()
                .unwrap();
        let session_tag = session_id_hmac(&auth_key, &session_id);

        // Derive bidirectional record keys (client->server, server->client).
        let record_keys: [u8; 64] = hkdf_expand(HKDF_SALT, shared.as_bytes(), KEY_INFO, 64)
            .try_into()
            .unwrap();
        let send_key: [u8; 32] = record_keys[..32].try_into().unwrap();
        let recv_key: [u8; 32] = record_keys[32..].try_into().unwrap();

        // Reality material rides in REAL TLS 1.3 ClientHello fields (see
        // tls.rs): the ephemeral public key in key_share, the session tag in
        // random, the short ID in legacy_session_id, the SNI in server_name.
        // Authentication does not depend on any non-TLS payload: the server
        // recomputes the session tag from the ECDH shared secret and compares
        // it byte-for-byte with the one in `random` before responding.
        let wire_hello = tls::build_client_hello(
            Some(&params.sni),
            ephemeral_public.as_bytes(),
            &session_tag,
            &params.short_id,
        )
        .map_err(|_| HandshakeError::SealFailed)?;

        Ok(HandshakeState {
            ephemeral,
            ephemeral_public,
            session_id,
            send_key,
            recv_key,
            wire_client_hello: wire_hello,
            completed: AtomicBool::new(false),
        })
    }

    /// The real TLS 1.3 ClientHello record to write to the socket.
    pub fn client_hello(&self) -> &[u8] {
        &self.wire_client_hello
    }

    /// Verify the server's response is bound to our session and complete the
    /// handshake. Wire format: [32-byte session-id tag][sealed confirmation]
    /// where the tag is HMAC(recv_key, session_id) and the confirmation is
    /// sealed under the server->client key. Only after this returns Ok may
    /// the data-plane probe run.
    pub fn complete(&self, server_response: &[u8]) -> Result<(), HandshakeError> {
        if self
            .completed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(HandshakeError::SessionAuthRejected);
        }
        if server_response.len() < SERVER_RESPONSE_MIN {
            self.completed.store(false, Ordering::SeqCst);
            return Err(HandshakeError::SessionAuthRejected);
        }
        let (tagged, ciphertext) = server_response.split_at(32);
        let expected_tag = session_id_hmac(&self.recv_key, &self.session_id);
        if tagged != expected_tag.as_slice() {
            self.completed.store(false, Ordering::SeqCst);
            return Err(HandshakeError::SessionAuthRejected);
        }
        // Server also echoes a sealed confirmation under recv_key (its
        // send key), in the server nonce domain.
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.recv_key));
        let nonce = derive_nonce(
            &self.session_id,
            0,
            Direction::Server,
            NONCE_PURPOSE_RESPONSE,
        );
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
        let nonce = derive_nonce(&self.session_id, seq, Direction::Client, NONCE_PURPOSE_DATA);
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| HandshakeError::SealFailed)
    }

    pub fn open_record(&self, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.recv_key));
        cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(
                    &self.session_id,
                    seq,
                    Direction::Server,
                    NONCE_PURPOSE_DATA,
                )),
                ciphertext,
            )
            .map_err(|_| HandshakeError::SessionAuthRejected)
    }

    /// Loopback-only verification: opens a record sealed by THIS side under
    /// the send key. Superseded on the live path by wire round trips through
    /// the honest server; retained as the seal-path verifier for unit tests.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn open_local_record(
        &self,
        seq: u64,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.send_key));
        cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(
                    &self.session_id,
                    seq,
                    Direction::Client,
                    NONCE_PURPOSE_DATA,
                )),
                ciphertext,
            )
            .map_err(|_| HandshakeError::SessionAuthRejected)
    }
}

/// Which side produced a record. Direction and sequence together pick the
/// nonce domain, so a client record and a server record at the same seq
/// never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Client,
    Server,
}

/// Deterministic nonce from the session id, direction, purpose, and record
/// sequence. Never reused for a given (key, direction, purpose, seq) tuple.
pub(crate) fn derive_nonce(
    session_id: &[u8; 32],
    seq: u64,
    direction: Direction,
    purpose: &[u8],
) -> [u8; NONCE_LEN] {
    let domain = match direction {
        Direction::Client => NONCE_DOMAIN_CLIENT,
        Direction::Server => NONCE_DOMAIN_SERVER,
    };
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(purpose);
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
    fn initiates_and_builds_tls_hello() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        let hello = state.client_hello();
        // A real TLS record: handshake content type, then a ClientHello
        // message large enough to carry random (32) + key_share (32).
        assert_eq!(hello[0], 0x16);
        assert_eq!(hello[5], 0x01);
        assert!(hello.len() >= 5 + 4 + 2 + 32 + 32);
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
        // Honest server: knows the same static secret, reads ONLY the wire
        // hello, and derives everything else from the ephemeral pk in it.
        let server_secret = StaticSecret::from([7u8; 32]);
        let server_public = PublicKey::from(&server_secret);
        let mut params = test_params();
        params.server_public_key = *server_public.as_bytes();

        let client = HandshakeState::initiate(&params).expect("client initiate");
        let wire_hello = client.client_hello().to_vec();

        // ---- server side, from wire bytes only ----
        let hello = crate::tls::parse_client_hello(&wire_hello).expect("parse TLS hello");
        let client_ephemeral = PublicKey::from(hello.ephemeral_public);
        let shared = server_secret.diffie_hellman(&client_ephemeral);
        let session_id: [u8; 32] =
            hkdf_expand(HKDF_SALT, shared.as_bytes(), SESSION_ID_VALUE_INFO, 32)
                .try_into()
                .unwrap();
        let record_keys: [u8; 64] = hkdf_expand(HKDF_SALT, shared.as_bytes(), KEY_INFO, 64)
            .try_into()
            .unwrap();
        let server_send = &record_keys[32..]; // server->client key

        // Wire truth: SNI, short ID, and the authenticated session tag all
        // arrived inside real TLS fields.
        assert_eq!(hello.sni.as_deref(), Some(params.sni.as_str()));
        assert_eq!(hello.short_id, params.short_id);
        let auth_key: [u8; 32] = hkdf_expand(HKDF_SALT, shared.as_bytes(), SESSION_INFO, 32)
            .try_into()
            .unwrap();
        let expected_tag = session_id_hmac(&auth_key, &session_id);
        assert_eq!(
            hello.session_tag, expected_tag,
            "session tag in random must authenticate"
        );

        // Server builds its authenticated response: tag || sealed confirm.
        let response_plain: &[u8] = b"shadevpn-server-ok";
        let server_seal = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(server_send));
        let sealed_response = server_seal
            .encrypt(
                Nonce::from_slice(&derive_nonce(
                    &session_id,
                    0,
                    Direction::Server,
                    NONCE_PURPOSE_RESPONSE,
                )),
                response_plain,
            )
            .expect("server seals");
        let mut server_response = Vec::new();
        let mut mac = make_mac(server_send);
        mac.update(&session_id);
        server_response.extend_from_slice(&mac.finalize().into_bytes());
        server_response.extend_from_slice(&sealed_response);
        // ---- end server side ----

        assert!(client.complete(&server_response).is_ok());
        assert!(client.is_completed());

        // The session is single-use: a replayed response cannot re-complete.
        assert!(client.complete(&server_response).is_err());

        // Impostor: wrong HMAC tag prefix must be rejected.
        let bad_client = HandshakeState::initiate(&test_params()).unwrap();
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
