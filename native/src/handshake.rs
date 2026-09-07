//! Reality (VISION-preflight style) handshake state machine.
//!
//! Scope: real cryptographic state, not just TCP reachability.
//!
//! The client hello is a REAL TLS 1.3 ClientHello record (built by
//! `crate::tls`) carrying Xray-construction REALITY material (see
//! `crate::reality`):
//!
//! 1. Ephemeral X25519 key in `key_share`; REALITY AuthKey = HKDF-SHA256
//!    over X25519(ephemeral, server static), salted by random[..20].
//! 2. The legacy session id carries an AES-256-GCM seal of
//!    [client version][reserved][unix time][short id], keyed by AuthKey,
//!    nonce = random[20..32], AAD = the hello with the session id zeroed.
//! 3. The server answers with a temporary trusted certificate (Ed25519
//!    pubkey || HMAC-SHA512(AuthKey, pub)) plus a FRESH X25519 server key
//!    share. The client verifies the temp cert, then derives forward-secret
//!    record keys from X25519(ephemeral, server_share) bound to the session.
//!
//! The transport layer writes the hello to the socket verbatim.
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
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::reality;
use crate::tls;

pub(crate) const HKDF_SALT: &[u8] = b"shadevpn-reality-hkdf-salt-v1";
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
/// Client version bytes reported in the sealed session id (Xray reports its
/// core version here; ShadeVPN reports its own protocol version).
pub(crate) const CLIENT_VERSION: [u8; 3] = [0x53, 0x56, 0x01]; // "SV" + protocol rev 1
/// Response layout: [temp certificate 96][server key share 32][sealed confirm].
const CERT_LEN: usize = 96;
const SERVER_SHARE_LEN: usize = 32;
/// Server response wire format: [96-byte temp cert][32-byte server share]
/// [sealed confirmation].
pub const SERVER_RESPONSE_MIN: usize = CERT_LEN + SERVER_SHARE_LEN + TAG_LEN;
/// Record keys, fixed once the server response is authenticated.
#[derive(Debug, Clone, Copy)]
struct RecordKeys {
    send: [u8; 32],
    recv: [u8; 32],
}

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
            HandshakeError::BadShortId => "short ID must be 1-8 bytes",
            HandshakeError::SessionAuthRejected => "session authentication rejected",
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
    /// Kept for drop-time zeroization and for the post-handshake ECDHE in
    /// `complete`; never leaves this struct.
    ephemeral: StaticSecret,
    /// Retained for diagnostics; the wire copy rides in the hello key_share.
    #[allow(dead_code)]
    ephemeral_public: PublicKey,
    /// REALITY AuthKey (Xray construction) for this session.
    auth_key: [u8; 32],
    /// The wire hello with the sealed session id patched in.
    wire_hello: Vec<u8>,
    /// The sealed session id; nonces bind to it so records cannot be
    /// replayed across sessions.
    sealed_session_id: [u8; 32],
    /// Record keys, fixed only after the server response authenticates.
    record_keys: OnceLock<RecordKeys>,
    completed: AtomicBool,
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out)
        .expect("hkdf expand length is fixed and valid");
    out
}

impl HandshakeState {
    /// Perform the client-side REALITY key agreement and build the hello.
    /// The returned state holds the sealed session id and every input needed
    /// to authenticate the server response later (`complete`).
    pub fn initiate(params: &HandshakeParams) -> Result<HandshakeState, HandshakeError> {
        if params.short_id.is_empty() || params.short_id.len() > reality::SID_SHORT_ID_LEN {
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

        // REALITY AuthKey, Xray construction: HKDF over the ECDH secret,
        // salted by the first 20 bytes of the hello random.
        let mut random = [0u8; 32];
        random.copy_from_slice(&hkdf_expand(
            HKDF_SALT,
            shared.as_bytes(),
            b"shadevpn-hello-random-v1",
            32,
        ));
        let auth_key = reality::auth_key(shared.as_bytes(), &random);

        // Hello with the session id zeroed: the AEAD AAD window.
        let hello_zeroed = tls::build_client_hello(
            Some(&params.sni),
            ephemeral_public.as_bytes(),
            &random,
            &[0u8; 32],
        )
        .map_err(|_| HandshakeError::SealFailed)?;

        // Seal [version|reserved|time|short id] into the session id slot.
        let unix_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);
        let sealed_session_id = reality::seal_session_id(
            &auth_key,
            &random,
            &hello_zeroed,
            CLIENT_VERSION,
            unix_time,
            &params.short_id,
        )
        .map_err(|_| HandshakeError::SealFailed)?;

        // Patch the sealed session id into the wire hello.
        let mut wire_hello = hello_zeroed.clone();
        let off = tls::SESSION_ID_OFFSET;
        wire_hello[off..off + 32].copy_from_slice(&sealed_session_id);

        Ok(HandshakeState {
            ephemeral,
            ephemeral_public,
            auth_key,
            wire_hello,
            sealed_session_id,
            record_keys: OnceLock::new(),
            completed: AtomicBool::new(false),
        })
    }

    /// The real TLS 1.3 ClientHello record to write to the socket.
    pub fn client_hello(&self) -> &[u8] {
        &self.wire_hello
    }

    /// Verify the server's response and complete the handshake.
    ///
    /// Wire layout: [96-byte temporary trusted certificate][32-byte server
    /// key share][sealed confirmation]. The temp cert must satisfy the Xray
    /// construction HMAC-SHA512(AuthKey, pub) == signature; anything else is
    /// the real certificate of the target site (redirection or MITM) and the
    /// session is rejected. Record keys are then derived from a FRESH
    /// X25519(ephemeral, server_share) with forward secrecy, bound to the
    /// authenticated session. Only after this returns Ok may the data-plane
    /// probe run.
    pub fn complete(&self, server_response: &[u8]) -> Result<(), HandshakeError> {
        if self
            .completed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(HandshakeError::SessionAuthRejected);
        }
        let reject = || {
            self.completed.store(false, Ordering::SeqCst);
            HandshakeError::SessionAuthRejected
        };
        if server_response.len() < SERVER_RESPONSE_MIN {
            return Err(reject());
        }

        // 1. Temporary trusted certificate: the session is authentic only
        //    if HMAC-SHA512(AuthKey, pub) == signature.
        let certificate = &server_response[..CERT_LEN];
        if reality::verify_temporary_certificate(&self.auth_key, certificate).is_err() {
            return Err(reject());
        }

        // 2. Fresh server key share -> forward-secret record keys.
        let server_share: [u8; 32] = server_response[CERT_LEN..CERT_LEN + SERVER_SHARE_LEN]
            .try_into()
            .map_err(|_| reject())?;
        let ecdhe = self
            .ephemeral
            .diffie_hellman(&PublicKey::from(server_share));
        if ecdhe.as_bytes() == &[0u8; 32] {
            return Err(reject());
        }
        let session_binding = reality::session_identity(&self.sealed_session_id, ecdhe.as_bytes());
        let record_keys: [u8; 64] = hkdf_expand(HKDF_SALT, &session_binding, KEY_INFO, 64)
            .try_into()
            .unwrap();
        let keys = RecordKeys {
            send: record_keys[..32].try_into().unwrap(),
            recv: record_keys[32..].try_into().unwrap(),
        };
        if self.record_keys.set(keys).is_err() {
            return Err(reject());
        }

        // 3. Sealed confirmation under the fresh recv key (its send key),
        //    in the server nonce domain.
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.recv));
        let nonce = derive_nonce(
            &self.sealed_session_id,
            0,
            Direction::Server,
            NONCE_PURPOSE_RESPONSE,
        );
        if cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                &server_response[CERT_LEN + SERVER_SHARE_LEN..],
            )
            .is_err()
        {
            return Err(reject());
        }
        Ok(())
    }

    pub fn is_completed(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    fn keys(&self) -> Result<RecordKeys, HandshakeError> {
        self.record_keys
            .get()
            .copied()
            .ok_or(HandshakeError::SessionAuthRejected)
    }

    pub fn seal_record(&self, seq: u64, plaintext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let keys = self.keys()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.send));
        let nonce = derive_nonce(
            &self.sealed_session_id,
            seq,
            Direction::Client,
            NONCE_PURPOSE_DATA,
        );
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| HandshakeError::SealFailed)
    }

    pub fn open_record(&self, seq: u64, ciphertext: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let keys = self.keys()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys.recv));
        cipher
            .decrypt(
                Nonce::from_slice(&derive_nonce(
                    &self.sealed_session_id,
                    seq,
                    Direction::Server,
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

    /// Simulate the honest server entirely from the wire hello bytes: unseal
    /// the session id, issue the temp certificate, and derive the fresh ECDHE
    /// record keys. Returns the response plus both server-side record keys
    /// (recv = client->server, send = server->client) for cross-verification.
    fn simulate_honest_server(
        hello_bytes: &[u8],
        server_secret: &StaticSecret,
    ) -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let hello = tls::parse_client_hello(hello_bytes).expect("parse TLS hello");
        let shared = server_secret.diffie_hellman(&PublicKey::from(hello.ephemeral_public));
        let auth_key = reality::auth_key(shared.as_bytes(), &hello.random);
        let mut aad = hello_bytes.to_vec();
        let off = tls::SESSION_ID_OFFSET;
        aad[off..off + 32].fill(0);
        let sid: [u8; 32] = hello.session_id.clone().try_into().unwrap();
        let plain =
            reality::unseal_session_id(&auth_key, &hello.random, &aad, &sid).expect("unseal");
        assert_eq!(plain.client_version, CLIENT_VERSION);

        let server_eph = reality::ServerEphemeral::generate();
        let ecdhe = server_eph.shared_secret(&hello.ephemeral_public);
        let binding = reality::session_identity(&sid, &ecdhe);
        let keys = hkdf_expand(HKDF_SALT, &binding, KEY_INFO, 64);

        let mut response = Vec::new();
        response.extend_from_slice(&reality::temporary_certificate(&auth_key));
        response.extend_from_slice(&server_eph.public);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&keys[32..]));
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&derive_nonce(
                    &sid,
                    0,
                    Direction::Server,
                    NONCE_PURPOSE_RESPONSE,
                )),
                b"shadevpn-server-ok".as_ref(),
            )
            .expect("server seals");
        response.extend_from_slice(&sealed);
        (
            response,
            keys[..32].try_into().unwrap(),
            keys[32..].try_into().unwrap(),
        )
    }

    fn completed_pair() -> (
        HandshakeState,
        [u8; 32], // server recv key (client->server)
        [u8; 32], // server send key (server->client)
    ) {
        let server_secret = StaticSecret::from([7u8; 32]);
        let mut params = test_params();
        params.server_public_key = *PublicKey::from(&server_secret).as_bytes();
        let client = HandshakeState::initiate(&params).expect("initiate");
        let (response, recv, send) = simulate_honest_server(client.client_hello(), &server_secret);
        client.complete(&response).expect("complete");
        (client, recv, send)
    }

    #[test]
    fn records_fail_before_completion() {
        let state = HandshakeState::initiate(&test_params()).expect("initiate");
        assert!(state.seal_record(0, b"x").is_err());
        assert!(state.open_record(0, &[0u8; 16]).is_err());
        assert!(!state.is_completed());
    }

    #[test]
    fn record_seal_open_roundtrip_across_parties() {
        let (client, server_recv, _server_send) = completed_pair();
        let plaintext = b"vless frame bytes";
        let sealed = client.seal_record(0, plaintext).expect("seal");
        assert_ne!(sealed, plaintext);
        // The server opens it with ITS recv key under the client nonce domain.
        let opened = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_recv))
            .decrypt(
                Nonce::from_slice(&derive_nonce(
                    &client.sealed_session_id,
                    0,
                    Direction::Client,
                    NONCE_PURPOSE_DATA,
                )),
                sealed.as_ref(),
            )
            .expect("server opens client record");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn record_nonce_differs_per_seq() {
        let (client, _recv, _send) = completed_pair();
        let pt = b"same plaintext";
        let s0 = client.seal_record(0, pt).unwrap();
        let s1 = client.seal_record(1, pt).unwrap();
        assert_ne!(s0, s1, "nonce reuse would make these identical");
    }

    #[test]
    fn tampered_record_fails_to_open() {
        let (client, server_recv, _send) = completed_pair();
        let mut sealed = client.seal_record(0, b"hello").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert!(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_recv))
            .decrypt(
                Nonce::from_slice(&derive_nonce(
                    &client.sealed_session_id,
                    0,
                    Direction::Client,
                    NONCE_PURPOSE_DATA,
                )),
                sealed.as_ref(),
            )
            .is_err());
    }

    #[test]
    fn completes_against_honest_server_and_rejects_impostor() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let mut params = test_params();
        params.server_public_key = *PublicKey::from(&server_secret).as_bytes();

        let client = HandshakeState::initiate(&params).expect("client initiate");
        let wire_hello = client.client_hello().to_vec();

        // Wire truth before any response: the sealed session id is inside the
        // legacy session id field, and the short id is nowhere in the clear.
        let hello = tls::parse_client_hello(&wire_hello).expect("parse TLS hello");
        assert_eq!(hello.sni.as_deref(), Some(params.sni.as_str()));
        assert_eq!(hello.session_id.len(), 32);
        assert!(
            !wire_hello.windows(2).any(|w| w == [0xabu8, 0xcd]),
            "short id must not appear in the clear"
        );

        let (server_response, _recv, _send) = simulate_honest_server(&wire_hello, &server_secret);
        assert!(client.complete(&server_response).is_ok());
        assert!(client.is_completed());

        // The session is single-use: a replayed response cannot re-complete.
        assert!(client.complete(&server_response).is_err());

        // Impostor: one flipped byte in the temp certificate (wrong key or
        // wrong HMAC) must be rejected.
        let bad_client = HandshakeState::initiate(&test_params()).unwrap();
        let mut forged = server_response.clone();
        forged[40] ^= 0xff;
        assert!(bad_client.complete(&forged).is_err());
        assert!(!bad_client.is_completed());
    }

    #[test]
    fn rejects_certificate_from_a_different_session() {
        let server_secret = StaticSecret::from([7u8; 32]);
        let mut params = test_params();
        params.server_public_key = *PublicKey::from(&server_secret).as_bytes();
        let client = HandshakeState::initiate(&params).expect("initiate");

        // A cert issued under a DIFFERENT AuthKey (e.g. a replayed cert from
        // another session, or a cert for a different client) must fail.
        let other_auth_key = [0x5au8; 32];
        let mut response = Vec::new();
        response.extend_from_slice(&reality::temporary_certificate(&other_auth_key));
        response.extend_from_slice(&[0u8; 32]); // server share
        response.extend_from_slice(&[0u8; 16]); // confirm placeholder
        assert!(client.complete(&response).is_err());
        assert!(!client.is_completed());
    }

    #[test]
    fn rejects_short_id_over_eight_bytes() {
        let mut p = test_params();
        p.short_id = vec![0u8; 9];
        assert_eq!(
            HandshakeState::initiate(&p).err(),
            Some(HandshakeError::BadShortId)
        );
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
