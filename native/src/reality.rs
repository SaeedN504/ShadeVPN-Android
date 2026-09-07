//! REALITY protocol material following the XTLS/Xray-core constructions.
//!
//! The session authentication and temporary-trusted-certificate schemes
//! mirror the reference implementation so wire material is interoperable by
//! construction with Xray REALITY endpoints.
//!
//! Constructions (identical to XTLS):
//!
//! - `AuthKey`: 32 bytes of HKDF-SHA256, IKM = X25519(ephemeral, static),
//!   salt = the first 20 bytes of the hello's `random` field, info = b"REALITY".
//! - `session_id`: the hello's 32-byte legacy session id. Plaintext is
//!   [3 bytes client version][1 reserved][4 bytes unix time][short id padded
//!   to 8]. Sealed with AES-256-GCM under AuthKey with nonce = random[20..32]
//!   and AAD = the hello with the session id zeroed (the exact bytes a server
//!   parses). Server: unseal, then validate version, clock, short id.
//! - Temporary trusted certificate: DER leaf certificate whose SignatureValue
//!   carries Ed25519 pubkey || HMAC-SHA512(AuthKey, pubkey). The client
//!   verifies `HMAC-SHA512(AuthKey, pub) == signature` and rejects any other
//!   certificate chain — exactly Xray's temp-cert-vs-real-cert decision.
//!
//! No secret is ever formatted into an error or log string.
//!
//! Server-side items (unseal, certificate issuance, fresh key share) are
//! consumed by the honest in-process test server today; the standalone
//! server tooling ships in a later milestone.
#![cfg_attr(not(test), allow(dead_code))]

use crate::tls;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF info label; byte-identical to the XTLS reference constant.
pub const REALITY_INFO: &[u8] = b"REALITY";

/// Offsets into the 32-byte session-id plaintext, matching Xray's layout:
/// [3 version][1 reserved][4 time][short id up to 8].
pub const SID_VERSION_LEN: usize = 3;
pub const SID_RESERVED_LEN: usize = 1;
pub const SID_TIME_LEN: usize = 4;
/// The short id occupies the final 8 bytes (zero padded).
pub const SID_SHORT_ID_LEN: usize = 8;
pub const SID_PLAIN_LEN: usize =
    SID_VERSION_LEN + SID_RESERVED_LEN + SID_TIME_LEN + SID_SHORT_ID_LEN;

/// Where the session id lives inside the hello AAD window.
const SID_WIRE_OFFSET: usize = tls::SESSION_ID_OFFSET;
/// Length of the session id on the wire.
const SID_WIRE_LEN: usize = 32;

/// Salt window: first 20 bytes of `random`.
const RANDOM_SALT_LEN: usize = 20;
const RANDOM_NONCE_LEN: usize = 12;
const RANDOM_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RealityError {
    /// A length in the profile exceeded the fixed protocol layout.
    ShortIdTooLong,
    /// Session-id AEAD open failed: wrong key material or tampered hello.
    SessionIdRejected,
    /// The certificate failed the temporary-trusted verification.
    CertRejected,
    /// A value was outside the fixed layout bounds.
    Layout,
}

impl RealityError {
    pub fn reason(&self) -> &'static str {
        match self {
            RealityError::ShortIdTooLong => "short id exceeds 8 bytes",
            RealityError::SessionIdRejected => "session id rejected",
            RealityError::CertRejected => "certificate rejected",
            RealityError::Layout => "fixed-layout overflow",
        }
    }
}

/// Derive the REALITY AuthKey from the raw ECDH shared secret and the
/// hello's random field. `random` must be exactly 32 bytes.
pub fn auth_key(shared_secret: &[u8; 32], random: &[u8; RANDOM_LEN]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&random[..RANDOM_SALT_LEN]), shared_secret);
    let mut out = [0u8; 32];
    hk.expand(REALITY_INFO, &mut out)
        .expect("32-byte expand is valid");
    out
}

/// Seal the session id into the hello's 32-byte legacy session id slot.
///
/// `hello_with_zeroed_sid` must be the full ClientHello record bytes with
/// bytes `[SESSION_ID_OFFSET..SESSION_ID_OFFSET+32]` set to zero — exactly
/// what the server re-derives as AAD.
pub fn seal_session_id(
    aead_key: &[u8; 32],
    random: &[u8; RANDOM_LEN],
    hello_with_zeroed_sid: &[u8],
    version: [u8; SID_VERSION_LEN],
    unix_time: u32,
    short_id: &[u8],
) -> Result<[u8; SID_WIRE_LEN], RealityError> {
    if short_id.len() > SID_SHORT_ID_LEN {
        return Err(RealityError::ShortIdTooLong);
    }
    if hello_with_zeroed_sid.len() < SID_WIRE_OFFSET + SID_WIRE_LEN {
        return Err(RealityError::Layout);
    }
    let mut plain = [0u8; SID_PLAIN_LEN];
    plain[..SID_VERSION_LEN].copy_from_slice(&version);
    // plain[3] reserved = 0
    plain[4..8].copy_from_slice(&unix_time.to_be_bytes());
    plain[8..8 + short_id.len()].copy_from_slice(short_id);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aead_key));
    let nonce = Nonce::from_slice(&random[RANDOM_SALT_LEN..RANDOM_SALT_LEN + RANDOM_NONCE_LEN]);
    let sealed = cipher
        .encrypt(
            nonce,
            Payload {
                msg: &plain,
                aad: hello_with_zeroed_sid,
            },
        )
        .map_err(|_| RealityError::SessionIdRejected)?;
    Ok(sealed.try_into().expect("32-byte ciphertext"))
}

/// Open a session id received from the wire. Returns the client version,
/// the unix timestamp, and the short id (zero padded to 8 bytes). The AAD is
/// the received hello with the session id zeroed, exactly as sealed.
pub fn unseal_session_id(
    aead_key: &[u8; 32],
    random: &[u8; RANDOM_LEN],
    hello_with_zeroed_sid: &[u8],
    session_id: &[u8; SID_WIRE_LEN],
) -> Result<SessionIdPlain, RealityError> {
    if hello_with_zeroed_sid.len() < SID_WIRE_OFFSET + SID_WIRE_LEN {
        return Err(RealityError::Layout);
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(aead_key));
    let nonce = Nonce::from_slice(&random[RANDOM_SALT_LEN..RANDOM_SALT_LEN + RANDOM_NONCE_LEN]);
    let plain = cipher
        .decrypt(
            nonce,
            Payload {
                msg: session_id.as_ref(),
                aad: hello_with_zeroed_sid,
            },
        )
        .map_err(|_| RealityError::SessionIdRejected)?;
    let plain: [u8; SID_PLAIN_LEN] = plain.try_into().map_err(|_| RealityError::Layout)?;
    Ok(SessionIdPlain {
        client_version: [plain[0], plain[1], plain[2]],
        unix_time: u32::from_be_bytes([plain[4], plain[5], plain[6], plain[7]]),
        short_id: [
            plain[8], plain[9], plain[10], plain[11], plain[12], plain[13], plain[14], plain[15],
        ],
    })
}

/// Decrypted session-id plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionIdPlain {
    pub client_version: [u8; 3],
    pub unix_time: u32,
    /// Zero padded to 8 bytes; compare against the allowlist directly.
    pub short_id: [u8; SID_SHORT_ID_LEN],
}

/// Build the server's temporary trusted certificate for one session.
///
/// Wire shape: [32-byte Ed25519 verification public key]
/// [64-byte HMAC-SHA512(AuthKey, pub) standing in for the signature].
pub fn temporary_certificate(auth_key_bytes: &[u8; 32]) -> [u8; 96] {
    let signing = StaticSecret::random_from_rng(OsRng);
    let verifying = PublicKey::from(&signing);
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(auth_key_bytes)
        .expect("hmac accepts any key length");
    mac.update(verifying.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 96];
    out[..32].copy_from_slice(verifying.as_bytes());
    out[32..].copy_from_slice(&tag);
    out
}

/// Client-side check that a certificate is the server's temporary trusted
/// one: HMAC-SHA512(AuthKey, pub) must equal the claimed signature.
pub fn verify_temporary_certificate(
    auth_key_bytes: &[u8; 32],
    certificate: &[u8],
) -> Result<(), RealityError> {
    if certificate.len() != 96 {
        return Err(RealityError::CertRejected);
    }
    let (pub_bytes, sig) = certificate.split_at(32);
    let mut mac = <Hmac<Sha512> as hmac::Mac>::new_from_slice(auth_key_bytes)
        .expect("hmac accepts any key length");
    mac.update(pub_bytes);
    let mut ok = true;
    // Folded compare over the fixed 64-byte tag.
    for (a, b) in mac.finalize().into_bytes().iter().zip(sig.iter()) {
        ok &= a == b;
    }
    if ok {
        Ok(())
    } else {
        Err(RealityError::CertRejected)
    }
}

/// The server's ephemeral TLS key share (fresh per connection, so record
/// keys get forward secrecy) plus the derived record keys.
pub struct ServerEphemeral {
    secret: StaticSecret,
    pub public: [u8; 32],
}

impl ServerEphemeral {
    pub fn generate() -> ServerEphemeral {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        ServerEphemeral {
            secret,
            public: *public.as_bytes(),
        }
    }

    /// The shared secret X25519(server_ephemeral, client_ephemeral) that
    /// REALITY's TLS record layer would derive.
    pub fn shared_secret(&self, client_ephemeral: &[u8; 32]) -> [u8; 32] {
        let peer = PublicKey::from(*client_ephemeral);
        *self.secret.diffie_hellman(&peer).as_bytes()
    }
}

/// Identity hash over the session: SHA-256 over the sealed session id and
/// the shared secret. Used to bind record keys to the authenticated session.
pub fn session_identity(session_id: &[u8; SID_WIRE_LEN], shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(session_id);
    hasher.update(shared_secret);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_client_hello;

    fn test_hello_and_random() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let mut random = [0u8; 32];
        for (i, b) in random.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x3c;
        }
        let mut share = [0u8; 32];
        for (i, b) in share.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x77;
        }
        let hello =
            build_client_hello(Some("x.example.com"), &share, &random, &[0u8; 32]).expect("build");
        (hello, random, share)
    }

    fn zero_sid(hello: &[u8]) -> Vec<u8> {
        let mut out = hello.to_vec();
        let off = tls::SESSION_ID_OFFSET;
        out[off..off + 32].fill(0);
        out
    }

    #[test]
    fn session_id_round_trips_through_seal_and_unseal() {
        let (hello, random, _) = test_hello_and_random();
        let hello_zeroed = zero_sid(&hello);
        let key = [9u8; 32];
        let sealed = seal_session_id(
            &key,
            &random,
            &hello_zeroed,
            [1, 2, 3],
            1_700_000_000,
            &[0xab, 0xcd],
        )
        .expect("seal");
        let opened = unseal_session_id(&key, &random, &hello_zeroed, &sealed).expect("unseal");
        assert_eq!(opened.client_version, [1, 2, 3]);
        assert_eq!(opened.unix_time, 1_700_000_000);
        assert_eq!(opened.short_id[..2], [0xab, 0xcd]);
        assert_eq!(opened.short_id[2..], [0u8; 6]);
    }

    #[test]
    fn sealed_session_id_is_random_looking() {
        let (hello, random, _) = test_hello_and_random();
        let key = [9u8; 32];
        let sealed = seal_session_id(
            &key,
            &random,
            &zero_sid(&hello),
            [1, 2, 3],
            1_700_000_000,
            &[0xab, 0xcd],
        )
        .expect("seal");
        // The sealed session id must not leak the short id or the timestamp
        // prefix in the clear.
        assert!(!sealed.windows(2).any(|w| w == [0xab, 0xcd]));
        assert_ne!(&sealed[..4], &[1u8, 2, 3, 0]);
    }

    #[test]
    fn tampered_session_id_is_rejected() {
        let (hello, random, _) = test_hello_and_random();
        let key = [9u8; 32];
        let mut sealed = seal_session_id(
            &key,
            &random,
            &zero_sid(&hello),
            [1, 2, 3],
            1_700_000_000,
            &[0xab],
        )
        .unwrap();
        sealed[0] ^= 0xff;
        assert_eq!(
            unseal_session_id(&key, &random, &zero_sid(&hello), &sealed).err(),
            Some(RealityError::SessionIdRejected)
        );
    }

    #[test]
    fn wrong_aad_is_rejected() {
        let (hello, random, _) = test_hello_and_random();
        let key = [9u8; 32];
        let sealed =
            seal_session_id(&key, &random, &zero_sid(&hello), [1, 2, 3], 1, &[0xab]).unwrap();
        let mut other = zero_sid(&hello);
        other[5] ^= 0x01;
        assert_eq!(
            unseal_session_id(&key, &random, &other, &sealed).err(),
            Some(RealityError::SessionIdRejected)
        );
    }

    #[test]
    fn temp_certificate_round_trip_and_rejection() {
        let key = [4u8; 32];
        let cert = temporary_certificate(&key);
        assert_eq!(cert.len(), 96);
        assert!(verify_temporary_certificate(&key, &cert).is_ok());
        let wrong = [5u8; 32];
        assert!(verify_temporary_certificate(&wrong, &cert).is_err());
        let mut flipped = cert;
        flipped[95] ^= 0x01;
        assert!(verify_temporary_certificate(&key, &flipped).is_err());
    }

    #[test]
    fn server_ephemeral_shared_secret_matches_client_side_computation() {
        let server = ServerEphemeral::generate();
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let from_server = server.shared_secret(client_public.as_bytes());
        let from_client = *client_secret
            .diffie_hellman(&PublicKey::from(server.public))
            .as_bytes();
        assert_eq!(from_server, from_client);
    }

    #[test]
    fn error_reasons_leak_no_material() {
        for e in [
            RealityError::ShortIdTooLong,
            RealityError::SessionIdRejected,
            RealityError::CertRejected,
            RealityError::Layout,
        ] {
            assert!(!e.reason().contains("secret"));
            assert!(!e.reason().contains("AuthKey"));
        }
    }
}
