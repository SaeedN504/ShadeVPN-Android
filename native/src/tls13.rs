//! A real TLS 1.3 client core: enough of RFC 8446 to interoperate with a
//! genuine TLS 1.3 server (Xray REALITY answers with true TLS records after
//! the ClientHello; the custom post-hello dialect does not).
//!
//! Scope (deliberately minimal but real):
//! - full handshake transcript hash
//! - ServerHello parsing (x25519 key share, negotiated suite)
//! - RFC 8446 key schedule: early/derive/handshake/master secrets,
//!   handshake and application traffic secrets for both directions
//! - AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 record protection
//!   with direction-separated keys and record-header AAD
//! - EncryptedExtensions, Certificate, CertificateVerify, Finished
//! - RSA-PSS / RSA-PKCS1 CertificateVerify verification via minimal DER
//!   SPKI parsing of the leaf certificate
//! - client Finished transmission and application-data record sealing
//!
//! Out of scope (documented): session resumption, client certificates,
//! KeyUpdate, HelloRetryRequest, ECDSA CertificateVerify (Xray servers sign
//! with RSA), hostname/web-PKI verification (REALITY authenticates the
//! chain via its temp-cert HMAC; web-PKI trust is irrelevant).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use rsa::pkcs1v15::{Signature as Pkcs1Sig, VerifyingKey as Pkcs1VerifyingKey};
use rsa::pss::{Signature as PssSig, VerifyingKey as PssVerifyingKey};
use rsa::signature::{SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret as XSecret};

/// TLS record content types.
pub const CONTENT_HANDSHAKE: u8 = 0x16;
pub const CONTENT_APPDATA: u8 = 0x17;
pub const CONTENT_ALERT: u8 = 0x15;

/// Handshake message types.
pub const HS_SERVER_HELLO: u8 = 0x02;
pub const HS_ENCRYPTED_EXTENSIONS: u8 = 0x08;
pub const HS_CERTIFICATE: u8 = 0x0b;
pub const HS_CERTIFICATE_VERIFY: u8 = 0x0f;
pub const HS_FINISHED: u8 = 0x14;

/// AEAD tag length (same for every suite we support).
const TAG_LEN: usize = 16;
/// TLS 1.3 record IV length.
const IV_LEN: usize = 12;
/// Extension type: key_share.
const EXT_KEY_SHARE: u16 = 0x0033;
/// Named group: x25519.
const GROUP_X25519: u16 = 0x001d;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// 0x1301
    Aes128GcmSha256,
    /// 0x1302
    Aes256GcmSha384,
    /// 0x1303
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    fn from_u16(v: u16) -> Option<CipherSuite> {
        match v {
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::ChaCha20Poly1305Sha256),
            _ => None,
        }
    }

    fn hash(self) -> HashAlg {
        match self {
            CipherSuite::Aes256GcmSha384 => HashAlg::S384,
            _ => HashAlg::S256,
        }
    }

    fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::Aes256GcmSha384 | CipherSuite::ChaCha20Poly1305Sha256 => 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tls13Error {
    Truncated,
    BadRecord,
    BadHandshake,
    /// ServerHello offered no x25519 key share.
    NoKeyShare,
    /// Server negotiated a suite we do not support.
    BadCipherSuite,
    /// AEAD open failed: wrong keys or tampering.
    DecryptFailed,
    /// Server Finished did not match the transcript.
    FinishedMismatch,
    /// CertificateVerify signature did not verify.
    CertVerifyRejected,
    /// Signature scheme or key type unsupported.
    BadScheme,
    /// A record type appeared where it cannot.
    UnexpectedRecord,
}

impl std::fmt::Display for Tls13Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Tls13Error::Truncated => "TLS record is truncated",
            Tls13Error::BadRecord => "malformed TLS record",
            Tls13Error::BadHandshake => "malformed TLS handshake message",
            Tls13Error::NoKeyShare => "server offered no x25519 key share",
            Tls13Error::BadCipherSuite => "server negotiated an unsupported suite",
            Tls13Error::DecryptFailed => "record failed to decrypt",
            Tls13Error::FinishedMismatch => "server Finished verification failed",
            Tls13Error::CertVerifyRejected => "certificate signature rejected",
            Tls13Error::BadScheme => "unsupported signature scheme",
            Tls13Error::UnexpectedRecord => "unexpected record type",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Tls13Error {}

/// The two hashes TLS 1.3 key schedules use, dispatched at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashAlg {
    S256,
    S384,
}

impl HashAlg {
    fn len(self) -> usize {
        match self {
            HashAlg::S256 => 32,
            HashAlg::S384 => 48,
        }
    }
    fn empty_hash(self) -> Vec<u8> {
        match self {
            HashAlg::S256 => Sha256::digest([]).to_vec(),
            HashAlg::S384 => Sha384::digest([]).to_vec(),
        }
    }
}

fn hmac_hash(h: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8> {
    match h {
        HashAlg::S256 => {
            let mut m = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
        HashAlg::S384 => {
            let mut m = <hmac::Hmac<Sha384> as Mac>::new_from_slice(key).expect("hmac key");
            m.update(data);
            m.finalize().into_bytes().to_vec()
        }
    }
}

use hmac::Mac;

fn hkdf_extract(h: HashAlg, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    hmac_hash(h, salt, ikm)
}

fn hkdf_expand(h: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_hash(h, prk, &input);
        okm.extend_from_slice(&t);
        counter += 1;
    }
    okm.truncate(len);
    okm
}

/// HKDF-Expand-Label (RFC 8446 §7.1).
fn hkdf_expand_label(
    h: HashAlg,
    secret: &[u8],
    label: &str,
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(2 + 1 + full_label.len() + 1 + context.len());
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    hkdf_expand(h, secret, &info, len)
}

/// Derive-Secret(secret, label, Hash(transcript)).
fn derive_secret(h: HashAlg, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
    hkdf_expand_label(h, secret, label, transcript_hash, h.len())
}

fn finished_key(h: HashAlg, secret: &[u8]) -> Vec<u8> {
    hkdf_expand_label(h, secret, "finished", &[], h.len())
}

/// RFC 8446 §5.3 per-record nonce: static IV XOR sequence number.
fn record_nonce(iv: &[u8], seq: u64) -> Vec<u8> {
    let mut n = iv.to_vec();
    let s = seq.to_be_bytes();
    let base = n.len() - 8;
    for i in 0..8 {
        n[base + i] ^= s[i];
    }
    n
}

/// One AEAD instance (a key + suite binding).
enum RecordCipher {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl RecordCipher {
    fn seal(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Tls13Error> {
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            RecordCipher::Aes128(c) => c
                .encrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
            RecordCipher::Aes256(c) => c
                .encrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
            RecordCipher::ChaCha(c) => c
                .encrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
        }
    }
    fn open(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Tls13Error> {
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            RecordCipher::Aes128(c) => c
                .decrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
            RecordCipher::Aes256(c) => c
                .decrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
            RecordCipher::ChaCha(c) => c
                .decrypt(nonce.into(), payload)
                .map_err(|_| Tls13Error::DecryptFailed),
        }
    }
}

fn cipher_from_key(suite: CipherSuite, key: &[u8]) -> Result<RecordCipher, Tls13Error> {
    match suite {
        CipherSuite::Aes128GcmSha256 => Ok(RecordCipher::Aes128(
            Aes128Gcm::new_from_slice(key).map_err(|_| Tls13Error::BadCipherSuite)?,
        )),
        CipherSuite::Aes256GcmSha384 => Ok(RecordCipher::Aes256(
            Aes256Gcm::new_from_slice(key).map_err(|_| Tls13Error::BadCipherSuite)?,
        )),
        CipherSuite::ChaCha20Poly1305Sha256 => Ok(RecordCipher::ChaCha(
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| Tls13Error::BadCipherSuite)?,
        )),
    }
}

/// (key, iv) from a traffic secret, per RFC 8446 §7.3.
fn key_iv_from_secret(suite: CipherSuite, secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let h = suite.hash();
    let key = hkdf_expand_label(h, secret, "key", &[], suite.key_len());
    let iv = hkdf_expand_label(h, secret, "iv", &[], IV_LEN);
    (key, iv)
}

/// Handshake transcript over the negotiated hash.
enum Transcript {
    S256(Sha256),
    S384(Sha384),
}

impl Transcript {
    fn new(suite: CipherSuite) -> Transcript {
        match suite.hash() {
            HashAlg::S256 => Transcript::S256(Sha256::new()),
            HashAlg::S384 => Transcript::S384(Sha384::new()),
        }
    }
    fn update(&mut self, data: &[u8]) {
        match self {
            Transcript::S256(h) => h.update(data),
            Transcript::S384(h) => h.update(data),
        }
    }
    fn hash_of(&self) -> Vec<u8> {
        match self {
            Transcript::S256(h) => h.clone().finalize().to_vec(),
            Transcript::S384(h) => h.clone().finalize().to_vec(),
        }
    }
}

/// Strip the trailing content-type byte and zero padding from a decrypted
/// TLS 1.3 inner plaintext. Returns (content_type, payload).
fn strip_inner_padding(plain: &[u8]) -> Result<(u8, &[u8]), Tls13Error> {
    let mut end = plain.len();
    while end > 0 && plain[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 {
        return Err(Tls13Error::BadRecord);
    }
    let ct = plain[end - 1];
    Ok((ct, &plain[..end - 1]))
}

/// The client-side TLS 1.3 handshake state machine.
pub struct Tls13Client {
    suite: Option<CipherSuite>,
    transcript: Option<Transcript>,
    /// The ClientHello record we put on the wire (replayed into the
    /// transcript once the suite — and therefore hash — is known).
    client_hello: Option<Vec<u8>>,
    /// ECDHE private key matching the hello's key_share, for the shared
    /// secret the caller computes after ServerHello.
    // (the caller performs X25519 itself and passes the shared secret in)
    early_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    chts: Option<Vec<u8>>,
    shts: Option<Vec<u8>>,
    cets: Option<Vec<u8>>,
    sets: Option<Vec<u8>>,
    hs_read: Option<(RecordCipher, Vec<u8>, u64)>, // cipher, iv, seq
    hs_write: Option<(RecordCipher, Vec<u8>, u64)>, // cipher, iv, seq
    app_read: Option<(RecordCipher, Vec<u8>, u64)>,
    app_write: Option<(RecordCipher, Vec<u8>, u64)>,
}

/// Everything a caller needs from a completed server flight.
pub struct Tls13Outcome {
    /// The negotiated suite.
    pub suite: CipherSuite,
    /// Raw DER bodies of the server certificate chain.
    pub server_chain: Vec<Vec<u8>>,
    /// The server's application traffic secret (server->client records).
    pub server_app_secret: Vec<u8>,
    /// The client's application traffic secret (client->server records).
    pub client_app_secret: Vec<u8>,
}

impl Tls13Client {
    pub fn new() -> Tls13Client {
        Tls13Client {
            suite: None,
            transcript: None,
            client_hello: None,
            early_secret: None,
            handshake_secret: None,
            master_secret: None,
            chts: None,
            shts: None,
            cets: None,
            sets: None,
            hs_read: None,
            hs_write: None,
            app_read: None,
            app_write: None,
        }
    }

    /// Feed the ClientHello record we actually sent. The suite is not known
    /// until ServerHello, so the transcript starts there.
    pub fn set_client_hello(&mut self, record: &[u8]) {
        self.client_hello = Some(record.to_vec());
    }

    /// Process the server's (unprotected) ServerHello record. Returns the
    /// server's x25519 public key share.
    pub fn process_server_hello(&mut self, wire: &[u8]) -> Result<[u8; 32], Tls13Error> {
        if wire.len() < 5 || wire[0] != CONTENT_HANDSHAKE {
            return Err(Tls13Error::BadRecord);
        }
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        if wire.len() < 5 + rec_len {
            return Err(Tls13Error::Truncated);
        }
        let body = &wire[5..5 + rec_len];
        if body.is_empty() || body[0] != HS_SERVER_HELLO {
            return Err(Tls13Error::BadHandshake);
        }
        let mut sh = Reader::new(&body[4..]);
        let _legacy_version = sh.take(2)?;
        let _random = sh.take(32)?;
        let sid_len = sh.u8()? as usize;
        sh.take(sid_len)?;
        // ServerHello carries ONE selected cipher suite (not a list).
        let negotiated = sh.u16()?;
        let suite = CipherSuite::from_u16(negotiated).ok_or(Tls13Error::BadCipherSuite)?;
        sh.u8()?; // legacy compression methods: single null byte
        let ext_total = sh.u16()? as usize;
        let mut read = 0usize;
        let mut server_share: Option<[u8; 32]> = None;
        while read < ext_total {
            let t = sh.u16()?;
            let l = sh.u16()? as usize;
            let data = sh.take(l)?;
            read += 4 + l;
            if t == EXT_KEY_SHARE {
                // ServerHello carries a SINGLE KeyShareEntry (group, key)
                // with no list wrapper — unlike the client hello format.
                let mut ks = Reader::new(data);
                let group = ks.u16()?;
                let klen = ks.u16()? as usize;
                let key = ks.take(klen)?;
                if group == GROUP_X25519 && klen == 32 {
                    server_share = Some(key.try_into().expect("32-byte x25519 share"));
                }
            }
        }

        // Transcript begins here: ClientHello replay, then ServerHello.
        // RFC 8446 §4.4.1: only HANDSHAKE messages are hashed — strip the
        // 5-byte record header from the stored ClientHello record first.
        let hello = self.client_hello.clone().ok_or(Tls13Error::BadHandshake)?;
        let hello_hs = hello.get(5..).ok_or(Tls13Error::BadHandshake)?;
        let mut transcript = Transcript::new(suite);
        transcript.update(hello_hs);
        transcript.update(body);
        self.transcript = Some(transcript);
        self.suite = Some(suite);

        // RFC 8446 §7.1: early secret = HKDF-Extract(salt=0, IKM=0),
        // where IKM=0 means Hash.len() ZERO bytes (RFC 8448 §1.3 constant).
        let h = suite.hash();
        self.early_secret = Some(hkdf_extract(h, &vec![0u8; h.len()], &vec![0u8; h.len()]));

        server_share.ok_or(Tls13Error::NoKeyShare)
    }

    /// Complete the key schedule after ECDHE and switch to handshake-phase
    /// record protection. `shared_secret` is the raw x25519 shared secret
    /// between our hello key share and the server's.
    pub fn derive_handshake_keys(&mut self, shared_secret: &[u8]) -> Result<(), Tls13Error> {
        let suite = self.suite.ok_or(Tls13Error::BadHandshake)?;
        let h = suite.hash();

        // derived = Derive-Secret(early, "derived", "")
        let derived = derive_secret(
            h,
            self.early_secret.as_ref().unwrap(),
            "derived",
            &h.empty_hash(),
        );
        let hs = hkdf_extract(h, &derived, shared_secret);
        self.handshake_secret = Some(hs.clone());

        // master = HKDF-Extract(Derive-Secret(handshake, "derived", ""),
        // IKM = Hash.len() zero bytes).
        let derived2 = derive_secret(h, &hs, "derived", &h.empty_hash());
        self.master_secret = Some(hkdf_extract(h, &derived2, &vec![0u8; h.len()]));

        let th = self.transcript.as_ref().unwrap().hash_of();
        let shts = derive_secret(h, &hs, "s hs traffic", &th);
        let chts = derive_secret(h, &hs, "c hs traffic", &th);
        self.shts = Some(shts.clone());
        self.chts = Some(chts.clone());

        // Server->client records open with the server's handshake key.
        let (skey, siv) = key_iv_from_secret(suite, &shts);
        self.hs_read = Some((cipher_from_key(suite, &skey)?, siv, 0));
        // Client->server records seal with the client's handshake key.
        let (ckey, civ) = key_iv_from_secret(suite, &chts);
        self.hs_write = Some((cipher_from_key(suite, &ckey)?, civ, 0));
        Ok(())
    }

    /// Decrypt one encrypted record from the server during the handshake
    /// phase. Returns the inner (content_type, payload).
    fn open_hs_record(&mut self, wire: &[u8]) -> Result<(u8, Vec<u8>), Tls13Error> {
        if wire.len() < 5 || wire[0] != CONTENT_APPDATA {
            return Err(Tls13Error::BadRecord);
        }
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        if wire.len() < 5 + rec_len {
            return Err(Tls13Error::Truncated);
        }
        let aad = &wire[..5];
        let inner = &wire[5..5 + rec_len];
        let (cipher, iv, seq) = self.hs_read.as_mut().ok_or(Tls13Error::BadRecord)?;
        let nonce = record_nonce(iv, *seq);
        *seq += 1;
        let plain = cipher.open(&nonce, inner, aad)?;
        let (ct, payload) = strip_inner_padding(&plain)?;
        Ok((ct, payload.to_vec()))
    }

    /// Take one complete handshake message from `buf`, updating the
    /// transcript. Returns (type, body, transcript_hash_BEFORE_this_message).
    fn take_message(
        &mut self,
        buf: &mut Vec<u8>,
    ) -> Result<Option<(u8, Vec<u8>, Vec<u8>)>, Tls13Error> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = (buf[1] as usize) << 16 | (buf[2] as usize) << 8 | buf[3] as usize;
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let msg_type = buf[0];
        let th_before = self.transcript.as_ref().unwrap().hash_of();
        let body = buf[4..4 + len].to_vec();
        self.transcript.as_mut().unwrap().update(&buf[..4 + len]);
        buf.drain(..4 + len);
        Ok(Some((msg_type, body, th_before)))
    }

    /// Process the full encrypted server flight (EE, Certificate,
    /// CertificateVerify, Finished), verify it, derive application traffic
    /// keys. Returns the server chain and app secrets.
    pub fn process_server_flight(&mut self, records: &[u8]) -> Result<Tls13Outcome, Tls13Error> {
        let suite = self.suite.ok_or(Tls13Error::BadHandshake)?;
        let h = suite.hash();

        let mut pending: Vec<u8> = Vec::new();
        let mut rest = records;
        let mut server_chain: Vec<Vec<u8>> = Vec::new();
        let mut cv: Option<(u16, Vec<u8>, Vec<u8>)> = None; // scheme, sig, tbs
        let mut got_finished = false;

        while !got_finished {
            if pending.len() < 4
                || pending.len()
                    < 4 + ((pending[1] as usize) << 16
                        | (pending[2] as usize) << 8
                        | pending[3] as usize)
            {
                if rest.is_empty() {
                    return Err(Tls13Error::Truncated);
                }
                if rest.len() < 5 {
                    return Err(Tls13Error::Truncated);
                }
                let rec_len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
                if rest.len() < 5 + rec_len {
                    return Err(Tls13Error::Truncated);
                }
                let rec = rest[..5 + rec_len].to_vec();
                // Legacy middlebox compatibility: servers may send an
                // unencrypted ChangeCipherSpec record before the encrypted
                // flight. Skip it.
                if rec[0] == 0x14 {
                    rest = &rest[5 + rec_len..];
                    continue;
                }
                let (ct, payload) = self.open_hs_record(&rec)?;
                if ct != CONTENT_HANDSHAKE {
                    return Err(Tls13Error::UnexpectedRecord);
                }
                pending.extend_from_slice(&payload);
                rest = &rest[5 + rec_len..];
                continue;
            }
            let Some((mtype, body, th_before)) = self.take_message(&mut pending)? else {
                continue;
            };
            match mtype {
                HS_ENCRYPTED_EXTENSIONS => {}
                HS_CERTIFICATE => {
                    server_chain = parse_certificate_entry_bodies(&body)?;
                }
                HS_CERTIFICATE_VERIFY => {
                    if body.len() < 4 {
                        return Err(Tls13Error::BadHandshake);
                    }
                    let scheme = u16::from_be_bytes([body[0], body[1]]);
                    let sig_len = u16::from_be_bytes([body[2], body[3]]) as usize;
                    if body.len() < 4 + sig_len {
                        return Err(Tls13Error::BadHandshake);
                    }
                    let sig = body[4..4 + sig_len].to_vec();
                    // To-be-signed: 64 spaces, context string, 0x00,
                    // transcript hash through the Certificate message
                    // (captured BEFORE this message hit the transcript).
                    let mut tbs = Vec::with_capacity(64 + 34 + th_before.len());
                    tbs.extend_from_slice(&[0x20; 64]);
                    tbs.extend_from_slice(b"TLS 1.3, server CertificateVerify");
                    tbs.push(0);
                    tbs.extend_from_slice(&th_before);
                    cv = Some((scheme, sig, tbs));
                }
                HS_FINISHED => {
                    let shts = self.shts.as_ref().ok_or(Tls13Error::BadHandshake)?;
                    let fk = finished_key(h, shts);
                    // The transcript hash through CertificateVerify is what
                    // Finished verifies over.
                    let expect = hmac_hash(h, &fk, &th_before);
                    if body != expect {
                        return Err(Tls13Error::FinishedMismatch);
                    }
                    got_finished = true;
                }
                _ => {}
            }
        }

        // CertificateVerify: present, correct scheme, verifies against the
        // leaf certificate's public key.
        let (scheme, sig, tbs) = cv.ok_or(Tls13Error::BadHandshake)?;
        let leaf = server_chain.first().ok_or(Tls13Error::BadHandshake)?;
        verify_certificate_verify(scheme, leaf, &sig, &tbs)?;

        // Application traffic secrets, keyed off the transcript through the
        // server Finished (now fully in the transcript).
        let th = self.transcript.as_ref().unwrap().hash_of();
        let master = self
            .master_secret
            .as_ref()
            .ok_or(Tls13Error::BadHandshake)?;
        let cets = derive_secret(h, master, "c ap traffic", &th);
        let sets = derive_secret(h, master, "s ap traffic", &th);
        self.cets = Some(cets.clone());
        self.sets = Some(sets.clone());
        let (ckey, civ) = key_iv_from_secret(suite, &cets);
        let (skey, siv) = key_iv_from_secret(suite, &sets);
        self.app_write = Some((cipher_from_key(suite, &ckey)?, civ, 0));
        self.app_read = Some((cipher_from_key(suite, &skey)?, siv, 0));

        Ok(Tls13Outcome {
            suite,
            server_chain,
            server_app_secret: sets,
            client_app_secret: cets,
        })
    }

    /// Seal the client Finished handshake message as the first
    /// client-handshake-key record. Returns the full record bytes to send.
    pub fn client_finished_record(&mut self) -> Result<Vec<u8>, Tls13Error> {
        let suite = self.suite.ok_or(Tls13Error::BadHandshake)?;
        let h = suite.hash();
        let chts = self.chts.as_ref().ok_or(Tls13Error::BadHandshake)?;
        let fk = finished_key(h, chts);
        let th = self.transcript.as_ref().unwrap().hash_of();
        let verify = hmac_hash(h, &fk, &th);
        let msg = &[&[HS_FINISHED, 0, 0, verify.len() as u8][..], &verify].concat();
        self.transcript.as_mut().unwrap().update(msg);

        // Encrypt under client handshake keys, inner content type handshake,
        // AAD = the record header.
        let inner_len = msg.len() + 1 + TAG_LEN;
        let mut record = vec![CONTENT_APPDATA, 0x03, 0x03];
        record.extend_from_slice(&(inner_len as u16).to_be_bytes());
        let mut inner = msg.clone();
        inner.push(CONTENT_HANDSHAKE);
        let (cipher, iv, seq) = self.hs_write.as_mut().ok_or(Tls13Error::BadHandshake)?;
        let nonce = record_nonce(iv, *seq);
        *seq += 1;
        let sealed = cipher.seal(&nonce, &inner, &record)?;
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// Seal an application-data record under client application keys.
    pub fn seal_app_record(&mut self, data: &[u8]) -> Result<Vec<u8>, Tls13Error> {
        let inner_len = data.len() + 1 + TAG_LEN;
        let mut record = vec![CONTENT_APPDATA, 0x03, 0x03];
        record.extend_from_slice(&(inner_len as u16).to_be_bytes());
        let mut inner = data.to_vec();
        inner.push(CONTENT_APPDATA);
        let (cipher, iv, seq) = self
            .app_write
            .as_mut()
            .ok_or(Tls13Error::UnexpectedRecord)?;
        let nonce = record_nonce(iv, *seq);
        *seq += 1;
        let sealed = cipher.seal(&nonce, &inner, &record)?;
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// Open one server record during the application phase. Returns
    /// (inner content type, payload) so callers can skip post-handshake
    /// messages (e.g. NewSessionTicket) explicitly.
    pub fn open_record(&mut self, wire: &[u8]) -> Result<(u8, Vec<u8>), Tls13Error> {
        if wire.len() < 5 || wire[0] != CONTENT_APPDATA {
            return Err(Tls13Error::UnexpectedRecord);
        }
        let rec_len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
        if wire.len() < 5 + rec_len {
            return Err(Tls13Error::Truncated);
        }
        let aad = &wire[..5];
        let inner = &wire[5..5 + rec_len];
        let (cipher, iv, seq) = self.app_read.as_mut().ok_or(Tls13Error::UnexpectedRecord)?;
        let nonce = record_nonce(iv, *seq);
        *seq += 1;
        let plain = cipher.open(&nonce, inner, aad)?;
        let (ct, payload) = strip_inner_padding(&plain)?;
        Ok((ct, payload.to_vec()))
    }

    /// Open one application-data record, rejecting non-app-data inner
    /// content.
    pub fn open_app_record(&mut self, wire: &[u8]) -> Result<Vec<u8>, Tls13Error> {
        let (ct, payload) = self.open_record(wire)?;
        if ct != CONTENT_APPDATA {
            return Err(Tls13Error::UnexpectedRecord);
        }
        Ok(payload)
    }
}

impl Default for Tls13Client {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal bounds-checked reader over a byte slice.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], Tls13Error> {
        if self.buf.len() - self.pos < n {
            return Err(Tls13Error::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, Tls13Error> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Tls13Error> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize, Tls13Error> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
}

/// Parse a TLS 1.3 Certificate message into the raw DER bodies of the
/// chain. Structure: certificate_request_context<0..2^8-1>,
/// certificate_list<0..2^24-1>, each entry cert_data<1..2^24-1> +
/// extensions<0..2^16-1>.
fn parse_certificate_entry_bodies(body: &[u8]) -> Result<Vec<Vec<u8>>, Tls13Error> {
    let mut r = Reader::new(body);
    let ctx_len = r.u8()? as usize;
    r.take(ctx_len)?;
    let list_len = r.u24()?;
    let list = r.take(list_len)?;
    let mut lr = Reader::new(list);
    let mut out = Vec::new();
    while lr.pos < lr.buf.len() {
        let cert_len = lr.u24()?;
        let cert = lr.take(cert_len)?.to_vec();
        let ext_len = lr.u16()? as usize;
        lr.take(ext_len)?;
        out.push(cert);
    }
    Ok(out)
}

/// Minimal DER walker for SubjectPublicKeyInfo.
struct Der<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    /// Like `tlv`, but returns the full TLV bytes (tag + length + content).
    fn tlv_full(&mut self) -> Option<(u8, &'a [u8])> {
        let start = self.pos;
        let (tag, _) = self.tlv()?;
        let end = self.pos;
        Some((tag, &self.buf[start..end]))
    }

    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let tag = self.buf[self.pos];
        let mut p = self.pos + 1;
        let len = self.buf[p] as usize;
        p += 1;
        if len > 0x80 {
            // long form: first byte & 0x7f = length-of-length
            let n = len & 0x7f;
            if n == 0 || n > 4 || p + n > self.buf.len() {
                return None;
            }
            let mut l = 0usize;
            for b in &self.buf[p..p + n] {
                l = (l << 8) | *b as usize;
            }
            p += n;
            let l = l;
            if p + l > self.buf.len() {
                return None;
            }
            let content = &self.buf[p..p + l];
            self.pos = p + l;
            return Some((tag, content));
        }
        if p + len > self.buf.len() {
            return None;
        }
        let content = &self.buf[p..p + len];
        self.pos = p + len;
        Some((tag, content))
    }
}

/// Extract an RSA public key from a DER SubjectPublicKeyInfo
/// (rsaEncryption OID 1.2.840.113549.1.1.1).
/// Locate the SubjectPublicKeyInfo inside a full X.509 certificate DER.
/// Returns the SPKI bytes (ready for `parse_rsa_spki`).
fn parse_cert_spki(der: &[u8]) -> Option<&[u8]> {
    let mut d = Der { buf: der, pos: 0 };
    let (t, cert) = d.tlv()?; // Certificate SEQUENCE
    if t != 0x30 {
        return None;
    }
    let mut c = Der { buf: cert, pos: 0 };
    let (t, tbs) = c.tlv()?; // tbsCertificate
    if t != 0x30 {
        return None;
    }
    let mut t = Der { buf: tbs, pos: 0 };
    // version [0] EXPLICIT (optional), serialNumber, signature, issuer,
    // validity, subject, then subjectPublicKeyInfo.
    let (tag, _) = t.tlv()?;
    if tag == 0xa0 {
        // skip version; continue below
    } else {
        // Rewind: this TLV was the serialNumber, not a version.
        t.pos = 0;
    }
    let (t1, _) = t.tlv()?; // serialNumber
    if t1 != 0x02 {
        return None;
    }
    for _ in 0..4 {
        let (ti, _) = t.tlv()?; // signature, issuer, validity, subject
        if ti != 0x30 {
            return None;
        }
    }
    let (t6, spki) = t.tlv_full()?; // subjectPublicKeyInfo (full TLV)
    if t6 != 0x30 {
        return None;
    }
    Some(spki)
}

fn parse_rsa_spki(der: &[u8]) -> Option<RsaPublicKey> {
    let mut d = Der { buf: der, pos: 0 };
    let (t, spki) = d.tlv()?; // SEQUENCE
    if t != 0x30 {
        return None;
    }
    let mut s = Der { buf: spki, pos: 0 };
    let (t, alg) = s.tlv()?; // AlgorithmIdentifier SEQUENCE
    if t != 0x30 {
        return None;
    }
    let (t, bitstr) = s.tlv()?; // BIT STRING
    if t != 0x03 || bitstr.is_empty() || bitstr[0] != 0 {
        return None;
    }
    // Check the OID is rsaEncryption inside alg: SEQUENCE { OID, ... }
    let mut a = Der { buf: alg, pos: 0 };
    let (t, oid) = a.tlv()?;
    if t != 0x06 || oid != [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] {
        return None;
    }
    // RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER }
    let key_der = &bitstr[1..];
    let mut k = Der {
        buf: key_der,
        pos: 0,
    };
    let (t, seq) = k.tlv()?;
    if t != 0x30 {
        return None;
    }
    let mut kv = Der { buf: seq, pos: 0 };
    let (t, n) = kv.tlv()?;
    if t != 0x02 {
        return None;
    }
    let (t, e) = kv.tlv()?;
    if t != 0x02 {
        return None;
    }
    // Strip a possible leading zero byte (sign placeholder).
    let n = if !n.is_empty() && n[0] == 0 {
        &n[1..]
    } else {
        n
    };
    let e = if !e.is_empty() && e[0] == 0 {
        &e[1..]
    } else {
        e
    };
    RsaPublicKey::new(BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)).ok()
}

/// Verify the CertificateVerify signature over the RFC 8446 §4.4.3
/// to-be-signed blob. Supports rsa_pss_rsae_sha256/384/512 and
/// rsa_pkcs1_sha256/384/512 (what Xray/Go servers sign with).
fn verify_certificate_verify(
    scheme: u16,
    leaf_der: &[u8],
    sig: &[u8],
    tbs: &[u8],
) -> Result<(), Tls13Error> {
    let spki = parse_cert_spki(leaf_der).ok_or(Tls13Error::BadScheme)?;
    let key = parse_rsa_spki(spki).ok_or(Tls13Error::BadScheme)?;
    match scheme {
        0x0804 | 0x0805 | 0x0806 => {
            let s = PssSig::try_from(sig).map_err(|_| Tls13Error::CertVerifyRejected)?;
            let ok = match scheme {
                0x0804 => PssVerifyingKey::<Sha256>::new(key).verify(tbs, &s).is_ok(),
                0x0805 => PssVerifyingKey::<Sha384>::new(key).verify(tbs, &s).is_ok(),
                _ => PssVerifyingKey::<Sha512>::new(key).verify(tbs, &s).is_ok(),
            };
            if ok {
                Ok(())
            } else {
                Err(Tls13Error::CertVerifyRejected)
            }
        }
        0x0401 | 0x0501 | 0x0601 => {
            let s = Pkcs1Sig::try_from(sig).map_err(|_| Tls13Error::CertVerifyRejected)?;
            let ok = match scheme {
                0x0401 => Pkcs1VerifyingKey::<Sha256>::new(key)
                    .verify(tbs, &s)
                    .is_ok(),
                0x0501 => Pkcs1VerifyingKey::<Sha384>::new(key)
                    .verify(tbs, &s)
                    .is_ok(),
                _ => Pkcs1VerifyingKey::<Sha512>::new(key)
                    .verify(tbs, &s)
                    .is_ok(),
            };
            if ok {
                Ok(())
            } else {
                Err(Tls13Error::CertVerifyRejected)
            }
        }
        _ => Err(Tls13Error::BadScheme),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::build_client_hello;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::process::{Command, Stdio};

    fn chrome_hello(secret: &XSecret) -> Vec<u8> {
        let mut random = [0u8; 32];
        random[..17].copy_from_slice(b"tls13-test-random");
        let session_id = vec![7u8; 32];
        build_client_hello(
            Some("localhost"),
            XPublic::from(secret).as_bytes(),
            &random,
            &session_id,
        )
        .expect("hello")
    }

    #[test]
    fn hkdf_expand_label_matches_rfc8448_shape() {
        // Self-consistency: expand twice with the same inputs is stable, and
        // different labels produce different output.
        let secret = [3u8; 32];
        let a = hkdf_expand_label(HashAlg::S256, &secret, "key", &[], 16);
        let b = hkdf_expand_label(HashAlg::S256, &secret, "key", &[], 16);
        let c = hkdf_expand_label(HashAlg::S256, &secret, "iv", &[], 16);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn record_nonce_xor_is_deterministic_and_seq_dependent() {
        let iv = [0x11u8; 12];
        let n0 = record_nonce(&iv, 0);
        let n1 = record_nonce(&iv, 1);
        let n_big = record_nonce(&iv, u64::MAX);
        assert_eq!(n0, iv.to_vec());
        assert_ne!(n0, n1);
        assert_ne!(n1, n_big);
        // XOR only touches the last 8 bytes.
        assert_eq!(&n1[..4], &iv[..4]);
    }

    #[test]
    fn certificate_message_yields_chain_bodies() {
        // Two fake 3-byte certs with no extensions.
        let mut body = vec![0u8]; // empty request context
        body.extend_from_slice(&[
            0x00, 0x00, 0x0f, // list length: 3 + 4 + 2 + 3 + 4 + 2 - 3? compute below
        ]);
        // Build properly instead: cert1 (3 bytes) + ext(0) + cert2 (3 bytes) + ext(0)
        let mut inner = Vec::new();
        inner.extend_from_slice(&3u32.to_be_bytes()[1..]);
        inner.extend_from_slice(b"abc");
        inner.extend_from_slice(&0u16.to_be_bytes());
        inner.extend_from_slice(&3u32.to_be_bytes()[1..]);
        inner.extend_from_slice(b"def");
        inner.extend_from_slice(&0u16.to_be_bytes());
        body = vec![0u8];
        body.extend_from_slice(&(inner.len() as u32).to_be_bytes()[1..]);
        body.extend_from_slice(&inner);
        let chain = parse_certificate_entry_bodies(&body).expect("parse");
        assert_eq!(chain, vec![b"abc".to_vec(), b"def".to_vec()]);
    }

    #[test]
    fn truncated_flight_is_rejected() {
        let mut client = Tls13Client::new();
        let secret = XSecret::random_from_rng(rand_core::OsRng);
        client.set_client_hello(&chrome_hello(&secret));
        // Never got a ServerHello: flight processing must fail cleanly.
        let err = client.process_server_flight(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]);
        assert!(matches!(err, Err(Tls13Error::BadHandshake)));
    }

    /// Spin up a REAL TLS 1.3 server (openssl + python3 stdlib ssl), drive
    /// the full handshake with our Chrome-fingerprint hello + this core,
    /// and exchange application data. Skipped silently when the toolchain
    /// is unavailable.
    #[test]
    fn full_handshake_against_a_real_tls13_server() {
        let have = |bin: &str| {
            Command::new("which")
                .arg(bin)
                .stdout(Stdio::piped())
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        if !have("openssl") || !have("python3") {
            eprintln!("skipping: openssl/python3 unavailable");
            return;
        }

        let dir = std::env::temp_dir().join(format!("shadevpn-tls13-{}", std::process::id()));
        let dir = dir.as_path();
        std::fs::create_dir_all(dir).expect("tmpdir");
        let key = dir.join("key.pem");
        let cert = dir.join("cert.pem");
        let gen = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key.to_str().unwrap(),
                "-out",
                cert.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
            ])
            .output()
            .expect("spawn openssl");
        assert!(gen.status.success(), "openssl cert generation failed");

        // Reserve a free port, then hand it to the Python server. The Rust
        // listener MUST be dropped first or Python's bind fails with
        // EADDRINUSE and the client talks to a deaf socket.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().unwrap().port()
        };
        let key_str = key.display().to_string();
        let cert_str = cert.display().to_string();
        let server_script = format!(
            r#"
import ssl, socket, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.keylog_file = "/tmp/shade-dbg-keys.log"
ctx.load_cert_chain(r"{cert_str}", r"{key_str}")
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", {port}))
s.listen(1)
s.settimeout(15)
conn, _ = s.accept()
tls = ctx.wrap_socket(conn, server_side=True)
tls.settimeout(15)
data = tls.recv(4096)
tls.sendall(b"ECHO:" + data)
tls.shutdown(socket.SHUT_RDWR)
tls.close()
s.close()
"#
        );

        let mut python = Command::new("python3")
            .arg("-c")
            .arg(&server_script)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python3");

        // Wait for the listener (python binds after the spawn race).
        let mut stream = loop {
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(s) => break s,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        };
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();

        // --- ClientHello (the real Chrome-fingerprint record) ---
        let eph = XSecret::random_from_rng(rand_core::OsRng);
        let hello = chrome_hello(&eph);
        let mut client = Tls13Client::new();
        client.set_client_hello(&hello);
        stream.write_all(&hello).expect("send hello");

        // --- read ServerHello (unprotected) ---
        let sh = read_one_record(&mut stream).unwrap_or_else(|e| {
            let mut msg = String::new();
            if let Some(mut err) = python.stderr.take() {
                use std::io::Read as _;
                let _ = err.read_to_string(&mut msg);
            }
            panic!("read SH failed: {e}; server stderr: {msg}");
        });
        let server_share = client
            .process_server_hello(&sh)
            .unwrap_or_else(|e| panic!("server hello: {e}; record: {:02x?}", &sh));

        // --- ECDHE and key schedule ---
        eprintln!("DBG eph_secret = {}", hex::encode(eph.as_bytes()));
        eprintln!("DBG server_share = {}", hex::encode(server_share));
        eprintln!("DBG hello_full = {}", hex::encode(&hello));
        eprintln!("DBG sh_record = {}", hex::encode(&sh));
        let shared = eph.diffie_hellman(&XPublic::from(server_share));
        client
            .derive_handshake_keys(shared.as_bytes())
            .expect("handshake keys");

        // --- read the encrypted flight (EE/Cert/CV/Fin) ---
        let mut flight = Vec::new();
        // Keep reading until the client Finished could be derived: the
        // flight is exactly the records before we must respond. Read until
        // a short poll finds no more data (the server stops after Finished;
        // NewSessionTicket may follow immediately, which we must NOT feed).
        read_flight(&mut stream, &mut flight);
        let outcome = client
            .process_server_flight(&flight)
            .expect("server flight");
        assert!(
            !outcome.server_chain.is_empty(),
            "server chain must be present"
        );
        assert!(matches!(
            outcome.suite,
            CipherSuite::Aes128GcmSha256
                | CipherSuite::Aes256GcmSha384
                | CipherSuite::ChaCha20Poly1305Sha256
        ));

        // --- client Finished completes the handshake on the server side ---
        let fin = client.client_finished_record().expect("client finished");
        stream.write_all(&fin).expect("send finished");

        // --- application data round trip through REAL TLS ---
        let payload = b"shadevpn-interop-ping";
        let rec = client.seal_app_record(payload).expect("seal app");
        stream.write_all(&rec).expect("send app");

        // Read (possibly NewSessionTicket first), then the echo.
        let mut buf: Vec<u8> = Vec::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let echoed = loop {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for echo"
            );
            let r = read_one_record(&mut stream).expect("read response");
            let (ct, inner) = client.open_record(&r).expect("open response record");
            if ct == CONTENT_APPDATA {
                break inner;
            }
            // Handshake post-handshake (NST) — skip.
            buf.clear();
        };
        assert_eq!(echoed, b"ECHO:shadevpn-interop-ping");
        drop(buf);

        let _ = python.wait();
        // Surface server-side errors on failure for debuggability.
        let _ = python
            .stderr
            .take()
            .map(|mut e| std::io::Read::read_to_string(&mut e, &mut String::new()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Read exactly one TLS record from the stream.
    fn read_one_record(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
        let mut header = [0u8; 5];
        stream.read_exact(&mut header)?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body)?;
        let mut rec = header.to_vec();
        rec.extend_from_slice(&body);
        Ok(rec)
    }

    /// Read records until the peer pauses (the flight boundary): the server
    /// sends EE/Cert/CV/Finished then waits for our Finished.
    fn read_flight(stream: &mut TcpStream, out: &mut Vec<u8>) {
        loop {
            match read_one_record(stream) {
                Ok(rec) => out.extend_from_slice(&rec),
                Err(_) => break,
            }
            // Heuristic: after the last flight record the server is silent,
            // and the next read times out — but NST can race ahead. The
            // flight always ends with a Finished whose plaintext we cannot
            // see here, so use a short poll: if no more bytes are buffered
            // after a brief sleep, stop.
            std::thread::sleep(std::time::Duration::from_millis(30));
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(150)))
                .unwrap();
            match stream.peek(&mut [0u8; 1]) {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
    }
}
