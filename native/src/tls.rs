//! Real TLS 1.3 ClientHello record: build and parse.
//!
//! The Reality hello is a byte-exact, legal TLS 1.3 ClientHello record — the
//! first thing on the wire looks like a browser handshake to any passive
//! observer (and to Xray's parser). Reality material rides in standard TLS
//! fields:
//!
//! - ephemeral X25519 public key -> `key_share` extension (group x25519)
//! - session tag (HMAC over the session id) -> 32-byte `random` field
//! - short ID -> `legacy_session_id` field (the Xray Reality selector slot)
//! - SNI -> `server_name` extension
//!
//! Authentication does NOT depend on any non-TLS payload: the session tag is
//! an unforgeable AEAD seal inside the legacy session id field, keyed by an
//! Xray-construction HKDF over the ECDH shared secret and salted by bytes of
//! `random` itself, so only a client holding the server's Reality key
//! material can produce a valid (key_share, session_id) pair. A censor or
//! prober that opens the record sees nothing but a plausible browser
//! ClientHello.
//!
//! NOTE: the reference REALITY deployment inspects the ClientHello through a
//! full Go TLS stack (uTLS client, Go server parser) and tolerates only
//! shapes a real TLS stack produces. Our hello is byte-legal and parses with
//! any conforming parser, but until the client rides a full TLS stack its
//! fingerprint is NONSTANDARD — a hand-built hello. Fingerprint realism is
//! tracked for the on-device TLS-camouflage layer; nothing here depends on
//! being mistaken for one particular browser.
//!
//! Bounds-checked everywhere; no secret material is embedded beyond the
//! public ephemeral key and the (already MACed) session tag.

/// TLS content type: handshake.
const CONTENT_HANDSHAKE: u8 = 0x16;
/// Handshake message type: ClientHello.
const HS_CLIENT_HELLO: u8 = 0x01;
/// Extension type: server_name.
const EXT_SERVER_NAME: u16 = 0x0000;
/// Extension type: supported_groups.
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
/// Extension type: signature_algorithms.
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// Extension type: key_share.
const EXT_KEY_SHARE: u16 = 0x0033;
/// Extension type: supported_versions.
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// Extension type: psk_key_exchange_modes.
const EXT_PSK_MODES: u16 = 0x002d;
/// Extension type: extended_master_secret.
const EXT_EMS: u16 = 0x0017;
/// Extension type: renegotiation_info.
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/// Named group: x25519.
const GROUP_X25519: u16 = 0x001d;
/// legacy_session_id is capped at 32 bytes by RFC 8446.
const MAX_SESSION_ID_LEN: usize = 32;
const X25519_PK_LEN: usize = 32;
/// Byte offset of the legacy session id BYTES inside the full ClientHello
/// record: record header (5) + handshake header (4) + legacy version (2) +
/// random (32) + the 1-byte session-id length prefix. The length byte itself
/// stays untouched — matching Xray, whose AAD window (`hello.Raw[39:]`)
/// covers exactly the 32 id bytes. Exported so the REALITY layer can zero
/// the session id when computing the AEAD additional authenticated data.
pub const SESSION_ID_OFFSET: usize = 5 + 4 + 2 + 32 + 1;

/// Test-only reachability: the parser's production consumer (standalone
/// server tooling) ships in a later milestone; today only the honest
/// in-process test server parses hellos.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// Record or message ended before all declared fields were present.
    Truncated,
    /// Record content type is not a handshake, or message type is not a
    /// ClientHello.
    BadRecordType,
    /// Record version outside the legacy range real clients use.
    BadRecordVersion,
    /// A declared length disagrees with the bytes actually present.
    LengthMismatch,
    /// Bytes remain after the ClientHello body that the extensions block
    /// does not account for.
    TrailingBytes,
    /// The server_name extension is present but malformed.
    BadServerName,
    /// legacy_session_id exceeds the RFC 8446 cap.
    ShortIdTooLong,
    /// No x25519 share was offered.
    NoX25519KeyShare,
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            TlsError::Truncated => "TLS record is truncated",
            TlsError::BadRecordType => "not a TLS ClientHello record",
            TlsError::BadRecordVersion => "unexpected legacy record version",
            TlsError::LengthMismatch => "declared length does not match payload",
            TlsError::TrailingBytes => "trailing bytes after ClientHello",
            TlsError::BadServerName => "malformed server_name extension",
            TlsError::ShortIdTooLong => "session id exceeds 32 bytes",
            TlsError::NoX25519KeyShare => "no x25519 share offered",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TlsError {}

/// A parsed ClientHello: exactly the fields the Reality server needs.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedClientHello {
    /// Host from the server_name extension, if offered.
    pub sni: Option<String>,
    /// The 32-byte `random` field: REALITY salt and nonce source.
    pub random: [u8; 32],
    /// legacy_session_id bytes: the sealed REALITY session material.
    pub session_id: Vec<u8>,
    /// X25519 public key from the key_share extension.
    pub ephemeral_public: [u8; 32],
    /// Whether the client offered TLS 1.3 in supported_versions.
    pub tls13_negotiable: bool,
}

fn push_u16(out: &mut Vec<u8>, n: u16) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn push_u24(out: &mut Vec<u8>, n: usize) {
    debug_assert!(n <= 0xFF_FFFF);
    out.extend_from_slice(&(n as u32).to_be_bytes()[1..4]);
}

fn push_extension(out: &mut Vec<u8>, ext_type: u16, data: &[u8]) {
    push_u16(out, ext_type);
    push_u16(out, data.len() as u16);
    out.extend_from_slice(data);
}

/// Build a complete TLS 1.3 ClientHello record.
///
/// `random` is the real hello random (32 bytes): the REALITY layer salts its
/// key derivation with `random[..20]` and uses `random[20..32]` as the AEAD
/// nonce for the session-id seal. `session_id` is the (already sealed)
/// 32-byte legacy session id, or zeros before sealing.
///
/// `sni = None` omits the server_name extension entirely (still legal TLS).
pub fn build_client_hello(
    sni: Option<&str>,
    ephemeral_public: &[u8; X25519_PK_LEN],
    random: &[u8; 32],
    session_id: &[u8],
) -> Result<Vec<u8>, TlsError> {
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(TlsError::ShortIdTooLong);
    }

    let mut exts: Vec<u8> = Vec::new();
    if let Some(host) = sni {
        // server_name: [u16 list_len][u8 name_type=0][u16 name_len][name]
        let mut list: Vec<u8> = Vec::with_capacity(host.len() + 3);
        list.push(0u8); // host_name name type
        push_u16(&mut list, host.len() as u16);
        list.extend_from_slice(host.as_bytes());
        let mut ext = Vec::with_capacity(list.len() + 2);
        push_u16(&mut ext, list.len() as u16);
        ext.extend_from_slice(&list);
        push_extension(&mut exts, EXT_SERVER_NAME, &ext);
    }
    // Browser-realistic extensions an untyped prober expects to see.
    push_extension(&mut exts, EXT_EMS, &[]);
    push_extension(&mut exts, EXT_RENEGOTIATION_INFO, &[0x00]);
    // supported_groups: x25519, secp256r1.
    push_extension(
        &mut exts,
        EXT_SUPPORTED_GROUPS,
        &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17],
    );
    // signature_algorithms: ecdsa_sha256, rsa_pss_sha256, rsa_pkcs1_sha256,
    // rsa_pss_sha384.
    push_extension(
        &mut exts,
        EXT_SIGNATURE_ALGORITHMS,
        &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x05],
    );
    // key_share: one client share, x25519.
    let mut share: Vec<u8> = Vec::with_capacity(4 + X25519_PK_LEN);
    push_u16(&mut share, GROUP_X25519);
    push_u16(&mut share, X25519_PK_LEN as u16);
    share.extend_from_slice(ephemeral_public);
    let mut key_share: Vec<u8> = Vec::with_capacity(share.len() + 2);
    push_u16(&mut key_share, share.len() as u16);
    key_share.extend_from_slice(&share);
    push_extension(&mut exts, EXT_KEY_SHARE, &key_share);
    // supported_versions: TLS 1.3 only.
    push_extension(&mut exts, EXT_SUPPORTED_VERSIONS, &[0x01, 0x03, 0x04]);
    // psk_key_exchange_modes: psk_dhe_ke.
    push_extension(&mut exts, EXT_PSK_MODES, &[0x01, 0x01]);

    // ---- ClientHello body ----
    let cipher_suites: [u8; 10] = [
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b, // ECDHE_RSA_AES_128_GCM
        0xc0, 0x30, // ECDHE_RSA_AES_256_GCM
    ];
    let mut body: Vec<u8> = Vec::with_capacity(
        2 + 32 + 1 + session_id.len() + 2 + cipher_suites.len() + 2 + 2 + exts.len(),
    );
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version
    body.extend_from_slice(random); // real hello random (REALITY salt + nonce)
    body.push(session_id.len() as u8); // legacy_session_id: sealed REALITY material
    body.extend_from_slice(session_id);
    push_u16(&mut body, cipher_suites.len() as u16);
    body.extend_from_slice(&cipher_suites);
    body.push(0x01); // compression_methods: length 1
    body.push(0x00); // null compression
    push_u16(&mut body, exts.len() as u16);
    body.extend_from_slice(&exts);

    // ---- handshake message + record layer ----
    let mut handshake = Vec::with_capacity(4 + body.len());
    handshake.push(HS_CLIENT_HELLO);
    push_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(CONTENT_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // legacy record version
    push_u16(&mut record, handshake.len() as u16);
    record.extend_from_slice(&handshake);
    Ok(record)
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if self.buf.len() - self.pos < n {
            return Err(TlsError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, TlsError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TlsError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u24(&mut self) -> Result<usize, TlsError> {
        let b = self.take(3)?;
        Ok((b[0] as usize) << 16 | (b[1] as usize) << 8 | b[2] as usize)
    }
    fn exhausted(&self) -> bool {
        self.pos == self.buf.len()
    }
}

/// Parse a complete TLS 1.3 ClientHello record from raw wire bytes.
#[cfg_attr(not(test), allow(dead_code))]
pub fn parse_client_hello(wire: &[u8]) -> Result<ParsedClientHello, TlsError> {
    let mut r = Reader::new(wire);
    if r.u8()? != CONTENT_HANDSHAKE {
        return Err(TlsError::BadRecordType);
    }
    let version = r.take(2)?;
    if version[0] != 0x03 || version[1] > 0x03 {
        return Err(TlsError::BadRecordVersion);
    }
    let record_len = r.u16()? as usize;
    if r.buf.len() - r.pos != record_len {
        return Err(TlsError::LengthMismatch);
    }
    if r.u8()? != HS_CLIENT_HELLO {
        return Err(TlsError::BadRecordType);
    }
    let body_len = r.u24()?;
    if r.buf.len() - r.pos != body_len {
        return Err(TlsError::LengthMismatch);
    }

    let _legacy_version = r.take(2)?;
    let random: [u8; 32] = r.take(32)?.try_into().expect("32 bytes taken");
    let sid_len = r.u8()? as usize;
    if sid_len > MAX_SESSION_ID_LEN {
        return Err(TlsError::ShortIdTooLong);
    }
    let session_id = r.take(sid_len)?.to_vec();
    let cipher_len = r.u16()? as usize;
    if !cipher_len.is_multiple_of(2) {
        return Err(TlsError::LengthMismatch);
    }
    r.take(cipher_len)?;
    let comp_len = r.u8()? as usize;
    r.take(comp_len)?;

    let mut sni: Option<String> = None;
    let mut ephemeral_public: Option<[u8; X25519_PK_LEN]> = None;
    let mut tls13_negotiable = false;

    let ext_total = r.u16()? as usize;
    let mut ext_read = 0usize;
    while ext_read < ext_total {
        let ext_type = r.u16()?;
        let ext_len = r.u16()? as usize;
        if ext_read + 4 + ext_len > ext_total {
            return Err(TlsError::LengthMismatch);
        }
        let mut er = Reader::new(r.take(ext_len)?);
        match ext_type {
            EXT_SERVER_NAME => {
                let list_len = er.u16()? as usize;
                let name_type = er.u8()?;
                let name_len = er.u16()? as usize;
                if name_type != 0 || list_len != 1 + 2 + name_len {
                    return Err(TlsError::BadServerName);
                }
                let name = er.take(name_len)?;
                if !er.exhausted() {
                    return Err(TlsError::BadServerName);
                }
                sni = Some(
                    std::str::from_utf8(name)
                        .map_err(|_| TlsError::BadServerName)?
                        .to_owned(),
                );
            }
            EXT_KEY_SHARE => {
                let shares_len = er.u16()? as usize;
                let mut share_read = 0usize;
                while share_read < shares_len {
                    let group = er.u16()?;
                    let klen = er.u16()? as usize;
                    let key = er.take(klen)?;
                    share_read += 4 + klen;
                    if group == GROUP_X25519 && klen == X25519_PK_LEN && ephemeral_public.is_none()
                    {
                        ephemeral_public = Some(key.try_into().expect("32-byte key"));
                    }
                }
                if !er.exhausted() {
                    return Err(TlsError::LengthMismatch);
                }
            }
            EXT_SUPPORTED_VERSIONS => {
                let count = er.u8()? as usize;
                for _ in 0..count {
                    if er.u16()? == 0x0304 {
                        tls13_negotiable = true;
                    }
                }
                if !er.exhausted() {
                    return Err(TlsError::LengthMismatch);
                }
            }
            // Extensions we don't interpret are skipped wholesale; only the
            // parsed ones above must consume their body exactly.
            _ => {}
        }
        ext_read += 4 + ext_len;
    }
    if !r.exhausted() {
        return Err(TlsError::TrailingBytes);
    }

    Ok(ParsedClientHello {
        sni,
        random,
        session_id,
        ephemeral_public: ephemeral_public.ok_or(TlsError::NoX25519KeyShare)?,
        tls13_negotiable,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> (&'static str, [u8; 32], [u8; 32], Vec<u8>) {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        let mut tag = [0u8; 32];
        for (i, b) in tag.iter_mut().enumerate() {
            *b = (i as u8) ^ 0xa5;
        }
        ("tunnel.example.com", pk, tag, vec![0x01, 0x02])
    }

    #[test]
    fn round_trip_preserves_all_reality_fields() {
        let (sni, pk, random, sid) = sample_inputs();
        let record = build_client_hello(Some(sni), &pk, &random, &sid).expect("build");
        let parsed = parse_client_hello(&record).expect("parse");
        assert_eq!(parsed.sni.as_deref(), Some(sni));
        assert_eq!(parsed.ephemeral_public, pk);
        assert_eq!(parsed.random, random);
        assert_eq!(parsed.session_id, sid);
        assert!(parsed.tls13_negotiable);
    }

    #[test]
    fn record_opens_with_handshake_type_and_legacy_version() {
        let (_, pk, tag, short_id) = sample_inputs();
        let record = build_client_hello(Some("x.example.com"), &pk, &tag, &short_id).unwrap();
        assert_eq!(record[0], CONTENT_HANDSHAKE, "record content type");
        assert_eq!(&record[1..3], &[0x03, 0x01], "legacy record version");
        assert_eq!(record[5], HS_CLIENT_HELLO, "handshake message type");
        // Record length must cover exactly the handshake message.
        let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), 5 + record_len);
    }

    #[test]
    fn random_field_rides_at_the_documented_offset() {
        let (_, pk, random, sid) = sample_inputs();
        let record = build_client_hello(Some("x.example.com"), &pk, &random, &sid).unwrap();
        // random starts after: record(5) + hs header(4) + legacy_version(2)
        assert_eq!(&record[11..43], random.as_slice());
        // The session id bytes start after random AND the 1-byte length
        // prefix — the offset the REALITY layer uses for its AAD window.
        assert_eq!(SESSION_ID_OFFSET, 44);
        assert_eq!(
            &record[SESSION_ID_OFFSET..SESSION_ID_OFFSET + sid.len()],
            sid.as_slice()
        );
    }

    #[test]
    fn key_share_carries_ephemeral_public_key() {
        let (_, pk, tag, short_id) = sample_inputs();
        let record = build_client_hello(Some("x.example.com"), &pk, &tag, &short_id).unwrap();
        let parsed = parse_client_hello(&record).unwrap();
        assert_eq!(parsed.ephemeral_public, pk);
    }

    #[test]
    fn hello_without_sni_is_still_valid_tls() {
        let (_, pk, tag, short_id) = sample_inputs();
        let record = build_client_hello(None, &pk, &tag, &short_id).expect("build");
        let parsed = parse_client_hello(&record).expect("parse");
        assert_eq!(parsed.sni, None);
        assert_eq!(parsed.ephemeral_public, pk);
    }

    #[test]
    fn short_id_over_32_bytes_is_rejected() {
        let (_, pk, random, _) = sample_inputs();
        let long = vec![0u8; 33];
        assert_eq!(
            build_client_hello(Some("x.example.com"), &pk, &random, &long),
            Err(TlsError::ShortIdTooLong)
        );
    }

    #[test]
    fn truncated_records_are_rejected() {
        let (sni, pk, tag, short_id) = sample_inputs();
        let record = build_client_hello(Some(sni), &pk, &tag, &short_id).unwrap();
        for cut in [1usize, 5, 6, 11, 40, record.len() / 2, record.len() - 1] {
            assert!(
                parse_client_hello(&record[..cut]).is_err(),
                "cut at {cut} must not parse"
            );
        }
    }

    #[test]
    fn trailing_bytes_after_the_hello_are_rejected() {
        let (sni, pk, tag, short_id) = sample_inputs();
        let mut record = build_client_hello(Some(sni), &pk, &tag, &short_id).unwrap();
        record.push(0x00);
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn non_handshake_record_type_is_rejected() {
        let (sni, pk, tag, short_id) = sample_inputs();
        let mut record = build_client_hello(Some(sni), &pk, &tag, &short_id).unwrap();
        record[0] = 0x15; // alert
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn record_length_mismatch_is_rejected() {
        let (sni, pk, tag, short_id) = sample_inputs();
        let mut record = build_client_hello(Some(sni), &pk, &tag, &short_id).unwrap();
        // Claim one byte less than present.
        let declared = u16::from_be_bytes([record[3], record[4]]);
        let shorter = declared - 1;
        record[3..5].copy_from_slice(&shorter.to_be_bytes());
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn truncated_body_length_is_rejected() {
        let (sni, pk, tag, short_id) = sample_inputs();
        let mut record = build_client_hello(Some(sni), &pk, &tag, &short_id).unwrap();
        // Handshake length is a 3-byte field at record[6..9]; claim one less.
        record[8] = record[8].saturating_sub(1);
        assert!(parse_client_hello(&record).is_err());
    }

    #[test]
    fn error_strings_reveal_no_material() {
        for e in [
            TlsError::Truncated,
            TlsError::BadRecordType,
            TlsError::BadRecordVersion,
            TlsError::LengthMismatch,
            TlsError::TrailingBytes,
            TlsError::BadServerName,
            TlsError::ShortIdTooLong,
            TlsError::NoX25519KeyShare,
        ] {
            assert!(!e.to_string().contains("secret"));
            assert!(!e.to_string().contains("key"));
        }
    }
}
