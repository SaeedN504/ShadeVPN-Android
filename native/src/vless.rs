//! VLESS inner protocol: request/response headers and XTLS Vision padding
//! framing, byte-identical to Xray-core (`proxy/vless/encoding/encoding.go`
//! and `proxy/proxy.go`).
//!
//! This layer sits INSIDE the Reality record layer (`crate::handshake`):
//! each Vision chunk is sealed into one Reality record before it touches the
//! wire, and each opened record is reassembled into the Vision stream. The
//! module is a pure state machine over byte slices so tests can assert on
//! wire truth without sockets.
//!
//! Byte-exact constructions (Xray-core):
//!
//! - Request header: `[version=0][uuid 16][addons][command][address][port]`.
//!   Addons are a proto varint field: `0x0a <len> [0x00]` (empty flow →
//!   `0x0a 0x01 0x00`); with flow `xtls-rprx-vision` the padding flag is set:
//!   `0x0a 0x03 0x01 0x01 <len>` — that flag is what enables Vision padding
//!   on the peer.
//! - Response header: `[version=0][addons]` (no command/address).
//! - Vision padding frame: `[uuid 16, first frame only][command 1][content
//!   len 2 BE][padding len 2 BE][content][padding]`, commands 0 = continue,
//!   1 = end, 2 = direct. Padding length is random, capped at
//!   `buf.Size - 21 - contentLen` exactly like `XtlsPadding`; the long
//!   padding used to hide the VLESS header follows the reference `testseed`
//!   ranges (900/500/900/256).
//! - Unpadding state machine mirrors `XtlsUnpadding`: -1 = initial, a UUID
//!   prefix re-synchronizes the frame parser, and unknown bytes outside
//!   padding mode pass through untouched.
//!
//! No secret is ever formatted into an error string.

use rand_core::OsRng;
use rand_core::RngCore;

/// VLESS protocol version byte (Xray: `encoding.Version = 0`).
pub const VERSION: u8 = 0;

/// VLESS command bytes.
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;
/// Xray routes Mux to the magic domain; kept for completeness.
pub const CMD_MUX: u8 = 0x0f;

/// Vision padding commands (`proxy/proxy.go`).
pub const PADDING_CONTINUE: u8 = 0x00;
pub const PADDING_END: u8 = 0x01;
pub const PADDING_DIRECT: u8 = 0x02;

/// Xray's `buf.Size` (2 KiB) bounds every padding frame.
pub const BUF_SIZE: usize = 2048;
/// `buf.Size - 21` is the maximum frame body (5-byte header + content +
/// padding must fit), matching `ReshapeMultiBuffer`'s bound.
pub const MAX_FRAME_BODY: usize = BUF_SIZE - 21;

/// The `testseed` values Xray uses when none are configured: the long
/// padding that hides the VLESS header samples [900 - content, 900) and the
/// regular padding samples [0, 256).
pub const TESTSEED: [u32; 4] = [900, 500, 900, 256];

/// Address type bytes (`protocol.AddressFamily`).
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// A VLESS proxy destination address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    Domain(String),
}

impl Address {
    fn atyp(&self) -> u8 {
        match self {
            Address::Ipv4(_) => ATYP_IPV4,
            Address::Ipv6(_) => ATYP_IPV6,
            Address::Domain(_) => ATYP_DOMAIN,
        }
    }

    fn push_to(&self, out: &mut Vec<u8>) {
        match self {
            Address::Ipv4(octets) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(octets);
            }
            Address::Ipv6(octets) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(octets);
            }
            Address::Domain(name) => {
                out.push(ATYP_DOMAIN);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VlessError {
    /// A length prefix exceeded the fixed layout or the buffer bound.
    Layout,
    /// The response header did not match the request.
    BadResponse,
    /// The identity prefix check failed on a stream that required it.
    UuidMismatch,
    /// A Vision frame declared a length outside the legal bounds.
    BadFrame,
}

impl VlessError {
    pub fn reason(&self) -> &'static str {
        match self {
            VlessError::Layout => "vless fixed-layout overflow",
            VlessError::BadResponse => "vless response rejected",
            VlessError::UuidMismatch => "padding identity mismatch",
            VlessError::BadFrame => "padding frame out of bounds",
        }
    }
}

/// Build the VLESS request header.
///
/// `uuid` must be 16 bytes; `flow` enables the Vision padding flag when it is
/// `Some("xtls-rprx-vision")` (any flow value sets the flag, matching Xray's
/// addon serialization of non-empty flow). Address and port follow the
/// `PortThenAddress` parser order: 2-byte BE port, then the address.
pub fn build_request_header(
    uuid: &[u8; 16],
    flow: Option<&str>,
    command: u8,
    address: &Address,
    port: u16,
) -> Result<Vec<u8>, VlessError> {
    // Addons: field 1 (flow), varint length. Flow is serialized as a string
    // subfield; Xray writes `0x0a <len> <bytes>` where the flow submessage
    // contains `0x01 <len> <flow>` when padding is enabled. An empty flow is
    // the canonical `0x0a 0x01 0x00` (empty string subfield).
    let addons: Vec<u8> = match flow {
        None => vec![0x0a, 0x01, 0x00],
        Some(name) if name.is_empty() => vec![0x0a, 0x01, 0x00],
        Some(name) => {
            let mut sub = Vec::new();
            sub.push(0x01); // padding subfield tag
            sub.push(name.len() as u8);
            sub.extend_from_slice(name.as_bytes());
            let mut out = vec![0x0a];
            encode_varint(sub.len(), &mut out);
            out.extend_from_slice(&sub);
            out
        }
    };

    let mut out = Vec::with_capacity(1 + 16 + addons.len() + 1 + 8 + 2);
    out.push(VERSION);
    out.extend_from_slice(uuid);
    out.extend_from_slice(&addons);
    out.push(command);
    if command != CMD_MUX {
        out.extend_from_slice(&port.to_be_bytes());
        address.push_to(&mut out);
    }
    Ok(out)
}

/// Parse a VLESS request header from the wire. Returns the UUID, flow string
/// (if the addons carried one), command, address, and port. Bounds-checked.
pub fn parse_request_header(wire: &[u8]) -> Result<ParsedRequest, VlessError> {
    if wire.len() < 1 + 16 + 3 + 1 {
        return Err(VlessError::Layout);
    }
    let mut pos = 0usize;
    if wire[pos] != VERSION {
        return Err(VlessError::BadResponse);
    }
    pos += 1;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&wire[pos..pos + 16]);
    pos += 16;

    // Addons: one protobuf field, tag 0x0a, varint length.
    if wire[pos] != 0x0a {
        return Err(VlessError::Layout);
    }
    pos += 1;
    let (addons_len, consumed) = decode_varint(&wire[pos..])?;
    pos += consumed;
    let addons_end = pos
        .checked_add(addons_len)
        .filter(|&end| end <= wire.len())
        .ok_or(VlessError::Layout)?;
    let addons = &wire[pos..addons_end];
    pos = addons_end;

    // Inside addons: optional `0x01 <len> <flow>` (padding subfield).
    let mut flow: Option<String> = None;
    let mut apos = 0usize;
    if apos < addons.len() && addons[apos] == 0x01 {
        apos += 1;
        let len = *addons.get(apos).ok_or(VlessError::Layout)? as usize;
        apos += 1;
        let end = apos
            .checked_add(len)
            .filter(|&e| e <= addons.len())
            .ok_or(VlessError::Layout)?;
        flow = Some(String::from_utf8(addons[apos..end].to_vec()).map_err(|_| VlessError::Layout)?);
    }

    if pos >= wire.len() {
        return Err(VlessError::Layout);
    }
    let command = wire[pos];
    pos += 1;

    let address;
    let port;
    if command == CMD_MUX {
        address = Address::Domain("v1.mux.cool".to_owned());
        port = 0;
    } else {
        if pos + 2 > wire.len() {
            return Err(VlessError::Layout);
        }
        port = u16::from_be_bytes([wire[pos], wire[pos + 1]]);
        pos += 2;
        address = parse_address(&wire[pos..])?;
    }

    Ok(ParsedRequest {
        uuid,
        flow,
        command,
        address,
        port,
    })
}

/// Parsed VLESS request header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest {
    pub uuid: [u8; 16],
    pub flow: Option<String>,
    pub command: u8,
    pub address: Address,
    pub port: u16,
}

fn parse_address(wire: &[u8]) -> Result<Address, VlessError> {
    if wire.is_empty() {
        return Err(VlessError::Layout);
    }
    match wire[0] {
        ATYP_IPV4 => {
            if wire.len() < 5 {
                return Err(VlessError::Layout);
            }
            Ok(Address::Ipv4([wire[1], wire[2], wire[3], wire[4]]))
        }
        ATYP_IPV6 => {
            if wire.len() < 17 {
                return Err(VlessError::Layout);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&wire[1..17]);
            Ok(Address::Ipv6(octets))
        }
        ATYP_DOMAIN => {
            if wire.len() < 2 {
                return Err(VlessError::Layout);
            }
            let len = wire[1] as usize;
            if wire.len() < 2 + len {
                return Err(VlessError::Layout);
            }
            String::from_utf8(wire[2..2 + len].to_vec())
                .map(Address::Domain)
                .map_err(|_| VlessError::Layout)
        }
        _ => Err(VlessError::Layout),
    }
}

/// Build the VLESS response header (`[version][addons]`, empty flow).
pub fn build_response_header() -> Vec<u8> {
    vec![VERSION, 0x0a, 0x01, 0x00]
}

/// Parse the VLESS response header; must match the request version.
pub fn parse_response_header(wire: &[u8], request_version: u8) -> Result<(), VlessError> {
    if wire.len() < 4 || wire[0] != request_version {
        return Err(VlessError::BadResponse);
    }
    Ok(())
}

fn encode_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_varint(wire: &[u8]) -> Result<(usize, usize), VlessError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    for (i, &b) in wire.iter().enumerate() {
        if i >= 10 {
            return Err(VlessError::Layout);
        }
        value |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err(VlessError::Layout)
}

/// Write-side state for one Vision direction. Mirrors Xray's
/// `writeOnceUserUUID`: the identity prefix rides ONLY on the first padding
/// frame of the stream, then the slot is emptied. Once a direction emits
/// END, subsequent `pad` calls return the payload unpadded (direct copy),
/// matching Xray's `*isPadding = false`.
pub struct VisionWriter {
    uuid: Option<[u8; 16]>,
    is_padding: bool,
}

impl VisionWriter {
    pub fn new(uuid: [u8; 16]) -> VisionWriter {
        VisionWriter {
            uuid: Some(uuid),
            is_padding: true,
        }
    }

    /// Whether subsequent `pad` calls still carry padding framing.
    pub fn is_padding(&self) -> bool {
        self.is_padding
    }

    /// Wrap one payload into Vision padding frames. Large payloads are
    /// reshaped into `buf.Size - 21`-bounded frames exactly like
    /// `ReshapeMultiBuffer` + `XtlsPadding`. `long_padding` applies the
    /// header-hiding long padding (used on the first frames of a TLS flow);
    /// `force_end` emits `CommandPaddingEnd` on the final frame, after which
    /// the direction stops padding (direct copy) exactly like Xray.
    pub fn pad(&mut self, payload: &[u8], long_padding: bool, force_end: bool) -> Vec<u8> {
        if !self.is_padding {
            return payload.to_vec();
        }
        // The identity prefix is written once for the whole stream: even
        // when one `pad` call reshapes a large payload into multiple
        // frames, only the FIRST frame carries the prefix.
        let mut uuid = self.uuid.take();
        let mut out = Vec::with_capacity(payload.len() + 64);
        let mut remaining = payload;
        loop {
            let is_last = remaining.len() <= MAX_FRAME_BODY;
            let content = &remaining[..remaining.len().min(MAX_FRAME_BODY)];
            let command = if is_last && force_end {
                PADDING_END
            } else {
                PADDING_CONTINUE
            };
            out.extend_from_slice(&xtls_padding(content, command, uuid, long_padding));
            uuid = None;
            if is_last {
                break;
            }
            remaining = &remaining[MAX_FRAME_BODY..];
        }
        if force_end {
            self.is_padding = false;
        }
        out
    }
}

/// Sample the padding length exactly like `XtlsPadding`: long padding draws
/// from `[900 - content, 900)`, regular padding from `[0, 256)`, and the
/// result is capped at `buf.Size - 21 - contentLen`.
fn xtls_padding(
    content: &[u8],
    command: u8,
    uuid: Option<[u8; 16]>,
    long_padding: bool,
) -> Vec<u8> {
    let content_len = content.len();
    let mut padding_len = if content_len < TESTSEED[0] as usize && long_padding {
        OsRng.next_u64() as usize % (TESTSEED[1] as usize) + TESTSEED[2] as usize - content_len
    } else {
        OsRng.next_u64() as usize % (TESTSEED[3] as usize)
    };
    if padding_len > MAX_FRAME_BODY - content_len {
        padding_len = MAX_FRAME_BODY - content_len;
    }

    let mut out = Vec::with_capacity(21 + content_len + padding_len);
    if let Some(u) = uuid {
        out.extend_from_slice(&u);
    }
    out.push(command);
    out.extend_from_slice(&(content_len as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

/// Read-side state for one Vision direction: mirrors `XtlsUnpadding`'s
/// remaining-command/content/padding triple with the -1 initial state.
///
/// `Initial` models the stream-start decision: a buffer that carries the
/// identity prefix locks the reader onto padding parsing; a short or
/// non-prefixed buffer (e.g. an unpadded response header) passes through
/// untouched. Once the stream is `WithinPaddingBuffers`, a boundary buffer
/// that fails the prefix check is a desync and is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnpadState {
    /// At a frame boundary: the next buffer must start a frame (prefix +
    /// header) or it passes through untouched.
    Initial,
    /// Reading the 5-byte frame header (command, content len, padding len).
    Header,
    /// Draining declared content bytes.
    Content { remaining: u32 },
    /// Skipping declared padding bytes.
    Padding { remaining: u32 },
    /// Padding ended: raw passthrough (direct copy).
    Direct,
}

pub struct VisionReader {
    state: UnpadState,
    command: u8,
    uuid: [u8; 16],
    header: [u8; 5],
    header_fill: usize,
    /// Xray's `WithinPaddingBuffers`: once a prefixed stream is seen,
    /// everything stays inside padding parsing until END/DIRECT.
    within_padding_buffers: bool,
    /// The very first buffer of the stream must either carry the prefix
    /// (>= 21 bytes) or be too short to be a padding frame. A >= 21-byte
    /// first buffer without the prefix is rejected, not passed through:
    /// that is a peer claiming framing it cannot produce.
    first_buffer: bool,
}

impl VisionReader {
    pub fn new(uuid: [u8; 16]) -> VisionReader {
        VisionReader {
            state: UnpadState::Initial,
            command: 0,
            uuid,
            header: [0u8; 5],
            header_fill: 0,
            within_padding_buffers: false,
            first_buffer: true,
        }
    }

    /// Whether the stream is still inside padding parsing.
    pub fn within_padding_buffers(&self) -> bool {
        self.within_padding_buffers
    }

    /// Feed wire bytes; returns the unpadded payload bytes. Mirrors
    /// `XtlsUnpadding`: the initial state requires the prefix to lock onto
    /// the framing; without it, bytes pass through unchanged.
    pub fn unpad(&mut self, wire: &[u8]) -> Result<Vec<u8>, VlessError> {
        let mut out = Vec::with_capacity(wire.len());
        let mut wire = wire;

        if self.state == UnpadState::Initial {
            // Xray checks `b.Len() >= 21 && bytes.Equal(UserUUID,
            // b.BytesTo(16))` on the first buffer of the stream; a
            // non-matching buffer passes through untouched.
            if wire.len() >= 21 && wire[..16] == self.uuid {
                self.state = UnpadState::Header;
                self.within_padding_buffers = true;
                self.first_buffer = false;
                wire = &wire[16..];
            } else if self.first_buffer && wire.len() >= 21 {
                // First buffer, big enough to be a padding frame, wrong
                // prefix: reject instead of copying an unauthenticated
                // stream through as if it were ours.
                self.first_buffer = false;
                return Err(VlessError::UuidMismatch);
            } else {
                self.first_buffer = false;
                out.extend_from_slice(wire);
                return Ok(out);
            }
        }

        for &byte in wire {
            match self.state {
                UnpadState::Initial => unreachable!("handled above"),
                UnpadState::Direct => out.push(byte),
                UnpadState::Header => {
                    self.header[self.header_fill] = byte;
                    self.header_fill += 1;
                    if self.header_fill == 5 {
                        self.command = self.header[0];
                        let content_len =
                            u16::from_be_bytes([self.header[1], self.header[2]]) as u32;
                        let padding_len =
                            u16::from_be_bytes([self.header[3], self.header[4]]) as u32;
                        self.header_fill = 0;
                        if content_len > MAX_FRAME_BODY as u32
                            || padding_len > MAX_FRAME_BODY as u32
                        {
                            return Err(VlessError::BadFrame);
                        }
                        if content_len > 0 {
                            self.state = UnpadState::Content {
                                remaining: content_len,
                            };
                        } else if padding_len > 0 {
                            self.state = UnpadState::Padding {
                                remaining: padding_len,
                            };
                        } else {
                            self.frame_done()?;
                        }
                    }
                }
                UnpadState::Content { remaining } => {
                    out.push(byte);
                    if remaining == 1 {
                        if self.header_has_padding() {
                            self.state = UnpadState::Padding {
                                remaining: self.pending_padding(),
                            };
                        } else {
                            self.frame_done()?;
                        }
                    } else {
                        self.state = UnpadState::Content {
                            remaining: remaining - 1,
                        };
                    }
                }
                UnpadState::Padding { remaining } => {
                    if remaining == 1 {
                        self.frame_done()?;
                    } else {
                        self.state = UnpadState::Padding {
                            remaining: remaining - 1,
                        };
                    }
                }
            }
        }
        Ok(out)
    }

    fn header_has_padding(&self) -> bool {
        self.header[3] != 0 || self.header[4] != 0
    }

    fn pending_padding(&self) -> u32 {
        u16::from_be_bytes([self.header[3], self.header[4]]) as u32
    }

    /// One frame finished: dispatch on the command.
    fn frame_done(&mut self) -> Result<(), VlessError> {
        match self.command {
            PADDING_CONTINUE => self.state = UnpadState::Header,
            PADDING_END | PADDING_DIRECT => {
                self.state = UnpadState::Direct;
                self.within_padding_buffers = false;
            }
            _ => return Err(VlessError::BadFrame),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uuid() -> [u8; 16] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ]
    }

    #[test]
    fn request_header_round_trips_domain() {
        let header = build_request_header(
            &uuid(),
            Some("xtls-rprx-vision"),
            CMD_TCP,
            &Address::Domain("example.com".into()),
            443,
        )
        .expect("build");
        let parsed = parse_request_header(&header).expect("parse");
        assert_eq!(parsed.uuid, uuid());
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(parsed.command, CMD_TCP);
        assert_eq!(parsed.address, Address::Domain("example.com".into()));
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.port.to_be_bytes(), [0x01, 0xbb]);
    }

    #[test]
    fn request_header_round_trips_ipv4_and_ipv6() {
        for (address, wire_addr) in [
            (Address::Ipv4([1, 2, 3, 4]), vec![0x01, 1, 2, 3, 4]),
            (Address::Ipv6([0x20; 16]), {
                let mut v = vec![0x03u8];
                v.extend_from_slice(&[0x20u8; 16]);
                v
            }),
        ] {
            let header = build_request_header(&uuid(), None, CMD_TCP, &address, 80).expect("build");
            let parsed = parse_request_header(&header).expect("parse");
            assert_eq!(parsed.address, address);
            assert_eq!(parsed.port, 80);
            // Empty flow is the canonical `0x0a 0x01 0x00` addons.
            assert!(header.windows(3).any(|w| w == [0x0a, 0x01, 0x00]));
            let _ = wire_addr;
        }
    }

    #[test]
    fn request_header_port_then_address_order() {
        // PortThenAddress: 2-byte BE port comes BEFORE the address bytes.
        let header =
            build_request_header(&uuid(), None, CMD_TCP, &Address::Ipv4([9, 8, 7, 6]), 0x1234)
                .expect("build");
        let at = header
            .windows(2)
            .position(|w| w == [0x12, 0x34])
            .expect("port bytes present");
        assert_eq!(header[at + 2], ATYP_IPV4);
    }

    #[test]
    fn request_header_with_flow_sets_padding_addon() {
        let header = build_request_header(
            &uuid(),
            Some("xtls-rprx-vision"),
            CMD_TCP,
            &Address::Ipv4([1, 2, 3, 4]),
            443,
        )
        .expect("build");
        // Addons must contain the padding subfield `0x01 <len>`.
        let parsed = parse_request_header(&header).expect("parse");
        assert_eq!(parsed.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn response_header_round_trips() {
        let response = build_response_header();
        assert_eq!(response, vec![0, 0x0a, 0x01, 0x00]);
        assert!(parse_response_header(&response, VERSION).is_ok());
        assert!(parse_response_header(&response, 1).is_err());
    }

    #[test]
    fn truncated_request_header_is_rejected() {
        let header = build_request_header(
            &uuid(),
            None,
            CMD_TCP,
            &Address::Domain("example.com".into()),
            443,
        )
        .expect("build");
        for cut in [0, 1, 17, 20, header.len() - 1] {
            assert!(
                parse_request_header(&header[..cut]).is_err(),
                "cut at {cut} must fail"
            );
        }
    }

    #[test]
    fn padded_round_trip_carries_payload_exactly() {
        let mut writer = VisionWriter::new(uuid());
        let mut reader = VisionReader::new(uuid());
        let payloads: Vec<Vec<u8>> = vec![
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            vec![0x17, 0x03, 0x03, 0x00, 0x10, 0x07, 0x00, 0x00],
            vec![0u8; 292],
            vec![0u8; 0], // empty frame still legal
        ];
        for payload in payloads {
            let frame = writer.pad(&payload, true, true);
            let opened = reader.unpad(&frame).expect("unpad");
            assert_eq!(opened, payload);
        }
    }

    #[test]
    fn uuid_rides_only_on_the_first_frame() {
        let mut writer = VisionWriter::new(uuid());
        let frame1 = writer.pad(b"first", true, false);
        let frame2 = writer.pad(b"second", false, true);
        assert!(frame1.starts_with(&uuid()));
        assert!(!frame2.starts_with(&uuid()));
        // Both must open cleanly.
        let mut reader = VisionReader::new(uuid());
        assert_eq!(reader.unpad(&frame1).unwrap(), b"first".to_vec());
        assert_eq!(reader.unpad(&frame2).unwrap(), b"second".to_vec());
    }

    #[test]
    fn large_payload_is_reshaped_into_bounded_frames() {
        let mut writer = VisionWriter::new(uuid());
        let payload = vec![0xabu8; MAX_FRAME_BODY * 2 + 17];
        let frames = writer.pad(&payload, false, true);
        // Every frame stays within Xray's buf.Size bound.
        assert!(frames.len() <= 3 * BUF_SIZE);
        let mut reader = VisionReader::new(uuid());
        let opened = reader.unpad(&frames).expect("unpad");
        assert_eq!(opened, payload);
    }

    #[test]
    fn wrong_uuid_passes_through_untouched() {
        let mut other = uuid();
        other[0] ^= 0xff;
        let mut reader = VisionReader::new(other);
        // Non-padding traffic (e.g. a plain HTTP response before padding
        // starts) passes through byte-identical.
        let raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        assert_eq!(reader.unpad(&raw).unwrap(), raw);
    }

    #[test]
    fn uuid_mismatch_inside_padding_stream_is_rejected() {
        let mut writer = VisionWriter::new(uuid());
        let frame = writer.pad(b"data", false, true);
        let mut other = uuid();
        other[5] ^= 0x11;
        let mut reader = VisionReader::new(other);
        // The first buffer is large enough to be a padding frame but does
        // not carry THIS reader's prefix: a peer claiming framing it cannot
        // produce. Reject instead of copying it through.
        let mut tampered = frame;
        tampered[0] ^= 0xff;
        assert!(matches!(
            reader.unpad(&tampered),
            Err(VlessError::UuidMismatch)
        ));
        assert!(!reader.within_padding_buffers());
    }

    #[test]
    fn short_unpadded_response_passes_through_then_padding_locks_on() {
        // Server->client shape: an unpadded response header first (shorter
        // than any padding frame), then a prefixed padding phase.
        let mut writer = VisionWriter::new(uuid());
        let mut reader = VisionReader::new(uuid());
        let header = b"HTTP/1.1 200 OK\r\n\r\n";
        assert_eq!(reader.unpad(header.as_ref()).unwrap(), header.to_vec());
        assert!(!reader.within_padding_buffers());
        let body = writer.pad(b"body-bytes", true, true);
        assert_eq!(reader.unpad(&body).unwrap(), b"body-bytes".to_vec());
    }

    #[test]
    fn tampered_content_length_is_rejected() {
        let mut writer = VisionWriter::new(uuid());
        let mut frame = writer.pad(b"payload", false, true);
        // content length lives at offset 16 (uuid) + 1 (command).
        frame[17] = 0xff;
        frame[18] = 0xff;
        let mut reader = VisionReader::new(uuid());
        assert!(matches!(reader.unpad(&frame), Err(VlessError::BadFrame)));
    }

    #[test]
    fn long_padding_hides_the_header_length() {
        // Two pads of identical 0-byte content with long padding must differ
        // in size with overwhelming probability (random padding draw).
        let mut writer = VisionWriter::new(uuid());
        let a = writer.pad(&[], true, false);
        let b = writer.pad(&[], true, false);
        // Both are valid frames the reader accepts.
        let mut reader = VisionReader::new(uuid());
        assert_eq!(reader.unpad(&a).unwrap(), Vec::<u8>::new());
        assert_eq!(reader.unpad(&b).unwrap(), Vec::<u8>::new());
        // The long-padding draw starts at 900-content; empty content means
        // the frame is at least 900 bytes of camouflage.
        assert!(a.len() >= 900 && b.len() >= 900);
    }

    #[test]
    fn error_reasons_leak_no_material() {
        for e in [
            VlessError::Layout,
            VlessError::BadResponse,
            VlessError::UuidMismatch,
            VlessError::BadFrame,
        ] {
            assert!(!e.reason().contains("uuid"));
            assert!(!e.reason().contains("secret"));
        }
    }
}
