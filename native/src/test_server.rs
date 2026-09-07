//! Integration-test helpers: an honest in-process REALITY server plus a
//! client-side tunnel helper, both wire-true.
//!
//! The server reads ONLY framed TLS ClientHello records from the socket and
//! runs the real server-side flow with no access to client state:
//!
//! 1. Parse the hello (SNI, random, session id, key_share) from raw bytes.
//! 2. Derive the REALITY AuthKey (Xray construction) from the ECDH shared
//!    secret and unseal the session id; reject on failure.
//! 3. Check the client version and the short-id allowlist.
//! 4. Issue the temporary trusted certificate, generate a FRESH X25519
//!    server key share, derive the forward-secret record keys, and seal the
//!    confirmation.
//! 5. Mirror data records under the negotiated keys.
//!
//! The `ServerObservation` returned by the server thread is what makes the
//! integration tests strong: tests assert on what ACTUALLY crossed the wire
//! (SNI seen, session authenticated, how many records were mirrored), so a
//! "leak shield" claim is proven by a dropped packet never reaching the
//! server at all.
//!
//! Test-only: included from lib.rs under #[cfg(test)].

use crate::handshake::{
    derive_nonce, Direction, HandshakeParams, HandshakeState, CLIENT_VERSION, HKDF_SALT, KEY_INFO,
    NONCE_PURPOSE_DATA, NONCE_PURPOSE_RESPONSE,
};
use crate::reality::{self, ServerEphemeral};
use crate::tls;
use crate::transport::{read_frame, write_frame};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use x25519_dalek::{PublicKey, StaticSecret};

/// What the server observed during the session — returned to the test so
/// assertions can be made on what actually crossed the wire.
#[derive(Debug)]
pub struct ServerObservation {
    pub sni: String,
    pub session_authenticated: bool,
    pub records_mirrored: u64,
}

/// Client side of a completed wire handshake, ready for the tunnel pump,
/// plus the server thread handle so tests can join and assert observations.
pub struct ClientTunnel {
    pub socket: TcpStream,
    pub state: Arc<HandshakeState>,
    pub server: thread::JoinHandle<Result<ServerObservation, String>>,
}

/// Spawn the honest server and run a real client handshake against it.
pub fn open_tunnel(sni: &str, server_secret_bytes: [u8; 32]) -> Result<ClientTunnel, String> {
    let (port, server) = spawn(server_secret_bytes);
    let params = HandshakeParams {
        server_address: "127.0.0.1".into(),
        server_port: port,
        sni: sni.into(),
        server_public_key: *PublicKey::from(&StaticSecret::from(server_secret_bytes)).as_bytes(),
        short_id: vec![0x01, 0x02],
        fingerprint: None,
    };
    let state = HandshakeState::initiate(&params).map_err(|e| format!("initiate: {e:?}"))?;
    let mut socket =
        TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("connect: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("timeout: {e}"))?;
    write_frame(&mut socket, state.client_hello()).map_err(|e| format!("write hello: {e:?}"))?;
    let response = read_frame(&mut socket)
        .map_err(|e| format!("read response: {e:?}"))?
        .ok_or("server closed before response")?;
    state
        .complete(&response)
        .map_err(|e| format!("complete: {e:?}"))?;
    Ok(ClientTunnel {
        socket,
        state: Arc::new(state),
        server,
    })
}

/// Spawn a single-connection honest server on an ephemeral port. Returns the
/// bound port and a handle whose join yields the observation (or error).
pub fn spawn(
    server_secret_bytes: [u8; 32],
) -> (u16, thread::JoinHandle<Result<ServerObservation, String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().expect("local addr").port();
    let handle = thread::spawn(move || run_server(listener, server_secret_bytes));
    (port, handle)
}

/// The short id the test client presents, zero padded to the 8-byte slot.
fn expected_short_id() -> [u8; 8] {
    let mut sid = [0u8; 8];
    sid[..2].copy_from_slice(&[0x01, 0x02]);
    sid
}

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("fixed-length expand is valid");
    out
}

fn run_server(
    listener: TcpListener,
    server_secret_bytes: [u8; 32],
) -> Result<ServerObservation, String> {
    let (mut stream, _peer) = listener
        .accept()
        .map_err(|e| format!("accept failed: {e}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("set timeout: {e}"))?;

    let server_secret = StaticSecret::from(server_secret_bytes);

    // ---- handshake: read the framed TLS ClientHello from the wire ----
    let hello_frame = read_frame(&mut stream)
        .map_err(|e| format!("read hello frame: {e}"))?
        .ok_or("client closed before hello")?;
    let hello =
        tls::parse_client_hello(&hello_frame).map_err(|e| format!("bad TLS ClientHello: {e}"))?;
    let sni = hello.sni.clone().ok_or("no SNI offered")?;

    // REALITY AuthKey (Xray construction) from the ECDH shared secret.
    let shared = server_secret.diffie_hellman(&PublicKey::from(hello.ephemeral_public));
    let auth_key = reality::auth_key(shared.as_bytes(), &hello.random);

    // Unseal the session id. AAD = the received hello with the session id
    // zeroed — exactly what the client sealed against.
    let mut aad = hello_frame.clone();
    let off = tls::SESSION_ID_OFFSET;
    aad[off..off + 32].fill(0);
    let sid: [u8; 32] = hello
        .session_id
        .clone()
        .try_into()
        .map_err(|_| "session id is not 32 bytes".to_owned())?;
    let plain = reality::unseal_session_id(&auth_key, &hello.random, &aad, &sid)
        .map_err(|e| format!("session id rejected: {e:?}"))?;
    if plain.client_version != CLIENT_VERSION {
        return Err("client version mismatch".to_owned());
    }
    if plain.short_id != expected_short_id() {
        return Err("short id not on the allowlist".to_owned());
    }

    // Fresh server key share -> forward-secret record keys.
    let server_eph = ServerEphemeral::generate();
    let ecdhe = server_eph.shared_secret(&hello.ephemeral_public);
    let binding = reality::session_identity(&sid, &ecdhe);
    let record_keys = hkdf_expand(HKDF_SALT, &binding, KEY_INFO, 64);
    let server_recv_key: [u8; 32] = record_keys[..32].try_into().unwrap();
    let server_send_key: [u8; 32] = record_keys[32..].try_into().unwrap();

    // ---- respond: [temp cert 96][server share 32][sealed confirmation] ----
    let send_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_send_key));
    let response_nonce = derive_nonce(&sid, 0, Direction::Server, NONCE_PURPOSE_RESPONSE);
    let sealed_confirm = send_cipher
        .encrypt(
            Nonce::from_slice(&response_nonce),
            b"shadevpn-server-ok".as_ref(),
        )
        .map_err(|_| "server seal failed".to_owned())?;
    let mut response = Vec::with_capacity(96 + 32 + sealed_confirm.len());
    response.extend_from_slice(&reality::temporary_certificate(&auth_key));
    response.extend_from_slice(&server_eph.public);
    response.extend_from_slice(&sealed_confirm);
    write_frame(&mut stream, &response).map_err(|e| format!("write response: {e}"))?;

    // ---- record loop: open client data records, seal a mirror back ----
    let recv_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_recv_key));
    let mut seq_in: u64 = 0;
    let mut seq_out: u64 = 0;
    loop {
        match read_frame(&mut stream) {
            Ok(Some(frame)) => {
                if frame.is_empty() {
                    continue;
                }
                let in_nonce = derive_nonce(&sid, seq_in, Direction::Client, NONCE_PURPOSE_DATA);
                let opened = recv_cipher
                    .decrypt(Nonce::from_slice(&in_nonce), frame.as_ref())
                    .map_err(|_| "record failed to open".to_owned())?;
                seq_in += 1;
                let out_nonce = derive_nonce(&sid, seq_out, Direction::Server, NONCE_PURPOSE_DATA);
                let resealed = send_cipher
                    .encrypt(Nonce::from_slice(&out_nonce), opened.as_ref())
                    .map_err(|_| "re-seal failed".to_owned())?;
                seq_out += 1;
                write_frame(&mut stream, &resealed).map_err(|e| format!("write record: {e}"))?;
            }
            Ok(None) => break, // clean close
            Err(e) => return Err(format!("record loop: {e}")),
        }
    }

    Ok(ServerObservation {
        sni,
        session_authenticated: true,
        records_mirrored: seq_out,
    })
}
