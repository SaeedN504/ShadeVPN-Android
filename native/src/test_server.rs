//! Integration-test helpers: an honest in-process Reality server plus a
//! client-side tunnel helper, both wire-true.
//!
//! The server reads ONLY framed TLS ClientHello records from the socket,
//! parses the hello from raw bytes (a real TLS 1.3 record: SNI in
//! server_name, ephemeral key in key_share, session tag in random, short ID
//! in legacy_session_id), derives the shared secret from the ephemeral key
//! found there, authenticates the session tag from `random`, and answers
//! with properly framed, sealed responses. It has no access to client-side
//! state. The client helper runs the real `HandshakeState` over the wire —
//! no shortcut anywhere.
//!
//! The `ServerObservation` returned by the server thread is what makes the
//! integration tests strong: tests assert on what ACTUALLY crossed the wire
//! (SNI seen, session authenticated, how many records were mirrored), so a
//! "leak shield" claim is proven by a dropped packet never reaching the
//! server at all.
//!
//! Test-only: included from lib.rs under #[cfg(test)].

use crate::handshake::{
    derive_nonce, make_mac, session_id_hmac, Direction, HandshakeParams, HandshakeState, HKDF_SALT,
    KEY_INFO, NONCE_PURPOSE_DATA, NONCE_PURPOSE_RESPONSE, SESSION_ID_VALUE_INFO, SESSION_INFO,
};
use crate::tls;
use crate::transport::{read_frame, write_frame};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::Mac;
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

    let client_ephemeral = PublicKey::from(hello.ephemeral_public);
    let shared = server_secret.diffie_hellman(&client_ephemeral);
    let shared_bytes = shared.as_bytes();

    let session_id: [u8; 32] = hkdf_expand(HKDF_SALT, shared_bytes, SESSION_ID_VALUE_INFO, 32)
        .try_into()
        .map_err(|_| "session id expand failed".to_owned())?;

    // Record keys: [client->server (server's recv)][server->client (server's send)].
    let record_keys = hkdf_expand(HKDF_SALT, shared_bytes, KEY_INFO, 64);
    let server_recv_key: [u8; 32] = record_keys[..32].try_into().unwrap();
    let server_send_key: [u8; 32] = record_keys[32..].try_into().unwrap();

    // Authenticate the session: recompute the tag from the shared secret and
    // compare it byte-for-byte with the one the client put in `random`.
    let auth_key: [u8; 32] = hkdf_expand(HKDF_SALT, shared_bytes, SESSION_INFO, 32)
        .try_into()
        .map_err(|_| "auth key expand failed".to_owned())?;
    let expected_tag = session_id_hmac(&auth_key, &session_id);
    if hello.session_tag != expected_tag {
        return Err("session tag in random did not authenticate".to_owned());
    }
    let sni = hello.sni.clone().ok_or("no SNI offered")?;

    // ---- respond: [32-byte session tag][sealed confirmation] ----
    let send_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_send_key));
    let response_nonce = derive_nonce(&session_id, 0, Direction::Server, NONCE_PURPOSE_RESPONSE);
    let sealed_confirm = send_cipher
        .encrypt(
            Nonce::from_slice(&response_nonce),
            b"shadevpn-server-ok".as_ref(),
        )
        .map_err(|_| "server seal failed".to_owned())?;
    let mut response = Vec::with_capacity(32 + sealed_confirm.len());
    let mut mac = make_mac(&server_send_key);
    mac.update(&session_id);
    response.extend_from_slice(&mac.finalize().into_bytes());
    response.extend_from_slice(&sealed_confirm);
    write_frame(&mut stream, &response).map_err(|e| format!("write response: {e}"))?;

    // ---- record loop: open client data records, seal a mirror back ----
    let mut seq_in: u64 = 0;
    let mut seq_out: u64 = 0;
    loop {
        match read_frame(&mut stream) {
            Ok(Some(frame)) => {
                if frame.is_empty() {
                    continue;
                }
                let in_nonce =
                    derive_nonce(&session_id, seq_in, Direction::Client, NONCE_PURPOSE_DATA);
                let opened = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&server_recv_key))
                    .decrypt(Nonce::from_slice(&in_nonce), frame.as_ref())
                    .map_err(|_| "record failed to open".to_owned())?;
                seq_in += 1;
                let out_nonce =
                    derive_nonce(&session_id, seq_out, Direction::Server, NONCE_PURPOSE_DATA);
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

fn hkdf_expand(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .expect("fixed-length expand is valid");
    out
}
