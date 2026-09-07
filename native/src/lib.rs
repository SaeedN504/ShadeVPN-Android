use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde::Deserialize;
use serde_json::json;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod handshake;
mod pump;
mod reality;
mod tls;
mod transport;
mod vless;

#[cfg(test)]
mod test_server;

use handshake::{HandshakeMaterial, HandshakeState};
use pump::{PumpConfig, TunnelPump};

#[derive(Debug, Deserialize)]
struct RealityProfile {
    #[serde(rename = "serverAddress")]
    server_address: String,
    #[serde(rename = "serverPort")]
    server_port: u16,
    security: String,
    network: String,
    sni: Option<String>,
    #[serde(rename = "publicKeyPresent")]
    public_key_present: bool,
    #[serde(rename = "shortIdPresent")]
    short_id_present: bool,
    #[serde(default)]
    #[serde(rename = "publicKey")]
    public_key: Option<String>,
    #[serde(default)]
    #[serde(rename = "shortId")]
    short_id: Option<String>,
}

fn json_string(env: &mut JNIEnv, value: &str) -> jstring {
    env.new_string(value).expect("JNI string").into_raw()
}

/// Session state shared across JNI calls. One connection at a time.
/// Data-plane records share the DATA nonce purpose with the handshake-time
/// probe, so the session tracks the next sequence explicitly and the pump
/// resumes from it — no nonce reuse is possible.
struct Session {
    handshake: Option<Arc<HandshakeState>>,
    pump: TunnelPump,
    /// Next data record sequence to seal (client->server).
    next_out_seq: u64,
    /// Next data record sequence expected when opening (server->client).
    next_in_seq: u64,
    /// The established tunnel socket, kept open across JNI calls.
    socket: Option<TcpStream>,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn with_session<T>(f: impl FnOnce(&mut Session) -> T) -> T {
    let mut guard = SESSION.lock().expect("session mutex");
    if guard.is_none() {
        *guard = Some(Session {
            handshake: None,
            pump: TunnelPump::new(),
            next_out_seq: 0,
            next_in_seq: 0,
            socket: None,
        });
    }
    f(guard.as_mut().expect("session present"))
}

/// Full teardown: stop the pump, drop the keys, close the socket.
fn teardown_session(s: &mut Session) {
    s.pump.stop();
    s.handshake = None;
    s.socket = None; // TcpStream drop closes the fd
    s.next_out_seq = 0;
    s.next_in_seq = 0;
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    json_string(&mut env, "shadevpn-native/0.7.0")
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeBuildLane(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let result = read_profile(&mut env, profile_json).and_then(|profile| {
        if !profile.security.eq_ignore_ascii_case("reality") {
            return Err("only Reality profiles are accepted".to_owned());
        }
        if !matches!(profile.network.as_str(), "tcp" | "ws" | "xhttp") {
            return Err("unsupported Reality network".to_owned());
        }
        if profile.sni.as_deref().unwrap_or_default().is_empty() {
            return Err("Reality SNI is required".to_owned());
        }
        if !profile.public_key_present || !profile.short_id_present {
            return Err("Reality public key and short ID are required".to_owned());
        }
        Ok(json!({
            "lane": "vless-reality",
            "transport": "tcp",
            "host": profile.server_address,
            "port": profile.server_port,
            "status": "validated"
        }))
    });

    let value = result.unwrap_or_else(
        |reason| json!({"lane": "invalid", "status": "rejected", "reason": reason}),
    );
    json_string(&mut env, &value.to_string())
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeValidateProfile(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let value = match read_profile(&mut env, profile_json) {
        Ok(profile) => {
            let valid = profile.security.eq_ignore_ascii_case("reality")
                && profile.public_key_present
                && profile.short_id_present
                && profile.sni.as_deref().is_some_and(|v| !v.is_empty());
            json!({
                "valid": valid,
                "reason": if profile.security.eq_ignore_ascii_case("reality") {
                    "Reality profile parsed"
                } else {
                    "security must be Reality"
                }
            })
        }
        Err(reason) => json!({"valid": false, "reason": reason}),
    };
    json_string(&mut env, &value.to_string())
}

/// Bounded TCP reachability (pre-handshake check). A positive result is
/// still not Connected; the data-plane probe is what proves it.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeProbeControlPlane(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let value = match read_profile(&mut env, profile_json).and_then(|profile| {
        let address = format!("{}:{}", profile.server_address, profile.server_port);
        let socket = address
            .to_socket_addrs()
            .map_err(|_| "DNS resolution failed".to_owned())?
            .next()
            .ok_or_else(|| "no resolved address".to_owned())?;
        TcpStream::connect_timeout(&socket, Duration::from_secs(8))
            .map(|_| ())
            .map_err(|error| format!("TCP connect failed: {error}"))
    }) {
        Ok(()) => json!({"reachable": true}),
        Err(reason) => json!({"reachable": false, "reason": reason}),
    };
    json_string(&mut env, &value.to_string())
}

/// The REAL tunnel establishment: TCP connect + the full cryptographic
/// Reality handshake over the wire (X25519, HKDF, HMAC session auth,
/// AES-256-GCM sealed hello). Returns the base64 server response that Kotlin
/// must feed back to nativeCompleteHandshake — the native layer deliberately
/// does NOT auto-complete, so the orchestrator state machine stays honest.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeConnectTunnel(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let value = match run_connect(&mut env, profile_json) {
        Ok(response_b64) => json!({"ok": true, "serverResponseB64": response_b64}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    };
    json_string(&mut env, &value.to_string())
}

fn run_connect(env: &mut JNIEnv, profile_json: JString) -> Result<String, String> {
    let profile = read_profile(env, profile_json)?;

    if !profile.public_key_present || !profile.short_id_present {
        return Err("publicKey and shortId are required".to_owned());
    }
    let material = HandshakeMaterial {
        server_address: profile.server_address.clone(),
        server_port: profile.server_port,
        sni: profile.sni.clone().unwrap_or_default(),
        server_public_key_b64: profile.public_key.clone().unwrap_or_default(),
        short_id_hex: profile.short_id.clone().unwrap_or_default(),
    };
    let params = material.into_params().map_err(|e| e.reason().to_owned())?;

    // 1. TCP connect.
    let addr = format!("{}:{}", params.server_address, params.server_port);
    let socket_addr = addr
        .to_socket_addrs()
        .map_err(|_| "DNS resolution failed".to_owned())?
        .next()
        .ok_or("no resolved address")?;
    let mut socket = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(8))
        .map_err(|e| format!("TCP connect failed: {e}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|e| format!("socket setup failed: {e}"))?;
    let _ = socket.set_nodelay(true);

    // 2. Write the REAL TLS 1.3 ClientHello record carrying the Reality
    //    material (ephemeral key_share, session tag in random, short ID).
    let state = HandshakeState::initiate(&params).map_err(|e| e.reason().to_owned())?;
    transport::write_frame(&mut socket, state.client_hello())
        .map_err(|e| format!("hello send failed: {e:?}"))?;

    // 3. Read the framed server response.
    let response = transport::read_frame(&mut socket)
        .map_err(|e| format!("response read failed: {e:?}"))?
        .ok_or("server closed before handshake response")?;

    // Store state + socket BEFORE returning; completion is a separate step so
    // the orchestrator state machine governs the progression.
    let response_b64 = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&response)
    };
    with_session(|s| {
        s.handshake = Some(Arc::new(state));
        s.socket = Some(socket);
    });
    Ok(response_b64)
}

/// Completes the handshake against the base64 server response. Only a
/// response that passes the session HMAC + GCM checks completes the session;
/// anything else tears the whole session down (keys AND socket) so a later
/// probe or pump start can never fake completion.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeCompleteHandshake(
    mut env: JNIEnv,
    _class: JClass,
    response_b64: JString,
) -> jstring {
    let raw = env
        .get_string(&response_b64)
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let decoded = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(raw.as_bytes())
    };
    let bytes = decoded.ok();
    let state = with_session(|s| s.handshake.clone());

    let value = match (bytes, state) {
        (Some(bytes), Some(state)) => match state.complete(&bytes) {
            Ok(()) => json!({"ok": true, "handshake": "completed"}),
            Err(e) => {
                with_session(teardown_session);
                json!({"ok": false, "reason": e.reason()})
            }
        },
        (None, _) => json!({"ok": false, "reason": "response is not valid base64"}),
        (Some(_), None) => json!({"ok": false, "reason": "no handshake in progress"}),
    };
    json_string(&mut env, &value.to_string())
}

/// Data-plane probe over the LIVE tunnel: seals a probe record at the
/// session's next sequence, writes it to the real socket, waits for the
/// mirrored response, and requires it to open cleanly. CONNECTED is only
/// ever reported when this passes after a completed handshake.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeProbeDataPlane(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let outcome = with_session(|s| -> Result<(), String> {
        let state = s.handshake.clone().ok_or("handshake not completed")?;
        if !state.is_completed() {
            return Err("handshake not completed".to_owned());
        }
        let mut socket = s
            .socket
            .as_ref()
            .ok_or("tunnel socket not established")?
            .try_clone()
            .map_err(|e| format!("socket clone failed: {e}"))?;

        let probe = b"shadevpn-dataplane-probe";
        let seq = s.next_out_seq;
        let sealed = state
            .seal_record(seq, probe)
            .map_err(|e| e.reason().to_owned())?;
        transport::write_frame(&mut socket, &sealed)
            .map_err(|e| format!("probe send failed: {e:?}"))?;
        s.next_out_seq += 1;

        // The honest server mirrors the record back on its send side.
        let echoed = transport::read_frame(&mut socket)
            .map_err(|e| format!("probe response read failed: {e:?}"))?
            .ok_or("server closed during probe")?;
        let opened = state
            .open_record(s.next_in_seq, &echoed)
            .map_err(|e| e.reason().to_owned())?;
        if opened != probe {
            return Err("probe response mismatch".to_owned());
        }
        s.next_in_seq += 1;
        Ok(())
    });
    let value = match outcome {
        Ok(()) => json!({"ok": true, "probe": "passed"}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    };
    json_string(&mut env, &value.to_string())
}

/// Starts the bidirectional tunnel pump on the TUN fd. Requires a completed
/// handshake and an established tunnel socket; record sequences continue
/// where the data-plane probe left off.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeStartTunnelPump(
    mut env: JNIEnv,
    _class: JClass,
    fd: i32,
    block_ipv6: bool,
) -> jstring {
    let outcome = with_session(|s| -> Result<(), String> {
        let state = s.handshake.clone().ok_or("handshake not completed")?;
        if !state.is_completed() {
            return Err("handshake not completed".to_owned());
        }
        let socket = s
            .socket
            .as_ref()
            .ok_or("tunnel socket not established")?
            .try_clone()
            .map_err(|e| format!("socket clone failed: {e}"))?;
        s.pump
            .start(
                fd,
                socket,
                state,
                PumpConfig { block_ipv6 },
                s.next_out_seq,
                s.next_in_seq,
            )
    });
    let value = match outcome {
        Ok(()) => json!({"ok": true, "pump": "started"}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    };
    json_string(&mut env, &value.to_string())
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeStopPump(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    with_session(|s| s.pump.stop());
    json_string(
        &mut env,
        &json!({"ok": true, "pump": "stopped"}).to_string(),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeDisconnectTunnel(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    with_session(teardown_session);
    json_string(
        &mut env,
        &json!({"ok": true, "tunnel": "disconnected"}).to_string(),
    )
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativePumpStats(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let stats = with_session(|s| s.pump.stats());
    let value = json!({
        "packetsIn": stats.packets_in,
        "packetsOut": stats.packets_out,
        "bytesIn": stats.bytes_in,
        "bytesOut": stats.bytes_out,
        "deliveredPackets": stats.delivered_packets,
        "deliveredBytes": stats.delivered_bytes,
        "sealErrors": stats.seal_errors,
        "openErrors": stats.open_errors,
        "droppedPackets": stats.dropped_packets
    });
    json_string(&mut env, &value.to_string())
}

fn read_profile(env: &mut JNIEnv, value: JString) -> Result<RealityProfile, String> {
    let raw = env
        .get_string(&value)
        .map_err(|_| "unable to read profile payload".to_owned())?
        .to_string_lossy()
        .into_owned();
    serde_json::from_str(&raw).map_err(|_| "invalid sanitized profile JSON".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_state_initializes_lazily() {
        with_session(|s| {
            assert!(s.handshake.is_none());
            assert!(!s.pump.is_running());
            assert_eq!(s.next_out_seq, 0);
            assert!(s.socket.is_none());
        });
    }
}
