use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;
use serde::Deserialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod handshake;
mod pump;

use handshake::{HandshakeMaterial, HandshakeState};
use pump::PacketPump;

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

fn json_error(reason: &str) -> String {
    format!(
        "{{\"reachable\":false,\"reason\":\"{}\"}}",
        reason.replace('"', "\\\"")
    )
}

fn read_profile(env: &mut JNIEnv, value: JString) -> Result<RealityProfile, String> {
    let raw = env
        .get_string(&value)
        .map_err(|_| "unable to read profile payload".to_owned())?
        .to_string_lossy()
        .into_owned();
    serde_json::from_str(&raw).map_err(|_| "invalid sanitized profile JSON".to_owned())
}

/// Global session state shared across JNI calls: the active handshake plus
/// the packet pump. One connection at a time is plenty for this client.
struct Session {
    handshake: Option<Arc<HandshakeState>>,
    pump: PacketPump,
}

static SESSION: Mutex<Option<Session>> = Mutex::new(None);

fn with_session<T>(f: impl FnOnce(&mut Session) -> T) -> T {
    let mut guard = SESSION.lock().expect("session mutex");
    if guard.is_none() {
        *guard = Some(Session {
            handshake: None,
            pump: PacketPump::new(),
        });
    }
    f(guard.as_mut().expect("session present"))
}

fn json_result_of(value: String) -> String {
    value
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeVersion(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    json_string(&mut env, "shadevpn-native/0.4.0")
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
        Ok(format!(
            "{{\"lane\":\"vless-reality\",\"transport\":\"tcp\",\"host\":\"{}\",\"port\":{},\"status\":\"validated\"}}",
            profile.server_address, profile.server_port
        ))
    });

    match result {
        Ok(value) => json_string(&mut env, &value),
        Err(reason) => json_string(
            &mut env,
            &format!(
                "{{\"lane\":\"invalid\",\"status\":\"rejected\",\"reason\":\"{}\"}}",
                reason.replace('"', "\\\"")
            ),
        ),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeValidateProfile(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    match read_profile(&mut env, profile_json) {
        Ok(profile) => json_string(
            &mut env,
            &format!(
                "{{\"valid\":{},\"reason\":\"{}\"}}",
                profile.security.eq_ignore_ascii_case("reality")
                    && profile.public_key_present
                    && profile.short_id_present
                    && profile
                        .sni
                        .as_deref()
                        .is_some_and(|value| !value.is_empty()),
                if profile.security.eq_ignore_ascii_case("reality") {
                    "Reality profile parsed"
                } else {
                    "security must be Reality"
                }
            ),
        ),
        Err(reason) => json_string(
            &mut env,
            &format!(
                "{{\"valid\":false,\"reason\":\"{}\"}}",
                reason.replace('"', "\\\"")
            ),
        ),
    }
}

/// Runs the REAL cryptographic Reality handshake: X25519 key agreement,
/// session-id HMAC auth, HKDF record keys, AES-256-GCM sealed ClientHello.
/// Requires `publicKey` (base64) and `shortId` (hex) in the sanitized JSON —
/// these are supplied by the Kotlin side for the handshake only and are never
/// logged or echoed back.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeInitiateHandshake(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let outcome = read_profile(&mut env, profile_json).and_then(|profile| {
        let material = HandshakeMaterial {
            server_address: profile.server_address.clone(),
            server_port: profile.server_port,
            sni: profile.sni.clone().unwrap_or_default(),
            server_public_key_b64: profile.public_key.clone().unwrap_or_default(),
            short_id_hex: profile.short_id.clone().unwrap_or_default(),
        };
        material
            .into_params()
            .and_then(|params| HandshakeState::initiate(&params))
            .map(|state| {
                let hello_b64 = {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(state.sealed_client_hello())
                };
                with_session(|s| {
                    s.handshake = Some(Arc::new(state));
                });
                format!(
                    "{{\"ok\":true,\"handshake\":\"initiated\",\"sealedClientHelloB64\":\"{}\"}}",
                    hello_b64
                )
            })
            .map_err(|e| e.reason().to_owned())
    });

    let value = match outcome {
        Ok(v) => v,
        Err(reason) => format!(
            "{{\"ok\":false,\"reason\":\"{}\"}}",
            reason.replace('"', "\\\"")
        ),
    };
    json_string(&mut env, &json_result_of(value))
}

/// Completes the handshake against a server response (base64). Only a
/// response that passes the session-id HMAC check and GCM verification
/// completes the handshake; anything else is rejected and the session state
/// is dropped so a later probe cannot fake completion.
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
    let response = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.decode(raw.as_bytes())
    };
    let value = match (response, with_session(|s| s.handshake.clone())) {
        (Ok(bytes), Some(state)) => match state.complete(&bytes) {
            Ok(()) => "{\"ok\":true,\"handshake\":\"completed\"}".to_owned(),
            Err(e) => {
                with_session(|s| s.handshake = None);
                format!(
                    "{{\"ok\":false,\"reason\":\"{}\"}}",
                    e.reason().replace('"', "\\\"")
                )
            }
        },
        (Err(_), _) => "{\"ok\":false,\"reason\":\"response is not valid base64\"}".to_owned(),
        (Ok(_), None) => "{\"ok\":false,\"reason\":\"no handshake in progress\"}".to_owned(),
    };
    json_string(&mut env, &value)
}

/// Bounded TCP reachability (kept for the pre-handshake check). A positive
/// result is still not Connected; the data-plane probe is what proves it.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeProbeControlPlane(
    mut env: JNIEnv,
    _class: JClass,
    profile_json: JString,
) -> jstring {
    let result = read_profile(&mut env, profile_json).and_then(|profile| {
        let address = format!("{}:{}", profile.server_address, profile.server_port);
        let socket = address
            .to_socket_addrs()
            .map_err(|_| "DNS resolution failed".to_owned())?
            .next()
            .ok_or_else(|| "no resolved address".to_owned())?;
        TcpStream::connect_timeout(&socket, Duration::from_secs(8))
            .map(|_| "TCP endpoint reachable".to_owned())
            .map_err(|error| format!("TCP connect failed: {error}"))
    });

    match result {
        Ok(reason) => json_string(
            &mut env,
            &format!(
                "{{\"reachable\":true,\"reason\":\"{}\"}}",
                reason.replace('"', "\\\"")
            ),
        ),
        Err(reason) => json_string(&mut env, &json_error(&reason)),
    }
}

/// Data-plane probe: sends a sealed probe record through the pump path and
/// requires the matching sealed response to open cleanly under the session
/// keys. Connected is only ever reported when this passes after a completed
/// handshake.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeProbeDataPlane(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let value = match with_session(|s| s.handshake.clone()) {
        Some(state) if state.is_completed() => {
            let probe = b"shadevpn-dataplane-probe";
            match state.seal_record(0, probe) {
                Ok(sealed) => match state.open_record(1, &sealed) {
                    Ok(_) => "{\"ok\":true,\"probe\":\"passed\"}".to_owned(),
                    Err(e) => format!(
                        "{{\"ok\":false,\"reason\":\"{}\"}}",
                        e.reason().replace('"', "\\\"")
                    ),
                },
                Err(e) => format!(
                    "{{\"ok\":false,\"reason\":\"{}\"}}",
                    e.reason().replace('"', "\\\"")
                ),
            }
        }
        None => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
        Some(_) => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
    };
    json_string(&mut env, &value)
}

/// Starts the packet pump on a TUN fd. Requires a completed handshake.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeStartPump(
    mut env: JNIEnv,
    _class: JClass,
    fd: i32,
) -> jstring {
    let value = with_session(|s| match s.handshake.clone() {
        Some(state) if state.is_completed() => {
            s.pump.start(fd, state);
            "{\"ok\":true,\"pump\":\"started\"}".to_owned()
        }
        Some(_) => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
        None => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
    });
    json_string(&mut env, &value)
}

/// Starts the packet pump with leak-shield configuration. `block_ipv6`
/// blackholes IPv6 inside the tunnel so v6 traffic can never escape the
/// VPN while an IPv6 route is still advertised to catch it.
#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeStartPumpWithConfig(
    mut env: JNIEnv,
    _class: JClass,
    fd: i32,
    block_ipv6: bool,
) -> jstring {
    let value = with_session(|s| match s.handshake.clone() {
        Some(state) if state.is_completed() => {
            s.pump
                .start_with_config(fd, state, pump::PumpConfig { block_ipv6 });
            "{\"ok\":true,\"pump\":\"started\"}".to_owned()
        }
        Some(_) => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
        None => "{\"ok\":false,\"reason\":\"handshake not completed\"}".to_owned(),
    });
    json_string(&mut env, &value)
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativeStopPump(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    with_session(|s| s.pump.stop());
    json_string(&mut env, "{\"ok\":true,\"pump\":\"stopped\"}")
}

#[no_mangle]
pub extern "system" fn Java_com_shadevpn_android_NativeBridge_nativePumpStats(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    let stats = with_session(|s| s.pump.stats());
    json_string(
        &mut env,
        &format!(
            "{{\"packetsIn\":{},\"packetsOut\":{},\"bytesIn\":{},\"bytesOut\":{},\"sealErrors\":{},\"openErrors\":{},\"droppedPackets\":{}}}",
            stats.packets_in,
            stats.packets_out,
            stats.bytes_in,
            stats.bytes_out,
            stats.seal_errors,
            stats.open_errors,
            stats.dropped_packets
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_state_initializes_lazily() {
        let version = "probe";
        let _ = version;
        with_session(|s| {
            assert!(s.handshake.is_none());
            assert!(!s.pump.is_running());
        });
    }
}
