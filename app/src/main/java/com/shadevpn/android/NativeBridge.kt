package com.shadevpn.android

object NativeBridge {
    init {
        runCatching { System.loadLibrary("shadevpn_native") }
            .onFailure { throw UnsatisfiedLinkError("Failed to load shadevpn_native: ${it.message}") }
    }

    external fun nativeVersion(): String
    external fun nativeBuildLane(profileJson: String): String
    external fun nativeValidateProfile(profileJson: String): String

    /**
     * Bounded TCP reachability only. A positive result is not Connected and
     * must be followed by the real handshake and data-plane probe.
     */
    external fun nativeProbeControlPlane(profileJson: String): String

    /**
     * Runs the real Reality handshake state: X25519 key agreement, session-id
     * HMAC auth, HKDF record keys, AES-256-GCM sealed ClientHello. The JSON
     * payload must include `publicKey` (base64) and `shortId` (hex); they are
     * consumed by the handshake and never logged or echoed back.
     */
    external fun nativeInitiateHandshake(profileJson: String): String

    /** Completes the handshake against a base64 server response. */
    external fun nativeCompleteHandshake(responseB64: String): String

    /**
     * Data-plane probe: seals a probe record under the session keys and
     * requires it to open cleanly. This is the only path to CONNECTED.
     */
    external fun nativeProbeDataPlane(): String

    /** Starts the packet pump on the TUN fd. Requires a completed handshake. */
    external fun nativeStartPump(fd: Int): String

    external fun nativeStopPump(): String

    external fun nativePumpStats(): String
}
