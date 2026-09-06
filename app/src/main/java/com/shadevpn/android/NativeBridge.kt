package com.shadevpn.android

object NativeBridge {
    init {
        lib = runCatching { System.loadLibrary("shadevpn_native") }
            .map { true }
            .getOrDefault(false)
        if (!lib) {
            throw UnsatisfiedLinkError("Failed to load shadevpn_native")
        }
    }

    private var lib = false

    external fun nativeVersion(): String
    external fun nativeBuildLane(profileJson: String): String
    external fun nativeValidateProfile(profileJson: String): String
    external fun nativeProbeControlPlane(profileJson: String): String

    /**
     * Real tunnel establishment: TCP connect + full cryptographic Reality
     * handshake over the wire (X25519, HKDF, HMAC session auth, sealed
     * ClientHello). Returns JSON with `serverResponseB64` — Kotlin must feed
     * it back through [nativeCompleteHandshake]; the native layer refuses to
     * auto-complete so the orchestrator state machine stays honest.
     */
    external fun nativeConnectTunnel(profileJson: String): String

    /**
     * Completes the handshake against the base64 server response. Only a
     * response passing session HMAC + GCM checks completes the session;
     * anything else tears the session (keys AND socket) down natively.
     */
    external fun nativeCompleteHandshake(responseB64: String): String

    /**
     * Data-plane probe over the LIVE tunnel: seals a probe at the session's
     * next sequence, sends it, requires the mirrored response to open
     * cleanly. The only path to CONNECTED.
     */
    external fun nativeProbeDataPlane(): String

    /**
     * Starts the bidirectional tunnel pump on the TUN fd. Requires a
     * completed handshake and the established tunnel socket; record
     * sequences continue where the probe left off.
     */
    external fun nativeStartTunnelPump(fd: Int, blockIpv6: Boolean): String

    external fun nativeStopPump(): String

    /** Full teardown: pump, keys, socket. */
    external fun nativeDisconnectTunnel(): String

    external fun nativePumpStats(): String
}
