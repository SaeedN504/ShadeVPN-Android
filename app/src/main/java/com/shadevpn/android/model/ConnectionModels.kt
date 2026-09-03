package com.shadevpn.android.model

enum class ConnectionPhase {
    IDLE,
    REQUESTING_PERMISSION,
    PREPARING,
    CONNECTING_CONTROL,
    PROBING_DATA,
    CONNECTED,
    DISCONNECTED,
    FAILED
}

enum class FailureReason {
    NONE,
    PERMISSION_DENIED,
    INVALID_PROFILE,
    JNI_ERROR,
    CONTROL_PLANE_FAILED,
    DATA_PLANE_FAILED,
    VPN_REVOKED,
    TUN_SETUP_FAILED,
    UNKNOWN
}

data class VlessProfile(
    val name: String,
    val serverAddress: String,
    val serverPort: Int,
    val uuid: String,
    val flow: String?,
    val security: String,
    val network: String,
    val host: String?,
    val path: String?,
    val sni: String?,
    val publicKey: String?,
    val shortId: String?,
    val fingerprint: String?
)

data class ConnectionSnapshot(
    val phase: ConnectionPhase = ConnectionPhase.IDLE,
    val activeLane: String = "none",
    val statusLine: String = "Not connected",
    val failureReason: FailureReason = FailureReason.NONE,
    val failureDetail: String = "",
    val permissionGranted: Boolean = false,
    val tunEstablished: Boolean = false,
    val controlPlaneReady: Boolean = false,
    val dataPlaneReady: Boolean = false,
    val handshakeInitiated: Boolean = false,
    val handshakeCompleted: Boolean = false,
    val pumpRunning: Boolean = false,
    val retryAttempt: Int = 0,
    val nativeVersion: String = "unavailable",
    val selectedProfile: VlessProfile? = null
)
