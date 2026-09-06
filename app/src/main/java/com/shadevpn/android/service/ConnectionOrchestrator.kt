package com.shadevpn.android.service

import com.shadevpn.android.NativeBridge
import com.shadevpn.android.model.ConnectionPhase
import com.shadevpn.android.model.ConnectionSnapshot
import com.shadevpn.android.model.FailureReason
import com.shadevpn.android.model.VlessProfile
import com.shadevpn.android.parser.VlessProfileParser
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

/**
 * Drives the REAL transport progression —
 * TUN -> control-plane reachability -> wire tunnel establishment (TCP +
 * X25519 + HMAC session auth + sealed ClientHello) -> server-response
 * authentication -> data-plane probe over the live tunnel -> tunnel pump.
 * CONNECTED is only ever reported after the data-plane probe passes.
 */
class ConnectionOrchestrator {

    /**
     * Server response returned by the wire handshake, awaiting
     * [completeHandshake]. Held only in memory, never logged.
     */
    private var pendingServerResponseB64: String? = null
    private val _state = MutableStateFlow(
        ConnectionSnapshot(nativeVersion = runCatching { NativeBridge.nativeVersion() }.getOrDefault("unavailable"))
    )
    val state: StateFlow<ConnectionSnapshot> = _state.asStateFlow()

    fun markPermissionRequested() = mutate { copy(phase = ConnectionPhase.REQUESTING_PERMISSION, statusLine = "VPN permission requested") }

    fun onPermissionResult(granted: Boolean) {
        mutate {
            copy(
                permissionGranted = granted,
                phase = if (granted) ConnectionPhase.PREPARING else ConnectionPhase.FAILED,
                statusLine = if (granted) "Permission granted, preparing tunnel" else "VPN permission denied",
                failureReason = if (granted) FailureReason.NONE else FailureReason.PERMISSION_DENIED
            )
        }
    }

    fun loadProfile(rawProfile: String): Result<VlessProfile> {
        val result = VlessProfileParser.parse(rawProfile)
        result.onSuccess { profile ->
            mutate {
                copy(
                    selectedProfile = profile,
                    activeLane = "vless-reality",
                    statusLine = "Profile loaded: ${profile.name}",
                    failureReason = FailureReason.NONE
                )
            }
        }.onFailure {
            mutate {
                copy(
                    phase = ConnectionPhase.FAILED,
                    statusLine = "Invalid Reality profile",
                    failureReason = FailureReason.INVALID_PROFILE,
                    failureDetail = it.message ?: ""
                )
            }
        }
        return result
    }

    fun establishTun(fd: Int) {
        mutate {
            copy(
                tunEstablished = fd >= 0,
                phase = if (fd >= 0) ConnectionPhase.CONNECTING_CONTROL else ConnectionPhase.FAILED,
                statusLine = if (fd >= 0) "TUN established, checking control plane" else "Failed to establish TUN",
                failureReason = if (fd >= 0) FailureReason.NONE else FailureReason.TUN_SETUP_FAILED
            )
        }
    }

    /** Lane validation (no key material crosses here). */
    fun buildRealityLane(): Result<String> {
        val profile = state.value.selectedProfile ?: return Result.failure(IllegalStateException("No profile selected"))
        return runCatching {
            val payload = VlessProfileParser.toSanitizedJson(profile)
            NativeBridge.nativeBuildLane(payload)
        }.onFailure {
            mutate { copy(phase = ConnectionPhase.FAILED, statusLine = "Native lane build failed", failureReason = FailureReason.JNI_ERROR) }
        }
    }

    /** Bounded TCP reachability — still not Connected. */
    fun probeControlPlane(): Result<Boolean> {
        val profile = state.value.selectedProfile ?: return Result.failure(IllegalStateException("No profile selected"))
        return runCatching {
            val response = JSONObject(NativeBridge.nativeProbeControlPlane(VlessProfileParser.toSanitizedJson(profile)))
            response.optBoolean("reachable", false)
        }.onSuccess { reachable ->
            if (reachable) {
                mutate { copy(statusLine = "Server reachable, initiating Reality handshake") }
            } else {
                mutate {
                    copy(
                        phase = ConnectionPhase.FAILED,
                        statusLine = "Server unreachable",
                        failureReason = FailureReason.CONTROL_PLANE_FAILED
                    )
                }
            }
        }
    }

    /**
     * Real tunnel establishment: TCP connect plus the full cryptographic
     * Reality handshake over the wire (X25519, HKDF, HMAC session auth,
     * sealed ClientHello). The native layer returns the server's response
     * WITHOUT auto-completing; Kotlin must feed it back through
     * [completeHandshake] so this state machine governs the progression.
     *
     * Key material (publicKey/shortId) is serialized into the handshake
     * payload only — never into status lines or logs.
     */
    fun connectTunnel(): Result<Unit> {
        val profile = state.value.selectedProfile ?: return Result.failure(IllegalStateException("No profile selected"))
        return runCatching {
            val response = JSONObject(NativeBridge.nativeConnectTunnel(VlessProfileParser.toHandshakeJson(profile)))
            require(response.optBoolean("ok", false)) { response.optString("reason", "tunnel connection rejected") }
            val responseB64 = response.optString("serverResponseB64")
            require(responseB64.isNotBlank()) { "server response missing from tunnel payload" }
            pendingServerResponseB64 = responseB64
        }.onSuccess {
            mutate {
                copy(
                    handshakeInitiated = true,
                    controlPlaneReady = true,
                    statusLine = "Reality hello sent, session awaiting authentication"
                )
            }
        }.onFailure {
            // Drop any stale tunnel state (socket + keys) so a retry starts clean.
            runCatching { NativeBridge.nativeDisconnectTunnel() }
            pendingServerResponseB64 = null
            mutate {
                copy(
                    phase = ConnectionPhase.FAILED,
                    statusLine = "Reality tunnel connection failed",
                    failureReason = FailureReason.CONTROL_PLANE_FAILED,
                    failureDetail = it.message ?: "",
                    handshakeInitiated = false
                )
            }
        }
    }

    /**
     * Completes the handshake with the server response (base64). Defaults to
     * the response captured by [connectTunnel]. A rejected response tears the
     * session down natively (keys AND socket); the UI can never mark the
     * connection as complete after this.
     */
    fun completeHandshake(serverResponseB64: String? = pendingServerResponseB64): Result<Unit> {
        if (serverResponseB64.isNullOrBlank()) {
            return Result.failure(IllegalStateException("No server response to authenticate"))
        }
        return runCatching {
            val response = JSONObject(NativeBridge.nativeCompleteHandshake(serverResponseB64))
            require(response.optBoolean("ok", false)) { response.optString("reason", "session auth rejected") }
        }.onSuccess {
            pendingServerResponseB64 = null
            mutate {
                copy(
                    handshakeCompleted = true,
                    phase = ConnectionPhase.PROBING_DATA,
                    statusLine = "Handshake authenticated, probing data plane"
                )
            }
        }.onFailure {
            pendingServerResponseB64 = null
            mutate {
                copy(
                    phase = ConnectionPhase.FAILED,
                    statusLine = "Server response rejected",
                    failureReason = FailureReason.CONTROL_PLANE_FAILED,
                    failureDetail = it.message ?: "",
                    handshakeCompleted = false
                )
            }
        }
    }

    /**
     * Data-plane probe: seals a probe record under the negotiated session
     * keys and requires it to open cleanly. This is the ONLY path to
     * CONNECTED — there is no manual override anymore.
     */
    fun runDataPlaneProbe(): Result<Unit> {
        return runCatching {
            val response = JSONObject(NativeBridge.nativeProbeDataPlane())
            require(response.optBoolean("ok", false)) { response.optString("reason", "probe failed") }
        }.onSuccess {
            mutate {
                copy(
                    phase = ConnectionPhase.CONNECTED,
                    dataPlaneReady = true,
                    retryAttempt = 0,
                    statusLine = "Connected — data-plane probe passed",
                    failureReason = FailureReason.NONE
                )
            }
        }.onFailure {
            mutate {
                copy(
                    phase = ConnectionPhase.FAILED,
                    statusLine = "Data-plane probe failed",
                    failureReason = FailureReason.DATA_PLANE_FAILED,
                    failureDetail = it.message ?: ""
                )
            }
        }
    }

    /**
     * Starts the bidirectional tunnel pump on the TUN fd. Requires a
     * completed handshake and the established tunnel socket; record
     * sequences continue where the data-plane probe left off.
     */
    fun startPump(fd: Int, blockIpv6: Boolean = false): Result<Unit> {
        return runCatching {
            val response = JSONObject(NativeBridge.nativeStartTunnelPump(fd, blockIpv6))
            require(response.optBoolean("ok", false)) { response.optString("reason", "pump start rejected") }
        }.onSuccess {
            mutate { copy(pumpRunning = true, statusLine = "Tunnel pump running${if (blockIpv6) " (IPv6 blocked)" else ""}") }
        }.onFailure {
            mutate {
                copy(
                    pumpRunning = false,
                    failureReason = FailureReason.JNI_ERROR,
                    failureDetail = it.message ?: ""
                )
            }
        }
    }

    /** Starts a retry: reports attempt N and clears stale plane state. */
    fun beginRetry(attempt: Int) {
        pendingServerResponseB64 = null
        mutate {
            copy(
                phase = ConnectionPhase.PREPARING,
                statusLine = "Reconnect attempt $attempt",
                failureReason = FailureReason.NONE,
                failureDetail = "",
                retryAttempt = attempt,
                controlPlaneReady = false,
                handshakeInitiated = false,
                handshakeCompleted = false,
                dataPlaneReady = false,
                pumpRunning = false
            )
        }
    }

    fun reportRetryExhausted() = mutate {
        copy(
            phase = ConnectionPhase.FAILED,
            statusLine = "Reconnect abandoned after retries",
            failureReason = FailureReason.CONTROL_PLANE_FAILED,
            retryAttempt = 0,
            handshakeCompleted = false,
            dataPlaneReady = false
        )
    }

    fun reportRetryDelay(attempt: Int, delayMs: Long) = mutate {
        copy(statusLine = "Reconnecting in ${delayMs}ms (attempt ${attempt + 1})")
    }

    /** Full teardown: pump, session keys, tunnel socket. */
    fun disconnect() {
        runCatching { NativeBridge.nativeDisconnectTunnel() }
        pendingServerResponseB64 = null
        mutate { copy(pumpRunning = false) }
    }

    fun pumpStats(): JSONObject = runCatching { JSONObject(NativeBridge.nativePumpStats()) }.getOrDefault(JSONObject())

    fun fail(reason: FailureReason, message: String) = mutate {
        copy(phase = ConnectionPhase.FAILED, statusLine = message, failureReason = reason, controlPlaneReady = false, dataPlaneReady = false)
    }

    fun revoke() = mutate {
        copy(
            phase = ConnectionPhase.DISCONNECTED,
            statusLine = "VPN permission revoked",
            failureReason = FailureReason.VPN_REVOKED,
            tunEstablished = false,
            controlPlaneReady = false,
            dataPlaneReady = false,
            handshakeInitiated = false,
            handshakeCompleted = false,
            pumpRunning = false
        )
    }

    fun reset() {
        pendingServerResponseB64 = null
        val cur = _state.value
        _state.value = ConnectionSnapshot(
            nativeVersion = cur.nativeVersion,
            selectedProfile = cur.selectedProfile,
            permissionGranted = cur.permissionGranted
        )
    }

    /**
     * Atomic compare-and-set update loop: the service (connect thread,
     * disconnect thread) and the UI can mutate concurrently, so a plain
     * read-modify-write could lose updates. Retries until the CAS wins.
     */
    private fun mutate(block: ConnectionSnapshot.() -> ConnectionSnapshot) {
        while (true) {
            val current = _state.value
            val updated = current.block()
            if (_state.compareAndSet(current, updated)) return
        }
    }
}
