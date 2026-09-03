package com.shadevpn.android.service

import com.shadevpn.android.model.ConnectionPhase
import com.shadevpn.android.model.FailureReason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Orchestrator state-machine tests that do not touch the JNI layer. JNI paths
 * (handshake, probes, pump) need the native library and are covered by the
 * Rust host tests plus on-device runs.
 */
class ConnectionOrchestratorTest {

    private fun orchestrator() = ConnectionOrchestrator()

    private val validProfile =
        "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443" +
            "?security=reality&type=tcp&sni=cdn.example.com&pbk=AbCdEf123&sid=01ab#Test"

    @Test
    fun permission_denied_fails_with_structured_reason() {
        val o = orchestrator()
        o.onPermissionResult(false)
        val s = o.state.value
        assertEquals(ConnectionPhase.FAILED, s.phase)
        assertEquals(FailureReason.PERMISSION_DENIED, s.failureReason)
        assertFalse(s.permissionGranted)
    }

    @Test
    fun valid_profile_loads_and_sets_lane() {
        val o = orchestrator()
        val result = o.loadProfile(validProfile)
        assertTrue(result.isSuccess)
        val s = o.state.value
        assertEquals("vless-reality", s.activeLane)
        assertEquals("cdn.example.com", s.selectedProfile?.serverAddress)
    }

    @Test
    fun invalid_profile_fails_with_detail() {
        val o = orchestrator()
        val result = o.loadProfile("vless://broken")
        assertTrue(result.isFailure)
        val s = o.state.value
        assertEquals(ConnectionPhase.FAILED, s.phase)
        assertEquals(FailureReason.INVALID_PROFILE, s.failureReason)
        assertTrue(s.failureDetail.isNotBlank())
    }

    @Test
    fun tun_failure_is_structured() {
        val o = orchestrator()
        o.onPermissionResult(true)
        o.establishTun(-1)
        val s = o.state.value
        assertEquals(ConnectionPhase.FAILED, s.phase)
        assertEquals(FailureReason.TUN_SETUP_FAILED, s.failureReason)
        assertFalse(s.tunEstablished)
    }

    @Test
    fun tun_success_moves_to_control_phase() {
        val o = orchestrator()
        o.onPermissionResult(true)
        o.establishTun(42)
        val s = o.state.value
        assertTrue(s.tunEstablished)
        assertEquals(ConnectionPhase.CONNECTING_CONTROL, s.phase)
    }

    @Test
    fun revoke_clears_all_plane_state() {
        val o = orchestrator()
        o.onPermissionResult(true)
        o.establishTun(42)
        o.revoke()
        val s = o.state.value
        assertEquals(ConnectionPhase.DISCONNECTED, s.phase)
        assertEquals(FailureReason.VPN_REVOKED, s.failureReason)
        assertFalse(s.tunEstablished)
        assertFalse(s.handshakeInitiated)
        assertFalse(s.handshakeCompleted)
        assertFalse(s.pumpRunning)
    }

    @Test
    fun begin_retry_clears_stale_plane_state_and_sets_attempt() {
        val o = orchestrator()
        o.onPermissionResult(true)
        o.establishTun(42)
        o.beginRetry(3)
        val s = o.state.value
        assertEquals(3, s.retryAttempt)
        assertEquals(ConnectionPhase.PREPARING, s.phase)
        assertEquals(FailureReason.NONE, s.failureReason)
        // Stale flags from the failed attempt must not leak into the retry.
        assertFalse(s.controlPlaneReady)
        assertFalse(s.handshakeInitiated)
        assertFalse(s.handshakeCompleted)
        assertFalse(s.dataPlaneReady)
        assertFalse(s.pumpRunning)
        assertTrue(s.failureDetail.isBlank())
    }

    @Test
    fun retry_exhausted_resets_transient_flags() {
        val o = orchestrator()
        o.onPermissionResult(true)
        o.establishTun(42)
        o.beginRetry(5)
        o.reportRetryExhausted()
        val s = o.state.value
        assertEquals(ConnectionPhase.FAILED, s.phase)
        assertEquals(FailureReason.CONTROL_PLANE_FAILED, s.failureReason)
        assertEquals(0, s.retryAttempt)
        assertFalse(s.handshakeCompleted)
        assertFalse(s.dataPlaneReady)
        // The TUN stays up: exhaustion is a transport failure, not a tunnel one.
        assertTrue(s.tunEstablished)
    }
}
