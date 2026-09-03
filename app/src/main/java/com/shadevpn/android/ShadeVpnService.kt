package com.shadevpn.android

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.shadevpn.android.model.FailureReason
import com.shadevpn.android.service.BackoffPolicy
import com.shadevpn.android.service.ConnectionOrchestrator
import com.shadevpn.android.service.ShadeVpnServiceController
import kotlin.concurrent.thread

/**
 * Milestone 4a service: leak protection + reconnect resilience.
 *
 * Tunnel setup hardening:
 * - the app's own UID is excluded from the TUN so the tunnel's own traffic
 *   to the Reality server can never loop back into the tunnel;
 * - when the IPv6 leak shield is on, an IPv6 route is still advertised so
 *   v6 traffic is captured and then blackholed by the native pump;
 * - a sane MTU leaves room for Reality record overhead.
 *
 * Reconnect: failed connect attempts are retried with exponential backoff
 * and full jitter; disconnect (or revocation) cancels retries.
 */
class ShadeVpnService : VpnService() {
    private val orchestrator = ConnectionOrchestrator()
    private var tunInterface: ParcelFileDescriptor? = null

    /** Guards the connect/retry loop against stop/re-attach races. */
    @Volatile
    private var connectGeneration = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ShadeVpnServiceController.ACTION_STOP -> {
                connectGeneration++
                thread(name = "shadevpn-disconnect") { stopTunnel() }
            }
            ShadeVpnServiceController.ACTION_START -> {
                val generation = ++connectGeneration
                val profile = intent.getStringExtra(ShadeVpnServiceController.EXTRA_PROFILE)
                val blockIpv6 = intent.getBooleanExtra(ShadeVpnServiceController.EXTRA_BLOCK_IPV6, false)
                thread(name = "shadevpn-connect") {
                    startTunnel(generation, profile, blockIpv6)
                }
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(generation: Int, rawProfile: String?, blockIpv6: Boolean) {
        if (rawProfile.isNullOrBlank()) {
            orchestrator.fail(FailureReason.INVALID_PROFILE, "No profile supplied to service")
            stopSelf()
            return
        }
        orchestrator.onPermissionResult(true)

        val profile = orchestrator.loadProfile(rawProfile).getOrElse {
            stopSelf()
            return
        }

        // TUN: exclude our own UID (breaks the self-routing loop), capture
        // IPv6 when the leak shield is on so it can be blackholed.
        val builder = Builder()
            .setSession("ShadeVPN")
            .setMtu(DEFAULT_MTU)
            .addAddress("10.10.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0)
        if (blockIpv6) {
            // A global-scope address is required for apps to actually source
            // v6 traffic into the TUN (source selection rejects ULA for
            // global destinations). 2001:db8::/32 is reserved documentation
            // space — never routable on the real internet, and the pump
            // blackholes everything that arrives on it anyway.
            builder.addAddress("2001:db8:6b6b::2", 128)
            builder.addRoute("2000::", 3)
        }
        runCatching { builder.addDisallowedApplication(android.os.Process.myUid()) }
            .onFailure {
                orchestrator.fail(FailureReason.TUN_SETUP_FAILED, "Could not exclude own UID from TUN")
                stopSelf()
                return
            }
        tunInterface = builder.establish()

        val fd = tunInterface?.fd ?: -1
        orchestrator.establishTun(fd)
        if (fd < 0) {
            stopSelf()
            return
        }

        // Connect sequence, with reconnect-with-backoff around it.
        val backoff = BackoffPolicy()
        while (orchestrator.state.value.tunEstablished) {
            val attemptResult = attemptConnect(fd, blockIpv6, generation)
            if (attemptResult) return // connected (pump running) or fatal stop

            if (generation != connectGeneration) return // superseded or stopped
            val delay = backoff.nextDelayMs()
            if (delay == null) {
                orchestrator.reportRetryExhausted()
                stopSelf()
                return
            }
            orchestrator.reportRetryDelay(backoff.attemptsSoFar(), delay)
            sleepUnlessStopped(delay, generation) ?: return
            if (generation != connectGeneration) return
            orchestrator.beginRetry(backoff.attemptsSoFar() + 1)
        }
    }

    /** One full connect attempt. True = terminal (connected or fatal). */
    private fun attemptConnect(fd: Int, blockIpv6: Boolean, generation: Int): Boolean {
        // 1. Lane validation (sanitized payload only)
        orchestrator.buildRealityLane().onFailure {
            orchestrator.fail(FailureReason.JNI_ERROR, "Failed to build Reality lane")
            stopSelf()
            return true
        }

        // 2. Bounded control-plane reachability (TCP connect)
        orchestrator.probeControlPlane().getOrElse { return false }

        // 3. Real Reality handshake: X25519 + session HMAC + AES-GCM records.
        orchestrator.initiateHandshake().getOrElse { return false }

        // 4. Data-plane probe: natively refuses to pass without live keys.
        orchestrator.runDataPlaneProbe().getOrElse { return false }

        // 5. Data plane proven. Re-check the generation immediately before
        // starting the pump: a stop or re-attach must never leave a pump
        // running on a TUN the service has torn down.
        if (generation != connectGeneration) return true
        orchestrator.startPump(fd, blockIpv6).getOrElse {
            stopSelf()
            return true
        }
        return true
    }

    /** Sleeps unless a new command arrives; null means stop requested. */
    private fun sleepUnlessStopped(delayMs: Long, generation: Int): Unit? {
        var slept = 0L
        while (slept < delayMs) {
            if (generation != connectGeneration) return null
            val step = minOf(100L, delayMs - slept)
            Thread.sleep(step)
            slept += step
        }
        return Unit
    }

    private fun stopTunnel() {
        orchestrator.stopPump()
        tunInterface?.close()
        tunInterface = null
        stopSelf()
    }

    override fun onRevoke() {
        connectGeneration++
        stopTunnel()
        orchestrator.revoke()
        super.onRevoke()
    }

    override fun onDestroy() {
        connectGeneration++
        stopTunnel()
        super.onDestroy()
    }

    companion object {
        /** Leaves headroom for Reality/AES-GCM record overhead. */
        const val DEFAULT_MTU = 1400
    }
}
