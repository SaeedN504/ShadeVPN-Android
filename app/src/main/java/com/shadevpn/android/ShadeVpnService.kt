package com.shadevpn.android

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.shadevpn.android.model.FailureReason
import com.shadevpn.android.service.ConnectionOrchestrator
import com.shadevpn.android.service.ShadeVpnServiceController
import kotlin.concurrent.thread

/**
 * Milestone 3 service: establishes the TUN, then drives
 * reachability -> Reality handshake -> data-plane probe -> packet pump.
 * Connection state stays honest: CONNECTED only after the probe passes.
 */
class ShadeVpnService : VpnService() {
    private val orchestrator = ConnectionOrchestrator()
    private var tunInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ShadeVpnServiceController.ACTION_STOP -> stopTunnel()
            ShadeVpnServiceController.ACTION_START -> thread(name = "shadevpn-connect") {
                startTunnel(intent.getStringExtra(ShadeVpnServiceController.EXTRA_PROFILE))
            }
        }
        return START_NOT_STICKY
    }

    private fun startTunnel(rawProfile: String?) {
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

        // 1. TUN
        tunInterface = Builder()
            .setSession("ShadeVPN")
            .addAddress("10.10.0.2", 32)
            .addDnsServer("1.1.1.1")
            .addRoute("0.0.0.0", 0)
            .establish()
        val fd = tunInterface?.fd ?: -1
        orchestrator.establishTun(fd)
        if (fd < 0) {
            stopSelf()
            return
        }

        // 2. Lane validation (sanitized payload only)
        orchestrator.buildRealityLane().onFailure {
            orchestrator.fail(FailureReason.JNI_ERROR, "Failed to build Reality lane")
            stopSelf()
            return
        }

        // 3. Bounded control-plane reachability (TCP connect)
        orchestrator.probeControlPlane().getOrElse {
            stopSelf()
            return
        }

        // 4. Real Reality handshake: X25519 + session HMAC + AES-GCM records.
        orchestrator.initiateHandshake().getOrElse {
            stopSelf()
            return
        }
        // Server response is delivered on the socket by the transport pump;
        // the handshake completes natively when the response arrives. Here we
        // run the data-plane probe, which natively refuses to pass unless the
        // handshake session keys are live.
        orchestrator.runDataPlaneProbe().getOrElse {
            orchestrator.fail(FailureReason.DATA_PLANE_FAILED, "Data-plane probe failed")
            stopSelf()
            return
        }

        // 5. Data plane proven — start the packet pump on the TUN fd.
        orchestrator.startPump(fd)
    }

    private fun stopTunnel() {
        orchestrator.stopPump()
        tunInterface?.close()
        tunInterface = null
        stopSelf()
    }

    override fun onRevoke() {
        stopTunnel()
        orchestrator.revoke()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }
}
