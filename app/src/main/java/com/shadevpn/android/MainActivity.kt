package com.shadevpn.android

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.shadevpn.android.model.ConnectionPhase
import com.shadevpn.android.model.ConnectionSnapshot
import com.shadevpn.android.model.FailureReason
import com.shadevpn.android.service.ConnectionOrchestrator
import com.shadevpn.android.service.ShadeVpnServiceController
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val orchestrator = ConnectionOrchestrator()
    private val scope = CoroutineScope(Dispatchers.Main)

    private val vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        orchestrator.onPermissionResult(result.resultCode == Activity.RESULT_OK)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val state by orchestrator.state.collectAsState()
            ShadeVpnApp(
                state = state,
                onPrepare = { requestVpnPermission() },
                onLoadProfile = { raw -> orchestrator.loadProfile(raw) },
                onConnect = { profile ->
                    scope.launch {
                        val ok = orchestrator.loadProfile(profile).isSuccess &&
                            orchestrator.state.value.permissionGranted
                        if (ok) {
                            ShadeVpnServiceController.start(this@MainActivity, profile)
                        }
                    }
                },
                onProbeControlPlane = {
                    scope.launch(Dispatchers.IO) { orchestrator.probeControlPlane() }
                },
                onProbeDataPlane = {
                    scope.launch(Dispatchers.IO) { orchestrator.runDataPlaneProbe() }
                },
                onStop = {
                    orchestrator.stopPump()
                    ShadeVpnServiceController.stop(this)
                }
            )
        }
    }

    private fun requestVpnPermission() {
        orchestrator.markPermissionRequested()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            orchestrator.onPermissionResult(true)
        } else {
            vpnPermissionLauncher.launch(prepareIntent)
        }
    }
}

@Composable
private fun ShadeVpnApp(
    state: ConnectionSnapshot,
    onPrepare: () -> Unit,
    onLoadProfile: (String) -> Result<*>,
    onConnect: (String) -> Unit,
    onProbeControlPlane: () -> Unit,
    onProbeDataPlane: () -> Unit,
    onStop: () -> Unit
) {
    var rawProfile by remember {
        mutableStateOf("vless://00000000-0000-0000-0000-000000000000@example.com:443?security=reality&type=tcp&sni=cdn.example.com&pbk=publicKey&sid=01ab#ShadeVPN%20Reality")
    }

    MaterialTheme {
        Scaffold { padding -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(24.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.Top
            ) {
                Text("ShadeVPN", style = MaterialTheme.typography.headlineLarge)
                Spacer(Modifier.height(8.dp))
                Text("Milestone 3: real Reality handshake, data-plane probe, packet pump")
                Spacer(Modifier.height(20.dp))
                StatusCard(state)
                Spacer(Modifier.height(20.dp))
                OutlinedTextField(
                    value = rawProfile,
                    onValueChange = { rawProfile = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Reality profile") },
                    minLines = 4,
                    supportingText = { Text("Key material never leaves the handshake path or gets logged.") }
                )
                Spacer(Modifier.height(12.dp))
                Button(onClick = onPrepare, modifier = Modifier.fillMaxWidth()) { Text("1. Request VPN permission") }
                Spacer(Modifier.height(8.dp))
                Button(onClick = { onLoadProfile(rawProfile) }, modifier = Modifier.fillMaxWidth()) { Text("2. Parse VLESS + Reality profile") }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = { onConnect(rawProfile) },
                    enabled = state.selectedProfile != null && state.permissionGranted,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("3. Connect (handshake + probe + pump)") }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onProbeControlPlane,
                    enabled = state.selectedProfile != null && !state.controlPlaneReady,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Check control plane (TCP reachability)") }
                Spacer(Modifier.height(8.dp))
                Button(
                    onClick = onProbeDataPlane,
                    enabled = state.handshakeCompleted,
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Run data-plane probe") }
                Spacer(Modifier.height(8.dp))
                Button(onClick = onStop, modifier = Modifier.fillMaxWidth()) { Text("Disconnect") }
            }
        }
    }
}

@Composable
private fun StatusCard(state: ConnectionSnapshot) {
    Column {
        Text("Status: ${state.statusLine}")
        Spacer(Modifier.height(6.dp))
        Text("Phase: ${state.phase}")
        Text("Lane: ${state.activeLane}")
        Text("Failure: ${state.failureReason}${if (state.failureDetail.isNotBlank()) \" (${state.failureDetail})\" else \"\"}")
        Text("Native: ${state.nativeVersion}")
        Text("Permission: ${state.permissionGranted}")
        Text("TUN: ${state.tunEstablished}")
        Text("Control probe: ${state.controlPlaneReady}")
        Text("Handshake initiated: ${state.handshakeInitiated}")
        Text("Handshake completed: ${state.handshakeCompleted}")
        Text("Data probe: ${state.dataPlaneReady}")
        Text("Pump: ${state.pumpRunning}")
        Spacer(Modifier.height(10.dp))
        Text(
            text = when (state.phase) {
                ConnectionPhase.CONNECTED -> "Connected for real: data-plane probe passed."
                ConnectionPhase.FAILED -> "Failure: ${failureText(state.failureReason)}${if (state.failureDetail.isNotBlank()) \" — ${state.failureDetail}\" else \"\"}"
                else -> "Not connected until the data-plane probe passes."
            },
            fontFamily = FontFamily.Monospace
        )
    }
}

private fun failureText(reason: FailureReason): String = when (reason) {
    FailureReason.PERMISSION_DENIED -> "user blocked VPN permission"
    FailureReason.INVALID_PROFILE -> "profile parse or validation failed"
    FailureReason.JNI_ERROR -> "native layer rejected the request"
    FailureReason.CONTROL_PLANE_FAILED -> "reachability or handshake failed"
    FailureReason.DATA_PLANE_FAILED -> "probe failed"
    FailureReason.VPN_REVOKED -> "Android revoked the tunnel"
    FailureReason.TUN_SETUP_FAILED -> "builder never produced a TUN fd"
    FailureReason.NONE, FailureReason.UNKNOWN -> "none"
}
