package com.shadevpn.android.service

/**
 * Process-wide single connection orchestrator.
 *
 * The service drives the transport (handshake, probe, pump, retries) and
 * the activity observes the same [ConnectionOrchestrator.state] flow.
 * There must be exactly one instance per process, or service-side progress
 * never reaches the UI.
 */
object ShadeConnection {
    val orchestrator: ConnectionOrchestrator = ConnectionOrchestrator()
}
