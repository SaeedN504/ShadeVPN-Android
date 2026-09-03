package com.shadevpn.android.service

import android.content.Context
import android.content.Intent
import android.net.VpnService

object ShadeVpnServiceController {
    const val ACTION_START = "com.shadevpn.android.action.START"
    const val ACTION_STOP = "com.shadevpn.android.action.STOP"
    const val EXTRA_PROFILE = "profile"
    const val EXTRA_BLOCK_IPV6 = "block_ipv6"

    fun start(context: Context, profile: String, blockIpv6: Boolean = false) {
        val intent = Intent(context, com.shadevpn.android.ShadeVpnService::class.java).apply {
            action = ACTION_START
            putExtra(EXTRA_PROFILE, profile)
            putExtra(EXTRA_BLOCK_IPV6, blockIpv6)
        }
        context.startService(intent)
    }

    fun stop(context: Context) {
        val intent = Intent(context, com.shadevpn.android.ShadeVpnService::class.java).apply {
            action = ACTION_STOP
        }
        context.startService(intent)
    }

    fun permissionIntent(context: Context): Intent? = VpnService.prepare(context)
}
