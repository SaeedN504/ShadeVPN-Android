package com.shadevpn.android.parser

import com.shadevpn.android.model.VlessProfile
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Pure-JVM parser for VLESS + Reality share links. Uses java.net.URI instead
 * of android.net.Uri so the parsing logic is unit-testable on the host JVM.
 */
object VlessProfileParser {
    fun parse(uri: String): Result<VlessProfile> = runCatching {
        require(uri.startsWith("vless://")) { "Only vless:// profiles are supported" }
        val parsed = URI(uri)
        val uuid = parsed.userInfo?.takeIf { it.isNotBlank() }
            ?: error("Missing UUID")
        val host = parsed.host?.takeIf { it.isNotBlank() }
            ?: error("Missing host")
        val port = parsed.port.takeIf { it > 0 } ?: 443
        val params = parseQuery(parsed.rawQuery)
        // URI.fragment is already percent-decoded; decoding again would
        // corrupt names containing '+' or '%'.
        val fragment = parsed.fragment
        val security = params["security"]?.ifBlank { null } ?: "reality"
        require(security.equals("reality", ignoreCase = true)) { "Only Reality is supported" }
        val network = params["type"]?.ifBlank { null } ?: "tcp"
        require(network.lowercase() in setOf("tcp", "ws", "xhttp")) { "Unsupported network type: $network" }

        VlessProfile(
            name = fragment ?: "ShadeVPN Reality",
            serverAddress = host,
            serverPort = port,
            uuid = uuid,
            flow = params["flow"]?.ifBlank { null },
            security = security,
            network = network,
            host = params["host"]?.ifBlank { null },
            path = params["path"]?.ifBlank { null },
            sni = (params["sni"] ?: params["serverName"])?.ifBlank { null },
            publicKey = (params["pbk"] ?: params["publicKey"])?.ifBlank { null },
            shortId = (params["sid"] ?: params["shortId"])?.ifBlank { null },
            fingerprint = (params["fp"] ?: params["fingerprint"])?.ifBlank { null }
        )
    }

    /** Parses `a=1&b=2` into a map, URL-decoding keys and values. */
    private fun parseQuery(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        return rawQuery.split('&')
            .filter { it.isNotBlank() }
            .associate { pair ->
                val idx = pair.indexOf('=')
                if (idx < 0) {
                    decode(pair) to ""
                } else {
                    decode(pair.take(idx)) to decode(pair.substring(idx + 1))
                }
            }
    }

    private fun decode(value: String): String =
        URLDecoder.decode(value, StandardCharsets.UTF_8.name())

    /** Sanitized payload for lane validation — no key material. */
    fun toSanitizedJson(profile: VlessProfile): String = buildString {
        append('{')
        append("\"name\":\"").append(escape(profile.name)).append("\",")
        append("\"serverAddress\":\"").append(escape(profile.serverAddress)).append("\",")
        append("\"serverPort\":").append(profile.serverPort).append(',')
        append("\"network\":\"").append(escape(profile.network)).append("\",")
        append("\"security\":\"").append(escape(profile.security)).append("\",")
        append("\"sni\":").append(nullable(profile.sni)).append(',')
        append("\"host\":").append(nullable(profile.host)).append(',')
        append("\"path\":").append(nullable(profile.path)).append(',')
        append("\"flow\":").append(nullable(profile.flow)).append(',')
        append("\"publicKeyPresent\":").append(profile.publicKey != null).append(',')
        append("\"shortIdPresent\":").append(profile.shortId != null).append(',')
        append("\"fingerprint\":").append(nullable(profile.fingerprint))
        append('}')
    }

    /**
     * Handshake payload: same shape plus the actual `publicKey` (base64) and
     * `shortId` (hex). For the native handshake only — never logged.
     */
    fun toHandshakeJson(profile: VlessProfile): String = buildString {
        append('{')
        append("\"serverAddress\":\"").append(escape(profile.serverAddress)).append("\",")
        append("\"serverPort\":").append(profile.serverPort).append(',')
        append("\"network\":\"").append(escape(profile.network)).append("\",")
        append("\"security\":\"").append(escape(profile.security)).append("\",")
        append("\"sni\":").append(nullable(profile.sni)).append(',')
        append("\"publicKeyPresent\":").append(profile.publicKey != null).append(',')
        append("\"shortIdPresent\":").append(profile.shortId != null).append(',')
        append("\"publicKey\":").append(nullable(profile.publicKey)).append(',')
        append("\"shortId\":").append(nullable(profile.shortId)).append('}')
    }

    private fun escape(value: String): String = value.replace("\\", "\\\\").replace("\"", "\\\"")
    private fun nullable(value: String?): String = value?.let { "\"${escape(it)}\"" } ?: "null"
}
