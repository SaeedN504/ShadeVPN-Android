package com.shadevpn.android.parser

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VlessProfileParserTest {

    private val validUri =
        "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443" +
            "?security=reality&type=tcp&sni=cdn.example.com&fp=chrome&pbk=AbCdEf123&sid=01ab#ShadeVPN%20Reality"

    @Test
    fun parses_full_reality_uri() {
        val profile = VlessProfileParser.parse(validUri).getOrThrow()
        assertEquals("cdn.example.com", profile.serverAddress)
        assertEquals(443, profile.serverPort)
        assertEquals("00000000-0000-0000-0000-000000000000", profile.uuid)
        assertEquals("reality", profile.security)
        assertEquals("tcp", profile.network)
        assertEquals("cdn.example.com", profile.sni)
        assertEquals("chrome", profile.fingerprint)
        assertEquals("AbCdEf123", profile.publicKey)
        assertEquals("01ab", profile.shortId)
        assertEquals("ShadeVPN Reality", profile.name)
    }

    @Test
    fun rejects_non_vless_scheme() {
        val result = VlessProfileParser.parse("https://example.com:443")
        assertTrue(result.isFailure)
    }

    @Test
    fun rejects_missing_uuid() {
        val result = VlessProfileParser.parse("vless://@cdn.example.com:443?security=reality")
        assertTrue(result.isFailure)
    }

    @Test
    fun rejects_missing_host() {
        val result = VlessProfileParser.parse("vless://uuid-only")
        assertTrue(result.isFailure)
    }

    @Test
    fun rejects_non_reality_security() {
        val result = VlessProfileParser.parse(
            "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?security=tls"
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun rejects_unsupported_network() {
        val result = VlessProfileParser.parse(
            "vless://00000000-0000-0000-0000-000000000000@cdn.example.com:443?security=reality&type=grpc"
        )
        assertTrue(result.isFailure)
    }

    @Test
    fun defaults_port_to_443() {
        val profile = VlessProfileParser.parse(
            "vless://00000000-0000-0000-0000-000000000000@cdn.example.com?security=reality"
        ).getOrThrow()
        assertEquals(443, profile.serverPort)
    }

    @Test
    fun sanitized_json_omits_key_material() {
        val profile = VlessProfileParser.parse(validUri).getOrThrow()
        val json = VlessProfileParser.toSanitizedJson(profile)
        assertTrue(json.contains("\"publicKeyPresent\":true"))
        assertTrue(json.contains("\"shortIdPresent\":true"))
        assertFalse(json.contains("AbCdEf123"))
        assertFalse(json.contains("01ab"))
        assertFalse(json.contains("00000000-0000-0000-0000-000000000000"))
    }

    @Test
    fun handshake_json_carries_key_material_exactly_once() {
        val profile = VlessProfileParser.parse(validUri).getOrThrow()
        val json = VlessProfileParser.toHandshakeJson(profile)
        assertTrue(json.contains("\"publicKey\":\"AbCdEf123\""))
        assertTrue(json.contains("\"shortId\":\"01ab\""))
        assertFalse(json.contains("uuid"))
    }

    @Test
    fun nullable_fields_omit_blank_values() {
        val profile = VlessProfileParser.parse(
            "vless://00000000-0000-0000-0000-000000000000@cdn.example.com?security=reality"
        ).getOrThrow()
        assertNull(profile.sni)
        assertNull(profile.publicKey)
        assertNull(profile.shortId)
    }
}
