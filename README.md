# ShadeVPN Android

Android client and native transport layer for ShadeVPN.

## Milestone 3

The first real transport lane is now implemented end to end at the
protocol-crypto level: **VLESS + Reality over TCP**.

What exists now:

- Kotlin connection state model with explicit control-plane vs data-plane phases
- `VpnService` lifecycle with TUN ownership staying on Android
- VLESS + Reality profile parser for `tcp`, `ws`, and `xhttp`
- **Real Reality handshake state** in Rust: X25519 ephemeral key agreement,
  HKDF-SHA256 key schedule, HMAC session-id authentication, AES-256-GCM
  sealed ClientHello and per-record sealing/opening
- **Data-plane probe**: a sealed probe record must open cleanly under the
  negotiated session keys; CONNECTED is only ever reported after this passes
- **Packet pump JNI surface**: reads IP packets from the TUN fd, seals each
  into a Reality record, with live counters (packets/bytes in/out, seal and
  open errors) surfaced back to Kotlin
- Host-side verified packet round trip through a real fd pair (socketpair)
- Structured, secret-free failure reasons surfaced to the UI
- Compose debug surface wired to the real progression — no manual
  "mark probe success" override exists anymore

Crypto stack (pure Rust, no foreign bindings, MIT-compatible):
`x25519-dalek`, `hkdf`/`sha2`/`hmac`, `aes-gcm`.

What still does **not** exist yet:

- Wire-level server interop test against a real Xray Reality endpoint
- Kill switch, leak protection, reconnect, fallback racing

### Repository split

- `ShadeVPN`: TypeScript/React/Xray server panel and PWA.
- `ShadeVPN-Android`: Android client, VpnService/TUN owner, and native transport adapters.

### Transport policy for Iran

1. VLESS + Reality over TCP: primary, because the existing Xray panel supports it and UDP/QUIC availability is inconsistent on Iranian networks.
2. MASQUE H2 over TCP: fallback after the primary adapter is proven.
3. Shadowsocks 2022: compatibility lane, never preferred over Reality.
4. Hysteria2/MASQUE H3: experimental until UDP/QUIC passes a real network test.

OpenVPN and MTProto are intentionally out of scope.

## Next build target

Milestone 4 candidates:

- wire-level interop against a real Xray Reality server
- kill switch and leak protection
- reconnect with backoff and fallback lane racing

## Security rules

- Never disable TLS verification in production code.
- Never log UUIDs, passwords, private keys, subscription tokens, or raw profile URLs.
- Keep GPL components out of this MIT-licensed client.
- A connection is healthy only after a real data-plane probe succeeds.
