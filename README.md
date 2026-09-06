# ShadeVPN Android

Android client and native transport layer for ShadeVPN.

## Milestone 4b (in progress)

The tunnel has leak protection and reconnect resilience (milestone 4a), and
the Reality hello is now a **real TLS 1.3 ClientHello record** — the first
4b step toward wire-level interop with Xray-style Reality endpoints.

What exists now:

- Kotlin connection state model with explicit control-plane vs data-plane phases
- `VpnService` lifecycle with TUN ownership staying on Android
- VLESS + Reality profile parser for `tcp`, `ws`, and `xhttp`
- **Real Reality handshake state** in Rust: X25519 ephemeral key agreement,
  HKDF-SHA256 key schedule, HMAC session-id authentication, AES-256-GCM
  record sealing/opening
- **Real TLS 1.3 ClientHello on the wire**: the hello is a byte-legal TLS
  1.3 record — ephemeral X25519 key in `key_share`, session tag in
  `random`, short ID in `legacy_session_id`, SNI in `server_name`, plus
  browser-realistic cipher suites and extensions. Authentication does not
  depend on any non-TLS payload: only a client holding the server's Reality
  key material can produce a valid (`key_share`, `random`) pair, and a
  passive observer sees nothing but a plausible browser handshake
- **Data-plane probe**: a sealed probe record must open cleanly under the
  negotiated session keys; CONNECTED is only ever reported after this passes
- **Wire-level transport**: length-prefixed record framing on the tunnel
  socket; the handshake, probe, and pump records all flow over the live
  connection instead of loopback-only verification
- **Honest in-process Reality server** for interop tests: parses the TLS
  1.3 ClientHello from raw wire bytes, derives the shared secret from the
  key_share found there, authenticates the session tag from `random`, and
  reports what actually crossed the wire (SNI seen, session authenticated,
  records mirrored) so tests assert on wire truth, not client-side
  bookkeeping
- **Staged handshake in the orchestrator**: the native layer establishes the
  tunnel and returns the server response without auto-completing; Kotlin's
  state machine decides when to authenticate it, and any rejection tears the
  session (keys AND socket) down natively
- **Packet pump JNI surface** with per-session record sequence, reading IP
  packets from the TUN fd and sealing each into a Reality record
- **Leak shield**: the app's own UID is excluded from the TUN (no
  self-routing loop); with IPv6 blocking on, a `2000::/3` route is still
  advertised so v6 traffic is captured and blackholed by the pump, with a
  live `droppedPackets` counter
- **Reconnect with exponential backoff and full jitter** (5 attempts,
  0.5s–15s), cancelled by disconnect/revocation
- Structured, secret-free failure reasons surfaced to the UI
- Host-side verified packet round trip through a real fd pair (socketpair)

Crypto stack (pure Rust, no foreign bindings, MIT-compatible):
`x25519-dalek`, `hkdf`/`sha2`/`hmac`, `aes-gcm`.

What still does **not** exist yet:

- Interop against a real Xray Reality endpoint (the hello is now a real TLS
  1.3 ClientHello record, but Xray's server side — certificate forging,
  VISION inner protocol, session-id leniency — is not yet replicated; the
  honest in-process server covers wire-level interop in CI)
- Always-on/kill-switch enforcement (the settings deep-link exists;
  programmatic verification of Android's lockdown mode is on-device work)
- Fallback lane racing (MASQUE H2, Shadowsocks 2022)

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

Remaining milestone 4b candidates:

- Xray server-side behavior: certificate forging for proxied SNI and the
  VLESS VISION inner protocol after the TLS record
- fallback lane racing (MASQUE H2 as proven backup)
- on-device soak test of reconnect under real network loss

## Security rules

- Never disable TLS verification in production code.
- Never log UUIDs, passwords, private keys, subscription tokens, or raw profile URLs.
- Keep GPL components out of this MIT-licensed client.
- A connection is healthy only after a real data-plane probe succeeds.
