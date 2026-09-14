# ShadeVPN Android

Android client and native transport layer for ShadeVPN.

## Milestone 4b (in progress)

The tunnel has leak protection and reconnect resilience (milestone 4a), the
Reality hello is a **real TLS 1.3 ClientHello record**, and the session
authentication now follows the **Xray REALITY constructions** byte-for-byte:
Xray-compat session-id sealing, temporary trusted certificates, and
forward-secret record keys.

What exists now:

- Kotlin connection state model with explicit control-plane vs data-plane phases
- `VpnService` lifecycle with TUN ownership staying on Android
- VLESS + Reality profile parser for `tcp`, `ws`, and `xhttp`
- **REALITY session authentication, Xray constructions**: `AuthKey =
  HKDF-SHA256(X25519(ephemeral, static), salt = random[..20], "REALITY")`;
  the legacy session id carries an AES-256-GCM seal of
  `[client version][reserved][unix time][short id]` with nonce =
  `random[20..32]` and AAD = the hello with the session id zeroed —
  identical to `XTLS/REALITY` `tls.go` and Xray-core `reality.go`
- **Temporary trusted certificates**: the server answers with
  `[Ed25519 pubkey][HMAC-SHA512(AuthKey, pubkey)]`; the client accepts the
  session only on that HMAC and rejects anything else — so a redirected or
  MITM'd connection presenting the target site's real certificate is
  detected exactly as Xray clients detect it
- **Forward-secret record keys**: the server response carries a FRESH
  X25519 key share; record keys derive from the post-hello ECDHE bound to
  the authenticated session, so recording today's traffic cannot decrypt
  future sessions even if the server static key leaks
- **Real TLS 1.3 client core** (`tls13.rs`): full RFC 8446 handshake
  transcript, key schedule (verified against RFC 8448), ServerHello parsing,
  AES-GCM/ChaCha20 record protection, RSA-PSS/PKCS1 CertificateVerify via
  minimal DER parsing, and Finished verification — proven end-to-end in CI
  against a **real OpenSSL TLS 1.3 server** (Chrome-fingerprint hello →
  full handshake → encrypted app-data round trip)
- **Real TLS 1.3 ClientHello on the wire**: a byte-legal TLS 1.3 record
  with a **Chrome-accurate fingerprint** — Chrome 131's cipher list and
  order (GREASE first), Chrome's extension sequence (GREASE ext leading,
  RFC 7685 padding trailing, ALPN `h2`/`http/1.1`, compress_certificate,
  ALPS, delegated_credentials, session_ticket, …), the GREASE dummy
  key share before the real x25519 key, and 512-byte-boundary padding —
  so passive DPI sees a browser-shaped handshake
- **Data-plane probe**: a sealed probe record must open cleanly under the
  negotiated session keys; CONNECTED is only ever reported after this passes
- **Wire-level transport**: length-prefixed record framing on the tunnel
  socket; the handshake, probe, and pump records all flow over the live
  connection instead of loopback-only verification
- **Honest in-process REALITY server** for interop tests: runs the real
  server-side flow (parse hello, derive AuthKey, unseal session id, check
  version + short-id allowlist, issue temp cert, fresh key share) from raw
  wire bytes only, and reports what actually crossed the wire (SNI seen,
  session authenticated, records mirrored) so tests assert on wire truth,
  not client-side bookkeeping
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

- Interop against a real Xray Reality endpoint (the crypto constructions
  now match XTLS byte-for-byte and the hello is Chrome-fingerprinted;
  run `sh ./server/install-xray.sh` on a VPS and dial it to close this out)
- Always-on/kill-switch enforcement (the settings deep-link exists;
  programmatic verification of Android's lockdown mode is on-device work)
- Fallback lane racing (MASQUE H2, Shadowsocks 2022)

### Running a test server (Xray on your VPS)

The native client currently speaks a byte-exact REALITY handshake against
the honest in-process test server. To interop against the real thing, set
up Xray-core on any Debian/Ubuntu VPS:

```sh
sh ./server/install-xray.sh
```

The script is fully self-contained: it installs Xray-core, generates the
UUID / x25519 keypair / short id **on the server** (no key material is ever
in this repo or your laptop), writes `/usr/local/etc/xray/config.json`, and
prints a ready-to-paste `vless://` link for the app. Re-running it rotates
all secrets. It targets port 443 with SNI camouflage to `www.microsoft.com`
(swap `DEST_SNI` in the script for a different decoy).

Note: the client's TLS 1.3 core now completes a real handshake against
OpenSSL (see the `full_handshake_against_a_real_tls13_server` test). The
remaining transport milestone is routing the live REALITY dialer through
this core and the first on-device interop against the endpoint above.

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

- VLESS VISION inner protocol over the TLS record layer
- fallback lane racing (MASQUE H2 as proven backup)
- on-device soak test of reconnect under real network loss

## Security rules

- Never disable TLS verification in production code.
- Never log UUIDs, passwords, private keys, subscription tokens, or raw profile URLs.
- Keep GPL components out of this MIT-licensed client.
- A connection is healthy only after a real data-plane probe succeeds.
