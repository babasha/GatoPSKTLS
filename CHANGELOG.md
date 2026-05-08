# Changelog

All notable changes to this fork are documented here. See `NOTICE` for the
upstream attribution; commits prior to the fork point are part of the
[`drogue-iot/embedded-tls`](https://github.com/drogue-iot/embedded-tls)
history and not duplicated below.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this fork uses its own `0.x` version line independent of upstream.

## [0.2.0] — server-mode `psk_dhe_ke` (X25519) + HelloRetryRequest

### Added

* Server-side `psk_dhe_ke` (X25519) key exchange. The mode is auto-selected
  per handshake: if the client advertises `psk_dhe_ke` and the config
  supplies a `dhe_keypair`, the server emits a `key_share` extension in its
  ServerHello, performs ECDH, and feeds the X25519 shared secret into
  `handshake_secret` derivation per RFC 8446 §7.1. Falls back to plain
  `psk_ke` (zero IKM) when the client only offered that mode or no
  `dhe_keypair` is configured.
* HelloRetryRequest support for the case where the client offered
  `psk_dhe_ke` only, advertised X25519 in `supported_groups`, and forgot
  to include an X25519 `key_share`. The server emits a HRR record (a
  ServerHello with `random` = SHA-256("HelloRetryRequest")) and rewrites
  the running transcript per RFC 8446 §4.4.1 (synthetic `message_hash` ||
  Hash(ClientHello1) || HRR). The session refuses a second HRR per
  §4.1.4 — if the second ClientHello still lacks a usable share, the
  handshake fails with `HandshakeFailure`.
* `TlsServerSession::encrypt_alert(level, desc, &mut out)` and free
  `encrypt_alert_record` — emit a TLS 1.3 post-handshake Alert (RFC 8446
  §6) wrapped in an outer ApplicationData TLSCiphertext. Primary use:
  proper `close_notify` on graceful server-side shutdown.
* `AppDataOrAlert` enum + `decrypt_app_data_or_alert` (method on
  `TlsServerSession` and free function). Distinguishes user payload from
  a peer-initiated Alert (e.g. `close_notify` from mosquitto/openssl on
  graceful client disconnect) instead of returning `InvalidRecord` like
  the original `decrypt_application_data` does. The old method is
  preserved for callers who want strict app-data-only semantics.
* RFC 8446 §4.1.2 consistency check on the second ClientHello. CH2 is
  required to match CH1 in `random` and `legacy_session_id` (the cipher
  suite and PSK identity are pinned automatically by existing validators).
  Mismatch → fatal `IllegalParameter` alert, raised before binder
  verification so a tampered random reads as the protocol violation it is
  rather than as a binder failure.
* New public `HandshakeOutput<'b>` enum returned by
  `TlsServerSession::process_client_hello`:
  * `FirstFlight(&[u8])` — full server flight as before.
  * `HelloRetryRequest(&[u8])` — caller writes the HRR bytes, drains the
    dummy CCS, reads CH2, and calls the same session again.
* `server::DheKeyShare { secret, public }` — caller-owned ephemeral X25519
  keypair, with `from_secret(secret_bytes)` and a CSPRNG-driven
  `generate(rng)` helper.
* `TlsServerConfig::dhe_keypair: Option<DheKeyShare>` field. Existing
  `psk_ke`-only callers add `dhe_keypair: None` and behave identically to
  0.1.x.
* All-zero X25519 shared-secret rejection (RFC 7748 §6.1 / RFC 8446 §7.4.2)
  with a fatal `IllegalParameter` alert.
* New tests:
  * `process_client_hello_and_finished_round_trip_dhe` — full PSK_DHE_KE
    self-loop including bidirectional appdata exchange.
  * `process_client_hello_hrr_then_dhe_round_trip` — full HRR self-loop:
    CH1 with empty `key_share` triggers HRR, CH2 with X25519 share
    completes the handshake; verifies HRR random, transcript munging, and
    application data exchange after a successful retry.
  * `decide_kex_chooses_dhe_when_possible` — DHE preferred when available;
    psk_ke fallback when DHE is not negotiable; failure when neither side
    supports the offered modes.
  * `decide_kex_rejects_second_hrr` — RFC 8446 §4.1.4 conformance.
  * `validate_ch2_consistency_random_mismatch`,
    `validate_ch2_consistency_session_id_mismatch`,
    `ch2_random_tamper_rejected_at_public_api` — RFC 8446 §4.1.2
    enforcement, including end-to-end byte-flip via the public
    `TlsServerSession` API.
  * `reject_zero_x25519_shared_secret` — small-subgroup output triggers a
    fatal alert.
  * `encrypt_alert_round_trip_close_notify`,
    `decrypt_app_data_or_alert_distinguishes_alerts` — Alert API
    round-trip in both directions, including a peer-initiated
    `close_notify` post-handshake.

### Changed (breaking on `TlsServerSession`)

* `TlsServerSession::process_client_hello` now returns
  `Result<HandshakeOutput<'b>, TlsError>` instead of
  `Result<&'b [u8], TlsError>`. Migration: match on the enum and write
  whichever bytes you got; on `HelloRetryRequest`, drain the dummy CCS
  and call the method again with the second ClientHello. The free-function
  `process_client_hello` keeps its 0.2-compatible signature and returns
  `FirstFlight`; CHs that would require HRR collapse to
  `HandshakeFailure` for back-compat.
* `KeyShareClientHello` in `messages.rs` extension group: capacity bumped
  from 1 to 4. Stock OpenSSL/mbedtls clients send multiple shares; the
  parser would previously fail on a wire that contained more than one.
* `key_schedule::initialize_handshake_secret_psk_ke` is preserved as a
  thin alias around `initialize_handshake_secret(&[0; Hash::OUT_LEN])` for
  the psk_ke fallback path.

### Dependencies

* Added `x25519-dalek = "2"` (default-features off, `zeroize` feature on).

## [0.1.0] — initial publication of the `GatoPSKTLS` fork

### Added — server mode (TLS 1.3 PSK_KE)

* `server` module exposing the public, no-I/O API:
  * `TlsServerConfig` (PSK identity + secret + server random)
  * `TlsServerSession` (concrete type bound to `TLS_AES_128_GCM_SHA256`)
  * `process_client_hello` / `process_client_finished` — bytes-in / bytes-out
    handshake driver
  * `encrypt_application_data` / `decrypt_application_data`
* `handshake::client_hello::ClientHelloRef` — borrowed-view parser for an
  incoming ClientHello, including the critical `binders_start_offset` for
  the partial-transcript hash (RFC 8446 §4.2.11.2).
* `handshake::server_hello::ServerHelloEmit` — body-only ServerHello encoder.
* `handshake::encrypted_extensions::EncryptedExtensionsEmit` —
  EncryptedExtensions encoder (canonical `00 00` for plain PSK).
* `key_schedule::KeySchedule::verify_psk_binder`,
  `create_server_finished`, `verify_client_finished`,
  `initialize_handshake_secret_psk_ke`.
* `extensions::extension_data::pre_shared_key::PreSharedKeyClientHello::parse`
  (was `unimplemented!()` upstream).

### Changed

* `extensions::extension_data::signature_algorithms::SignatureAlgorithms::parse`
  is now tolerant of unknown 2-byte sig-scheme codes (RFC 8446 §4.2.3
  recommends ignoring them; upstream's strict reject blocked OpenSSL
  ClientHellos that still advertise legacy DSA codes).

### Tests

* Six new `#[cfg(test)]` units covering ClientHello parsing, PSK binder
  round-trip, server Finished round-trip, and a self-loop test that drives
  a full PSK_KE handshake and bidirectional application-data exchange
  byte-for-byte.

### Notes on RFC compliance

While bringing up the server we found two transcript-ordering bugs that the
self-loop did not catch (because both peers were symmetrically wrong) and
which only surfaced against `openssl s_client`:

1. `handshake_secret` derivation was being computed before the ServerHello
   was fed into the running transcript — RFC 8446 §7.1 derives
   `c_hs_traffic` / `s_hs_traffic` over `Hash(ClientHello || ServerHello)`.
2. `master_secret` derivation was being computed after the client Finished
   was absorbed into the transcript — RFC 8446 §7.1 derives
   `c_ap_traffic` / `s_ap_traffic` over `Hash(CH..server Finished)`, before
   the client Finished.

Both are now fixed and explicitly documented in `src/server.rs`.
