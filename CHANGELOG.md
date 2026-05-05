# Changelog

All notable changes to this fork are documented here. See `NOTICE` for the
upstream attribution; commits prior to the fork point are part of the
[`drogue-iot/embedded-tls`](https://github.com/drogue-iot/embedded-tls)
history and not duplicated below.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
this fork uses its own `0.x` version line independent of upstream.

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
