# GatoPSKTLS

[![Crates.io](https://img.shields.io/crates/v/GatoPSKTLS.svg)](https://crates.io/crates/GatoPSKTLS)
[![Docs.rs](https://docs.rs/GatoPSKTLS/badge.svg)](https://docs.rs/GatoPSKTLS)
[![License](https://img.shields.io/crates/l/GatoPSKTLS.svg)](https://github.com/babasha/GatoPSKTLS/blob/main/LICENSE)

`GatoPSKTLS` is a `no_std`, no-allocator TLS 1.3 implementation for embedded
Rust — focused on the **PSK (Pre-Shared Key) handshake on both ends of the
connection**. It is a fork of [`drogue-iot/embedded-tls`] (Apache-2.0)
extended with a complete server-mode PSK handshake driver, supporting both
`psk_ke` and `psk_dhe_ke` (X25519 forward-secrecy) modes.

The motivating use case is a TLS 1.3 MQTT broker running on a microcontroller
(e.g. ESP32-C3, RP2040) talking PSK to firmware peers — the original
`embedded-tls` provides an excellent client; `GatoPSKTLS` adds the matching
server.

[`drogue-iot/embedded-tls`]: https://github.com/drogue-iot/embedded-tls

## Features

* **TLS 1.3 PSK server** — `process_client_hello` + `process_client_finished`
  bytes-in/bytes-out functions, plus `TlsServerSession` and `TlsServerConfig`
  helpers. AEAD application data via `encrypt_application_data` /
  `decrypt_application_data`. Supports both `psk_ke` and `psk_dhe_ke`
  (X25519, forward-secrecy) — auto-selected based on what the client offers
  and whether the config provides a DHE keypair.
* **TLS 1.3 client** (inherited from upstream) — `TlsConnection`,
  `TlsConfig`, async + blocking variants, optional X.509 verification.
* **External PSK** with the binder verified against the partial-transcript
  hash exactly as RFC 8446 §4.2.11.2 prescribes (constant-time HMAC compare).
* `no_std` friendly. Only one mandatory cipher suite is needed:
  `TLS_AES_128_GCM_SHA256`.
* Validated against `openssl s_client 3.0.13` and `mbedtls 3.6.5 ssl_client2`
  on host, and on real ESP32-C3 hardware via `mbedtls`.

## Status

Server-mode supports **PSK_KE** and **PSK_DHE_KE** (X25519). The mode is
auto-selected per handshake: DHE if the client advertises `psk_dhe_ke` and
the config supplies a `dhe_keypair`, else fallback to plain `psk_ke`.
PSK_DHE_KE is the default for any modern stock client (OpenSSL 3,
mbedtls 3.6+, mosquitto/paho), so the typical deployment does not need
`-allow_no_dhe_kex` or equivalent flags.

The current scope:

| Area                        | Status |
|-----------------------------|--------|
| PSK_KE handshake            | ✅ |
| PSK_DHE_KE handshake (X25519) | ✅ |
| External PSK identity       | ✅ |
| Single cipher suite (`TLS_AES_128_GCM_SHA256`) | ✅ |
| Application data AEAD       | ✅ |
| HelloRetryRequest (X25519)  | ✅ |
| ECDHE on secp256r1 / secp384r1 | ❌ roadmap |
| Client certificates / mTLS  | ❌ (server side) |
| Resumption tickets / 0-RTT  | ❌ |
| Post-handshake KeyUpdate    | ❌ |
| Graceful `close_notify` alert | ❌ roadmap |

These restrictions reflect the embedded MQTT-broker target. The client side
inherits the broader feature set from upstream.

## Quick start — server

```rust,ignore
use GatoPSKTLS::server::{DheKeyShare, HandshakeOutput, TlsServerConfig, TlsServerSession};

// 1. Configure: external PSK identity + secret, fresh server random, and an
//    ephemeral X25519 keypair for psk_dhe_ke (forward secrecy). Drop the
//    `dhe_keypair` field — leave it as `None` — to fall back to legacy
//    psk_ke (no forward secrecy, smaller flight).
let mut server_random = [0u8; 32];
rng.fill_bytes(&mut server_random);
let config = TlsServerConfig {
    psk: (b"my-device-id", &shared_psk),
    server_random,
    dhe_keypair: Some(DheKeyShare::generate(&mut rng)),
};

// 2. Read the client's first record from the transport (5-byte TLSPlaintext
//    record header + body).
let ch_record = read_one_record(&mut socket).await?;
assert_eq!(ch_record[0], 0x16); // ContentType::Handshake
let ch_handshake = &ch_record[5..];

// 3. Process the ClientHello. Returns either the full first flight or a
//    HelloRetryRequest. On HRR, write the bytes, drain the dummy CCS,
//    read the second ClientHello, and call again on the same session.
let mut session = TlsServerSession::new();
let mut out = [0u8; 1024];
let flight = match session.process_client_hello(ch_handshake, &config, &mut out)? {
    HandshakeOutput::FirstFlight(bytes) => bytes,
    HandshakeOutput::HelloRetryRequest(bytes) => {
        socket.write_all(bytes).await?;
        let ch2_record = drain_ccs_then_read(&mut socket).await?;
        match session.process_client_hello(&ch2_record[5..], &config, &mut out)? {
            HandshakeOutput::FirstFlight(b) => b,
            HandshakeOutput::HelloRetryRequest(_) => unreachable!("RFC forbids second HRR"),
        }
    }
};
socket.write_all(flight).await?;

// 4. Drain any ChangeCipherSpec dummies, then process the encrypted client
//    Finished record.
let cf_record = drain_ccs_then_read(&mut socket).await?;
session.process_client_finished(&cf_record)?;

// 5. Application data exchange.
let mut tx = [0u8; 1024];
let echo = session.encrypt_app_data(b"hello", &mut tx)?;
socket.write_all(echo).await?;
```

A fully wired async TCP example using `tokio` lives in the companion
[`picobrokerTLS`](https://github.com/babasha/picobrokerTLS) workspace under
`tools/host_tls_psk_server/` — that repo also hosts the ESP32-C3 firmware
that integrates this crate with an MQTT broker.

## Cargo features

The lib defaults to `["std", "log", "tokio"]`. For embedded targets disable
defaults:

```toml
GatoPSKTLS = { version = "0.2", default-features = false }
```

| Feature   | Effect                                                                |
|-----------|-----------------------------------------------------------------------|
| `std`     | Enable `embedded-io[-async]/std`. Default on.                         |
| `log`     | Route internal warnings/traces through the `log` crate.               |
| `defmt`   | Route internal warnings/traces through `defmt`.                       |
| `tokio`   | Enable `embedded-io-adapters/tokio-1` for desktop testing.            |
| `webpki`  | Client-side WebPKI cert verification (uses `rustls-webpki`).          |
| `rustpki` | Client-side cert handling via the `der` crate (no `rustls-webpki`).   |
| `rsa`     | Client cert + RSA signing.                                            |
| `ed25519` | Client cert + Ed25519 signing.                                        |
| `p384`    | Client cert + ECDSA-P-384 signing.                                    |

## Interop matrix

The server-mode handshake has been verified against:

| Peer                         | Configuration                   | Where           | Mode |
|------------------------------|---------------------------------|-----------------|------|
| `openssl s_client` 3.0.13    | `-tls1_3 -psk -allow_no_dhe_kex`| WSL Ubuntu      | psk_ke |
| `openssl s_client` 3.0.13    | `-tls1_3 -psk -groups X25519`   | WSL Ubuntu      | psk_dhe_ke |
| `mbedtls ssl_client2` 3.6.5  | `tls13_kex_modes=psk`           | Windows         | psk_ke |
| `mbedtls ssl_client2` 3.6.5  | `tls13_kex_modes=psk_dhe`       | Windows         | psk_dhe_ke |
| `mbedtls ssl_client2` 3.6.5  | `tls13_kex_modes=psk`           | ESP32-C3 over Wi-Fi | psk_ke |

## Tests

Lib-level tests (host; on Windows MSVC the `openssl` dev-dependency requires
WSL to build):

```sh
cargo test --lib
# 34 tests pass — includes the full PSK_KE, PSK_DHE_KE (X25519), and
# HelloRetryRequest self-loops, RFC 8446 §4.1.2 CH1↔CH2 consistency
# checks, the bytes-in/bytes-out round-trip, and per-primitive RFC 8448
# vectors.
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This crate is a fork of [`drogue-iot/embedded-tls`]; the upstream
contributors' copyright is preserved. Modifications are documented in
[`CHANGELOG.md`](CHANGELOG.md).
