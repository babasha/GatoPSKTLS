# GatoPSKTLS

[![Crates.io](https://img.shields.io/crates/v/GatoPSKTLS.svg)](https://crates.io/crates/GatoPSKTLS)
[![Docs.rs](https://docs.rs/GatoPSKTLS/badge.svg)](https://docs.rs/GatoPSKTLS)
[![License](https://img.shields.io/crates/l/GatoPSKTLS.svg)](https://github.com/babasha/GatoPSKTLS/blob/main/LICENSE)

`GatoPSKTLS` is a `no_std`, no-allocator TLS 1.3 implementation for embedded
Rust — focused on the **PSK (Pre-Shared Key) handshake on both ends of the
connection**. It is a fork of [`drogue-iot/embedded-tls`] (Apache-2.0)
extended with a complete server-mode PSK_KE handshake driver.

The motivating use case is a TLS 1.3 MQTT broker running on a microcontroller
(e.g. ESP32-C3, RP2040) talking PSK to firmware peers — the original
`embedded-tls` provides an excellent client; `GatoPSKTLS` adds the matching
server.

[`drogue-iot/embedded-tls`]: https://github.com/drogue-iot/embedded-tls

## Features

* **TLS 1.3 PSK_KE server** — `process_client_hello` + `process_client_finished`
  bytes-in/bytes-out functions, plus `TlsServerSession` and `TlsServerConfig`
  helpers. AEAD application data via `encrypt_application_data` /
  `decrypt_application_data`.
* **TLS 1.3 client** (inherited from upstream) — `TlsConnection`,
  `TlsConfig`, async + blocking variants, optional X.509 verification.
* **External PSK** with the binder verified against the partial-transcript
  hash exactly as RFC 8446 §4.2.11.2 prescribes (constant-time HMAC compare).
* `no_std` friendly. Only one mandatory cipher suite is needed:
  `TLS_AES_128_GCM_SHA256`.
* Validated against `openssl s_client 3.0.13` and `mbedtls 3.6.5 ssl_client2`
  on host, and on real ESP32-C3 hardware via `mbedtls`.

## Status

Server-mode is **PSK_KE only** (no DHE). Suitable when forward secrecy is
not required at the session level (e.g. provisioned external PSK).
PSK_DHE_KE is on the roadmap.

The current scope:

| Area                        | Status |
|-----------------------------|--------|
| PSK_KE handshake            | ✅ |
| External PSK identity       | ✅ |
| Single cipher suite (`TLS_AES_128_GCM_SHA256`) | ✅ |
| Application data AEAD       | ✅ |
| PSK_DHE_KE (forward secrecy) | ❌ roadmap |
| HelloRetryRequest           | ❌ |
| Client certificates / mTLS  | ❌ (server side) |
| Resumption tickets / 0-RTT  | ❌ |
| Post-handshake KeyUpdate    | ❌ |
| Graceful `close_notify` alert | ❌ roadmap |

These restrictions reflect the embedded MQTT-broker target. The client side
inherits the broader feature set from upstream.

## Quick start — server

```rust,ignore
use GatoPSKTLS::server::{TlsServerConfig, TlsServerSession};

// 1. Configure: external PSK identity + secret, plus a fresh server random
//    drawn from a CSPRNG.
let mut server_random = [0u8; 32];
rng.fill_bytes(&mut server_random);
let config = TlsServerConfig {
    psk: (b"my-device-id", &shared_psk),
    server_random,
};

// 2. Read the client's first record from the transport (5-byte TLSPlaintext
//    record header + body).
let ch_record = read_one_record(&mut socket).await?;
assert_eq!(ch_record[0], 0x16); // ContentType::Handshake
let ch_handshake = &ch_record[5..];

// 3. Process the ClientHello, build the server's first flight (ServerHello
//    + EncryptedExtensions + Finished — the latter two AEAD-wrapped under the
//    server handshake traffic secret).
let mut session = TlsServerSession::new();
let mut out = [0u8; 1024];
let flight = session.process_client_hello(ch_handshake, &config, &mut out)?;
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
GatoPSKTLS = { version = "0.1", default-features = false }
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

| Peer                         | Configuration                   | Where           |
|------------------------------|---------------------------------|-----------------|
| `openssl s_client` 3.0.13    | `-tls1_3 -psk -allow_no_dhe_kex`| WSL Ubuntu      |
| `mbedtls ssl_client2` 3.6.5  | `tls13_kex_modes=psk`           | Windows         |
| `mbedtls ssl_client2` 3.6.5  | `tls13_kex_modes=psk`           | ESP32-C3 over Wi-Fi |

## Tests

Lib-level tests (host; on Windows MSVC the `openssl` dev-dependency requires
WSL to build):

```sh
cargo test --lib
# 26 tests pass — includes the full PSK_KE handshake self-loop, the
# bytes-in/bytes-out round-trip, and per-primitive RFC 8448 vectors.
```

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

This crate is a fork of [`drogue-iot/embedded-tls`]; the upstream
contributors' copyright is preserved. Modifications are documented in
[`CHANGELOG.md`](CHANGELOG.md).
