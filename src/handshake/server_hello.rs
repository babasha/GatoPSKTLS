use heapless::Vec;

use crate::buffer::CryptoBuffer;
use crate::cipher_suites::CipherSuite;
use crate::crypto_engine::CryptoEngine;
use crate::extensions::extension_data::key_share::KeyShareEntry;
use crate::extensions::messages::ServerHelloExtension;
use crate::handshake::{LEGACY_VERSION, Random};
use crate::parse_buffer::ParseBuffer;
use crate::{TlsError, unused};
use p256::PublicKey;
use p256::ecdh::{EphemeralSecret, SharedSecret};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ServerHello<'a> {
    extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHello<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<ServerHello<'a>, TlsError> {
        //let mut buf = ParseBuffer::new(&buf[0..content_length]);
        //let mut buf = ParseBuffer::new(&buf);

        let _version = buf.read_u16().map_err(|_| TlsError::InvalidHandshake)?;

        let mut random = [0; 32];
        buf.fill(&mut random)?;

        let session_id_length = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidSessionIdLength)?;

        //info!("sh 1");

        let session_id = buf
            .slice(session_id_length as usize)
            .map_err(|_| TlsError::InvalidSessionIdLength)?;
        //info!("sh 2");

        let cipher_suite = CipherSuite::parse(buf).map_err(|_| TlsError::InvalidCipherSuite)?;

        ////info!("sh 3");
        // skip compression method, it's 0.
        buf.read_u8()?;

        let extensions = ServerHelloExtension::parse_vector(buf)?;

        // debug!("server random {:x}", random);
        // debug!("server session-id {:x}", session_id.as_slice());
        debug!("server cipher_suite {:?}", cipher_suite);
        debug!("server extensions {:?}", extensions);

        unused(session_id);
        Ok(Self { extensions })
    }

    pub fn key_share(&self) -> Option<&KeyShareEntry<'_>> {
        self.extensions.iter().find_map(|e| {
            if let ServerHelloExtension::KeyShare(entry) = e {
                Some(&entry.0)
            } else {
                None
            }
        })
    }

    pub fn calculate_shared_secret(&self, secret: &EphemeralSecret) -> Option<SharedSecret> {
        let server_key_share = self.key_share()?;
        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        Some(secret.diffie_hellman(&server_public_key))
    }

    #[allow(dead_code)]
    pub fn initialize_crypto_engine(&self, secret: &EphemeralSecret) -> Option<CryptoEngine> {
        let server_key_share = self.key_share()?;

        let group = server_key_share.group;

        let server_public_key = PublicKey::from_sec1_bytes(server_key_share.opaque).ok()?;
        let shared = secret.diffie_hellman(&server_public_key);

        Some(CryptoEngine::new(group, shared))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side emission
// ─────────────────────────────────────────────────────────────────────────────

/// Owned-by-borrow representation of a ServerHello to be transmitted.
///
/// Produces the body of the handshake message — i.e. starting at
/// `legacy_version`. The 4-byte handshake header (`type=0x02`, length) is
/// added by the caller (see `ServerHandshakeEmit::encode`) so this struct
/// stays a pure wire-layout view.
#[derive(Debug)]
pub struct ServerHelloEmit<'a> {
    pub random: Random,
    /// Echo of the client's `legacy_session_id`. RFC 8446 §4.1.3 requires the
    /// server to mirror this verbatim. Length must be ≤ 32.
    pub legacy_session_id_echo: &'a [u8],
    /// Selected cipher suite as the on-the-wire u16 code point (e.g. 0x1301
    /// for TLS_AES_128_GCM_SHA256).
    pub cipher_suite: u16,
    pub extensions: Vec<ServerHelloExtension<'a>, 4>,
}

impl<'a> ServerHelloEmit<'a> {
    /// Serialise the ServerHello body (without handshake type/length header)
    /// into `buf`. Mirror of `ServerHello::parse`.
    pub fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        if self.legacy_session_id_echo.len() > 32 {
            return Err(TlsError::EncodeError);
        }

        // legacy_version: TLS 1.2 marker per RFC 8446 §4.1.3 — actual version
        // is negotiated via the supported_versions extension below.
        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| TlsError::EncodeError)?;

        buf.extend_from_slice(&self.random)
            .map_err(|_| TlsError::EncodeError)?;

        buf.push(self.legacy_session_id_echo.len() as u8)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(self.legacy_session_id_echo)
            .map_err(|_| TlsError::EncodeError)?;

        buf.push_u16(self.cipher_suite)
            .map_err(|_| TlsError::EncodeError)?;

        // legacy_compression_method = null (single 0 byte)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions<6..2^16-1>
        buf.with_u16_length(|buf| {
            for ext in &self.extensions {
                ext.encode(buf)?;
            }
            Ok(())
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod emit_tests {
    use super::*;
    use crate::extensions::extension_data::pre_shared_key::PreSharedKeyServerHello;
    use crate::extensions::extension_data::supported_versions::{
        SupportedVersionsServerHello, TLS13,
    };

    /// Encode a ServerHello via `ServerHelloEmit`, then round-trip it through
    /// the existing `ServerHello::parse` path. Both wire-format pieces must
    /// agree byte-for-byte.
    #[test]
    fn server_hello_emit_round_trip() {
        let random: Random = [0x42; 32];
        let session_id = [0x01u8, 0x02, 0x03, 0x04];

        let mut extensions: Vec<ServerHelloExtension<'_>, 4> = Vec::new();
        extensions
            .push(ServerHelloExtension::SupportedVersions(
                SupportedVersionsServerHello {
                    selected_version: TLS13,
                },
            ))
            .unwrap();
        extensions
            .push(ServerHelloExtension::PreSharedKey(PreSharedKeyServerHello {
                selected_identity: 0,
            }))
            .unwrap();

        let emit = ServerHelloEmit {
            random,
            legacy_session_id_echo: &session_id,
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            extensions,
        };

        let mut backing = [0u8; 256];
        let mut crypto = CryptoBuffer::wrap(&mut backing);
        emit.encode(&mut crypto).expect("encode");
        let written_len = crypto.len();
        let written = &backing[..written_len];

        // Walk the wire layout manually.
        // 2 (legacy_version) + 32 (random) + 1+4 (session_id_echo) + 2 (cipher) +
        //   1 (compression) + 2 (ext list len) + extensions...
        // PSK (PreSharedKey) ext: 2 + 2 + 2 = 6  bytes (type + len + selected_id).
        // SupportedVersions: 2 + 2 + 2 = 6 bytes (type + len + version).
        let expected_min = 2 + 32 + 1 + 4 + 2 + 1 + 2 + 6 + 6;
        assert_eq!(written_len, expected_min);

        // Byte-level spot checks.
        assert_eq!(&written[0..2], &[0x03, 0x03]); // legacy_version
        assert_eq!(&written[2..34], &random); // random
        assert_eq!(written[34], 4); // session_id length
        assert_eq!(&written[35..39], &session_id); // session_id_echo
        assert_eq!(&written[39..41], &[0x13, 0x01]); // cipher_suite
        assert_eq!(written[41], 0); // legacy_compression_method

        // Reparse via ServerHello::parse.
        let mut parse = ParseBuffer::new(written);
        let parsed = ServerHello::parse(&mut parse).expect("ServerHello::parse round-trip");

        // PreSharedKey ext should expose selected_identity = 0.
        let psk_id = parsed.extensions.iter().find_map(|ext| {
            if let ServerHelloExtension::PreSharedKey(p) = ext {
                Some(p.selected_identity)
            } else {
                None
            }
        });
        assert_eq!(psk_id, Some(0));

        // SupportedVersions ext should expose selected_version = TLS13.
        let sv = parsed.extensions.iter().find_map(|ext| {
            if let ServerHelloExtension::SupportedVersions(v) = ext {
                Some(v.selected_version)
            } else {
                None
            }
        });
        assert_eq!(sv, Some(TLS13));
    }

    /// Reject a session_id_echo longer than 32 octets — RFC 8446 §4.1.3 caps it.
    #[test]
    fn server_hello_emit_rejects_oversized_session_id() {
        let oversized = [0u8; 33];
        let emit = ServerHelloEmit {
            random: [0; 32],
            legacy_session_id_echo: &oversized,
            cipher_suite: 0x1301,
            extensions: Vec::new(),
        };
        let mut backing = [0u8; 256];
        let mut crypto = CryptoBuffer::wrap(&mut backing);
        let result = emit.encode(&mut crypto);
        assert!(matches!(result, Err(TlsError::EncodeError)));
    }
}
