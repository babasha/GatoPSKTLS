use core::marker::PhantomData;

use digest::{Digest, OutputSizeUser};
use heapless::Vec;
use p256::EncodedPoint;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::rand_core::RngCore;
use typenum::Unsigned;

use crate::TlsError;
use crate::alert::{AlertDescription, AlertLevel};
use crate::config::{TlsCipherSuite, TlsConfig};
use crate::extensions::extension_data::alpn::AlpnProtocolNameList;
use crate::extensions::extension_data::key_share::{KeyShareClientHello, KeyShareEntry};
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyClientHello;
use crate::extensions::extension_data::psk_key_exchange_modes::{
    PskKeyExchangeMode, PskKeyExchangeModes,
};
use crate::extensions::extension_data::server_name::ServerNameList;
use crate::extensions::extension_data::signature_algorithms::SignatureAlgorithms;
use crate::extensions::extension_data::supported_groups::{NamedGroup, SupportedGroups};
use crate::extensions::extension_data::supported_versions::{SupportedVersionsClientHello, TLS13};
use crate::extensions::messages::ClientHelloExtension;
use crate::handshake::{HandshakeType, LEGACY_VERSION, Random};
use crate::key_schedule::{HashOutputSize, WriteKeySchedule};
use crate::parse_buffer::ParseBuffer;
use crate::{CryptoProvider, buffer::CryptoBuffer};

pub struct ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) config: &'config TlsConfig<'config>,
    random: Random,
    cipher_suite: PhantomData<CipherSuite>,
    pub(crate) secret: EphemeralSecret,
}

impl<'config, CipherSuite> ClientHello<'config, CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new<Provider>(config: &'config TlsConfig<'config>, mut provider: Provider) -> Self
    where
        Provider: CryptoProvider,
    {
        let mut random = [0; 32];
        provider.rng().fill_bytes(&mut random);

        Self {
            config,
            random,
            cipher_suite: PhantomData,
            secret: EphemeralSecret::random(&mut provider.rng()),
        }
    }

    pub(crate) fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        let public_key = EncodedPoint::from(&self.secret.public_key());
        let public_key = public_key.as_ref();

        buf.push_u16(LEGACY_VERSION)
            .map_err(|_| TlsError::EncodeError)?;
        buf.extend_from_slice(&self.random)
            .map_err(|_| TlsError::EncodeError)?;

        // session id (empty)
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // cipher suites (2+)
        //buf.extend_from_slice(&((self.config.cipher_suites.len() * 2) as u16).to_be_bytes());
        //for c in self.config.cipher_suites.iter() {
        //buf.extend_from_slice(&(*c as u16).to_be_bytes());
        //}
        buf.push_u16(2).map_err(|_| TlsError::EncodeError)?;
        buf.push_u16(CipherSuite::CODE_POINT)
            .map_err(|_| TlsError::EncodeError)?;

        // compression methods, 1 byte of 0
        buf.push(1).map_err(|_| TlsError::EncodeError)?;
        buf.push(0).map_err(|_| TlsError::EncodeError)?;

        // extensions (1+)
        buf.with_u16_length(|buf| {
            // Section 4.2.1.  Supported Versions
            // Implementations of this specification MUST send this extension in the
            // ClientHello containing all versions of TLS which they are prepared to
            // negotiate
            ClientHelloExtension::SupportedVersions(SupportedVersionsClientHello {
                versions: Vec::from_slice(&[TLS13]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::SignatureAlgorithms(SignatureAlgorithms {
                supported_signature_algorithms: self.config.signature_schemes.clone(),
            })
            .encode(buf)?;

            if let Some(max_fragment_length) = self.config.max_fragment_length {
                ClientHelloExtension::MaxFragmentLength(max_fragment_length).encode(buf)?;
            }

            ClientHelloExtension::SupportedGroups(SupportedGroups {
                supported_groups: self.config.named_groups.clone(),
            })
            .encode(buf)?;

            ClientHelloExtension::PskKeyExchangeModes(PskKeyExchangeModes {
                modes: Vec::from_slice(&[PskKeyExchangeMode::PskDheKe]).unwrap(),
            })
            .encode(buf)?;

            ClientHelloExtension::KeyShare(KeyShareClientHello {
                client_shares: Vec::from_slice(&[KeyShareEntry {
                    group: NamedGroup::Secp256r1,
                    opaque: public_key,
                }])
                .unwrap(),
            })
            .encode(buf)?;

            if let Some(server_name) = self.config.server_name {
                ClientHelloExtension::ServerName(ServerNameList::single(server_name))
                    .encode(buf)?;
            }

            if let Some(alpn_protocols) = self.config.alpn_protocols {
                ClientHelloExtension::ApplicationLayerProtocolNegotiation(AlpnProtocolNameList {
                    protocols: alpn_protocols,
                })
                .encode(buf)?;
            }

            // Section 4.2
            // When multiple extensions of different types are present, the
            // extensions MAY appear in any order, with the exception of
            // "pre_shared_key" which MUST be the last extension in
            // the ClientHello.
            if let Some((_, identities)) = &self.config.psk {
                ClientHelloExtension::PreSharedKey(PreSharedKeyClientHello {
                    identities: identities.clone(),
                    // Binders are patched in by `ClientHello::finalize` after the
                    // transcript hash is known; the encode path writes a zero-fill
                    // placeholder of the correct length, so we don't supply them here.
                    binders: heapless::Vec::new(),
                    hash_size: <CipherSuite::Hash as OutputSizeUser>::output_size(),
                })
                .encode(buf)?;
            }

            Ok(())
        })?;

        Ok(())
    }

    pub fn finalize(
        &self,
        enc_buf: &mut [u8],
        transcript: &mut CipherSuite::Hash,
        write_key_schedule: &mut WriteKeySchedule<CipherSuite>,
    ) -> Result<(), TlsError> {
        // Special case for PSK which needs to:
        //
        // 1. Add the client hello without the binders to the transcript
        // 2. Create the binders for each identity using the transcript
        // 3. Add the rest of the client hello.
        //
        // This causes a few issues since lengths must be correctly inside the payload,
        // but won't actually be added to the record buffer until the end.
        if let Some((_, identities)) = &self.config.psk {
            let binders_len = identities.len() * (1 + HashOutputSize::<CipherSuite>::to_usize());

            let binders_pos = enc_buf.len() - binders_len;

            // NOTE: Exclude the binders_len itself from the digest
            transcript.update(&enc_buf[0..binders_pos - 2]);

            // Append after the client hello data. Sizes have already been set.
            let mut buf = CryptoBuffer::wrap(&mut enc_buf[binders_pos..]);
            // Create a binder and encode for each identity
            for _id in identities {
                let binder = write_key_schedule.create_psk_binder(transcript)?;
                binder.encode(&mut buf)?;
            }

            transcript.update(&enc_buf[binders_pos - 2..]);
        } else {
            transcript.update(enc_buf);
        }

        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-side parsing: ClientHelloRef
// ─────────────────────────────────────────────────────────────────────────────

/// Borrowed view of a parsed `ClientHello` handshake message.
///
/// The lifetime `'a` is tied to the input byte buffer; all variable-length
/// fields (session id, cipher suite list, compression methods, extensions
/// containing borrowed slices) reference into that buffer.
///
/// `binders_start_offset` tells the server-mode handshake code exactly how
/// many leading bytes of the original handshake message form the binder
/// transcript: `Hash(buf[0..binders_start_offset])` is the value MAC'd by
/// the PSK binder. RFC 8446 §4.2.11.2 specifies this partial-transcript
/// hash; getting the offset right is what makes binder verification work.
pub struct ClientHelloRef<'a, const NEXT: usize> {
    pub legacy_version: u16,
    pub random: Random,
    pub legacy_session_id: &'a [u8],
    /// Raw cipher-suite list bytes (each suite is a u16, big-endian; the
    /// length is implicit in `cipher_suites.len() / 2`).
    pub cipher_suites: &'a [u8],
    pub legacy_compression_methods: &'a [u8],
    pub extensions: Vec<ClientHelloExtension<'a>, NEXT>,
    /// Byte offset within the input handshake message buffer where the
    /// `pre_shared_key.binders` section begins. When no PSK extension is
    /// present, this equals the total handshake message length.
    pub binders_start_offset: usize,
}

impl<'a, const NEXT: usize> ClientHelloRef<'a, NEXT> {
    /// Parse a complete `ClientHello` handshake message (including the 4-byte
    /// handshake header) from `buf`.
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, TlsError> {
        // Handshake header: HandshakeType (1) || length (3)
        let msg_type_raw = buf.read_u8().map_err(|_| TlsError::InvalidHandshake)?;
        if msg_type_raw != HandshakeType::ClientHello as u8 {
            return Err(TlsError::InvalidHandshake);
        }
        let body_len = buf
            .read_u24()
            .map_err(|_| TlsError::InvalidHandshake)? as usize;
        let body_start = buf.offset();
        let total_message_length = body_start + body_len;

        // Body
        let legacy_version = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidHandshake)?;

        let mut random: Random = [0; 32];
        buf.fill(&mut random)
            .map_err(|_| TlsError::InvalidHandshake)?;

        // legacy_session_id<0..32>
        let session_id_len = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidHandshake)? as usize;
        if session_id_len > 32 {
            return Err(TlsError::InvalidSessionIdLength);
        }
        let session_id_buf = buf
            .slice(session_id_len)
            .map_err(|_| TlsError::InvalidHandshake)?;
        let legacy_session_id = session_id_buf.as_slice();

        // cipher_suites<2..2^16-2>
        let cipher_suites_len = buf
            .read_u16()
            .map_err(|_| TlsError::InvalidHandshake)? as usize;
        if cipher_suites_len < 2 || cipher_suites_len % 2 != 0 {
            return Err(TlsError::InvalidHandshake);
        }
        let cipher_suites_buf = buf
            .slice(cipher_suites_len)
            .map_err(|_| TlsError::InvalidHandshake)?;
        let cipher_suites = cipher_suites_buf.as_slice();

        // legacy_compression_methods<1..2^8-1>
        let comp_len = buf
            .read_u8()
            .map_err(|_| TlsError::InvalidHandshake)? as usize;
        if comp_len < 1 {
            return Err(TlsError::InvalidHandshake);
        }
        let comp_buf = buf
            .slice(comp_len)
            .map_err(|_| TlsError::InvalidHandshake)?;
        let legacy_compression_methods = comp_buf.as_slice();

        // Extensions (parse_vector eats the u16 length prefix internally).
        let extensions = ClientHelloExtension::parse_vector::<NEXT>(buf)?;

        // The body must exactly fill what the handshake header advertised.
        if buf.offset() != total_message_length {
            return Err(TlsError::InvalidHandshake);
        }

        // Compute binders_start_offset post-hoc.
        // RFC 8446 §4.2.11: pre_shared_key, when present, MUST be the last extension.
        // Knowing that, the binders section is exactly the trailing bytes of the
        // handshake message; we walk backwards by the parsed binders' wire size.
        let mut binders_start_offset = total_message_length;
        let psk_indices: Vec<usize, NEXT> = extensions
            .iter()
            .enumerate()
            .filter_map(|(i, ext)| {
                if matches!(ext, ClientHelloExtension::PreSharedKey(_)) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        if psk_indices.len() > 1 {
            return Err(TlsError::AbortHandshake(
                AlertLevel::Fatal,
                AlertDescription::IllegalParameter,
            ));
        }
        if let Some(&idx) = psk_indices.first() {
            if idx != extensions.len() - 1 {
                // pre_shared_key not last → fatal illegal_parameter.
                return Err(TlsError::AbortHandshake(
                    AlertLevel::Fatal,
                    AlertDescription::IllegalParameter,
                ));
            }
            if let ClientHelloExtension::PreSharedKey(psk) = &extensions[idx] {
                // PskBinderEntries section wire size: u16 list-length prefix +
                // sum over entries of (u8 length-prefix + binder bytes).
                let mut wire_len: usize = 2;
                for binder in &psk.binders {
                    wire_len += 1 + binder.len();
                }
                if wire_len > total_message_length {
                    return Err(TlsError::InvalidHandshake);
                }
                binders_start_offset = total_message_length - wire_len;
            }
        }

        Ok(Self {
            legacy_version,
            random,
            legacy_session_id,
            cipher_suites,
            legacy_compression_methods,
            extensions,
            binders_start_offset,
        })
    }
}

#[cfg(test)]
mod ref_tests {
    use super::*;
    use crate::extensions::extension_data::psk_key_exchange_modes::PskKeyExchangeMode;

    /// Strip whitespace and decode hex into a byte vector.
    fn unhex(s: &str) -> std::vec::Vec<u8> {
        let cleaned: std::string::String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..cleaned.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&cleaned[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8448 §4 (Resumed 0-RTT) ClientHello — full 512-byte handshake message
    /// (4-byte header + 508-byte body), captured verbatim from the trace
    /// (rfc8448.txt lines 972..996, "send handshake record" payload).
    /// Loaded from a sidecar hex file so we don't risk transcription errors.
    const RFC8448_CLIENT_HELLO_HEX: &str =
        include_str!("test_data/rfc8448_client_hello.hex");

    #[test]
    fn parse_rfc8448_client_hello() {
        let _ = env_logger::builder().is_test(true).try_init();
        let bytes = unhex(RFC8448_CLIENT_HELLO_HEX);
        assert_eq!(bytes.len(), 512, "RFC 8448 §4 ClientHello is 512 bytes");

        let mut buf = ParseBuffer::new(&bytes);
        let hello: ClientHelloRef<'_, 16> =
            ClientHelloRef::parse(&mut buf).expect("ClientHello parse failed");

        // Header / body invariants
        assert_eq!(hello.legacy_version, 0x0303);
        assert_eq!(
            &hello.random[..],
            &unhex("1bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7b4bc419d7876487d95")[..],
        );
        assert_eq!(hello.legacy_session_id, &[] as &[u8]);
        // cipher_suites contains 3: 1301, 1303, 1302 (TLS_AES_128_GCM_SHA256 first).
        assert_eq!(hello.cipher_suites, &[0x13, 0x01, 0x13, 0x03, 0x13, 0x02]);
        assert_eq!(hello.legacy_compression_methods, &[0u8]);

        // Critical for binder verify: byte 477 is the start of the binders section.
        // (RFC 8448 §4 explicitly labels the 477-byte prefix; the trailing 35 bytes
        // form the binders list = 2 + 1 + 32.)
        assert_eq!(hello.binders_start_offset, 477);

        // ── Extensions: confirm structure expected by server-mode ─────────────
        let mut saw_supported_versions = false;
        let mut saw_psk_modes = false;
        let mut saw_pre_shared_key = false;
        let mut psk_identity_len = 0usize;
        let mut binder_bytes: &[u8] = &[];

        for ext in &hello.extensions {
            match ext {
                ClientHelloExtension::SupportedVersions(_) => saw_supported_versions = true,
                ClientHelloExtension::PskKeyExchangeModes(modes) => {
                    saw_psk_modes = true;
                    // RFC 8448 §4 advertises psk_dhe_ke (0x01).
                    assert!(modes.modes.contains(&PskKeyExchangeMode::PskDheKe));
                }
                ClientHelloExtension::PreSharedKey(psk) => {
                    saw_pre_shared_key = true;
                    assert_eq!(psk.identities.len(), 1);
                    assert_eq!(psk.binders.len(), 1);
                    psk_identity_len = psk.identities[0].len();
                    binder_bytes = psk.binders[0];
                }
                _ => {}
            }
        }
        assert!(saw_supported_versions);
        assert!(saw_psk_modes);
        assert!(saw_pre_shared_key);
        // RFC 8448 §4 trace: identity is the 178-byte resumption ticket.
        assert_eq!(psk_identity_len, 178);
        // Expected binder published in RFC 8448 §4 (line 967-968 of rfc8448.txt).
        assert_eq!(
            binder_bytes,
            &unhex("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d")[..],
        );
    }
}
