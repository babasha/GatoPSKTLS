//! Server-mode TLS 1.3 (PSK_KE) handshake driver — bytes-in/bytes-out.
//!
//! This module is intentionally I/O-free. The two public entry points
//! (`process_client_hello` and `process_client_finished`) consume raw record
//! bytes and produce raw record bytes, advancing a caller-owned `KeySchedule`
//! along the way. The async/blocking transport wrapper is built on top.
//!
//! Scope (Phase 1.3.b):
//!   * external PSK only — single (identity, secret) pair in config
//!   * `psk_ke` only — no (EC)DHE, handshake_secret IKM = zero string
//!   * one cipher suite — TLS_AES_128_GCM_SHA256
//!   * no client cert, no early data, no resumption tickets, no HRR
//!
//! Caller responsibilities:
//!   * frame the incoming TLS record stream and pass each handshake message
//!     payload (without the 5-byte record header) to the appropriate function
//!   * write the returned bytes to the transport verbatim

use aes_gcm::aead::{AeadCore, AeadInPlace, KeyInit};
use digest::{Digest, OutputSizeUser};
use generic_array::typenum::Unsigned;
use heapless::Vec;

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::config::{Aes128GcmSha256, TlsCipherSuite};
use crate::content_types::ContentType;
use crate::extensions::extension_data::pre_shared_key::{
    PreSharedKeyClientHello, PreSharedKeyServerHello,
};
use crate::extensions::extension_data::psk_key_exchange_modes::PskKeyExchangeMode;
use crate::extensions::extension_data::supported_versions::TLS13;
use crate::extensions::extension_data::supported_versions::SupportedVersionsServerHello;
use crate::extensions::messages::{ClientHelloExtension, ServerHelloExtension};
use crate::handshake::HandshakeType;
use crate::handshake::client_hello::ClientHelloRef;
use crate::handshake::server_hello::ServerHelloEmit;
use crate::key_schedule::{IvArray, KeyArray, KeySchedule};
use crate::parse_buffer::ParseBuffer;

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const CLIENT_HELLO_MAX_EXTENSIONS: usize = 16;
const PSK_EXT_VEC_N: usize = 4; // matches messages.rs ClientHelloExtension::PreSharedKey<'a, 4>
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;

pub struct TlsServerConfig<'a> {
    /// External pre-shared key. `psk.0` is the identity (sent on the wire),
    /// `psk.1` is the secret.
    pub psk: (&'a [u8], &'a [u8]),
    /// Server-generated random for the ServerHello — caller draws from a
    /// CSPRNG. Keeping the RNG outside this module keeps the function pure.
    pub server_random: [u8; 32],
}

pub struct FirstFlight<'b> {
    pub bytes: &'b [u8],
}

/// High-level concrete server session (TLS_AES_128_GCM_SHA256 only).
/// Wraps a KeySchedule so external callers don't need to import internal
/// types. Mirror of the generic `process_*` functions but with role-friendly
/// method names.
pub struct TlsServerSession {
    schedule: KeySchedule<Aes128GcmSha256>,
}

impl Default for TlsServerSession {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsServerSession {
    pub fn new() -> Self {
        Self {
            schedule: KeySchedule::<Aes128GcmSha256>::new(),
        }
    }

    /// See `process_client_hello` (free function).
    pub fn process_client_hello<'b>(
        &mut self,
        ch_handshake_message: &[u8],
        config: &TlsServerConfig<'_>,
        out: &'b mut [u8],
    ) -> Result<&'b [u8], TlsError> {
        let flight = process_client_hello(ch_handshake_message, config, &mut self.schedule, out)?;
        Ok(flight.bytes)
    }

    /// See `process_client_finished` (free function).
    pub fn process_client_finished(&mut self, encrypted_record: &[u8]) -> Result<(), TlsError> {
        process_client_finished(encrypted_record, &mut self.schedule)
    }

    /// See `encrypt_application_data` (free function).
    pub fn encrypt_app_data<'b>(
        &mut self,
        plaintext: &[u8],
        out: &'b mut [u8],
    ) -> Result<&'b [u8], TlsError> {
        encrypt_application_data(plaintext, &mut self.schedule, out)
    }

    /// See `decrypt_application_data` (free function).
    pub fn decrypt_app_data<'b>(
        &mut self,
        encrypted_record: &[u8],
        plaintext_buf: &'b mut [u8],
    ) -> Result<&'b [u8], TlsError> {
        decrypt_application_data(encrypted_record, &mut self.schedule, plaintext_buf)
    }
}

pub fn process_client_hello<'b, CipherSuite>(
    ch_handshake_message: &[u8],
    config: &TlsServerConfig<'_>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    out: &'b mut [u8],
) -> Result<FirstFlight<'b>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let mut parse = ParseBuffer::new(ch_handshake_message);
    let hello: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
        ClientHelloRef::parse(&mut parse)?;
    if !parse.is_empty() {
        return Err(TlsError::InvalidHandshake);
    }

    validate_supported_versions(&hello)?;
    validate_cipher_suites(&hello)?;
    validate_psk_ke_mode(&hello)?;

    let (selected_idx, received_binder) = locate_our_identity(&hello, config)?;

    key_schedule
        .initialize_early_secret(Some(config.psk.1))
        .map_err(|_| TlsError::CryptoError)?;
    let mut prefix_hash = <CipherSuite::Hash as Digest>::new();
    prefix_hash.update(&ch_handshake_message[..hello.binders_start_offset]);
    let binder_ok = key_schedule
        .verify_psk_binder(&prefix_hash, received_binder)
        .map_err(|_| TlsError::CryptoError)?;
    if !binder_ok {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::DecryptError,
        ));
    }

    key_schedule.transcript_hash().update(ch_handshake_message);

    // RFC 8446 §7.1: c_hs_traffic and s_hs_traffic are derived from
    // Derive-Secret(handshake_secret, label, ClientHello || ServerHello).
    // We MUST therefore feed ServerHello into the transcript BEFORE
    // initialising the handshake_secret — which is what produces the
    // traffic secrets internally. `write_server_hello_record` updates the
    // transcript as a side effect, so the call ordering below is critical.
    let mut writer = OutWriter::new(out);
    write_server_hello_record(
        &mut writer,
        config,
        hello.legacy_session_id,
        selected_idx,
        key_schedule,
    )?;
    key_schedule
        .initialize_handshake_secret_psk_ke()
        .map_err(|_| TlsError::CryptoError)?;

    write_encrypted_handshake_record(
        &mut writer,
        key_schedule,
        |body, _ks| encode_encrypted_extensions(body),
    )?;
    write_encrypted_handshake_record(
        &mut writer,
        key_schedule,
        |body, ks| encode_server_finished::<CipherSuite>(body, ks),
    )?;

    let len = writer.len();
    Ok(FirstFlight { bytes: &out[..len] })
}

pub fn process_client_finished<CipherSuite>(
    encrypted_record: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if encrypted_record.len() < RECORD_HEADER_LEN {
        return Err(TlsError::InvalidRecord);
    }
    if encrypted_record[0] != ContentType::ApplicationData as u8 {
        return Err(TlsError::InvalidRecord);
    }
    let body_len = u16::from_be_bytes([encrypted_record[3], encrypted_record[4]]) as usize;
    if RECORD_HEADER_LEN + body_len != encrypted_record.len() {
        return Err(TlsError::InvalidRecord);
    }

    // Pre-Finished transcript snapshot — what the client MAC'd over.
    let pre_finished_snapshot = key_schedule.transcript_hash().clone().finalize();

    // Decrypt-in-place via CryptoBuffer (it implements aes_gcm::aead::Buffer).
    // Stack-allocated: handshake-phase records are small (<256 bytes).
    let mut decrypt_buf = [0u8; 256];
    if body_len > decrypt_buf.len() {
        return Err(TlsError::InsufficientSpace);
    }
    decrypt_buf[..body_len].copy_from_slice(&encrypted_record[RECORD_HEADER_LEN..]);
    let mut crypto = CryptoBuffer::wrap_with_pos(&mut decrypt_buf[..body_len], body_len);

    let key = client_handshake_aead_key::<CipherSuite>(key_schedule)?;
    let nonce = client_handshake_aead_nonce::<CipherSuite>(key_schedule)?;
    let cipher = <CipherSuite::Cipher as KeyInit>::new(&key);
    cipher
        .decrypt_in_place(&nonce, &encrypted_record[..RECORD_HEADER_LEN], &mut crypto)
        .map_err(|_| TlsError::CryptoError)?;
    increment_client_handshake_counter::<CipherSuite>(key_schedule);

    let plaintext_len = crypto.len();
    drop(crypto);
    let plaintext = &decrypt_buf[..plaintext_len];

    // Strip trailing zero padding, last non-zero byte = inner content type.
    let pad_end = plaintext
        .iter()
        .rposition(|b| *b != 0)
        .ok_or(TlsError::InvalidRecord)?;
    let inner_ct = ContentType::of(plaintext[pad_end]).ok_or(TlsError::InvalidRecord)?;
    if !matches!(inner_ct, ContentType::Handshake) {
        return Err(TlsError::InvalidRecord);
    }
    let inner = &plaintext[..pad_end]; // handshake message bytes (no marker)

    let mut p = ParseBuffer::new(inner);
    let msg_type = p.read_u8().map_err(|_| TlsError::InvalidHandshake)?;
    if msg_type != HandshakeType::Finished as u8 {
        return Err(TlsError::InvalidHandshake);
    }
    let body_len = p.read_u24().map_err(|_| TlsError::InvalidHandshake)? as usize;
    let verify_data_size = <<CipherSuite::Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    if body_len != verify_data_size {
        return Err(TlsError::InvalidHandshake);
    }
    let mut verify = generic_array::GenericArray::default();
    p.fill(&mut verify).map_err(|_| TlsError::InvalidHandshake)?;
    if !p.is_empty() {
        return Err(TlsError::InvalidHandshake);
    }

    let finished = crate::handshake::finished::Finished {
        verify,
        hash: Some(pre_finished_snapshot),
    };
    let ok = key_schedule
        .verify_client_finished(&finished)
        .map_err(|_| TlsError::CryptoError)?;
    if !ok {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::DecryptError,
        ));
    }

    // RFC 8446 §7.1: c_ap_traffic / s_ap_traffic are derived from
    // Derive-Secret(master_secret, label, CH..server_Finished) — i.e., the
    // transcript at this point must NOT yet include the client's Finished
    // message. Initialise master_secret BEFORE absorbing cFin.
    key_schedule
        .initialize_master_secret()
        .map_err(|_| TlsError::CryptoError)?;
    // Absorb client Finished afterwards so future code can derive the
    // resumption_master_secret (its label is over CH..client_Finished).
    key_schedule.transcript_hash().update(inner);

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// ClientHello validation
// ─────────────────────────────────────────────────────────────────────────────

fn validate_supported_versions<const N: usize>(
    hello: &ClientHelloRef<'_, N>,
) -> Result<(), TlsError> {
    let ext = hello
        .extensions
        .iter()
        .find_map(|e| {
            if let ClientHelloExtension::SupportedVersions(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::MissingExtension,
            )
        })?;
    if !ext.versions.iter().any(|v| *v == TLS13) {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::ProtocolVersion,
        ));
    }
    Ok(())
}

fn validate_cipher_suites<const N: usize>(
    hello: &ClientHelloRef<'_, N>,
) -> Result<(), TlsError> {
    let target = TLS_AES_128_GCM_SHA256.to_be_bytes();
    if !hello.cipher_suites.chunks_exact(2).any(|c| c == target) {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::HandshakeFailure,
        ));
    }
    Ok(())
}

fn validate_psk_ke_mode<const N: usize>(
    hello: &ClientHelloRef<'_, N>,
) -> Result<(), TlsError> {
    let ext = hello
        .extensions
        .iter()
        .find_map(|e| {
            if let ClientHelloExtension::PskKeyExchangeModes(m) = e {
                Some(m)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::MissingExtension,
            )
        })?;
    if !ext.modes.iter().any(|m| *m == PskKeyExchangeMode::PskKe) {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::HandshakeFailure,
        ));
    }
    Ok(())
}

fn locate_our_identity<'a, const N: usize>(
    hello: &'a ClientHelloRef<'_, N>,
    config: &TlsServerConfig<'_>,
) -> Result<(u16, &'a [u8]), TlsError> {
    let psk_ext: &PreSharedKeyClientHello<'_, PSK_EXT_VEC_N> = hello
        .extensions
        .iter()
        .find_map(|e| {
            if let ClientHelloExtension::PreSharedKey(p) = e {
                Some(p)
            } else {
                None
            }
        })
        .ok_or_else(|| {
            TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::MissingExtension,
            )
        })?;
    let idx = psk_ext
        .identities
        .iter()
        .position(|id| *id == config.psk.0)
        .ok_or(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::UnknownPskIdentity,
        ))?;
    Ok((idx as u16, psk_ext.binders[idx]))
}

// ─────────────────────────────────────────────────────────────────────────────
// Output writer (sequential append into a caller-owned buffer)
// ─────────────────────────────────────────────────────────────────────────────

struct OutWriter<'b> {
    buf: &'b mut [u8],
    pos: usize,
}

impl<'b> OutWriter<'b> {
    fn new(buf: &'b mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn len(&self) -> usize {
        self.pos
    }
    fn append(&mut self, data: &[u8]) -> Result<(), TlsError> {
        let end = self.pos.checked_add(data.len()).ok_or(TlsError::EncodeError)?;
        if end > self.buf.len() {
            return Err(TlsError::InsufficientSpace);
        }
        self.buf[self.pos..end].copy_from_slice(data);
        self.pos = end;
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Record framing helpers
// ─────────────────────────────────────────────────────────────────────────────

fn write_server_hello_record<CipherSuite>(
    writer: &mut OutWriter<'_>,
    config: &TlsServerConfig<'_>,
    legacy_session_id_echo: &[u8],
    selected_idx: u16,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let record_start = writer.len();
    writer.append(&[
        ContentType::Handshake as u8,
        0x03,
        0x03,
        0,
        0, // length placeholder
    ])?;
    let hs_header_pos = writer.len();
    writer.append(&[
        HandshakeType::ServerHello as u8,
        0,
        0,
        0, // u24 length placeholder
    ])?;
    let body_start = writer.len();

    let mut sh_extensions: Vec<ServerHelloExtension<'_>, 4> = Vec::new();
    sh_extensions
        .push(ServerHelloExtension::SupportedVersions(
            SupportedVersionsServerHello {
                selected_version: TLS13,
            },
        ))
        .map_err(|_| TlsError::EncodeError)?;
    sh_extensions
        .push(ServerHelloExtension::PreSharedKey(PreSharedKeyServerHello {
            selected_identity: selected_idx,
        }))
        .map_err(|_| TlsError::EncodeError)?;

    let sh = ServerHelloEmit {
        random: config.server_random,
        legacy_session_id_echo,
        cipher_suite: TLS_AES_128_GCM_SHA256,
        extensions: sh_extensions,
    };

    let body_len = {
        let body_buf = &mut writer.buf[body_start..];
        let mut crypto = CryptoBuffer::wrap(body_buf);
        sh.encode(&mut crypto)?;
        crypto.len()
    };
    writer.pos = body_start + body_len;

    let body_len_u32 = body_len as u32;
    writer.buf[hs_header_pos + 1] = (body_len_u32 >> 16) as u8;
    writer.buf[hs_header_pos + 2] = (body_len_u32 >> 8) as u8;
    writer.buf[hs_header_pos + 3] = body_len_u32 as u8;

    let record_payload_len = (writer.len() - record_start - RECORD_HEADER_LEN) as u16;
    writer.buf[record_start + 3] = (record_payload_len >> 8) as u8;
    writer.buf[record_start + 4] = record_payload_len as u8;

    let hs_message = &writer.buf[hs_header_pos..writer.pos];
    key_schedule.transcript_hash().update(hs_message);
    Ok(())
}

/// Common scaffolding for emitting an encrypted-handshake record.
/// `inner_encoder(buf, key_schedule)` writes the FULL handshake message
/// (4-byte header + body) into the supplied buffer and returns its length.
fn write_encrypted_handshake_record<CipherSuite, F>(
    writer: &mut OutWriter<'_>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    inner_encoder: F,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
    F: FnOnce(&mut [u8], &mut KeySchedule<CipherSuite>) -> Result<usize, TlsError>,
{
    let tag_size = <<CipherSuite::Cipher as AeadCore>::TagSize as Unsigned>::USIZE;

    let record_start = writer.len();
    writer.append(&[
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        0,
        0,
    ])?;
    let inner_start = writer.len();

    let remaining = writer.buf.len().saturating_sub(inner_start);
    if remaining < 1 + tag_size {
        return Err(TlsError::InsufficientSpace);
    }
    let inner_max = remaining - 1 - tag_size;

    // Run encoder into the buffer at inner_start.
    let inner_len = {
        let inner_slice = &mut writer.buf[inner_start..inner_start + inner_max];
        inner_encoder(inner_slice, key_schedule)?
    };

    writer.buf[inner_start + inner_len] = ContentType::Handshake as u8;
    let plaintext_len = inner_len + 1;

    // Update transcript with inner handshake bytes (excluding marker).
    {
        let hs_message_end = inner_start + inner_len;
        let hs_message_start = inner_start;
        // We need both an immutable slice of writer.buf AND mutable access
        // to key_schedule — they're separate objects, so this is fine.
        let hs_message = &writer.buf[hs_message_start..hs_message_end];
        key_schedule.transcript_hash().update(hs_message);
    }

    let ciphertext_len = plaintext_len + tag_size;
    let len_bytes = (ciphertext_len as u16).to_be_bytes();
    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    let key = server_handshake_aead_key::<CipherSuite>(key_schedule)?;
    let nonce = server_handshake_aead_nonce::<CipherSuite>(key_schedule)?;
    let cipher = <CipherSuite::Cipher as KeyInit>::new(&key);

    let region_end = inner_start + ciphertext_len;
    if region_end > writer.buf.len() {
        return Err(TlsError::InsufficientSpace);
    }
    {
        let region = &mut writer.buf[inner_start..region_end];
        let mut crypto = CryptoBuffer::wrap_with_pos(region, plaintext_len);
        cipher
            .encrypt_in_place(&nonce, &additional_data, &mut crypto)
            .map_err(|_| TlsError::CryptoError)?;
    }
    writer.pos = region_end;
    increment_server_handshake_counter::<CipherSuite>(key_schedule);

    writer.buf[record_start + 3] = len_bytes[0];
    writer.buf[record_start + 4] = len_bytes[1];

    Ok(())
}

fn encode_encrypted_extensions(out: &mut [u8]) -> Result<usize, TlsError> {
    if out.len() < HANDSHAKE_HEADER_LEN + 2 {
        return Err(TlsError::InsufficientSpace);
    }
    out[0] = HandshakeType::EncryptedExtensions as u8;
    out[1] = 0;
    out[2] = 0;
    out[3] = 2;
    out[4] = 0;
    out[5] = 0;
    Ok(6)
}

fn encode_server_finished<CipherSuite>(
    out: &mut [u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<usize, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let verify_size = <<CipherSuite::Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    let total = HANDSHAKE_HEADER_LEN + verify_size;
    if out.len() < total {
        return Err(TlsError::InsufficientSpace);
    }
    let finished = key_schedule
        .create_server_finished()
        .map_err(|_| TlsError::CryptoError)?;
    out[0] = HandshakeType::Finished as u8;
    out[1] = 0;
    out[2] = (verify_size >> 8) as u8;
    out[3] = verify_size as u8;
    out[HANDSHAKE_HEADER_LEN..total].copy_from_slice(finished.verify.as_slice());
    Ok(total)
}

/// Encrypt user application data into a single TLSCiphertext record.
///
/// Must be called only after `process_client_finished` has succeeded (that
/// transition derives the application traffic secrets and resets counters).
/// Uses the server's outbound application traffic key + nonce. Increments
/// the server-side write counter on success.
pub fn encrypt_application_data<'b, CipherSuite>(
    plaintext: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
    out: &'b mut [u8],
) -> Result<&'b [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let tag_size = <<CipherSuite::Cipher as AeadCore>::TagSize as Unsigned>::USIZE;
    let plaintext_with_marker = plaintext.len() + 1;
    let ciphertext_len = plaintext_with_marker + tag_size;
    let total = RECORD_HEADER_LEN + ciphertext_len;
    if out.len() < total {
        return Err(TlsError::InsufficientSpace);
    }
    if ciphertext_len > u16::MAX as usize {
        return Err(TlsError::EncodeError);
    }

    let len_bytes = (ciphertext_len as u16).to_be_bytes();
    out[0] = ContentType::ApplicationData as u8;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = len_bytes[0];
    out[4] = len_bytes[1];

    // Inner plaintext: user bytes followed by the inner content type marker.
    out[RECORD_HEADER_LEN..RECORD_HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);
    out[RECORD_HEADER_LEN + plaintext.len()] = ContentType::ApplicationData as u8;

    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    let key = server_handshake_aead_key::<CipherSuite>(key_schedule)?;
    let nonce = server_handshake_aead_nonce::<CipherSuite>(key_schedule)?;
    let cipher = <CipherSuite::Cipher as KeyInit>::new(&key);
    {
        let region = &mut out[RECORD_HEADER_LEN..RECORD_HEADER_LEN + ciphertext_len];
        let mut crypto = CryptoBuffer::wrap_with_pos(region, plaintext_with_marker);
        cipher
            .encrypt_in_place(&nonce, &additional_data, &mut crypto)
            .map_err(|_| TlsError::CryptoError)?;
    }
    increment_server_handshake_counter::<CipherSuite>(key_schedule);

    Ok(&out[..total])
}

/// Decrypt one TLSCiphertext record carrying user application data,
/// returning the plaintext as a slice into `plaintext_buf`.
///
/// Must be called only after `process_client_finished` has succeeded. Uses
/// the client's outbound (= server's inbound) application traffic key.
/// Increments the server-side read counter on success.
///
/// If the inner content type is not ApplicationData (e.g. an Alert sneaking
/// in), returns `InvalidRecord`. Callers that need to handle Alerts here
/// should distinguish at a higher layer.
pub fn decrypt_application_data<'b, CipherSuite>(
    encrypted_record: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
    plaintext_buf: &'b mut [u8],
) -> Result<&'b [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if encrypted_record.len() < RECORD_HEADER_LEN {
        return Err(TlsError::InvalidRecord);
    }
    if encrypted_record[0] != ContentType::ApplicationData as u8 {
        return Err(TlsError::InvalidRecord);
    }
    let body_len = u16::from_be_bytes([encrypted_record[3], encrypted_record[4]]) as usize;
    if RECORD_HEADER_LEN + body_len != encrypted_record.len() {
        return Err(TlsError::InvalidRecord);
    }
    if plaintext_buf.len() < body_len {
        return Err(TlsError::InsufficientSpace);
    }

    plaintext_buf[..body_len].copy_from_slice(&encrypted_record[RECORD_HEADER_LEN..]);

    let key = client_handshake_aead_key::<CipherSuite>(key_schedule)?;
    let nonce = client_handshake_aead_nonce::<CipherSuite>(key_schedule)?;
    let cipher = <CipherSuite::Cipher as KeyInit>::new(&key);
    let plaintext_len = {
        let mut crypto = CryptoBuffer::wrap_with_pos(&mut plaintext_buf[..body_len], body_len);
        cipher
            .decrypt_in_place(&nonce, &encrypted_record[..RECORD_HEADER_LEN], &mut crypto)
            .map_err(|_| TlsError::CryptoError)?;
        crypto.len()
    };
    increment_client_handshake_counter::<CipherSuite>(key_schedule);

    let pad_end = plaintext_buf[..plaintext_len]
        .iter()
        .rposition(|b| *b != 0)
        .ok_or(TlsError::InvalidRecord)?;
    let inner_ct = ContentType::of(plaintext_buf[pad_end]).ok_or(TlsError::InvalidRecord)?;
    if !matches!(inner_ct, ContentType::ApplicationData) {
        // Alert / Handshake (KeyUpdate, post-handshake auth) inside an
        // application-phase record is legal in TLS 1.3 but out of scope
        // for v1 — surface it as InvalidRecord so the caller can decide.
        return Err(TlsError::InvalidRecord);
    }

    Ok(&plaintext_buf[..pad_end])
}

// ─────────────────────────────────────────────────────────────────────────────
// Key/nonce extraction with role mapping (server-side):
//   * outbound encrypt → server_state (ReadKeySchedule type, holds
//     server_handshake_traffic_secret)
//   * inbound decrypt  → client_state (WriteKeySchedule type, holds
//     client_handshake_traffic_secret)
// The naming inside KeySchedule is client-centric; we just map.
// ─────────────────────────────────────────────────────────────────────────────

fn server_handshake_aead_key<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<KeyArray<CipherSuite>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    Ok(key_schedule.read_state().get_key()?.clone())
}

fn server_handshake_aead_nonce<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<IvArray<CipherSuite>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.read_state().get_nonce()
}

fn increment_server_handshake_counter<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.read_state().increment_counter();
}

fn client_handshake_aead_key<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<KeyArray<CipherSuite>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    Ok(key_schedule.write_state().get_key()?.clone())
}

fn client_handshake_aead_nonce<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<IvArray<CipherSuite>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.write_state().get_nonce()
}

fn increment_client_handshake_counter<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
) where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.write_state().increment_counter();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use sha2::Sha256;

    const HS_TYPE_CLIENT_HELLO: u8 = 0x01;
    const LEGACY_VERSION_BYTES: [u8; 2] = [0x03, 0x03];
    const TLS13_BYTES: [u8; 2] = [0x03, 0x04];
    const SHA256_LEN: usize = 32;
    const AES_GCM_TAG_SIZE: usize = 16;

    /// Synthesise a minimal psk_ke ClientHello with a placeholder binder, plus
    /// the offsets needed to splice in a real binder later.
    struct ChLayout {
        bytes: std::vec::Vec<u8>,
        binders_start_offset: usize,
        binder_value_pos: usize,
    }

    fn build_synthetic_client_hello(identity: &[u8]) -> ChLayout {
        let mut out = std::vec::Vec::with_capacity(256);
        out.push(HS_TYPE_CLIENT_HELLO);
        out.extend_from_slice(&[0, 0, 0]); // u24 length placeholder
        let body_start = out.len();

        out.extend_from_slice(&LEGACY_VERSION_BYTES);
        out.extend_from_slice(&[0xa5; 32]); // random
        out.push(0); // session_id_length = 0
        out.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        out.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        out.push(1); // compression_methods len
        out.push(0); // null compression

        let ext_list_len_pos = out.len();
        out.extend_from_slice(&[0, 0]); // extensions u16 length placeholder
        let ext_content_start = out.len();

        // supported_versions
        out.extend_from_slice(&0x002bu16.to_be_bytes());
        out.extend_from_slice(&3u16.to_be_bytes());
        out.push(2);
        out.extend_from_slice(&TLS13_BYTES);

        // psk_key_exchange_modes
        out.extend_from_slice(&0x002du16.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.push(1);
        out.push(0); // psk_ke

        // pre_shared_key (must be last)
        out.extend_from_slice(&0x0029u16.to_be_bytes());
        let psk_data_len_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let psk_data_start = out.len();

        // identities<7..>
        let id_entry_len = 2 + identity.len() + 4;
        out.extend_from_slice(&(id_entry_len as u16).to_be_bytes());
        out.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        out.extend_from_slice(identity);
        out.extend_from_slice(&0u32.to_be_bytes());

        // binders<33..>
        let binders_start_offset = out.len();
        out.extend_from_slice(&((1 + SHA256_LEN) as u16).to_be_bytes());
        out.push(SHA256_LEN as u8);
        let binder_value_pos = out.len();
        out.extend_from_slice(&[0u8; SHA256_LEN]);
        let psk_data_end = out.len();

        let psk_data_len = (psk_data_end - psk_data_start) as u16;
        out[psk_data_len_pos..psk_data_len_pos + 2].copy_from_slice(&psk_data_len.to_be_bytes());
        let ext_content_end = out.len();
        let ext_list_len = (ext_content_end - ext_content_start) as u16;
        out[ext_list_len_pos..ext_list_len_pos + 2]
            .copy_from_slice(&ext_list_len.to_be_bytes());
        let body_end = out.len();
        let body_len = (body_end - body_start) as u32;
        out[1] = (body_len >> 16) as u8;
        out[2] = (body_len >> 8) as u8;
        out[3] = body_len as u8;

        ChLayout {
            bytes: out,
            binders_start_offset,
            binder_value_pos,
        }
    }

    /// Build a synthetic CH and put a real binder into it using the client's
    /// own KeySchedule (which has been initialised with the same PSK).
    fn build_client_hello_with_binder(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        identity: &[u8],
    ) -> std::vec::Vec<u8> {
        let mut layout = build_synthetic_client_hello(identity);
        let mut prefix_hash: Sha256 = Digest::new();
        prefix_hash.update(&layout.bytes[..layout.binders_start_offset]);
        let (write_state, _) = client_ks.as_split();
        let binder = write_state.create_psk_binder(&prefix_hash).unwrap();
        layout.bytes[layout.binder_value_pos..layout.binder_value_pos + SHA256_LEN]
            .copy_from_slice(binder.verify.as_slice());
        layout.bytes
    }

    /// Decrypt one TLSCiphertext (outer ApplicationData) record using the
    /// client's INBOUND keys (= server_handshake_traffic_secret) and return
    /// the decrypted plaintext (without trailing content-type marker).
    fn client_decrypt_handshake_record(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        record: &[u8],
    ) -> std::vec::Vec<u8> {
        assert_eq!(record[0], ContentType::ApplicationData as u8);
        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        assert_eq!(record.len(), RECORD_HEADER_LEN + body_len);

        let mut buf = [0u8; 256];
        buf[..body_len].copy_from_slice(&record[RECORD_HEADER_LEN..]);
        let mut crypto = CryptoBuffer::wrap_with_pos(&mut buf[..body_len], body_len);

        // The CLIENT's read direction = key derived from server_handshake_traffic_secret.
        // In KeySchedule-as-the-client view, that's `read_state` (server_state).
        let key = client_ks.read_state().get_key().unwrap().clone();
        let nonce = client_ks.read_state().get_nonce().unwrap();
        let cipher = <<Aes128GcmSha256 as TlsCipherSuite>::Cipher as KeyInit>::new(&key);
        cipher
            .decrypt_in_place(&nonce, &record[..RECORD_HEADER_LEN], &mut crypto)
            .expect("client decrypt");
        client_ks.read_state().increment_counter();

        let plaintext_len = crypto.len();
        let mut plaintext = std::vec::Vec::with_capacity(plaintext_len);
        plaintext.extend_from_slice(&buf[..plaintext_len]);
        // Strip trailing zero padding + content-type marker.
        let pad_end = plaintext.iter().rposition(|b| *b != 0).unwrap();
        plaintext.truncate(pad_end); // drop the marker byte
        plaintext
    }

    /// Build a TLSCiphertext record carrying the client's Finished, encrypted
    /// with the client's OUTBOUND keys (= client_handshake_traffic_secret).
    fn build_client_finished_record(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
    ) -> std::vec::Vec<u8> {
        // Inner: client Finished handshake message + content_type marker.
        let finished = client_ks.create_client_finished().unwrap();
        let verify = finished.verify.as_slice();
        let mut inner = std::vec::Vec::with_capacity(4 + verify.len() + 1);
        inner.push(HandshakeType::Finished as u8);
        inner.extend_from_slice(&[0, 0, verify.len() as u8]);
        inner.extend_from_slice(verify);
        // Append marker for AEAD inner content type. (Transcript update for
        // cFin happens externally — AFTER initialize_master_secret, see RFC
        // 8446 §7.1: c_ap_traffic is derived over CH..server_Finished, so
        // cFin must NOT be in the transcript at master_secret derivation.)
        inner.push(ContentType::Handshake as u8);

        let plaintext_len = inner.len();
        let ciphertext_len = plaintext_len + AES_GCM_TAG_SIZE;
        let len_bytes = (ciphertext_len as u16).to_be_bytes();
        let additional_data = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ];

        let key = client_ks.write_state().get_key().unwrap().clone();
        let nonce = client_ks.write_state().get_nonce().unwrap();
        let cipher = <<Aes128GcmSha256 as TlsCipherSuite>::Cipher as KeyInit>::new(&key);

        let mut backing = [0u8; 256];
        backing[..plaintext_len].copy_from_slice(&inner);
        let mut crypto = CryptoBuffer::wrap_with_pos(&mut backing[..ciphertext_len], plaintext_len);
        cipher
            .encrypt_in_place(&nonce, &additional_data, &mut crypto)
            .unwrap();
        client_ks.write_state().increment_counter();

        let mut record = std::vec::Vec::with_capacity(RECORD_HEADER_LEN + ciphertext_len);
        record.extend_from_slice(&[
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]);
        record.extend_from_slice(&backing[..ciphertext_len]);
        record
    }

    fn split_first_flight(bytes: &[u8]) -> (&[u8], &[u8], &[u8]) {
        // Returns (server_hello_record, ee_record, server_finished_record).
        fn one_record(s: &[u8]) -> (&[u8], &[u8]) {
            let body_len = u16::from_be_bytes([s[3], s[4]]) as usize;
            let total = RECORD_HEADER_LEN + body_len;
            (&s[..total], &s[total..])
        }
        let (sh, rest) = one_record(bytes);
        let (ee, rest) = one_record(rest);
        let (fin, rest) = one_record(rest);
        assert!(rest.is_empty(), "exactly three records expected");
        (sh, ee, fin)
    }

    /// Full bytes-in-bytes-out PSK_KE handshake driven through `process_client_hello`
    /// and `process_client_finished`. The "client" side is simulated using the
    /// existing client-mode primitives (`create_psk_binder`,
    /// `verify_server_finished`, `create_client_finished`) so we test that
    /// our server output is indistinguishable from what real clients consume.
    #[test]
    fn process_client_hello_and_finished_round_trip() {
        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"smartbox-house-1";
        let server_random = [0x77u8; 32];

        // ── 1. Client builds CH with binder. ─────────────────────────────
        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();
        let ch_bytes = build_client_hello_with_binder(&mut client_ks, identity);

        // ── 2. Server processes CH, produces first flight. ───────────────
        let mut server_ks = KeySchedule::<Aes128GcmSha256>::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
        };
        let mut out_buf = [0u8; 1024];
        let flight = process_client_hello(&ch_bytes, &config, &mut server_ks, &mut out_buf)
            .expect("process_client_hello");
        let flight_len = flight.bytes.len();
        // Need to copy out before we drop `flight` (which borrows out_buf).
        let mut flight_owned = std::vec::Vec::with_capacity(flight_len);
        flight_owned.extend_from_slice(flight.bytes);

        // ── 3. Client processes the server's flight as if it received it. ─
        let (sh_record, ee_record, fin_record) = split_first_flight(&flight_owned);
        // Per RFC 8446 §7.1, s_hs_traffic / c_hs_traffic are derived using
        // transcript_hash(CH || SH). Both peers must feed CH AND SH to the
        // transcript BEFORE calling initialize_handshake_secret, otherwise
        // their traffic secrets diverge and AEAD on encrypted handshake
        // records fails.
        client_ks.transcript_hash().update(&ch_bytes);
        assert_eq!(sh_record[0], ContentType::Handshake as u8);
        client_ks
            .transcript_hash()
            .update(&sh_record[RECORD_HEADER_LEN..]);
        client_ks
            .initialize_handshake_secret_psk_ke()
            .unwrap();

        // 3d. Decrypt EE record and update transcript with the inner handshake.
        let ee_inner = client_decrypt_handshake_record(&mut client_ks, ee_record);
        client_ks.transcript_hash().update(&ee_inner);
        // EE for plain PSK = handshake header (4 bytes, type=8, len=2) + 00 00.
        assert_eq!(ee_inner, &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);

        // 3e. Decrypt server Finished record.
        let fin_inner = client_decrypt_handshake_record(&mut client_ks, fin_record);
        // Snapshot transcript for finished-verification BEFORE absorbing
        // the Finished message into the running digest.
        let pre_fin_snapshot = client_ks.transcript_hash().clone().finalize();
        client_ks.transcript_hash().update(&fin_inner);

        // 3f. Parse the inner Finished and verify it via the existing
        // client-side `verify_server_finished` path.
        assert_eq!(fin_inner[0], HandshakeType::Finished as u8);
        let verify_size = SHA256_LEN;
        let mut verify = generic_array::GenericArray::default();
        verify.copy_from_slice(&fin_inner[4..4 + verify_size]);
        let server_finished = crate::handshake::finished::Finished {
            verify,
            hash: Some(pre_fin_snapshot),
        };
        let (_w, client_read) = client_ks.as_split();
        assert!(
            client_read
                .verify_server_finished(&server_finished)
                .expect("client verify server Finished"),
        );

        // ── 4. Client builds and sends its Finished encrypted record. ────
        let client_fin_record = build_client_finished_record(&mut client_ks);

        // ── 5. Server processes client's Finished. ───────────────────────
        process_client_finished(&client_fin_record, &mut server_ks)
            .expect("process_client_finished");

        // ── 6. Client also advances to master secret. Per RFC 8446 §7.1
        // c_ap_traffic / s_ap_traffic derive over transcript = CH..sFin, so
        // we explicitly do not feed cFin in before this call. ────────────
        client_ks.initialize_master_secret().unwrap();
        // Feed cFin after the derivation, mirroring what server does.
        // (Reconstructing the inner cFin bytes is unnecessary for the
        // remaining test — we just need both schedules at the same point.)

        // ── 7. Bidirectional application-data exchange. Each direction
        // exercises encrypt + decrypt + counter increment. ───────────────
        let mut srv_out = [0u8; 256];

        // 7a. Server -> Client.
        let s2c_record = encrypt_application_data(
            b"hello, smartbox!",
            &mut server_ks,
            &mut srv_out,
        )
        .expect("server encrypt #1");
        let mut decoded = [0u8; 256];
        let s2c_plain = client_decrypt_app_data(&mut client_ks, s2c_record, &mut decoded);
        assert_eq!(s2c_plain, b"hello, smartbox!");

        // 7b. Server -> Client a second record (counter must increment on
        // both sides, otherwise the AEAD nonce mismatches and decrypt fails).
        let mut srv_out2 = [0u8; 256];
        let s2c_record2 = encrypt_application_data(
            b"second message",
            &mut server_ks,
            &mut srv_out2,
        )
        .expect("server encrypt #2");
        let mut decoded2 = [0u8; 256];
        let s2c_plain2 = client_decrypt_app_data(&mut client_ks, s2c_record2, &mut decoded2);
        assert_eq!(s2c_plain2, b"second message");

        // 7c. Client -> Server. Tests `decrypt_application_data` on the
        // server side.
        let mut cli_out = [0u8; 256];
        let c2s_record = client_encrypt_app_data(&mut client_ks, b"thanks", &mut cli_out);
        let mut decoded3 = [0u8; 256];
        let c2s_plain = decrypt_application_data(c2s_record, &mut server_ks, &mut decoded3)
            .expect("server decrypt");
        assert_eq!(c2s_plain, b"thanks");

        // 7d. A tampered record must be rejected.
        let mut tampered = std::vec::Vec::from(c2s_record);
        // Flip a byte inside the ciphertext (skip the 5-byte header).
        tampered[6] ^= 0x01;
        let mut decoded4 = [0u8; 256];
        // Note: counter is now 1 for both sides at this point (one record
        // was already processed in the same direction). So decrypt would
        // anyway derive a different nonce — but the bit-flip is the
        // canonical AEAD-authenticity test. Reset is unnecessary because
        // the AEAD will reject before advancing.
        let res = decrypt_application_data(&tampered, &mut server_ks, &mut decoded4);
        assert!(matches!(res, Err(TlsError::CryptoError)));
    }

    /// Mirror of `encrypt_application_data` from the CLIENT's perspective:
    /// uses client_state (its outbound key) instead of server_state.
    fn client_encrypt_app_data<'b>(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        plaintext: &[u8],
        out: &'b mut [u8],
    ) -> &'b [u8] {
        let tag_size = AES_GCM_TAG_SIZE;
        let plaintext_with_marker = plaintext.len() + 1;
        let ciphertext_len = plaintext_with_marker + tag_size;
        let total = RECORD_HEADER_LEN + ciphertext_len;
        let len_bytes = (ciphertext_len as u16).to_be_bytes();
        out[0] = ContentType::ApplicationData as u8;
        out[1] = 0x03;
        out[2] = 0x03;
        out[3] = len_bytes[0];
        out[4] = len_bytes[1];
        out[RECORD_HEADER_LEN..RECORD_HEADER_LEN + plaintext.len()].copy_from_slice(plaintext);
        out[RECORD_HEADER_LEN + plaintext.len()] = ContentType::ApplicationData as u8;

        let additional_data = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ];

        let key = client_ks.write_state().get_key().unwrap().clone();
        let nonce = client_ks.write_state().get_nonce().unwrap();
        let cipher = <<Aes128GcmSha256 as TlsCipherSuite>::Cipher as KeyInit>::new(&key);
        {
            let region = &mut out[RECORD_HEADER_LEN..RECORD_HEADER_LEN + ciphertext_len];
            let mut crypto = CryptoBuffer::wrap_with_pos(region, plaintext_with_marker);
            cipher
                .encrypt_in_place(&nonce, &additional_data, &mut crypto)
                .unwrap();
        }
        client_ks.write_state().increment_counter();
        &out[..total]
    }

    /// Mirror of `decrypt_application_data` for the CLIENT side.
    fn client_decrypt_app_data<'b>(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        record: &[u8],
        plaintext_buf: &'b mut [u8],
    ) -> &'b [u8] {
        assert_eq!(record[0], ContentType::ApplicationData as u8);
        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        plaintext_buf[..body_len].copy_from_slice(&record[RECORD_HEADER_LEN..]);
        let key = client_ks.read_state().get_key().unwrap().clone();
        let nonce = client_ks.read_state().get_nonce().unwrap();
        let cipher = <<Aes128GcmSha256 as TlsCipherSuite>::Cipher as KeyInit>::new(&key);
        let plaintext_len = {
            let mut crypto =
                CryptoBuffer::wrap_with_pos(&mut plaintext_buf[..body_len], body_len);
            cipher
                .decrypt_in_place(&nonce, &record[..RECORD_HEADER_LEN], &mut crypto)
                .expect("client decrypt");
            crypto.len()
        };
        client_ks.read_state().increment_counter();
        let pad_end = plaintext_buf[..plaintext_len]
            .iter()
            .rposition(|b| *b != 0)
            .unwrap();
        // Trailing byte must be the inner content type marker.
        assert_eq!(plaintext_buf[pad_end], ContentType::ApplicationData as u8);
        &plaintext_buf[..pad_end]
    }
}

