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
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use crate::TlsError;
use crate::buffer::CryptoBuffer;
use crate::config::{Aes128GcmSha256, TlsCipherSuite};
use crate::content_types::ContentType;
use crate::extensions::extension_data::key_share::{
    KeyShareClientHello, KeyShareEntry, KeyShareServerHello,
};
use crate::extensions::extension_data::pre_shared_key::{
    PreSharedKeyClientHello, PreSharedKeyServerHello,
};
use crate::extensions::extension_data::psk_key_exchange_modes::PskKeyExchangeMode;
use crate::extensions::extension_data::supported_groups::NamedGroup;
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
const KEY_SHARE_VEC_N: usize = 4; // matches messages.rs ClientHelloExtension::KeyShare<'a, 4>
const RECORD_HEADER_LEN: usize = 5;
const HANDSHAKE_HEADER_LEN: usize = 4;
const X25519_LEN: usize = 32;

/// Ephemeral X25519 keypair used for the `psk_dhe_ke` exchange. Caller draws
/// the secret from a CSPRNG and computes the public via `from_secret`, or
/// uses the `generate` convenience.
///
/// One instance per handshake. Reusing the same keypair across multiple
/// connections defeats forward secrecy.
#[derive(Clone)]
pub struct DheKeyShare {
    /// Raw 32-byte X25519 secret scalar. RFC 7748 §5 clamping is performed
    /// internally by `x25519_dalek` on use, so any 32 random bytes are valid.
    pub secret: [u8; X25519_LEN],
    /// X25519(secret, basepoint). Cached so the encode path doesn't redo
    /// scalar-mult on the hot path.
    pub public: [u8; X25519_LEN],
}

impl DheKeyShare {
    /// Build the keypair from a caller-supplied secret. Computes the public
    /// key by `secret * basepoint`.
    pub fn from_secret(secret: [u8; X25519_LEN]) -> Self {
        let public = x25519(secret, X25519_BASEPOINT_BYTES);
        Self { secret, public }
    }

    /// Convenience: draw 32 random bytes and derive the public key.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; X25519_LEN];
        rng.fill_bytes(&mut secret);
        Self::from_secret(secret)
    }
}

pub struct TlsServerConfig<'a> {
    /// External pre-shared key. `psk.0` is the identity (sent on the wire),
    /// `psk.1` is the secret.
    pub psk: (&'a [u8], &'a [u8]),
    /// Server-generated random for the ServerHello — caller draws from a
    /// CSPRNG. Keeping the RNG outside this module keeps the function pure.
    pub server_random: [u8; 32],
    /// Ephemeral X25519 keypair for `psk_dhe_ke` (forward-secrecy mode).
    /// `None` → server only does plain `psk_ke` (legacy 0.1 behaviour).
    /// `Some(_)` → server prefers `psk_dhe_ke` when the client offers it
    /// and supplies a usable X25519 share, else falls back to `psk_ke`.
    pub dhe_keypair: Option<DheKeyShare>,
}

/// Negotiated key-exchange mode for one handshake. Picked in
/// `decide_kex` from the (config, ClientHello) pair.
enum KexMode<'a> {
    PskKe,
    PskDheKe { client_x25519_pub: &'a [u8] },
}

/// Outcome of `decide_kex`: either we can proceed with a chosen mode, or we
/// must send a HelloRetryRequest asking the client for a key_share in
/// `retry_group`.
enum KexDecision<'a> {
    Use(KexMode<'a>),
    Retry { retry_group: NamedGroup },
}

pub struct FirstFlight<'b> {
    pub bytes: &'b [u8],
}

/// What `TlsServerSession::process_client_hello` produces. Two states:
///   * `FirstFlight` — full server flight (ServerHello + EncryptedExtensions
///     + server Finished). Caller writes it, drains the dummy CCS, and
///     reads the encrypted client Finished record next.
///   * `HelloRetryRequest` — caller writes the HRR record, drains the dummy
///     CCS, reads the second ClientHello, and calls `process_client_hello`
///     **again on the same session**. The session remembers internally
///     that it has already issued one HRR — it will not emit a second.
pub enum HandshakeOutput<'b> {
    FirstFlight(&'b [u8]),
    HelloRetryRequest(&'b [u8]),
}

/// RFC 8446 §4.1.3: HelloRetryRequest is encoded as a ServerHello whose
/// `random` is set to the SHA-256 hash of the literal ASCII string
/// "HelloRetryRequest". Receivers detect HRR by comparing this constant.
const HRR_SPECIAL_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

/// Snapshot of CH1 fields used to enforce RFC 8446 §4.1.2 consistency on
/// the second ClientHello. The RFC permits CH2 to differ from CH1 in
/// `key_share`, `early_data`, `cookie`, recomputed PSK binders, and
/// `padding` — everything else MUST match.
///
/// We snapshot the cheap-to-compare invariants:
///   * `random` — fixed across CH1/CH2; mismatch indicates a different
///     client (or a tampering middlebox).
///   * `legacy_session_id` — we already echo it in HRR; CH2 must repeat it.
///
/// Other invariants come for free from earlier validation:
///   * cipher suite — we always pick `TLS_AES_128_GCM_SHA256`, so any CH
///     (1 or 2) that doesn't offer it fails `validate_cipher_suites`.
///   * PSK identity — `locate_our_identity` always selects `config.psk.0`;
///     any CH2 omitting it fails with `UnknownPskIdentity`. Index can
///     legitimately shift if the client drops other identities (allowed
///     by §4.1.2), so we deliberately don't pin the index.
#[derive(Default)]
struct HrrState {
    sent: bool,
    ch1_random: [u8; 32],
    ch1_session_id_len: u8,
    ch1_session_id: [u8; 32],
}

/// High-level concrete server session (TLS_AES_128_GCM_SHA256 only).
/// Wraps a KeySchedule so external callers don't need to import internal
/// types. Mirror of the generic `process_*` functions but with role-friendly
/// method names.
///
/// HRR support: if `process_client_hello` returns
/// `HandshakeOutput::HelloRetryRequest`, the caller writes those bytes,
/// drains the dummy CCS, reads the second ClientHello, and calls
/// `process_client_hello` again on the same session. The session
/// remembers internally that one HRR has been issued and will refuse a
/// second (RFC 8446 §4.1.4).
pub struct TlsServerSession {
    schedule: KeySchedule<Aes128GcmSha256>,
    hrr_state: HrrState,
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
            hrr_state: HrrState::default(),
        }
    }

    /// Drive the server side of one ClientHello round.
    /// Returns either the full first flight or a HelloRetryRequest record;
    /// see `HandshakeOutput`.
    pub fn process_client_hello<'b>(
        &mut self,
        ch_handshake_message: &[u8],
        config: &TlsServerConfig<'_>,
        out: &'b mut [u8],
    ) -> Result<HandshakeOutput<'b>, TlsError> {
        process_client_hello_inner(
            ch_handshake_message,
            config,
            &mut self.schedule,
            &mut self.hrr_state,
            out,
        )
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

    /// See `encrypt_alert_record` (free function).
    pub fn encrypt_alert<'b>(
        &mut self,
        level: crate::alert::AlertLevel,
        description: crate::alert::AlertDescription,
        out: &'b mut [u8],
    ) -> Result<&'b [u8], TlsError> {
        encrypt_alert_record(level, description, &mut self.schedule, out)
    }

    /// See `decrypt_app_data_or_alert` (free function).
    pub fn decrypt_app_data_or_alert<'b>(
        &mut self,
        encrypted_record: &[u8],
        plaintext_buf: &'b mut [u8],
    ) -> Result<AppDataOrAlert<'b>, TlsError> {
        decrypt_app_data_or_alert(encrypted_record, &mut self.schedule, plaintext_buf)
    }
}

/// What an inbound TLSCiphertext (outer ApplicationData) record carries
/// after AEAD-decrypt: either user payload, or a peer-initiated Alert
/// (close_notify, etc). RFC 8446 §6 wraps post-handshake Alerts in the
/// same outer ApplicationData record type as user data; the inner content
/// type marker distinguishes them.
#[derive(Debug)]
pub enum AppDataOrAlert<'b> {
    AppData(&'b [u8]),
    Alert {
        level: crate::alert::AlertLevel,
        description: crate::alert::AlertDescription,
    },
}

/// Free function with the original 0.2 signature: returns `FirstFlight` and
/// does NOT support HelloRetryRequest. Use `TlsServerSession` for the
/// HRR-capable path.
///
/// Behaviour: identical to 0.2 — psk_ke and psk_dhe_ke (when the client
/// pre-supplies an X25519 share) work; clients that would force an HRR
/// instead trigger a `HandshakeFailure` here.
pub fn process_client_hello<'b, CipherSuite>(
    ch_handshake_message: &[u8],
    config: &TlsServerConfig<'_>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    out: &'b mut [u8],
) -> Result<FirstFlight<'b>, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let mut hrr_state = HrrState::default();
    match process_client_hello_inner(
        ch_handshake_message,
        config,
        key_schedule,
        &mut hrr_state,
        out,
    )? {
        HandshakeOutput::FirstFlight(bytes) => Ok(FirstFlight { bytes }),
        HandshakeOutput::HelloRetryRequest(_) => {
            // The free function exposes the original 0.2 contract — single
            // bytes-in, single bytes-out — and has no way to communicate
            // that a second ClientHello is needed. Callers wanting HRR use
            // `TlsServerSession`. Match the 0.2 abort-on-DHE-impossible
            // behaviour for back-compat.
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::HandshakeFailure,
            ))
        }
    }
}

fn process_client_hello_inner<'b, CipherSuite>(
    ch_handshake_message: &[u8],
    config: &TlsServerConfig<'_>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    hrr_state: &mut HrrState,
    out: &'b mut [u8],
) -> Result<HandshakeOutput<'b>, TlsError>
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

    // RFC 8446 §4.1.2: on CH2, validate that the unchanging fields really
    // do match CH1 before doing any further work. Earlier checks are cheap
    // and would have failed anyway, but the fields below (random,
    // session_id, psk identity) are NOT covered by the generic validators.
    if hrr_state.sent {
        validate_ch2_consistency(&hello, hrr_state)?;
    }

    let decision = decide_kex(&hello, config, hrr_state.sent)?;

    let (selected_idx, received_binder) = locate_our_identity(&hello, config)?;

    // RFC 8446 §4.1.4 + §4.4.1: on the second ClientHello, early_secret was
    // already initialised in CH1 — re-running it would extract a different
    // schedule. Likewise, the binder-prefix base on CH2 is the running
    // transcript (which already contains [message_hash || HRR]) instead
    // of a fresh hash.
    if !hrr_state.sent {
        key_schedule
            .initialize_early_secret(Some(config.psk.1))
            .map_err(|_| TlsError::CryptoError)?;
    }
    let mut prefix_hash = if hrr_state.sent {
        key_schedule.transcript_hash().clone()
    } else {
        <CipherSuite::Hash as Digest>::new()
    };
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

    // Branch on decide_kex's verdict. The Retry branch short-circuits the
    // rest of the flight: emit HRR, snapshot CH1 for §4.1.2, return.
    let mode = match decision {
        KexDecision::Use(m) => m,
        KexDecision::Retry { retry_group } => {
            let mut writer = OutWriter::new(out);
            write_hello_retry_request_record(
                &mut writer,
                hello.legacy_session_id,
                retry_group,
                ch_handshake_message,
                key_schedule,
            )?;
            // Snapshot CH1 fields we'll re-check on CH2.
            hrr_state.sent = true;
            hrr_state.ch1_random = hello.random;
            hrr_state.ch1_session_id_len = hello.legacy_session_id.len() as u8;
            hrr_state.ch1_session_id[..hello.legacy_session_id.len()]
                .copy_from_slice(hello.legacy_session_id);
            let _ = selected_idx; // bound-but-unused on the HRR path
            let len = writer.len();
            return Ok(HandshakeOutput::HelloRetryRequest(&out[..len]));
        }
    };

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
        &mode,
        key_schedule,
    )?;

    // Compute the (EC)DHE shared secret if we're in psk_dhe_ke mode; for
    // psk_ke RFC 8446 §7.1 substitutes the all-zero string of Hash.length
    // bytes as the IKM.
    match &mode {
        KexMode::PskKe => {
            key_schedule
                .initialize_handshake_secret_psk_ke()
                .map_err(|_| TlsError::CryptoError)?;
        }
        KexMode::PskDheKe { client_x25519_pub } => {
            let dhe = config
                .dhe_keypair
                .as_ref()
                .ok_or(TlsError::InternalError)?;
            let mut their_pub = [0u8; X25519_LEN];
            if client_x25519_pub.len() != X25519_LEN {
                return Err(TlsError::AbortHandshake(
                    crate::alert::AlertLevel::Fatal,
                    crate::alert::AlertDescription::IllegalParameter,
                ));
            }
            their_pub.copy_from_slice(client_x25519_pub);
            let shared = x25519(dhe.secret, their_pub);
            // RFC 7748 §6.1 / RFC 8446 §7.4.2: an all-zero output indicates
            // a small-subgroup or contributory-behaviour failure; abort.
            if shared.iter().all(|&b| b == 0) {
                return Err(TlsError::AbortHandshake(
                    crate::alert::AlertLevel::Fatal,
                    crate::alert::AlertDescription::IllegalParameter,
                ));
            }
            key_schedule
                .initialize_handshake_secret(&shared)
                .map_err(|_| TlsError::CryptoError)?;
        }
    }

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
    Ok(HandshakeOutput::FirstFlight(&out[..len]))
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

/// Pick the key-exchange path for this handshake.
///
/// Decision tree (RFC 8446 §4.2.9 leaves the choice to the server):
///   1. `psk_dhe_ke` directly — config has DHE keypair, client offered the
///      mode, client supplied a usable X25519 share. Forward secrecy in
///      one round-trip.
///   2. `psk_ke` fallback — client also offered psk_ke and we don't have
///      what we need to do DHE. No extra round-trip; no forward secrecy.
///   3. HelloRetryRequest — client offered psk_dhe_ke only, advertised
///      X25519 in supported_groups, but didn't include a key_share for it.
///      Asking for a retry is the only way forward. Only emitted when
///      `hrr_already_sent` is false (RFC 8446 §4.1.4 forbids two HRRs).
///   4. HandshakeFailure — none of the above match.
///
/// Aborts with `MissingExtension` if `psk_key_exchange_modes` is absent
/// (RFC 8446 §4.2.9 mandates it for any PSK-using ClientHello).
fn decide_kex<'a, const N: usize>(
    hello: &'a ClientHelloRef<'_, N>,
    config: &TlsServerConfig<'_>,
    hrr_already_sent: bool,
) -> Result<KexDecision<'a>, TlsError> {
    let modes = hello
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

    let offers_psk_ke = modes.modes.iter().any(|m| *m == PskKeyExchangeMode::PskKe);
    let offers_psk_dhe_ke = modes
        .modes
        .iter()
        .any(|m| *m == PskKeyExchangeMode::PskDheKe);

    let dhe_available = config.dhe_keypair.is_some();
    let dhe_acceptable = offers_psk_dhe_ke && dhe_available;

    if dhe_acceptable {
        if let Some(share) = find_client_x25519_share(hello)? {
            return Ok(KexDecision::Use(KexMode::PskDheKe {
                client_x25519_pub: share,
            }));
        }
        // No usable X25519 share. If the client also offered psk_ke we'd
        // rather take the no-extra-RT fallback than spend a HRR.
        if offers_psk_ke {
            return Ok(KexDecision::Use(KexMode::PskKe));
        }
        // psk_dhe_ke-only client without a share. HelloRetryRequest is the
        // only way to recover — but only if (a) we haven't already issued
        // one (a second HRR is forbidden), and (b) the client said it
        // supports the group we'd ask for.
        if !hrr_already_sent && client_supports_group(hello, NamedGroup::X25519) {
            return Ok(KexDecision::Retry {
                retry_group: NamedGroup::X25519,
            });
        }
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::HandshakeFailure,
        ));
    }

    if offers_psk_ke {
        return Ok(KexDecision::Use(KexMode::PskKe));
    }

    Err(TlsError::AbortHandshake(
        crate::alert::AlertLevel::Fatal,
        crate::alert::AlertDescription::HandshakeFailure,
    ))
}

/// RFC 8446 §4.1.2: enforce that the second ClientHello has the
/// fields we care about identical to the first. The full RFC permits a
/// few specific deltas (key_share, early_data, cookie, padding,
/// recomputed binders); the fields below are NOT in that allow-list.
///
/// Mismatch ⇒ fatal `IllegalParameter` alert.
fn validate_ch2_consistency<const N: usize>(
    hello: &ClientHelloRef<'_, N>,
    snapshot: &HrrState,
) -> Result<(), TlsError> {
    if hello.random != snapshot.ch1_random {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::IllegalParameter,
        ));
    }
    let snap_sid = &snapshot.ch1_session_id[..snapshot.ch1_session_id_len as usize];
    if hello.legacy_session_id != snap_sid {
        return Err(TlsError::AbortHandshake(
            crate::alert::AlertLevel::Fatal,
            crate::alert::AlertDescription::IllegalParameter,
        ));
    }
    Ok(())
}

/// True iff the client advertised the given group in `supported_groups`.
/// Used by HRR decision logic — there's no point retrying with X25519 if
/// the client said it doesn't support X25519 in the first place.
fn client_supports_group<const N: usize>(
    hello: &ClientHelloRef<'_, N>,
    group: NamedGroup,
) -> bool {
    hello
        .extensions
        .iter()
        .find_map(|e| {
            if let ClientHelloExtension::SupportedGroups(g) = e {
                Some(g)
            } else {
                None
            }
        })
        .map(|g| g.supported_groups.iter().any(|gg| *gg == group))
        .unwrap_or(false)
}

/// Walk the client `key_share` extension (if any) and return the first
/// X25519 share's public key. Multiple shares may be present; non-X25519
/// entries are ignored, not rejected. Length validation happens in the
/// caller (must be 32 bytes).
fn find_client_x25519_share<'a, const N: usize>(
    hello: &'a ClientHelloRef<'_, N>,
) -> Result<Option<&'a [u8]>, TlsError> {
    let ks: &KeyShareClientHello<'_, KEY_SHARE_VEC_N> = match hello
        .extensions
        .iter()
        .find_map(|e| {
            if let ClientHelloExtension::KeyShare(k) = e {
                Some(k)
            } else {
                None
            }
        }) {
        Some(k) => k,
        None => return Ok(None),
    };
    for entry in &ks.client_shares {
        if entry.group == NamedGroup::X25519 {
            if entry.opaque.len() != X25519_LEN {
                return Err(TlsError::AbortHandshake(
                    crate::alert::AlertLevel::Fatal,
                    crate::alert::AlertDescription::IllegalParameter,
                ));
            }
            return Ok(Some(entry.opaque));
        }
    }
    Ok(None)
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

/// Emit a HelloRetryRequest record into `writer` and update the running
/// transcript per RFC 8446 §4.4.1: the prior `Hash(ClientHello1)` is
/// wrapped in a synthetic `message_hash` handshake message and replaces
/// CH1 in the transcript, followed by the HRR bytes themselves.
///
/// Wire shape (handshake message body):
///   legacy_version (TLS 1.2)
///   random        (HRR_SPECIAL_RANDOM)
///   session_id_echo
///   cipher_suite  (TLS_AES_128_GCM_SHA256)
///   compression   (null)
///   extensions:
///     supported_versions(TLS13)
///     key_share(selected_group, no opaque)
///
/// The caller is responsible for *not* having fed CH1 into the running
/// transcript yet; this function does the synthetic `message_hash` rewrite.
fn write_hello_retry_request_record<CipherSuite>(
    writer: &mut OutWriter<'_>,
    legacy_session_id_echo: &[u8],
    selected_group: NamedGroup,
    ch1_handshake_message: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let record_start = writer.len();
    writer.append(&[ContentType::Handshake as u8, 0x03, 0x03, 0, 0])?;
    let hs_header_pos = writer.len();
    writer.append(&[HandshakeType::ServerHello as u8, 0, 0, 0])?;
    let body_start = writer.len();

    writer.append(&[0x03, 0x03])?; // legacy_version
    writer.append(&HRR_SPECIAL_RANDOM)?;
    if legacy_session_id_echo.len() > 32 {
        return Err(TlsError::EncodeError);
    }
    writer.append(&[legacy_session_id_echo.len() as u8])?;
    writer.append(legacy_session_id_echo)?;
    writer.append(&TLS_AES_128_GCM_SHA256.to_be_bytes())?;
    writer.append(&[0])?; // legacy_compression_method = null

    let ext_list_len_pos = writer.len();
    writer.append(&[0, 0])?;
    let ext_content_start = writer.len();

    // supported_versions: type 0x002b, data = TLS 1.3 code point (0x0304).
    writer.append(&0x002bu16.to_be_bytes())?;
    writer.append(&2u16.to_be_bytes())?;
    writer.append(&0x0304u16.to_be_bytes())?;

    // key_share for HRR: type 0x0033, data = selected_group (u16 BE).
    writer.append(&0x0033u16.to_be_bytes())?;
    writer.append(&2u16.to_be_bytes())?;
    writer.append(&selected_group.as_u16().to_be_bytes())?;

    let ext_content_end = writer.len();
    let ext_list_len = (ext_content_end - ext_content_start) as u16;
    writer.buf[ext_list_len_pos..ext_list_len_pos + 2]
        .copy_from_slice(&ext_list_len.to_be_bytes());

    let body_len = (writer.len() - body_start) as u32;
    writer.buf[hs_header_pos + 1] = (body_len >> 16) as u8;
    writer.buf[hs_header_pos + 2] = (body_len >> 8) as u8;
    writer.buf[hs_header_pos + 3] = body_len as u8;

    let record_payload_len = (writer.len() - record_start - RECORD_HEADER_LEN) as u16;
    writer.buf[record_start + 3] = (record_payload_len >> 8) as u8;
    writer.buf[record_start + 4] = record_payload_len as u8;

    // RFC 8446 §4.4.1: rewrite the running transcript so future MACs cover
    //   message_hash(0xfe) || u24(Hash.length) || Hash(ClientHello1)
    //   || HRR_handshake_message
    // instead of plain ClientHello1.
    let hash_len = <<CipherSuite::Hash as OutputSizeUser>::OutputSize as Unsigned>::USIZE;
    let mut ch1_hasher = <CipherSuite::Hash as Digest>::new();
    ch1_hasher.update(ch1_handshake_message);
    let ch1_hash = ch1_hasher.finalize();

    let mut fresh_transcript = <CipherSuite::Hash as Digest>::new();
    // Synthetic message_hash handshake header: type=0xfe, u24 length=hash_len.
    let synthetic_header = [
        HandshakeType::MessageHash as u8,
        0,
        (hash_len >> 8) as u8,
        hash_len as u8,
    ];
    fresh_transcript.update(synthetic_header);
    fresh_transcript.update(&ch1_hash);
    // HRR handshake-message bytes (everything inside the record but with the
    // handshake header included), i.e. starting at `hs_header_pos`.
    let hrr_hs_bytes = &writer.buf[hs_header_pos..writer.pos];
    fresh_transcript.update(hrr_hs_bytes);
    key_schedule.replace_transcript_hash(fresh_transcript);

    Ok(())
}

fn write_server_hello_record<CipherSuite>(
    writer: &mut OutWriter<'_>,
    config: &TlsServerConfig<'_>,
    legacy_session_id_echo: &[u8],
    selected_idx: u16,
    mode: &KexMode<'_>,
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
    if matches!(mode, KexMode::PskDheKe { .. }) {
        // ServerHello key_share carries our ephemeral X25519 public key. The
        // client multiplies its secret by this to recover the same shared
        // secret we use as `handshake_secret` IKM.
        let dhe = config
            .dhe_keypair
            .as_ref()
            .ok_or(TlsError::InternalError)?;
        sh_extensions
            .push(ServerHelloExtension::KeyShare(KeyShareServerHello(
                KeyShareEntry {
                    group: NamedGroup::X25519,
                    opaque: &dhe.public,
                },
            )))
            .map_err(|_| TlsError::EncodeError)?;
    }
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

/// Encrypt a TLS 1.3 Alert record using the application traffic keys.
///
/// RFC 8446 §6: post-handshake Alerts are wrapped in a TLSCiphertext with
/// outer `content_type = ApplicationData`; the inner plaintext is two
/// bytes (level || description) followed by the inner content type
/// marker `Alert (21)`.
///
/// Increments the server-side AEAD counter on success. Use this in
/// preference to crafting alerts by hand — it picks the right inner
/// marker and reuses the same nonce/key derivation as `encrypt_app_data`.
pub fn encrypt_alert_record<'b, CipherSuite>(
    level: crate::alert::AlertLevel,
    description: crate::alert::AlertDescription,
    key_schedule: &mut KeySchedule<CipherSuite>,
    out: &'b mut [u8],
) -> Result<&'b [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let tag_size = <<CipherSuite::Cipher as AeadCore>::TagSize as Unsigned>::USIZE;
    let plaintext_with_marker = 2 /* level + desc */ + 1 /* inner CT marker */;
    let ciphertext_len = plaintext_with_marker + tag_size;
    let total = RECORD_HEADER_LEN + ciphertext_len;
    if out.len() < total {
        return Err(TlsError::InsufficientSpace);
    }

    let len_bytes = (ciphertext_len as u16).to_be_bytes();
    out[0] = ContentType::ApplicationData as u8;
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = len_bytes[0];
    out[4] = len_bytes[1];

    out[RECORD_HEADER_LEN] = level as u8;
    out[RECORD_HEADER_LEN + 1] = description as u8;
    out[RECORD_HEADER_LEN + 2] = ContentType::Alert as u8;

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

/// Decrypt one TLSCiphertext record and report whether it carries
/// application data or a peer Alert. Permissive variant of
/// `decrypt_application_data` — RFC 8446 §6 explicitly allows Alerts to
/// appear at any point post-handshake under the same outer record type as
/// app data, and a polite peer (mosquitto, openssl) will issue
/// `close_notify` this way before closing the socket. Returning
/// `InvalidRecord` for that case forces the caller to invent a recovery
/// path; this method gives them the alert directly.
///
/// Inner content types other than ApplicationData or Alert (e.g. Handshake
/// for KeyUpdate / post-handshake auth) still come back as
/// `TlsError::InvalidRecord`.
pub fn decrypt_app_data_or_alert<'b, CipherSuite>(
    encrypted_record: &[u8],
    key_schedule: &mut KeySchedule<CipherSuite>,
    plaintext_buf: &'b mut [u8],
) -> Result<AppDataOrAlert<'b>, TlsError>
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
    match inner_ct {
        ContentType::ApplicationData => Ok(AppDataOrAlert::AppData(&plaintext_buf[..pad_end])),
        ContentType::Alert => {
            // Inner Alert payload is exactly 2 bytes (level + description),
            // sitting at plaintext_buf[..pad_end].
            if pad_end != 2 {
                return Err(TlsError::InvalidRecord);
            }
            let level = crate::alert::AlertLevel::of(plaintext_buf[0])
                .ok_or(TlsError::DecodeError)?;
            let description = crate::alert::AlertDescription::of(plaintext_buf[1])
                .ok_or(TlsError::DecodeError)?;
            Ok(AppDataOrAlert::Alert { level, description })
        }
        _ => Err(TlsError::InvalidRecord),
    }
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
            dhe_keypair: None,
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

    // ─────────────────────────────────────────────────────────────────────
    // psk_dhe_ke (X25519) self-loop coverage.
    // ─────────────────────────────────────────────────────────────────────

    /// Same shape as `build_synthetic_client_hello` but offers `psk_dhe_ke`
    /// (mode 0x01) and inserts a `key_share` extension with a single X25519
    /// entry holding the supplied client ephemeral public key.
    fn build_synthetic_client_hello_dhe(
        identity: &[u8],
        client_x25519_pub: &[u8; 32],
    ) -> ChLayout {
        let mut out = std::vec::Vec::with_capacity(320);
        out.push(HS_TYPE_CLIENT_HELLO);
        out.extend_from_slice(&[0, 0, 0]);
        let body_start = out.len();

        out.extend_from_slice(&LEGACY_VERSION_BYTES);
        out.extend_from_slice(&[0xa5; 32]);
        out.push(0);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        out.push(1);
        out.push(0);

        let ext_list_len_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let ext_content_start = out.len();

        // supported_versions (0x002b)
        out.extend_from_slice(&0x002bu16.to_be_bytes());
        out.extend_from_slice(&3u16.to_be_bytes());
        out.push(2);
        out.extend_from_slice(&TLS13_BYTES);

        // psk_key_exchange_modes — psk_dhe_ke (0x01)
        out.extend_from_slice(&0x002du16.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.push(1);
        out.push(1); // psk_dhe_ke

        // key_share (0x0033) — one X25519 entry.
        // ext_data layout: u16 list_len || (group u16 || u16 keylen || key bytes).
        // Inner entry size = 2 (group) + 2 (keylen) + 32 (key) = 36.
        // list_len = 36; ext_data length = 2 (list_len) + 36 = 38.
        out.extend_from_slice(&0x0033u16.to_be_bytes());
        out.extend_from_slice(&38u16.to_be_bytes());
        out.extend_from_slice(&36u16.to_be_bytes());
        out.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519
        out.extend_from_slice(&32u16.to_be_bytes());
        out.extend_from_slice(client_x25519_pub);

        // pre_shared_key (last)
        out.extend_from_slice(&0x0029u16.to_be_bytes());
        let psk_data_len_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let psk_data_start = out.len();

        let id_entry_len = 2 + identity.len() + 4;
        out.extend_from_slice(&(id_entry_len as u16).to_be_bytes());
        out.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        out.extend_from_slice(identity);
        out.extend_from_slice(&0u32.to_be_bytes());

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

    fn build_client_hello_dhe_with_binder(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        identity: &[u8],
        client_x25519_pub: &[u8; 32],
    ) -> std::vec::Vec<u8> {
        let mut layout = build_synthetic_client_hello_dhe(identity, client_x25519_pub);
        let mut prefix_hash: Sha256 = Digest::new();
        prefix_hash.update(&layout.bytes[..layout.binders_start_offset]);
        let (write_state, _) = client_ks.as_split();
        let binder = write_state.create_psk_binder(&prefix_hash).unwrap();
        layout.bytes[layout.binder_value_pos..layout.binder_value_pos + SHA256_LEN]
            .copy_from_slice(binder.verify.as_slice());
        layout.bytes
    }

    /// Full bytes-in-bytes-out PSK_DHE_KE handshake. Mirrors the psk_ke
    /// round-trip but feeds the X25519 shared secret into both peers'
    /// `initialize_handshake_secret`. Verifies that the server's ServerHello
    /// carries the expected key_share, both sides converge on the same
    /// handshake/application traffic secrets, and bidirectional appdata works.
    #[test]
    fn process_client_hello_and_finished_round_trip_dhe() {
        use crate::handshake::server_hello::ServerHello;

        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"smartbox-house-1";
        let server_random = [0x77u8; 32];

        // Deterministic ephemeral X25519 secrets for both peers.
        let client_secret = [0x42u8; 32];
        let client_pub = x25519(client_secret, X25519_BASEPOINT_BYTES);
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        // Sanity: ECDH commutes — both sides will end up here.
        assert_eq!(
            x25519(client_secret, server_dhe.public),
            x25519(server_dhe.secret, client_pub),
        );

        // ── 1. Client builds CH with X25519 share + binder. ───────────
        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();
        let ch_bytes =
            build_client_hello_dhe_with_binder(&mut client_ks, identity, &client_pub);

        // ── 2. Server processes CH → first flight. ────────────────────
        let mut server_ks = KeySchedule::<Aes128GcmSha256>::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe.clone()),
        };
        let mut out_buf = [0u8; 1024];
        let flight = process_client_hello(&ch_bytes, &config, &mut server_ks, &mut out_buf)
            .expect("process_client_hello dhe");
        let flight_owned: std::vec::Vec<u8> = flight.bytes.to_vec();

        // ── 3. Client side: extract server's key_share from ServerHello. ─
        let (sh_record, ee_record, fin_record) = split_first_flight(&flight_owned);
        let sh_body = &sh_record[RECORD_HEADER_LEN..];
        assert_eq!(sh_body[0], HandshakeType::ServerHello as u8);
        let mut p = ParseBuffer::new(&sh_body[HANDSHAKE_HEADER_LEN..]);
        let parsed_sh = ServerHello::parse(&mut p).expect("ServerHello::parse");
        let server_share_entry = parsed_sh
            .key_share()
            .expect("server must include key_share for psk_dhe_ke");
        let server_pub_bytes: [u8; 32] = server_share_entry
            .opaque
            .try_into()
            .expect("X25519 share must be 32 bytes");
        assert_eq!(
            server_pub_bytes, server_dhe.public,
            "server's emitted key_share must match dhe_keypair.public",
        );

        // ── 4. Both sides feed CH || SH into transcript and derive
        //       handshake_secret using the X25519 shared secret. ────────
        let shared = x25519(client_secret, server_pub_bytes);
        assert!(!shared.iter().all(|&b| b == 0));
        client_ks.transcript_hash().update(&ch_bytes);
        client_ks
            .transcript_hash()
            .update(&sh_record[RECORD_HEADER_LEN..]);
        client_ks.initialize_handshake_secret(&shared).unwrap();

        // ── 5. Client decrypts EncryptedExtensions + server Finished. ─
        let ee_inner = client_decrypt_handshake_record(&mut client_ks, ee_record);
        client_ks.transcript_hash().update(&ee_inner);
        assert_eq!(ee_inner, &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);

        let fin_inner = client_decrypt_handshake_record(&mut client_ks, fin_record);
        let pre_fin_snapshot = client_ks.transcript_hash().clone().finalize();
        client_ks.transcript_hash().update(&fin_inner);

        assert_eq!(fin_inner[0], HandshakeType::Finished as u8);
        let mut verify = generic_array::GenericArray::default();
        verify.copy_from_slice(&fin_inner[4..4 + SHA256_LEN]);
        let server_finished = crate::handshake::finished::Finished {
            verify,
            hash: Some(pre_fin_snapshot),
        };
        let (_w, client_read) = client_ks.as_split();
        assert!(
            client_read
                .verify_server_finished(&server_finished)
                .expect("verify server Finished"),
        );

        // ── 6. Client builds + sends its Finished. ────────────────────
        let client_fin_record = build_client_finished_record(&mut client_ks);
        process_client_finished(&client_fin_record, &mut server_ks)
            .expect("process_client_finished dhe");

        // ── 7. Both sides advance to master secret. ───────────────────
        client_ks.initialize_master_secret().unwrap();

        // ── 8. Bidirectional appdata exchange. ────────────────────────
        let mut srv_out = [0u8; 256];
        let s2c =
            encrypt_application_data(b"dhe!", &mut server_ks, &mut srv_out).expect("server enc");
        let mut decoded = [0u8; 256];
        let plain = client_decrypt_app_data(&mut client_ks, s2c, &mut decoded);
        assert_eq!(plain, b"dhe!");
    }

    /// `decide_kex` (with `hrr_already_sent = true` so we never branch into
    /// the Retry path here — that's exercised separately):
    ///   * dhe_keypair = Some + client offers psk_dhe_ke + has X25519 share → DHE
    ///   * dhe_keypair = None  + client offers psk_dhe_ke only              → fail
    ///   * dhe_keypair = Some + client offers psk_ke only                   → psk_ke
    #[test]
    fn decide_kex_chooses_dhe_when_possible() {
        let identity: &[u8] = b"x";
        let client_pub = [0x11u8; 32];

        // Case 1: full DHE happy path.
        let layout = build_synthetic_client_hello_dhe(identity, &client_pub);
        let mut parse = ParseBuffer::new(&layout.bytes);
        let hello: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut parse).unwrap();
        let cfg = TlsServerConfig {
            psk: (identity, &[0; 32]),
            server_random: [0; 32],
            dhe_keypair: Some(DheKeyShare::from_secret([0x33; 32])),
        };
        let decision = decide_kex(&hello, &cfg, true).expect("dhe path");
        match decision {
            KexDecision::Use(KexMode::PskDheKe { client_x25519_pub }) => {
                assert_eq!(client_x25519_pub, &client_pub[..]);
            }
            _ => panic!("expected Use(PskDheKe)"),
        }

        // Case 2: psk_dhe_ke-only client, server has no DHE keypair → fail.
        let cfg_no_dhe = TlsServerConfig {
            psk: (identity, &[0; 32]),
            server_random: [0; 32],
            dhe_keypair: None,
        };
        let mut parse2 = ParseBuffer::new(&layout.bytes);
        let hello2: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut parse2).unwrap();
        let result = decide_kex(&hello2, &cfg_no_dhe, true);
        assert!(matches!(
            result,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::HandshakeFailure,
            )),
        ));

        // Case 3: psk_ke-only client + dhe_keypair = Some → falls back to psk_ke.
        let psk_ke_layout = build_synthetic_client_hello(identity);
        let mut parse3 = ParseBuffer::new(&psk_ke_layout.bytes);
        let hello3: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut parse3).unwrap();
        let decision3 = decide_kex(&hello3, &cfg, true).expect("falls back to psk_ke");
        assert!(matches!(decision3, KexDecision::Use(KexMode::PskKe)));
    }

    /// All-zero X25519 shared secret (small-subgroup output) must abort
    /// with `IllegalParameter`. We force this by sending an all-zero client
    /// public key — `x25519(any, [0; 32])` returns all zeros.
    #[test]
    fn reject_zero_x25519_shared_secret() {
        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"x";
        let server_random = [0x77u8; 32];
        let zero_pub = [0u8; 32];
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();
        let ch_bytes =
            build_client_hello_dhe_with_binder(&mut client_ks, identity, &zero_pub);

        let mut server_ks = KeySchedule::<Aes128GcmSha256>::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe),
        };
        let mut out_buf = [0u8; 1024];
        let res = process_client_hello(&ch_bytes, &config, &mut server_ks, &mut out_buf);
        assert!(matches!(
            res,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::IllegalParameter,
            )),
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // HelloRetryRequest coverage.
    // ─────────────────────────────────────────────────────────────────────

    /// CH that offers `psk_dhe_ke` only, advertises X25519 in
    /// `supported_groups`, and includes an EMPTY `key_share` extension.
    /// This is exactly the shape that triggers HRR. PSK identity + binder
    /// placeholder are filled in like the other builders.
    fn build_synthetic_ch_dhe_no_share(identity: &[u8]) -> ChLayout {
        let mut out = std::vec::Vec::with_capacity(256);
        out.push(HS_TYPE_CLIENT_HELLO);
        out.extend_from_slice(&[0, 0, 0]);
        let body_start = out.len();

        out.extend_from_slice(&LEGACY_VERSION_BYTES);
        out.extend_from_slice(&[0xa5; 32]);
        out.push(0);
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
        out.push(1);
        out.push(0);

        let ext_list_len_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let ext_content_start = out.len();

        // supported_versions
        out.extend_from_slice(&0x002bu16.to_be_bytes());
        out.extend_from_slice(&3u16.to_be_bytes());
        out.push(2);
        out.extend_from_slice(&TLS13_BYTES);

        // supported_groups: type 0x000a — list contains X25519 only.
        out.extend_from_slice(&0x000au16.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // ext data len
        out.extend_from_slice(&2u16.to_be_bytes()); // group list len
        out.extend_from_slice(&0x001Du16.to_be_bytes()); // X25519

        // psk_key_exchange_modes — psk_dhe_ke only.
        out.extend_from_slice(&0x002du16.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.push(1);
        out.push(1);

        // key_share: empty list (RFC 8446 §4.2.8 permits zero entries).
        out.extend_from_slice(&0x0033u16.to_be_bytes());
        out.extend_from_slice(&2u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());

        // pre_shared_key (last)
        out.extend_from_slice(&0x0029u16.to_be_bytes());
        let psk_data_len_pos = out.len();
        out.extend_from_slice(&[0, 0]);
        let psk_data_start = out.len();

        let id_entry_len = 2 + identity.len() + 4;
        out.extend_from_slice(&(id_entry_len as u16).to_be_bytes());
        out.extend_from_slice(&(identity.len() as u16).to_be_bytes());
        out.extend_from_slice(identity);
        out.extend_from_slice(&0u32.to_be_bytes());

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

    /// Splice a real PSK binder into a CH built by `build_synthetic_ch_dhe_no_share`.
    fn finalize_ch1_binder(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        layout: &mut ChLayout,
    ) {
        let mut prefix_hash: Sha256 = Digest::new();
        prefix_hash.update(&layout.bytes[..layout.binders_start_offset]);
        let (write_state, _) = client_ks.as_split();
        let binder = write_state.create_psk_binder(&prefix_hash).unwrap();
        layout.bytes[layout.binder_value_pos..layout.binder_value_pos + SHA256_LEN]
            .copy_from_slice(binder.verify.as_slice());
    }

    /// Mirror of the server-side transcript rewrite from RFC 8446 §4.4.1:
    /// after seeing HRR, replace the running transcript with
    ///   message_hash || u24(Hash.length) || Hash(ClientHello1) || HRR.
    fn munge_client_transcript_for_hrr(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        ch1_handshake_message: &[u8],
        hrr_handshake_message: &[u8],
    ) {
        let mut ch1_hasher: Sha256 = Digest::new();
        ch1_hasher.update(ch1_handshake_message);
        let ch1_hash = ch1_hasher.finalize();
        let mut fresh: Sha256 = Digest::new();
        fresh.update([HandshakeType::MessageHash as u8, 0, 0, SHA256_LEN as u8]);
        fresh.update(&ch1_hash);
        fresh.update(hrr_handshake_message);
        client_ks.replace_transcript_hash(fresh);
    }

    /// Build a CH2 (post-HRR) with X25519 share; the binder MAC uses the
    /// running transcript (already containing message_hash || HRR) as the
    /// prefix base, per RFC 8446 §4.1.4 + §4.4.1.
    fn build_client_hello_dhe_with_binder_after_hrr(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        identity: &[u8],
        client_x25519_pub: &[u8; 32],
    ) -> std::vec::Vec<u8> {
        let mut layout = build_synthetic_client_hello_dhe(identity, client_x25519_pub);
        let mut prefix_hash = client_ks.transcript_hash().clone();
        prefix_hash.update(&layout.bytes[..layout.binders_start_offset]);
        let (write_state, _) = client_ks.as_split();
        let binder = write_state.create_psk_binder(&prefix_hash).unwrap();
        layout.bytes[layout.binder_value_pos..layout.binder_value_pos + SHA256_LEN]
            .copy_from_slice(binder.verify.as_slice());
        layout.bytes
    }

    /// Full HRR self-loop. CH1 is psk_dhe_ke-only with X25519 in
    /// `supported_groups` but no key_share entry → server returns
    /// HelloRetryRequest. Client munges its transcript per §4.4.1, builds
    /// CH2 with an X25519 share + fresh binder, and the handshake completes
    /// normally.
    #[test]
    fn process_client_hello_hrr_then_dhe_round_trip() {
        use crate::handshake::server_hello::ServerHello;

        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"hrr-device";
        let server_random = [0x77u8; 32];

        let client_secret = [0x42u8; 32];
        let client_pub = x25519(client_secret, X25519_BASEPOINT_BYTES);
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();

        // ── 1. Build CH1 (no X25519 share). ──────────────────────────────
        let mut ch1_layout = build_synthetic_ch_dhe_no_share(identity);
        finalize_ch1_binder(&mut client_ks, &mut ch1_layout);
        let ch1 = ch1_layout.bytes.clone();

        // ── 2. Server processes CH1 → HRR. ────────────────────────────────
        let mut session = TlsServerSession::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe.clone()),
        };
        let mut out_buf = [0u8; 1024];
        let result = session
            .process_client_hello(&ch1, &config, &mut out_buf)
            .expect("first call");
        let hrr_record = match result {
            HandshakeOutput::HelloRetryRequest(b) => b.to_vec(),
            HandshakeOutput::FirstFlight(_) => panic!("expected HRR, got FirstFlight"),
        };

        // Sanity: HRR record carries the special random.
        assert_eq!(hrr_record[0], ContentType::Handshake as u8);
        let random_offset = RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN + 2; // +2 = legacy_version
        assert_eq!(
            &hrr_record[random_offset..random_offset + 32],
            &HRR_SPECIAL_RANDOM,
            "HRR random must equal SHA-256(\"HelloRetryRequest\")",
        );

        // ── 3. Client munges its transcript per §4.4.1. ───────────────────
        let hrr_hs_message = &hrr_record[RECORD_HEADER_LEN..];
        munge_client_transcript_for_hrr(&mut client_ks, &ch1, hrr_hs_message);

        // ── 4. Build CH2 with X25519 share + new binder. ──────────────────
        let ch2 = build_client_hello_dhe_with_binder_after_hrr(
            &mut client_ks,
            identity,
            &client_pub,
        );

        // ── 5. Server processes CH2 → FirstFlight. ────────────────────────
        let mut out_buf2 = [0u8; 1024];
        let flight = match session
            .process_client_hello(&ch2, &config, &mut out_buf2)
            .expect("second call")
        {
            HandshakeOutput::FirstFlight(b) => b.to_vec(),
            HandshakeOutput::HelloRetryRequest(_) => panic!("expected FirstFlight, got HRR"),
        };

        // ── 6. Client absorbs CH2 + SH into transcript, derives DHE secret. ─
        let (sh_record, ee_record, fin_record) = split_first_flight(&flight);
        client_ks.transcript_hash().update(&ch2);
        client_ks
            .transcript_hash()
            .update(&sh_record[RECORD_HEADER_LEN..]);

        // Pull server's X25519 public from SH key_share.
        let sh_body = &sh_record[RECORD_HEADER_LEN + HANDSHAKE_HEADER_LEN..];
        let mut p = ParseBuffer::new(sh_body);
        let parsed_sh = ServerHello::parse(&mut p).expect("ServerHello parse");
        let server_share = parsed_sh
            .key_share()
            .expect("server must include key_share for DHE");
        let server_pub: [u8; 32] = server_share
            .opaque
            .try_into()
            .expect("X25519 share is 32 bytes");
        assert_eq!(server_pub, server_dhe.public);

        let shared = x25519(client_secret, server_pub);
        client_ks.initialize_handshake_secret(&shared).unwrap();

        // ── 7. Decrypt EE + server Finished, verify. ──────────────────────
        let ee_inner = client_decrypt_handshake_record(&mut client_ks, ee_record);
        client_ks.transcript_hash().update(&ee_inner);
        assert_eq!(ee_inner, &[0x08, 0x00, 0x00, 0x02, 0x00, 0x00]);

        let fin_inner = client_decrypt_handshake_record(&mut client_ks, fin_record);
        let pre_fin = client_ks.transcript_hash().clone().finalize();
        client_ks.transcript_hash().update(&fin_inner);

        let mut verify = generic_array::GenericArray::default();
        verify.copy_from_slice(&fin_inner[4..4 + SHA256_LEN]);
        let server_finished = crate::handshake::finished::Finished {
            verify,
            hash: Some(pre_fin),
        };
        let (_w, client_read) = client_ks.as_split();
        assert!(
            client_read
                .verify_server_finished(&server_finished)
                .expect("verify server Finished"),
        );

        // ── 8. Client Finished → server, advance master, app data. ────────
        let client_fin = build_client_finished_record(&mut client_ks);
        session
            .process_client_finished(&client_fin)
            .expect("process_client_finished");
        client_ks.initialize_master_secret().unwrap();

        let mut srv_out = [0u8; 256];
        let s2c = session
            .encrypt_app_data(b"hrr-OK", &mut srv_out)
            .expect("server encrypt");
        let mut decoded = [0u8; 256];
        let plain = client_decrypt_app_data(&mut client_ks, s2c, &mut decoded);
        assert_eq!(plain, b"hrr-OK");
    }

    /// RFC 8446 §4.1.4: "the server MUST NOT send a HelloRetryRequest a
    /// second time". When `hrr_already_sent = true`, even a CH that would
    /// otherwise match the Retry branch must collapse to HandshakeFailure.
    #[test]
    fn decide_kex_rejects_second_hrr() {
        let identity: &[u8] = b"x";
        let layout = build_synthetic_ch_dhe_no_share(identity);
        let mut parse = ParseBuffer::new(&layout.bytes);
        let hello: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut parse).unwrap();
        let cfg = TlsServerConfig {
            psk: (identity, &[0; 32]),
            server_random: [0; 32],
            dhe_keypair: Some(DheKeyShare::from_secret([0x33; 32])),
        };

        // First time around: Retry is the right move.
        let r1 = decide_kex(&hello, &cfg, false).expect("first HRR allowed");
        assert!(matches!(
            r1,
            KexDecision::Retry {
                retry_group: NamedGroup::X25519,
            },
        ));

        // Second HRR is forbidden.
        let r2 = decide_kex(&hello, &cfg, true);
        assert!(matches!(
            r2,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::HandshakeFailure,
            )),
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // RFC 8446 §4.1.2: CH1↔CH2 consistency.
    // ─────────────────────────────────────────────────────────────────────

    /// Helper: build a snapshot with custom random / session_id values.
    fn snapshot_with(random: [u8; 32], session_id: &[u8]) -> HrrState {
        let mut s = HrrState {
            sent: true,
            ch1_random: random,
            ch1_session_id_len: session_id.len() as u8,
            ch1_session_id: [0u8; 32],
        };
        s.ch1_session_id[..session_id.len()].copy_from_slice(session_id);
        s
    }

    #[test]
    fn validate_ch2_consistency_random_mismatch() {
        let identity: &[u8] = b"x";
        let layout = build_synthetic_client_hello_dhe(identity, &[0x11; 32]);
        let mut p = ParseBuffer::new(&layout.bytes);
        let hello: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut p).unwrap();

        // hello.random == [0xa5; 32] from the builder. Snapshot something different.
        let snap = snapshot_with([0x77u8; 32], &[]);
        let result = validate_ch2_consistency(&hello, &snap);
        assert!(matches!(
            result,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::IllegalParameter,
            )),
        ));

        // Same random → ok.
        let snap_ok = snapshot_with([0xa5; 32], &[]);
        assert!(validate_ch2_consistency(&hello, &snap_ok).is_ok());
    }

    #[test]
    fn validate_ch2_consistency_session_id_mismatch() {
        let identity: &[u8] = b"x";
        let layout = build_synthetic_client_hello_dhe(identity, &[0x11; 32]);
        let mut p = ParseBuffer::new(&layout.bytes);
        let hello: ClientHelloRef<'_, CLIENT_HELLO_MAX_EXTENSIONS> =
            ClientHelloRef::parse(&mut p).unwrap();

        // Builder uses empty session_id. Snapshot a non-empty one → mismatch.
        let snap = snapshot_with([0xa5; 32], &[0xde, 0xad, 0xbe, 0xef]);
        let result = validate_ch2_consistency(&hello, &snap);
        assert!(matches!(
            result,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::IllegalParameter,
            )),
        ));
    }

    /// End-to-end: tamper the `random` byte in CH2 (after a real HRR has
    /// been issued) and verify the public API rejects it with
    /// `IllegalParameter` BEFORE attempting binder verification (which
    /// would also fail, but with a different alert).
    #[test]
    fn ch2_random_tamper_rejected_at_public_api() {
        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"x";
        let server_random = [0x77u8; 32];
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();

        let mut ch1_layout = build_synthetic_ch_dhe_no_share(identity);
        finalize_ch1_binder(&mut client_ks, &mut ch1_layout);
        let ch1 = ch1_layout.bytes.clone();

        let mut session = TlsServerSession::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe),
        };

        // Drive HRR.
        let mut out_buf = [0u8; 1024];
        let hrr = match session
            .process_client_hello(&ch1, &config, &mut out_buf)
            .expect("HRR")
        {
            HandshakeOutput::HelloRetryRequest(b) => b.to_vec(),
            _ => panic!("expected HRR"),
        };
        munge_client_transcript_for_hrr(
            &mut client_ks,
            &ch1,
            &hrr[RECORD_HEADER_LEN..],
        );

        // Build legitimate CH2.
        let client_pub = x25519([0x42u8; 32], X25519_BASEPOINT_BYTES);
        let mut ch2 = build_client_hello_dhe_with_binder_after_hrr(
            &mut client_ks,
            identity,
            &client_pub,
        );

        // Tamper byte 0 of the random (offset = 4 hs-header + 2 legacy_version).
        let random_offset = HANDSHAKE_HEADER_LEN + 2;
        ch2[random_offset] ^= 0x80;

        // Server must reject before binder verify.
        let mut out_buf2 = [0u8; 1024];
        let result = session.process_client_hello(&ch2, &config, &mut out_buf2);
        assert!(matches!(
            result,
            Err(TlsError::AbortHandshake(
                crate::alert::AlertLevel::Fatal,
                crate::alert::AlertDescription::IllegalParameter,
            )),
        ));
    }

    // ─────────────────────────────────────────────────────────────────────
    // Alert API: encrypt_alert + decrypt_app_data_or_alert.
    // ─────────────────────────────────────────────────────────────────────

    /// Drive a full DHE handshake, then have the server emit a
    /// `close_notify` alert; the "client" side decrypts it and observes
    /// `inner_ct = Alert (21)` carrying `(Warning, CloseNotify)`. Mirrors
    /// the post-handshake close path that mosquitto / openssl use.
    #[test]
    fn encrypt_alert_round_trip_close_notify() {
        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"alert-device";
        let server_random = [0x77u8; 32];

        let client_secret = [0x42u8; 32];
        let client_pub = x25519(client_secret, X25519_BASEPOINT_BYTES);
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();
        let ch_bytes =
            build_client_hello_dhe_with_binder(&mut client_ks, identity, &client_pub);

        let mut session = TlsServerSession::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe.clone()),
        };
        let mut out_buf = [0u8; 1024];
        let flight = match session
            .process_client_hello(&ch_bytes, &config, &mut out_buf)
            .expect("first flight")
        {
            HandshakeOutput::FirstFlight(b) => b.to_vec(),
            HandshakeOutput::HelloRetryRequest(_) => panic!("expected FirstFlight"),
        };

        // Mirror the client side of the handshake, ending with both peers in
        // application-traffic phase.
        let (sh_record, ee_record, fin_record) = split_first_flight(&flight);
        client_ks.transcript_hash().update(&ch_bytes);
        client_ks
            .transcript_hash()
            .update(&sh_record[RECORD_HEADER_LEN..]);
        let shared = x25519(client_secret, server_dhe.public);
        client_ks.initialize_handshake_secret(&shared).unwrap();
        let ee_inner = client_decrypt_handshake_record(&mut client_ks, ee_record);
        client_ks.transcript_hash().update(&ee_inner);
        let fin_inner = client_decrypt_handshake_record(&mut client_ks, fin_record);
        client_ks.transcript_hash().update(&fin_inner);

        let cf_record = build_client_finished_record(&mut client_ks);
        session.process_client_finished(&cf_record).expect("cFin");
        client_ks.initialize_master_secret().unwrap();

        // Now: server emits close_notify.
        let mut alert_out = [0u8; 64];
        let alert_record = session
            .encrypt_alert(
                crate::alert::AlertLevel::Warning,
                crate::alert::AlertDescription::CloseNotify,
                &mut alert_out,
            )
            .expect("encrypt_alert");

        // Outer record: ApplicationData (RFC 8446 §6).
        assert_eq!(alert_record[0], ContentType::ApplicationData as u8);

        // Client decrypts the alert via the mirror helper.
        // We reuse `client_decrypt_handshake_record` for raw plaintext but
        // note: that helper truncates the trailing inner-CT marker before
        // returning. Inner Alert payload is exactly 2 bytes pre-marker.
        let alert_inner = client_decrypt_handshake_record(&mut client_ks, alert_record);
        // After the helper trims the marker, what remains is [level, desc].
        assert_eq!(alert_inner.len(), 2);
        assert_eq!(alert_inner[0], crate::alert::AlertLevel::Warning as u8);
        assert_eq!(
            alert_inner[1],
            crate::alert::AlertDescription::CloseNotify as u8,
        );
    }

    /// `decrypt_app_data_or_alert` distinguishes user data from a
    /// peer-initiated Alert. We drive the symmetric flow: client sends a
    /// "real" application record, then a close_notify alert. The server
    /// sees `AppData` then `Alert(Warning, CloseNotify)`.
    #[test]
    fn decrypt_app_data_or_alert_distinguishes_alerts() {
        let psk = [0xc0u8; 32];
        let identity: &[u8] = b"alert-rx-device";
        let server_random = [0x77u8; 32];

        let client_secret = [0x42u8; 32];
        let client_pub = x25519(client_secret, X25519_BASEPOINT_BYTES);
        let server_dhe = DheKeyShare::from_secret([0x99u8; 32]);

        let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
        client_ks.initialize_early_secret(Some(&psk)).unwrap();
        let ch_bytes =
            build_client_hello_dhe_with_binder(&mut client_ks, identity, &client_pub);

        let mut session = TlsServerSession::new();
        let config = TlsServerConfig {
            psk: (identity, &psk),
            server_random,
            dhe_keypair: Some(server_dhe.clone()),
        };
        let mut out_buf = [0u8; 1024];
        let flight = match session
            .process_client_hello(&ch_bytes, &config, &mut out_buf)
            .expect("first flight")
        {
            HandshakeOutput::FirstFlight(b) => b.to_vec(),
            _ => panic!("expected FirstFlight"),
        };
        let (sh_record, ee_record, fin_record) = split_first_flight(&flight);
        client_ks.transcript_hash().update(&ch_bytes);
        client_ks
            .transcript_hash()
            .update(&sh_record[RECORD_HEADER_LEN..]);
        let shared = x25519(client_secret, server_dhe.public);
        client_ks.initialize_handshake_secret(&shared).unwrap();
        let ee_inner = client_decrypt_handshake_record(&mut client_ks, ee_record);
        client_ks.transcript_hash().update(&ee_inner);
        let fin_inner = client_decrypt_handshake_record(&mut client_ks, fin_record);
        client_ks.transcript_hash().update(&fin_inner);
        let cf_record = build_client_finished_record(&mut client_ks);
        session.process_client_finished(&cf_record).expect("cFin");
        client_ks.initialize_master_secret().unwrap();

        // 1. Real app data: client → server.
        let mut cli_out = [0u8; 256];
        let app_record = client_encrypt_app_data(&mut client_ks, b"hello", &mut cli_out);
        let mut decoded = [0u8; 256];
        let result = session
            .decrypt_app_data_or_alert(app_record, &mut decoded)
            .expect("decrypt app");
        match result {
            AppDataOrAlert::AppData(plaintext) => assert_eq!(plaintext, b"hello"),
            AppDataOrAlert::Alert { .. } => panic!("expected AppData"),
        }

        // 2. close_notify alert: client → server. Build manually using the
        //    client-side AEAD keys with inner CT = Alert.
        let alert_record = client_encrypt_alert(
            &mut client_ks,
            crate::alert::AlertLevel::Warning,
            crate::alert::AlertDescription::CloseNotify,
        );
        let mut decoded2 = [0u8; 256];
        let result2 = session
            .decrypt_app_data_or_alert(&alert_record, &mut decoded2)
            .expect("decrypt alert");
        match result2 {
            AppDataOrAlert::Alert { level, description } => {
                assert!(matches!(level, crate::alert::AlertLevel::Warning));
                assert!(matches!(
                    description,
                    crate::alert::AlertDescription::CloseNotify,
                ));
            }
            AppDataOrAlert::AppData(_) => panic!("expected Alert"),
        }
    }

    /// Mirror of `encrypt_alert_record` from the CLIENT's perspective:
    /// uses client_state (its outbound key) to produce a TLSCiphertext
    /// alert record.
    fn client_encrypt_alert(
        client_ks: &mut KeySchedule<Aes128GcmSha256>,
        level: crate::alert::AlertLevel,
        description: crate::alert::AlertDescription,
    ) -> std::vec::Vec<u8> {
        let plaintext_with_marker = 3usize; // level + desc + inner CT
        let ciphertext_len = plaintext_with_marker + AES_GCM_TAG_SIZE;
        let len_bytes = (ciphertext_len as u16).to_be_bytes();

        let mut record = std::vec::Vec::with_capacity(RECORD_HEADER_LEN + ciphertext_len);
        record.extend_from_slice(&[
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ]);

        let additional_data = [
            ContentType::ApplicationData as u8,
            0x03,
            0x03,
            len_bytes[0],
            len_bytes[1],
        ];

        let mut backing = [0u8; 64];
        backing[0] = level as u8;
        backing[1] = description as u8;
        backing[2] = ContentType::Alert as u8;

        let key = client_ks.write_state().get_key().unwrap().clone();
        let nonce = client_ks.write_state().get_nonce().unwrap();
        let cipher = <<Aes128GcmSha256 as TlsCipherSuite>::Cipher as KeyInit>::new(&key);
        let mut crypto =
            CryptoBuffer::wrap_with_pos(&mut backing[..ciphertext_len], plaintext_with_marker);
        cipher
            .encrypt_in_place(&nonce, &additional_data, &mut crypto)
            .unwrap();
        client_ks.write_state().increment_counter();

        record.extend_from_slice(&backing[..ciphertext_len]);
        record
    }
}

