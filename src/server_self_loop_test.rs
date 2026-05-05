//! Phase 1.3 (a): Self-loop integration test for the server-mode primitives.
//!
//! Drives a full PSK_KE handshake from the server's perspective using the
//! pieces built in Phase 1.1 + 1.2 — `ClientHelloRef::parse`,
//! `KeySchedule::verify_psk_binder`, `ServerHelloEmit::encode`,
//! `EncryptedExtensionsEmit::encode`, `KeySchedule::create_server_finished`,
//! and `KeySchedule::verify_client_finished`. No real socket, no async; just
//! bytes-in / bytes-out symmetric checks.
//!
//! What this proves:
//!   * the parser and the binder verifier compose on a synthesised ClientHello
//!   * the key schedule transitions (early → handshake → master) work for the
//!     PSK_KE branch (handshake_secret IKM = all zeros)
//!   * server's Finished is consistent with the client's view of the schedule
//!     (verified via the existing client-side `verify_server_finished`)

use crate::buffer::CryptoBuffer;
use crate::config::Aes128GcmSha256;
use crate::extensions::extension_data::pre_shared_key::PreSharedKeyServerHello;
use crate::extensions::extension_data::supported_versions::{
    SupportedVersionsServerHello, TLS13,
};
use crate::extensions::messages::{ClientHelloExtension, ServerHelloExtension};
use crate::handshake::client_hello::ClientHelloRef;
use crate::handshake::encrypted_extensions::EncryptedExtensionsEmit;
use crate::handshake::server_hello::ServerHelloEmit;
use crate::key_schedule::KeySchedule;
use crate::parse_buffer::ParseBuffer;
use heapless::Vec as HVec;
use sha2::{Digest, Sha256};

// ─── Wire-format constants ───────────────────────────────────────────────────
const HS_TYPE_CLIENT_HELLO: u8 = 0x01;
const LEGACY_VERSION: u16 = 0x0303;
const TLS13_VERSION: u16 = 0x0304;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const PSK_KE_MODE: u8 = 0;
const SHA256_LEN: usize = 32;

/// Carved-out positions of patchable fields in a synthesised ClientHello.
struct ChLayout {
    bytes: std::vec::Vec<u8>,
    /// Offset where the partial-transcript ends (= start of binders section).
    binders_start_offset: usize,
    /// Offset of the first byte of the (placeholder) binder value itself.
    binder_value_pos: usize,
}

/// Build a minimal psk_ke ClientHello with a placeholder binder. The caller
/// fills in the real binder bytes after computing them via the key schedule.
///
/// Layout:
///   handshake_header(4) || legacy_version(2) || random(32) || sid_len(1) ||
///   cipher_suites(4) || compression(2) ||
///   extensions { supported_versions, psk_key_exchange_modes, pre_shared_key }
fn build_synthetic_client_hello(identity: &[u8]) -> ChLayout {
    let mut out = std::vec::Vec::with_capacity(256);

    // 0..1: handshake_type
    out.push(HS_TYPE_CLIENT_HELLO);
    // 1..4: u24 length (placeholder)
    out.extend_from_slice(&[0, 0, 0]);
    let body_start = out.len(); // 4

    // legacy_version
    out.extend_from_slice(&LEGACY_VERSION.to_be_bytes());
    // random — fixed pattern so tests are deterministic
    out.extend_from_slice(&[0xa5; 32]);
    // legacy_session_id<0..32>
    out.push(0);
    // cipher_suites<2..2^16-2>
    out.extend_from_slice(&2u16.to_be_bytes());
    out.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    // legacy_compression_methods<1..2^8-1>
    out.push(1);
    out.push(0);

    // extensions<8..2^16-1>
    let ext_list_len_pos = out.len();
    out.extend_from_slice(&[0, 0]); // placeholder u16
    let ext_content_start = out.len();

    // supported_versions
    out.extend_from_slice(&EXT_SUPPORTED_VERSIONS.to_be_bytes());
    out.extend_from_slice(&3u16.to_be_bytes()); // ext_data_len
    out.push(2); // versions list u8 length
    out.extend_from_slice(&TLS13_VERSION.to_be_bytes());

    // psk_key_exchange_modes
    out.extend_from_slice(&EXT_PSK_KEY_EXCHANGE_MODES.to_be_bytes());
    out.extend_from_slice(&2u16.to_be_bytes()); // ext_data_len
    out.push(1); // modes list u8 length
    out.push(PSK_KE_MODE);

    // pre_shared_key (MUST be last per RFC 8446 §4.2.11)
    out.extend_from_slice(&EXT_PRE_SHARED_KEY.to_be_bytes());
    let psk_data_len_pos = out.len();
    out.extend_from_slice(&[0, 0]); // ext_data_len placeholder
    let psk_data_start = out.len();

    // identities<7..2^16-1>: u16 length + entries
    let id_entry_len = 2 + identity.len() + 4;
    out.extend_from_slice(&(id_entry_len as u16).to_be_bytes());
    out.extend_from_slice(&(identity.len() as u16).to_be_bytes());
    out.extend_from_slice(identity);
    out.extend_from_slice(&0u32.to_be_bytes()); // obfuscated_ticket_age

    // binders<33..2^16-1>: u16 length + entries
    let binders_start_offset = out.len();
    let binders_section_len: u16 = 1 + SHA256_LEN as u16; // single binder
    out.extend_from_slice(&binders_section_len.to_be_bytes());
    out.push(SHA256_LEN as u8);
    let binder_value_pos = out.len();
    out.extend_from_slice(&[0u8; SHA256_LEN]); // placeholder binder
    let psk_data_end = out.len();

    // Back-patch the three lengths.
    let psk_data_len = (psk_data_end - psk_data_start) as u16;
    out[psk_data_len_pos..psk_data_len_pos + 2]
        .copy_from_slice(&psk_data_len.to_be_bytes());

    let ext_content_end = out.len();
    let ext_list_len = (ext_content_end - ext_content_start) as u16;
    out[ext_list_len_pos..ext_list_len_pos + 2]
        .copy_from_slice(&ext_list_len.to_be_bytes());

    let body_end = out.len();
    let body_len = (body_end - body_start) as u32;
    // u24 length lives at out[1..4]
    out[1] = (body_len >> 16) as u8;
    out[2] = (body_len >> 8) as u8;
    out[3] = body_len as u8;

    ChLayout {
        bytes: out,
        binders_start_offset,
        binder_value_pos,
    }
}

#[test]
fn full_psk_ke_handshake_self_loop() {
    // ── Setup: a single external PSK shared by both peers. ─────────────────
    let psk = [0x42u8; 32];
    let identity: &[u8] = b"smartbox-house-1";

    // ── Step 1: synthesize a ClientHello with placeholder binder. ──────────
    let mut layout = build_synthetic_client_hello(identity);

    // ── Step 2: client-side computes the binder over the ClientHello prefix
    // using its own KeySchedule. (We're standing in for the client.)
    let mut client_ks = KeySchedule::<Aes128GcmSha256>::new();
    client_ks
        .initialize_early_secret(Some(&psk))
        .expect("client init early secret");

    // Hash the prefix bytes [0 .. binders_start_offset] into a transcript.
    let mut prefix_hash: Sha256 = Digest::new();
    prefix_hash.update(&layout.bytes[..layout.binders_start_offset]);

    let (write_state, _read_state) = client_ks.as_split();
    let binder = write_state
        .create_psk_binder(&prefix_hash)
        .expect("client create binder");

    // Splice the real binder into the ClientHello buffer.
    layout.bytes[layout.binder_value_pos..layout.binder_value_pos + SHA256_LEN]
        .copy_from_slice(binder.verify.as_slice());

    // ── Step 3: server parses the ClientHello. ─────────────────────────────
    let mut parse_buf = ParseBuffer::new(&layout.bytes);
    let hello: ClientHelloRef<'_, 16> =
        ClientHelloRef::parse(&mut parse_buf).expect("server parse CH");
    assert_eq!(
        hello.binders_start_offset, layout.binders_start_offset,
        "parser and synthesiser must agree on the binder boundary",
    );

    // Pull out PSK identity + binder bytes from the parsed extensions.
    let (parsed_identity, parsed_binder) = hello
        .extensions
        .iter()
        .find_map(|ext| {
            if let ClientHelloExtension::PreSharedKey(p) = ext {
                Some((p.identities[0], p.binders[0]))
            } else {
                None
            }
        })
        .expect("CH has pre_shared_key extension");
    assert_eq!(parsed_identity, identity);
    assert_eq!(parsed_binder.len(), SHA256_LEN);

    // ── Step 4: server "looks up" PSK by identity, initialises its own key
    // schedule with that PSK, and verifies the binder. ─────────────────────
    let mut server_ks = KeySchedule::<Aes128GcmSha256>::new();
    server_ks
        .initialize_early_secret(Some(&psk))
        .expect("server init early secret");

    // Server recomputes the partial transcript hash over CH[0..binders_start].
    let mut server_prefix_hash: Sha256 = Digest::new();
    server_prefix_hash.update(&layout.bytes[..hello.binders_start_offset]);

    let binder_ok = server_ks
        .verify_psk_binder(&server_prefix_hash, parsed_binder)
        .expect("server verify binder");
    assert!(binder_ok, "server must accept the client's binder");

    // ── Step 5: from this point both sides feed the FULL ClientHello (incl.
    // binders) into the running transcript. ────────────────────────────────
    server_ks.transcript_hash().update(&layout.bytes);

    // ── Step 6: server emits ServerHello body. ─────────────────────────────
    let server_random = [0xc3u8; 32];
    let mut sh_extensions: HVec<ServerHelloExtension<'_>, 4> = HVec::new();
    sh_extensions
        .push(ServerHelloExtension::SupportedVersions(
            SupportedVersionsServerHello {
                selected_version: TLS13,
            },
        ))
        .unwrap();
    sh_extensions
        .push(ServerHelloExtension::PreSharedKey(PreSharedKeyServerHello {
            selected_identity: 0,
        }))
        .unwrap();

    let sh_emit = ServerHelloEmit {
        random: server_random,
        legacy_session_id_echo: hello.legacy_session_id,
        cipher_suite: TLS_AES_128_GCM_SHA256,
        extensions: sh_extensions,
    };

    let mut sh_backing = [0u8; 256];
    let mut sh_buf = CryptoBuffer::wrap(&mut sh_backing);
    sh_emit.encode(&mut sh_buf).expect("encode ServerHello");
    let sh_body_len = sh_buf.len();

    // Wrap with handshake header (type=2, u24 length).
    let mut sh_message = std::vec::Vec::with_capacity(4 + sh_body_len);
    sh_message.push(0x02); // HandshakeType::ServerHello
    sh_message.extend_from_slice(&[
        0,
        (sh_body_len >> 8) as u8,
        sh_body_len as u8,
    ]);
    sh_message.extend_from_slice(&sh_backing[..sh_body_len]);
    server_ks.transcript_hash().update(&sh_message);

    // ── Step 7: NOW initialize handshake_secret. Per RFC 8446 §7.1 the
    // c_hs_traffic and s_hs_traffic secrets are derived from
    // Derive-Secret(handshake_secret, label, CH || SH) — meaning both CH
    // and SH must already be in the transcript by this point. PSK_KE: IKM
    // is hash-output-size zeros. ───────────────────────────────────────────
    server_ks
        .initialize_handshake_secret(&[0u8; 32])
        .expect("server init handshake secret");

    // ── Step 8: server emits EncryptedExtensions (empty for plain PSK). ────
    let ee_emit: EncryptedExtensionsEmit<'_, 4> = EncryptedExtensionsEmit::default();
    let mut ee_backing = [0u8; 16];
    let mut ee_buf = CryptoBuffer::wrap(&mut ee_backing);
    ee_emit.encode(&mut ee_buf).expect("encode EE");
    let ee_body_len = ee_buf.len();
    assert_eq!(&ee_backing[..ee_body_len], &[0x00, 0x00]);

    let mut ee_message = std::vec::Vec::with_capacity(4 + ee_body_len);
    ee_message.push(0x08); // HandshakeType::EncryptedExtensions
    ee_message.extend_from_slice(&[
        0,
        (ee_body_len >> 8) as u8,
        ee_body_len as u8,
    ]);
    ee_message.extend_from_slice(&ee_backing[..ee_body_len]);
    server_ks.transcript_hash().update(&ee_message);

    // ── Step 9: server creates its Finished. ───────────────────────────────
    let mut server_finished = server_ks
        .create_server_finished()
        .expect("server create Finished");

    // ── Step 10: simulate the client receiving SH, EE, and Finished. The
    // client does the same key-schedule transitions (init handshake secret
    // with zeros, feed transcript) and then verifies server's Finished.
    // We re-use `client_ks` from earlier — its early secret is already set
    // and its transcript needs to be brought up to the same state.
    client_ks.transcript_hash().update(&layout.bytes); // CH (with real binder)
    client_ks.transcript_hash().update(&sh_message);
    client_ks
        .initialize_handshake_secret(&[0u8; 32])
        .expect("client init handshake secret");
    client_ks.transcript_hash().update(&ee_message);

    // The client's verify_server_finished consumes finished.hash, which is the
    // transcript snapshot taken BEFORE the Finished bytes are absorbed.
    server_finished.hash = Some(client_ks.transcript_hash().clone().finalize());
    let (_w, client_read) = client_ks.as_split();
    assert!(
        client_read
            .verify_server_finished(&server_finished)
            .expect("client verify server Finished"),
        "server's Finished must verify under the client's parallel schedule",
    );
}
