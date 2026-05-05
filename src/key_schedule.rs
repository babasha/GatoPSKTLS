use crate::handshake::binder::PskBinder;
use crate::handshake::finished::Finished;
use crate::{TlsError, config::TlsCipherSuite};
use digest::OutputSizeUser;
use digest::generic_array::ArrayLength;
use hmac::{Mac, SimpleHmac};
use sha2::Digest;
use sha2::digest::generic_array::{GenericArray, typenum::Unsigned};

pub type HashOutputSize<CipherSuite> =
    <<CipherSuite as TlsCipherSuite>::Hash as OutputSizeUser>::OutputSize;
pub type LabelBufferSize<CipherSuite> = <CipherSuite as TlsCipherSuite>::LabelBufferSize;

pub type IvArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::IvLen>;
pub type KeyArray<CipherSuite> = GenericArray<u8, <CipherSuite as TlsCipherSuite>::KeyLen>;
pub type HashArray<CipherSuite> = GenericArray<u8, HashOutputSize<CipherSuite>>;

type Hkdf<CipherSuite> = hkdf::Hkdf<
    <CipherSuite as TlsCipherSuite>::Hash,
    SimpleHmac<<CipherSuite as TlsCipherSuite>::Hash>,
>;

enum Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    Uninitialized,
    Initialized(Hkdf<CipherSuite>),
}

impl<CipherSuite> Secret<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn replace(&mut self, secret: Hkdf<CipherSuite>) {
        *self = Self::Initialized(secret);
    }

    fn as_ref(&self) -> Result<&Hkdf<CipherSuite>, TlsError> {
        match self {
            Secret::Initialized(secret) => Ok(secret),
            Secret::Uninitialized => Err(TlsError::InternalError),
        }
    }

    fn make_expanded_hkdf_label<N: ArrayLength<u8>>(
        &self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<GenericArray<u8, N>, TlsError> {
        //info!("make label {:?} {}", label, len);
        let mut hkdf_label = heapless_typenum::Vec::<u8, LabelBufferSize<CipherSuite>>::new();
        hkdf_label
            .extend_from_slice(&N::to_u16().to_be_bytes())
            .map_err(|()| TlsError::InternalError)?;

        let label_len = 6 + label.len() as u8;
        hkdf_label
            .extend_from_slice(&label_len.to_be_bytes())
            .map_err(|()| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(b"tls13 ")
            .map_err(|()| TlsError::InternalError)?;
        hkdf_label
            .extend_from_slice(label)
            .map_err(|()| TlsError::InternalError)?;

        match context_type {
            ContextType::None => {
                hkdf_label.push(0).map_err(|_| TlsError::InternalError)?;
            }
            ContextType::Hash(context) => {
                hkdf_label
                    .extend_from_slice(&(context.len() as u8).to_be_bytes())
                    .map_err(|()| TlsError::InternalError)?;
                hkdf_label
                    .extend_from_slice(&context)
                    .map_err(|()| TlsError::InternalError)?;
            }
        }

        let mut okm = GenericArray::default();
        //info!("label {:x?}", label);
        self.as_ref()?
            .expand(&hkdf_label, &mut okm)
            .map_err(|_| TlsError::CryptoError)?;
        //info!("expand {:x?}", okm);
        Ok(okm)
    }
}

pub struct SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    secret: HashArray<CipherSuite>,
    hkdf: Secret<CipherSuite>,
}

impl<CipherSuite> SharedState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            secret: GenericArray::default(),
            hkdf: Secret::Uninitialized,
        }
    }

    fn initialize(&mut self, ikm: &[u8]) {
        let (secret, hkdf) = Hkdf::<CipherSuite>::extract(Some(self.secret.as_ref()), ikm);
        self.hkdf.replace(hkdf);
        self.secret = secret;
    }

    fn derive_secret(
        &mut self,
        label: &[u8],
        context_type: ContextType<CipherSuite>,
    ) -> Result<HashArray<CipherSuite>, TlsError> {
        self.hkdf
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(label, context_type)
    }

    fn derived(&mut self) -> Result<(), TlsError> {
        self.secret = self.derive_secret(b"derived", ContextType::empty_hash())?;
        Ok(())
    }
}

pub(crate) struct KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_secret: Secret<CipherSuite>,
    counter: u64,
    key: KeyArray<CipherSuite>,
    iv: IvArray<CipherSuite>,
}

impl<CipherSuite> KeyScheduleState<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn new() -> Self {
        Self {
            traffic_secret: Secret::Uninitialized,
            counter: 0,
            key: KeyArray::<CipherSuite>::default(),
            iv: IvArray::<CipherSuite>::default(),
        }
    }

    #[inline]
    pub fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        Ok(&self.key)
    }

    #[inline]
    pub fn get_iv(&self) -> Result<&IvArray<CipherSuite>, TlsError> {
        Ok(&self.iv)
    }

    pub fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        let iv = self.get_iv()?;
        Ok(KeySchedule::<CipherSuite>::get_nonce(self.counter, iv))
    }

    fn calculate_traffic_secret(
        &mut self,
        label: &[u8],
        shared: &mut SharedState<CipherSuite>,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<(), TlsError> {
        let secret = shared.derive_secret(label, ContextType::transcript_hash(transcript_hash))?;
        let traffic_secret =
            Hkdf::<CipherSuite>::from_prk(&secret).map_err(|_| TlsError::InternalError)?;

        self.traffic_secret.replace(traffic_secret);
        self.key = self
            .traffic_secret
            .make_expanded_hkdf_label(b"key", ContextType::None)?;
        self.iv = self
            .traffic_secret
            .make_expanded_hkdf_label(b"iv", ContextType::None)?;
        self.counter = 0;
        Ok(())
    }

    pub fn increment_counter(&mut self) {
        self.counter = unwrap!(self.counter.checked_add(1));
    }
}

enum ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    None,
    Hash(HashArray<CipherSuite>),
}

impl<CipherSuite> ContextType<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn transcript_hash(hash: &CipherSuite::Hash) -> Self {
        Self::Hash(hash.clone().finalize())
    }

    fn empty_hash() -> Self {
        Self::Hash(
            <CipherSuite::Hash as Digest>::new()
                .chain_update([])
                .finalize(),
        )
    }
}

pub struct KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    shared: SharedState<CipherSuite>,
    client_state: WriteKeySchedule<CipherSuite>,
    server_state: ReadKeySchedule<CipherSuite>,
}

impl<CipherSuite> KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Self {
        Self {
            shared: SharedState::new(),
            client_state: WriteKeySchedule {
                state: KeyScheduleState::new(),
                binder_key: Secret::Uninitialized,
            },
            server_state: ReadKeySchedule {
                state: KeyScheduleState::new(),
                transcript_hash: <CipherSuite::Hash as Digest>::new(),
            },
        }
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.server_state.transcript_hash
    }

    pub(crate) fn replace_transcript_hash(&mut self, hash: CipherSuite::Hash) {
        self.server_state.transcript_hash = hash;
    }

    pub fn as_split(
        &mut self,
    ) -> (
        &mut WriteKeySchedule<CipherSuite>,
        &mut ReadKeySchedule<CipherSuite>,
    ) {
        (&mut self.client_state, &mut self.server_state)
    }

    pub(crate) fn write_state(&mut self) -> &mut WriteKeySchedule<CipherSuite> {
        &mut self.client_state
    }

    pub(crate) fn read_state(&mut self) -> &mut ReadKeySchedule<CipherSuite> {
        &mut self.server_state
    }

    pub fn create_client_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(
            &mut hmac,
            &self.server_state.transcript_hash.clone().finalize(),
        );
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    /// Server-side mirror of `WriteKeySchedule::create_psk_binder`: given the
    /// transcript-hash state at the point of the binder (i.e., the digest fed
    /// with `ClientHello[0..binders_start_offset]`) and the binder bytes pulled
    /// off the wire, recompute the expected MAC and compare in constant time.
    ///
    /// `initialize_early_secret(Some(psk))` must have been called first so the
    /// binder key is materialised. Returns `Ok(true)` iff the binder matches.
    pub fn verify_psk_binder(
        &self,
        transcript_hash: &CipherSuite::Hash,
        received: &[u8],
    ) -> Result<bool, TlsError> {
        let key = self
            .client_state
            .binder_key
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &transcript_hash.clone().finalize());
        // verify_slice does a constant-time compare under the hood (subtle).
        Ok(hmac.verify_slice(received).is_ok())
    }

    /// Server-side analogue of `create_client_finished`: build the Finished
    /// message the server sends, MAC'd with the server-side handshake traffic
    /// secret over the running transcript hash. `initialize_handshake_secret`
    /// must have been called before this.
    pub fn create_server_finished(
        &self,
    ) -> Result<Finished<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .server_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(
            &mut hmac,
            &self.server_state.transcript_hash.clone().finalize(),
        );
        let verify = hmac.finalize().into_bytes();

        Ok(Finished { verify, hash: None })
    }

    /// Verify a Finished message received from the client. The `finished.hash`
    /// field must hold the transcript-hash snapshot captured BEFORE the
    /// Finished message bytes themselves were absorbed into the running
    /// digest — `ServerHandshake::read` populates this for the client-side
    /// verify of server Finished, server-mode does the symmetric thing.
    pub fn verify_client_finished(
        &self,
        finished: &Finished<HashOutputSize<CipherSuite>>,
    ) -> Result<bool, TlsError> {
        let key = self
            .client_state
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::InternalError)?;
        Mac::update(
            &mut hmac,
            finished.hash.as_ref().ok_or_else(|| {
                warn!("No transcript snapshot in client Finished");
                TlsError::InternalError
            })?,
        );
        Ok(hmac.verify(&finished.verify).is_ok())
    }

    fn get_nonce(counter: u64, iv: &IvArray<CipherSuite>) -> IvArray<CipherSuite> {
        //info!("counter = {} {:x?}", counter, &counter.to_be_bytes(),);
        let counter = Self::pad::<CipherSuite::IvLen>(&counter.to_be_bytes());

        //info!("counter = {:x?}", counter);
        // info!("iv = {:x?}", iv);

        let mut nonce = GenericArray::default();

        for (index, (l, r)) in iv[0..CipherSuite::IvLen::to_usize()]
            .iter()
            .zip(counter.iter())
            .enumerate()
        {
            nonce[index] = l ^ r;
        }

        //debug!("nonce {:x?}", nonce);

        nonce
    }

    fn pad<N: ArrayLength<u8>>(input: &[u8]) -> GenericArray<u8, N> {
        // info!("padding input = {:x?}", input);
        let mut padded = GenericArray::default();
        for (index, byte) in input.iter().rev().enumerate() {
            /*info!(
                "{} pad {}={:x?}",
                index,
                ((N::to_usize() - index) - 1),
                *byte
            );*/
            padded[(N::to_usize() - index) - 1] = *byte;
        }
        padded
    }

    fn zero() -> HashArray<CipherSuite> {
        GenericArray::default()
    }

    // Initializes the early secrets with a callback for any PSK binders
    pub fn initialize_early_secret(&mut self, psk: Option<&[u8]>) -> Result<(), TlsError> {
        self.shared.initialize(
            #[allow(clippy::or_fun_call)]
            psk.unwrap_or(Self::zero().as_slice()),
        );

        let binder_key = self
            .shared
            .derive_secret(b"ext binder", ContextType::empty_hash())?;
        self.client_state.binder_key.replace(
            Hkdf::<CipherSuite>::from_prk(&binder_key).map_err(|_| TlsError::InternalError)?,
        );
        self.shared.derived()
    }

    pub fn initialize_handshake_secret(&mut self, ikm: &[u8]) -> Result<(), TlsError> {
        self.shared.initialize(ikm);

        self.calculate_traffic_secrets(b"c hs traffic", b"s hs traffic")?;
        self.shared.derived()
    }

    /// Convenience for the PSK-only `psk_ke` mode where there is no (EC)DHE
    /// shared secret to feed into the handshake-secret extraction. RFC 8446
    /// §7.1: when a secret isn't available the all-zero string of `Hash.length`
    /// bytes stands in.
    pub fn initialize_handshake_secret_psk_ke(&mut self) -> Result<(), TlsError> {
        self.initialize_handshake_secret(Self::zero().as_slice())
    }

    pub fn initialize_master_secret(&mut self) -> Result<(), TlsError> {
        self.shared.initialize(Self::zero().as_slice());

        //let context = self.transcript_hash.as_ref().unwrap().clone().finalize();
        //info!("Derive keys, hash: {:x?}", context);

        self.calculate_traffic_secrets(b"c ap traffic", b"s ap traffic")?;
        self.shared.derived()
    }

    fn calculate_traffic_secrets(
        &mut self,
        client_label: &[u8],
        server_label: &[u8],
    ) -> Result<(), TlsError> {
        self.client_state.state.calculate_traffic_secret(
            client_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        self.server_state.state.calculate_traffic_secret(
            server_label,
            &mut self.shared,
            &self.server_state.transcript_hash,
        )?;

        Ok(())
    }
}

impl<CipherSuite> Default for KeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    fn default() -> Self {
        KeySchedule::new()
    }
}

pub struct WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    binder_key: Secret<CipherSuite>,
}
impl<CipherSuite> WriteKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub fn create_psk_binder(
        &self,
        transcript_hash: &CipherSuite::Hash,
    ) -> Result<PskBinder<HashOutputSize<CipherSuite>>, TlsError> {
        let key = self
            .binder_key
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;

        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::CryptoError)?;
        Mac::update(&mut hmac, &transcript_hash.clone().finalize());
        let verify = hmac.finalize().into_bytes();
        Ok(PskBinder { verify })
    }
}

pub struct ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    state: KeyScheduleState<CipherSuite>,
    transcript_hash: CipherSuite::Hash,
}

impl<CipherSuite> ReadKeySchedule<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub(crate) fn increment_counter(&mut self) {
        self.state.increment_counter();
    }

    pub(crate) fn transcript_hash(&mut self) -> &mut CipherSuite::Hash {
        &mut self.transcript_hash
    }

    pub(crate) fn get_key(&self) -> Result<&KeyArray<CipherSuite>, TlsError> {
        self.state.get_key()
    }

    pub(crate) fn get_nonce(&self) -> Result<IvArray<CipherSuite>, TlsError> {
        self.state.get_nonce()
    }

    pub fn verify_server_finished(
        &self,
        finished: &Finished<HashOutputSize<CipherSuite>>,
    ) -> Result<bool, TlsError> {
        //info!("verify server finished: {:x?}", finished.verify);
        //self.client_traffic_secret.as_ref().unwrap().expand()
        //info!("size ===> {}", D::OutputSize::to_u16());
        let key = self
            .state
            .traffic_secret
            .make_expanded_hkdf_label::<HashOutputSize<CipherSuite>>(
                b"finished",
                ContextType::None,
            )?;
        // info!("hmac sign key {:x?}", key);
        let mut hmac = SimpleHmac::<CipherSuite::Hash>::new_from_slice(&key)
            .map_err(|_| TlsError::InternalError)?;
        Mac::update(
            &mut hmac,
            finished.hash.as_ref().ok_or_else(|| {
                warn!("No hash in Finished");
                TlsError::InternalError
            })?,
        );
        //let code = hmac.clone().finalize().into_bytes();
        Ok(hmac.verify(&finished.verify).is_ok())
        //info!("verified {:?}", verified);
        //unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Aes128GcmSha256;
    use sha2::Sha256;

    /// Round-trip: a binder created by `WriteKeySchedule::create_psk_binder` for
    /// a given transcript must be accepted by `KeySchedule::verify_psk_binder`
    /// for the same transcript and rejected for a tampered-with version.
    #[test]
    fn psk_binder_create_then_verify() {
        let psk = [0x42u8; 32];
        let mut ks = KeySchedule::<Aes128GcmSha256>::new();
        ks.initialize_early_secret(Some(&psk))
            .expect("init early secret");

        // Synthetic transcript: arbitrary bytes hashed into the running digest.
        let mut transcript: Sha256 = Digest::new();
        transcript.update(b"\x01\x00\x01\xfc"); // bogus ClientHello header
        transcript.update(b"the rest of a partial ClientHello prefix");

        // Client side: produce binder.
        let (write_state, _read_state) = ks.as_split();
        let binder = write_state
            .create_psk_binder(&transcript)
            .expect("create binder");

        // Server side: same transcript, same key -> verify should accept.
        assert!(
            ks.verify_psk_binder(&transcript, binder.verify.as_slice())
                .expect("verify binder"),
            "binder must verify against the transcript that produced it",
        );

        // Flip one bit; verify must reject.
        let mut tampered: std::vec::Vec<u8> = binder.verify.as_slice().to_vec();
        tampered[0] ^= 0x01;
        assert!(
            !ks.verify_psk_binder(&transcript, &tampered)
                .expect("verify tampered"),
            "single-bit flip must be detected",
        );

        // Different transcript, same binder bytes; verify must reject.
        let mut other_transcript: Sha256 = Digest::new();
        other_transcript.update(b"this is a different transcript entirely");
        assert!(
            !ks.verify_psk_binder(&other_transcript, binder.verify.as_slice())
                .expect("verify wrong transcript"),
            "binder must not verify against a different transcript",
        );
    }

    /// Server's Finished, produced by `create_server_finished`, must be
    /// accepted by `ReadKeySchedule::verify_server_finished` for the same key
    /// schedule state and same transcript snapshot.
    #[test]
    fn server_finished_round_trip() {
        let psk = [0xa5u8; 32];
        let mut ks = KeySchedule::<Aes128GcmSha256>::new();
        ks.initialize_early_secret(Some(&psk)).unwrap();
        // psk_ke: handshake_secret IKM is all zeros (RFC 8446 §7.1).
        ks.initialize_handshake_secret(&[0u8; 32]).unwrap();

        // Feed some bogus handshake bytes so transcript_hash is non-empty.
        ks.transcript_hash().update(b"ClientHello||ServerHello");

        let mut finished = ks.create_server_finished().expect("create");
        // verify_server_finished expects the transcript snapshot in finished.hash.
        finished.hash = Some(ks.transcript_hash().clone().finalize());

        let (_write, read) = ks.as_split();
        assert!(
            read.verify_server_finished(&finished).expect("verify"),
            "server's own Finished must verify against its own state",
        );

        // Tamper: flip a bit -> must be rejected.
        let mut tampered = finished;
        tampered.verify[0] ^= 0x01;
        assert!(
            !read.verify_server_finished(&tampered).expect("verify tampered"),
        );
    }

    /// Client Finished (produced by `create_client_finished`) must be accepted
    /// by `verify_client_finished` for the same key schedule + transcript.
    #[test]
    fn client_finished_round_trip() {
        let psk = [0x33u8; 32];
        let mut ks = KeySchedule::<Aes128GcmSha256>::new();
        ks.initialize_early_secret(Some(&psk)).unwrap();
        ks.initialize_handshake_secret(&[0u8; 32]).unwrap();
        ks.transcript_hash().update(b"transcript through server Finished");

        let mut finished = ks.create_client_finished().expect("create");
        finished.hash = Some(ks.transcript_hash().clone().finalize());

        assert!(
            ks.verify_client_finished(&finished).expect("verify"),
            "client's Finished must verify with the server's view of the schedule",
        );

        // Wrong-PSK schedule: must reject.
        let other_psk = [0x77u8; 32];
        let mut ks_other = KeySchedule::<Aes128GcmSha256>::new();
        ks_other.initialize_early_secret(Some(&other_psk)).unwrap();
        ks_other.initialize_handshake_secret(&[0u8; 32]).unwrap();
        ks_other
            .transcript_hash()
            .update(b"transcript through server Finished");
        assert!(
            !ks_other
                .verify_client_finished(&finished)
                .expect("verify other"),
            "Finished from one PSK must not verify under another PSK",
        );
    }

    /// Wrong-length received binder is rejected (defends against length-confusion
    /// or short-buffer attacks before constant-time comparison even runs).
    #[test]
    fn psk_binder_wrong_length_rejected() {
        let psk = [0x77u8; 32];
        let mut ks = KeySchedule::<Aes128GcmSha256>::new();
        ks.initialize_early_secret(Some(&psk))
            .expect("init early secret");

        let mut transcript: Sha256 = Digest::new();
        transcript.update(b"prefix");

        // Sha256 binder is 32 bytes; pass 16 bytes — must be rejected.
        let too_short = [0u8; 16];
        assert!(
            !ks.verify_psk_binder(&transcript, &too_short)
                .expect("verify too-short"),
        );

        // 64 bytes — also wrong, also rejected.
        let too_long = [0u8; 64];
        assert!(
            !ks.verify_psk_binder(&transcript, &too_long)
                .expect("verify too-long"),
        );
    }
}
