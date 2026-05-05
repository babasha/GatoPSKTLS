use core::marker::PhantomData;

use heapless::Vec;

use crate::buffer::CryptoBuffer;
use crate::extensions::messages::EncryptedExtensionsExtension;

use crate::TlsError;
use crate::parse_buffer::ParseBuffer;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct EncryptedExtensions<'a> {
    _todo: PhantomData<&'a ()>,
}

impl<'a> EncryptedExtensions<'a> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<EncryptedExtensions<'a>, TlsError> {
        EncryptedExtensionsExtension::parse_vector::<16>(buf)?;
        Ok(EncryptedExtensions { _todo: PhantomData })
    }
}

/// Server-side EncryptedExtensions emit. The body is a u16-prefixed list of
/// extensions (often empty for plain PSK sessions; required by RFC 8446 §4.3.1
/// even when empty).
#[derive(Debug)]
pub struct EncryptedExtensionsEmit<'a, const N: usize> {
    pub extensions: Vec<EncryptedExtensionsExtension<'a>, N>,
}

impl<'a, const N: usize> Default for EncryptedExtensionsEmit<'a, N> {
    fn default() -> Self {
        Self {
            extensions: Vec::new(),
        }
    }
}

impl<'a, const N: usize> EncryptedExtensionsEmit<'a, N> {
    /// Encode the EncryptedExtensions body (without handshake type/length
    /// header). For a plain PSK session with no negotiated extensions this
    /// emits the two-byte zero-length prefix `00 00`.
    pub fn encode(&self, buf: &mut CryptoBuffer<'_>) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for ext in &self.extensions {
                ext.encode(buf)?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Empty EncryptedExtensions for plain-PSK case must emit the canonical
    /// `00 00` (u16 length prefix = 0) and round-trip back to a parseable
    /// (empty) extensions list.
    #[test]
    fn encrypted_extensions_empty_round_trip() {
        let emit: EncryptedExtensionsEmit<'_, 4> = EncryptedExtensionsEmit::default();
        let mut backing = [0u8; 16];
        let mut buf = CryptoBuffer::wrap(&mut backing);
        emit.encode(&mut buf).expect("encode");
        assert_eq!(buf.len(), 2);
        assert_eq!(&backing[..2], &[0x00, 0x00]);

        let mut parse = ParseBuffer::new(&backing[..2]);
        let _parsed =
            EncryptedExtensions::parse(&mut parse).expect("parse round-trip");
    }
}
