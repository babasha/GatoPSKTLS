use crate::buffer::CryptoBuffer;

use crate::TlsError;
use crate::parse_buffer::{ParseBuffer, ParseError};

use heapless::Vec;

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PreSharedKeyClientHello<'a, const N: usize> {
    pub identities: Vec<&'a [u8], N>,
    /// Parsed PSK binders (one per identity). Empty when this struct is constructed
    /// for encoding — `ClientHello::finalize` patches the binder bytes in afterwards.
    pub binders: Vec<&'a [u8], N>,
    pub hash_size: usize,
}

impl<'a, const N: usize> PreSharedKeyClientHello<'a, N> {
    pub fn parse(buf: &mut ParseBuffer<'a>) -> Result<Self, ParseError> {
        // OfferedPsks {
        //     PskIdentity identities<7..2^16-1>;     -- u16 length-prefixed list
        //     PskBinderEntry binders<33..2^16-1>;    -- u16 length-prefixed list
        // }
        // PskIdentity { opaque identity<1..2^16-1>; uint32 obfuscated_ticket_age; }
        // PskBinderEntry: opaque PskBinderEntry<32..255>;        -- u8 length-prefixed

        let identities_len = buf.read_u16()? as usize;
        if identities_len < 7 {
            return Err(ParseError::InvalidData);
        }
        let mut id_buf = buf.slice(identities_len)?;
        let mut identities: Vec<&'a [u8], N> = Vec::new();
        while !id_buf.is_empty() {
            let id_len = id_buf.read_u16()? as usize;
            if id_len < 1 {
                return Err(ParseError::InvalidData);
            }
            let id_data = id_buf.slice(id_len)?;
            identities
                .push(id_data.as_slice())
                .map_err(|_| ParseError::InsufficientSpace)?;
            // obfuscated_ticket_age — meaningful only for resumption; for external
            // PSK clients (mosquitto, mbedtls in psk-only mode) this is 0. Either
            // way we just need to consume the four bytes to stay on the wire boundary.
            let _ = id_buf.read_u32()?;
        }
        if identities.is_empty() {
            return Err(ParseError::InvalidData);
        }

        let binders_total_len = buf.read_u16()? as usize;
        if binders_total_len < 33 {
            return Err(ParseError::InvalidData);
        }
        let mut bind_buf = buf.slice(binders_total_len)?;
        let mut binders: Vec<&'a [u8], N> = Vec::new();
        let mut hash_size = 0usize;
        while !bind_buf.is_empty() {
            let b_len = bind_buf.read_u8()? as usize;
            if b_len < 32 {
                return Err(ParseError::InvalidData);
            }
            let b_data = bind_buf.slice(b_len)?;
            binders
                .push(b_data.as_slice())
                .map_err(|_| ParseError::InsufficientSpace)?;
            // RFC 8446 §4.2.11.2: all binders use the same hash (cipher-suite-fixed).
            if hash_size == 0 {
                hash_size = b_len;
            } else if hash_size != b_len {
                return Err(ParseError::InvalidData);
            }
        }

        // RFC 8446 §4.2.11: "Each entry in the binders list is computed as an HMAC over
        // a transcript hash containing a partial ClientHello [...] with one entry per
        // PSK identity in the same order as the identities list."
        if binders.len() != identities.len() {
            return Err(ParseError::InvalidData);
        }

        Ok(Self {
            identities,
            binders,
            hash_size,
        })
    }

    pub fn encode(&self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.with_u16_length(|buf| {
            for identity in &self.identities {
                buf.with_u16_length(|buf| buf.extend_from_slice(identity))
                    .map_err(|_| TlsError::EncodeError)?;

                // NOTE: No support for ticket age, set to 0 as recommended by RFC
                buf.push_u32(0).map_err(|_| TlsError::EncodeError)?;
            }
            Ok(())
        })
        .map_err(|_| TlsError::EncodeError)?;

        // NOTE: We encode binders later after computing the transcript.
        let binders_len = (1 + self.hash_size) * self.identities.len();
        buf.push_u16(binders_len as u16)
            .map_err(|_| TlsError::EncodeError)?;

        for _ in 0..binders_len {
            buf.push(0).map_err(|_| TlsError::EncodeError)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PreSharedKeyServerHello {
    pub selected_identity: u16,
}

impl PreSharedKeyServerHello {
    pub fn parse(buf: &mut ParseBuffer) -> Result<Self, ParseError> {
        Ok(Self {
            selected_identity: buf.read_u16()?,
        })
    }

    pub fn encode(self, buf: &mut CryptoBuffer) -> Result<(), TlsError> {
        buf.push_u16(self.selected_identity)
            .map_err(|_| TlsError::EncodeError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: parse wire-format pre_shared_key extension data with a single
    /// 5-byte identity and a 32-byte binder. Confirms identities, binders, and
    /// hash_size are recovered correctly.
    #[test]
    fn parse_single_identity_and_binder() {
        let identity = b"vader";
        let binder = [0xabu8; 32];
        // identities_len(u16) = 2 + 5 + 4 = 11
        // identity_entry: u16(5) || "vader" || u32(0)
        // binders_len(u16) = 1 + 32 = 33
        // binder_entry: u8(32) || 32 bytes
        let mut wire = std::vec::Vec::new();
        wire.extend_from_slice(&11u16.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(identity);
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&33u16.to_be_bytes());
        wire.push(32);
        wire.extend_from_slice(&binder);

        let mut buf = ParseBuffer::new(&wire);
        let psk: PreSharedKeyClientHello<'_, 4> =
            PreSharedKeyClientHello::parse(&mut buf).expect("parse");
        assert_eq!(psk.identities.len(), 1);
        assert_eq!(psk.identities[0], identity);
        assert_eq!(psk.binders.len(), 1);
        assert_eq!(psk.binders[0], &binder);
        assert_eq!(psk.hash_size, 32);
        assert!(buf.is_empty());
    }

    /// Reject a binder shorter than the spec's 32-octet floor.
    #[test]
    fn reject_undersized_binder() {
        let mut wire = std::vec::Vec::new();
        // Same identity as above
        wire.extend_from_slice(&11u16.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"vader");
        wire.extend_from_slice(&0u32.to_be_bytes());
        // Binder list with a single 16-byte (illegal) binder
        wire.extend_from_slice(&17u16.to_be_bytes());
        wire.push(16);
        wire.extend_from_slice(&[0u8; 16]);
        let mut buf = ParseBuffer::new(&wire);
        let result: Result<PreSharedKeyClientHello<'_, 4>, _> =
            PreSharedKeyClientHello::parse(&mut buf);
        assert!(matches!(result, Err(ParseError::InvalidData)));
    }

    /// Reject if number of binders does not match number of identities.
    #[test]
    fn reject_binder_count_mismatch() {
        let mut wire = std::vec::Vec::new();
        // Two identities
        wire.extend_from_slice(&22u16.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"vader");
        wire.extend_from_slice(&0u32.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"luke!");
        wire.extend_from_slice(&0u32.to_be_bytes());
        // Only one binder (mismatch)
        wire.extend_from_slice(&33u16.to_be_bytes());
        wire.push(32);
        wire.extend_from_slice(&[0u8; 32]);
        let mut buf = ParseBuffer::new(&wire);
        let result: Result<PreSharedKeyClientHello<'_, 4>, _> =
            PreSharedKeyClientHello::parse(&mut buf);
        assert!(matches!(result, Err(ParseError::InvalidData)));
    }
}
