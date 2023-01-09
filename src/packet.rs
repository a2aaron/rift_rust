use std::{collections::HashMap, num::NonZeroU32};

use sha2::Digest;
use thrift::{
    protocol::{TBinaryInputProtocol, TSerializable},
    transport::ReadHalf,
};

use crate::models::{
    common::{INVALID_KEY_VALUE_KEY, UNDEFINED_PACKET_NUMBER},
    encoding::{ProtocolPacket, PROTOCOL_MAJOR_VERSION},
};

// Parse a slice of bytes into a ProtocolPacket. The ProtocolPacket should not be contained in a
// security envelope.
pub fn parse_protocol_packet(bytes: &[u8]) -> Result<ProtocolPacket, ParsingError> {
    // TODO: Should this be in "strict mode"?
    // TODO: Parsing is done using `thrift`, but it seems that `thrift` does panic on some inputs.
    // Maybe we should do the parsing in a way that can catch panics? (Notably it's possible to try
    // and make thrift allocate huge amounts of memory, and memory allocation is not always a
    // catchable panic...). Alternatively: We should maybe fix `thrift` ourselves?
    let mut binary_protocol = TBinaryInputProtocol::new(ReadHalf::new(bytes), true);
    let protocol_packet = ProtocolPacket::read_from_in_protocol(&mut binary_protocol)
        .map_err(ParsingError::ThriftError)?;

    Ok(protocol_packet)
}

// Parse a ProtocolPacket contained in a security envelope.
// The returned tuple consists of three things. First is the header of the outer security envelope.
// If a TIE Origin security envelope present, that is also returned. Finally, the unconsumed
// portion of the input (which should correspond to the start of the raw `ProtocolPacket` data)
// is returned.
// This function will fail if either security envelope is found to be invalid.
// Note that the `ProtocolPacket` data itself is unparsed and may be invalid.
pub fn parse_security_envelope<'a>(
    bytes: &'a [u8],
    keystore: &SecretKeyStore,
) -> Result<
    (
        OuterSecurityEnvelopeHeader<'a>,
        Option<TIEOriginSecurityEnvelopeHeader<'a>>,
        &'a [u8],
    ),
    ParsingError,
> {
    let (outer_security_header, bytes, payload_with_nonces) =
        OuterSecurityEnvelopeHeader::parse_packet(bytes)?;

    if !outer_security_header.validate(keystore, payload_with_nonces) {
        return Err(ParsingError::InvalidOuterEnvelope);
    }

    let (tie_origin_security_header, bytes) =
        if outer_security_header.remaining_tie_lifetime.is_none() {
            (None, bytes)
        } else {
            let (header, bytes) = TIEOriginSecurityEnvelopeHeader::parse_packet(bytes)?;

            if !header.validate(keystore, bytes) {
                return Err(ParsingError::InvalidOuterEnvelope);
            }

            (Some(header), bytes)
        };
    Ok((outer_security_header, tie_origin_security_header, bytes))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterSecurityEnvelopeHeader<'a> {
    pub packet_number: PacketNumber,
    pub major_version: u8,
    pub outer_key_id: KeyID,
    pub security_fingerprint: &'a [u8],
    pub weak_nonce_local: u16,
    pub weak_nonce_remote: u16,
    pub remaining_tie_lifetime: Option<u32>,
}

impl<'a> OuterSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(OuterSecurityEnvelopeHeader<'a>, &'a [u8], &'a [u8]), ParsingError> {
        // Check RIFT_MAGIC bytes (RIFT_MAGIC value is expected to equal 0xA1F7)
        let rift_magic = get_u16(bytes, 0)?;
        if rift_magic != 0xA1F7 {
            return Err(ParsingError::NotMagical);
        }

        let packet_number = get_u16(bytes, 2)?.into();

        let _reserved = get_u8(bytes, 4)?;

        let major_version = get_u8(bytes, 5)?;
        if major_version != PROTOCOL_MAJOR_VERSION as u8 {
            return Err(ParsingError::WrongMajorVersion);
        }

        let outer_key_id = get_u8(bytes, 6)?.into();

        let fingerprint_length = get_u8(bytes, 7)?;
        let fingerprint_end = 8 + fingerprint_length as usize * 4;

        let security_fingerprint = &bytes
            .get(8..fingerprint_end)
            .ok_or(ParsingError::OutOfRange)?;

        let weak_nonce_local = get_u16(bytes, fingerprint_end)?;
        let weak_nonce_remote = get_u16(bytes, fingerprint_end + 2)?;
        let remaining_tie_lifetime = {
            let lifetime = get_u32(bytes, fingerprint_end + 4)?;
            if lifetime == 0xFFFF_FFFF {
                None
            } else {
                Some(lifetime)
            }
        };
        let header = OuterSecurityEnvelopeHeader {
            packet_number,
            major_version,
            outer_key_id,
            security_fingerprint,
            weak_nonce_local,
            weak_nonce_remote,
            remaining_tie_lifetime,
        };

        let payload = &bytes[fingerprint_end + 8..];
        let payload_with_nonces = &bytes[fingerprint_end..];
        Ok((header, payload, payload_with_nonces))
    }

    fn validate(&self, keystore: &SecretKeyStore, payload: &[u8]) -> bool {
        if let KeyID::Valid(key) = self.outer_key_id {
            keystore.validate(key, self.security_fingerprint, payload)
        } else {
            // TODO: If the key id is invalid, should this return always false or always true?
            false
        }
    }
}

/// From https://www.ietf.org/archive/id/draft-ietf-rift-rift-15.pdf, Section 4.4.3 (Security Envelope)
/// An optional, per adjacency, per packet type monotonically increasing number
/// rolling over using sequence number arithmetic defined in Appendix A. A node SHOULD
/// correctly set the number on subsequent packets or otherwise MUST set the value to
/// `undefined_packet_number` as provided in the schema. This number can be used to detect
/// losses and misordering in flooding for either operational purposes or in implementation to
/// adjust flooding behavior to current link or buffer quality. This number MUST NOT be used to
/// discard or validate the correctness of packets. Packet numbers are incremented on each
/// interface and within that for each type of packet independently. This allows to parallelize
/// packet generation and processing for different types within an implementation if so
/// desired
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketNumber {
    Undefined,
    Value(u16),
}

impl From<u16> for PacketNumber {
    fn from(number: u16) -> PacketNumber {
        if number == UNDEFINED_PACKET_NUMBER as u16 {
            PacketNumber::Undefined
        } else {
            PacketNumber::Value(number)
        }
    }
}

/// From https://www.ietf.org/archive/id/draft-ietf-rift-rift-15.pdf, Section 4.4.3 (Security Envelope)
/// 8 bits to allow key rollovers. This implies key type and algorithm. Value
/// `invalid_key_value_key` means that no valid fingerprint was computed. This key ID scope
/// is local to the nodes on both ends of the adjacency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyID {
    Invalid,
    Valid(NonZeroU32),
}

impl From<u8> for KeyID {
    fn from(number: u8) -> KeyID {
        (number as u32).into()
    }
}

impl From<u32> for KeyID {
    fn from(number: u32) -> KeyID {
        if number == INVALID_KEY_VALUE_KEY as u32 {
            KeyID::Invalid
        } else {
            KeyID::Valid(NonZeroU32::new(number).unwrap())
        }
    }
}

pub struct SecretKeyStore {
    secrets: HashMap<NonZeroU32, Key>,
}

impl SecretKeyStore {
    pub fn new() -> SecretKeyStore {
        SecretKeyStore {
            secrets: HashMap::new(),
        }
    }

    pub fn add_secret(&mut self, id: NonZeroU32, secret: Key) -> Option<Key> {
        self.secrets.insert(id, secret)
    }

    /// Returns true if the given fingerprint matches the given payload. If the key is not
    /// in the keystore, then the fingerprint is always considered invalid.
    fn validate(&self, key: NonZeroU32, fingerprint: &[u8], payload: &[u8]) -> bool {
        let Some(key) = self.secrets.get(&key) else {
            return false;
        };
        match key {
            Key::Sha256(secret) => {
                let mut hasher = sha2::Sha256::default();
                hasher.update(secret);
                hasher.update(payload);
                let hash = hasher.finalize();
                fingerprint == &hash[..]
            }
        }
    }
}

pub enum Key {
    Sha256(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TIEOriginSecurityEnvelopeHeader<'a> {
    pub tie_origin_key_id: KeyID, // this is actually only 24 bits long
    pub security_fingerprint: &'a [u8],
}

impl<'a> TIEOriginSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(TIEOriginSecurityEnvelopeHeader<'a>, &'a [u8]), ParsingError> {
        let tie_origin_key_id: KeyID = {
            let b0 = *bytes.get(0).ok_or(ParsingError::OutOfRange)?;
            let b1 = *bytes.get(1).ok_or(ParsingError::OutOfRange)?;
            let b2 = *bytes.get(2).ok_or(ParsingError::OutOfRange)?;
            u32::from_be_bytes([0, b0, b1, b2])
        }
        .into();
        let fingerprint_length = get_u8(bytes, 3)?;

        let fingerprint_end = 4 + fingerprint_length as usize * 4;
        let security_fingerprint = bytes
            .get(4..fingerprint_end)
            .ok_or(ParsingError::OutOfRange)?;

        let header = TIEOriginSecurityEnvelopeHeader {
            tie_origin_key_id,
            security_fingerprint,
        };
        Ok((header, &bytes[fingerprint_end..]))
    }

    fn validate(&self, keystore: &SecretKeyStore, payload: &[u8]) -> bool {
        if let KeyID::Valid(key) = self.tie_origin_key_id {
            keystore.validate(key, self.security_fingerprint, &payload)
        } else {
            // TODO: If the key id is invalid, should this return always false or always true?
            false
        }
    }
}

fn get_u8(slice: &[u8], index: usize) -> Result<u8, ParsingError> {
    let b0 = slice.get(index).ok_or(ParsingError::OutOfRange)?;
    Ok(*b0)
}

fn get_u16(slice: &[u8], index: usize) -> Result<u16, ParsingError> {
    let b0 = slice.get(index).ok_or(ParsingError::OutOfRange)?;
    let b1 = slice.get(index + 1).ok_or(ParsingError::OutOfRange)?;
    Ok(u16::from_be_bytes([*b0, *b1]))
}

fn get_u32(slice: &[u8], index: usize) -> Result<u32, ParsingError> {
    let b0 = slice.get(index).ok_or(ParsingError::OutOfRange)?;
    let b1 = slice.get(index + 1).ok_or(ParsingError::OutOfRange)?;
    let b2 = slice.get(index + 2).ok_or(ParsingError::OutOfRange)?;
    let b3 = slice.get(index + 3).ok_or(ParsingError::OutOfRange)?;

    Ok(u32::from_be_bytes([*b0, *b1, *b2, *b3]))
}

#[derive(Debug)]
pub enum ParsingError {
    NotMagical,
    WrongMajorVersion,
    InvalidOuterEnvelope,
    InvalidTIEEnvelope,
    ThriftError(thrift::Error),
    OutOfRange,
}

mod test {
    use std::num::NonZeroU32;

    use crate::{
        models::{
            common::{TIETypeType, TieDirectionType},
            encoding::{
                PacketContent, PacketHeader, PrefixTIEElement, ProtocolPacket, TIEElement,
                TIEHeader, TIEPacket, TIEID,
            },
        },
        packet::{parse_protocol_packet, TIEOriginSecurityEnvelopeHeader},
    };

    use super::{
        parse_security_envelope, Key, KeyID, OuterSecurityEnvelopeHeader, PacketNumber,
        SecretKeyStore,
    };

    fn get_keystore() -> SecretKeyStore {
        let mut keystore = SecretKeyStore::new();
        keystore.add_secret(
            NonZeroU32::new(1u32).unwrap(),
            Key::Sha256("super secret!".to_string()),
        );
        keystore
    }

    #[test]
    fn test_deserialize_outer_and_tie_envelopes() {
        // A packet containing the following data:
        // RIFT Outer Security Envelope
        //     Magic: 0xa1f7
        //     Packet Number: 0x0002 (2)
        //     RIFT Major Version: 6
        //     Outer Key ID: 0
        //     Fingerprint Length: 0
        //     Fingerprint: <MISSING>
        //     Weak Nonce Local: 0x7e5c
        //     Weak Nonce Remote: 0x39c0
        //     Remaining TIE Lifetime: 0x00093a80 (604800)
        // RIFT TIE Origin Security Envelope
        //     TIE Origin Key ID: 0x000000 (0)
        //     Fingerprint Length: 0
        // Routing In Fat Trees
        #[rustfmt::skip]
        let packet: [u8; 205] = [
            // Outer Security Envelope
            0xa1, 0xf7, // Magic
            0x00, 0x02, // Packet Number
            0x00, 0x06, // Major Version
            0x00,       // Outer Key ID
            0x00,       // Fingerprint Length (since this is zero, there is no fingerprint)
            0x7e, 0x5c, // Weak Nonce Local
            0x39, 0xc0, // Weak Nonce Remote
            0x00, 0x09, 0x3a, 0x80, // Remaining TIE Lifetime
            // TIE Origin Security Envelope
            0x00, 0x00, 0x00, // TIE Origin Key ID
            0x00,             // Fingerprint Length (since this is zero, there is no fingerprint)
            // ProtocolPacket payload (This starts 20 bytes after the above headers)
            0x0c, 0x00, 0x01, 0x03, 0x00, 0x01, 0x06, 0x06, 0x00, 0x02, 0x00, 0x01, 0x0a, 0x00,
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x04, 0x18, 0x00,
            0x0c, 0x00, 0x02, 0x0c, 0x00, 0x04, 0x0c, 0x00, 0x01, 0x0c, 0x00, 0x02, 0x08, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x02, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x0c, 0x00, 0x02, 0x0c, 0x00, 0x02, 0x0d, 0x00, 0x01, 0x0c, 0x0c, 0x00, 0x00,
            0x00, 0x02, 0x0c, 0x00, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x06,
            0x00, 0x02, 0x00, 0x07, 0x01, 0x00, 0x0c, 0x00, 0x02, 0x0b, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x01, 0x02, 0x00, 0x06, 0x00, 0x02, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        ];

        let expected_outer_header = OuterSecurityEnvelopeHeader {
            packet_number: PacketNumber::Value(0x02),
            major_version: 0x06,
            outer_key_id: KeyID::Invalid,
            security_fingerprint: &[],
            weak_nonce_local: 0x7e5c,
            weak_nonce_remote: 0x39c0,
            remaining_tie_lifetime: Some(0x00093a80),
        };

        let expected_tie_header = TIEOriginSecurityEnvelopeHeader {
            tie_origin_key_id: KeyID::Invalid,
            security_fingerprint: &[],
        };

        let expected_protocol_data = &packet[20..];

        let (actual_outer_header, packet, _) =
            OuterSecurityEnvelopeHeader::parse_packet(&packet).unwrap();
        let (actual_tie_header, actual_protocol_data) =
            TIEOriginSecurityEnvelopeHeader::parse_packet(packet).unwrap();

        assert_eq!(actual_outer_header, expected_outer_header);
        assert_eq!(actual_tie_header, expected_tie_header);
        assert_eq!(actual_protocol_data, expected_protocol_data);
    }

    #[test]
    fn test_deserialize_with_fingerprints() {
        // A packet containing the following data:
        // RIFT Outer Security Envelope
        //     Magic: 0xa1f7
        //     Packet Number: 0x0002 (2)
        //     RIFT Major Version: 6
        //     Outer Key ID: 3
        //     Fingerprint Length: 16
        //     Fingerprint: 47b92efdd34cf71e018f4b548e19fae4a62093858c4c17c39e5bc5f34613cb2d63b08a01…
        //     Weak Nonce Local: 0x5519
        //     Weak Nonce Remote: 0x4cb9
        //     Remaining TIE Lifetime: 0x00093a80 (604800)
        // RIFT TIE Origin Security Envelope
        //     TIE Origin Key ID: 0x010203 (66051)
        //     Fingerprint Length: 5
        //     Fingerprint: 06f87b9dee5d4e1aee50b32ec6b6ff4d876cef81
        // Routing In Fat Trees

        #[rustfmt::skip]
        let packet = [
            // Outer Security Envelope
            0xa1, 0xf7, // Magic
            0x00, 0x02, // Packet Number
            0x00, 0x06, // Major Version
            0x03,       // Outer Key ID
            0x10,       // Fingerprint Length
            // Fingerprint Start
            0x47, 0xb9, 0x2e, 0xfd,
            0xd3, 0x4c, 0xf7, 0x1e,
            0x01, 0x8f, 0x4b, 0x54,
            0x8e, 0x19, 0xfa, 0xe4,
            0xa6, 0x20, 0x93, 0x85,
            0x8c, 0x4c, 0x17, 0xc3,
            0x9e, 0x5b, 0xc5, 0xf3,
            0x46, 0x13, 0xcb, 0x2d,
            0x63, 0xb0, 0x8a, 0x01,
            0xff, 0x6c, 0xe8, 0x78,
            0x1e, 0x0c, 0xe0, 0xb2,
            0xf5, 0xb9, 0xd4, 0xc8,
            0x98, 0xce, 0xc3, 0x89,
            0xf1, 0xf7, 0x6d, 0x9b,
            0x5e, 0xc9, 0x38, 0x80,
            0xd6, 0xbc, 0xd1, 0x40,
            // Fingerprint End
            0x55, 0x19,             // Weak Nonce Local
            0x4c, 0xb9,             // Weak Nonce Remote
            0x00, 0x09, 0x3a, 0x80, // Remaining TIE Lifetime
            // TIE Origin Security Envelope
            0x01, 0x02, 0x03, // TIE Origin Key ID
            0x05,             // Fingerprint Length
            // Fingerprint Start
            0x06, 0xf8, 0x7b, 0x9d,
            0xee, 0x5d, 0x4e, 0x1a,
            0xee, 0x50, 0xb3, 0x2e,
            0xc6, 0xb6, 0xff, 0x4d,
            0x87, 0x6c, 0xef, 0x81,
            // Fingerprint End
            // ProtocolPacket payload (this starts 104 bytes after the above headers)
            0x0c, 0x00, 0x01, 0x03, 0x00, 0x01, 0x06, 0x06,
            0x00, 0x02, 0x00, 0x01, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x03, 0x00, 0x04, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x0c, 0x00, 0x04, 0x0c, 0x00,
            0x01, 0x0c, 0x00, 0x02, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x02,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x03, 0x08, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x03, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x02, 0x0c, 0x00, 0x02, 0x0d,
            0x00, 0x01, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x00, 0x01, 0x08, 0x00, 0x01,
            0x03, 0x03, 0x03, 0x03, 0x03, 0x00, 0x02, 0x20, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00,
            0x00, 0x00, 0x01, 0x0e, 0x00, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x06,
            0x00, 0x02, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let expected_outer_header = OuterSecurityEnvelopeHeader {
            packet_number: PacketNumber::Value(0x02),
            major_version: 0x06,
            outer_key_id: 0x03u32.into(),
            security_fingerprint: &[
                0x47, 0xb9, 0x2e, 0xfd, 0xd3, 0x4c, 0xf7, 0x1e, 0x01, 0x8f, 0x4b, 0x54, 0x8e, 0x19,
                0xfa, 0xe4, 0xa6, 0x20, 0x93, 0x85, 0x8c, 0x4c, 0x17, 0xc3, 0x9e, 0x5b, 0xc5, 0xf3,
                0x46, 0x13, 0xcb, 0x2d, 0x63, 0xb0, 0x8a, 0x01, 0xff, 0x6c, 0xe8, 0x78, 0x1e, 0x0c,
                0xe0, 0xb2, 0xf5, 0xb9, 0xd4, 0xc8, 0x98, 0xce, 0xc3, 0x89, 0xf1, 0xf7, 0x6d, 0x9b,
                0x5e, 0xc9, 0x38, 0x80, 0xd6, 0xbc, 0xd1, 0x40,
            ],
            weak_nonce_local: 0x5519,
            weak_nonce_remote: 0x4cb9,
            remaining_tie_lifetime: Some(0x00093a80),
        };

        let expected_tie_header = TIEOriginSecurityEnvelopeHeader {
            tie_origin_key_id: 0x010203u32.into(),
            security_fingerprint: &[
                0x06, 0xf8, 0x7b, 0x9d, 0xee, 0x5d, 0x4e, 0x1a, 0xee, 0x50, 0xb3, 0x2e, 0xc6, 0xb6,
                0xff, 0x4d, 0x87, 0x6c, 0xef, 0x81,
            ],
        };

        let expected_protocol_data = &packet[104..];

        let (actual_outer_header, packet, _) =
            OuterSecurityEnvelopeHeader::parse_packet(&packet).unwrap();
        let (actual_tie_header, actual_protocol_data) =
            TIEOriginSecurityEnvelopeHeader::parse_packet(packet).unwrap();

        assert_eq!(actual_outer_header, expected_outer_header);
        assert_eq!(actual_tie_header, expected_tie_header);
        assert_eq!(actual_protocol_data, expected_protocol_data);
    }
}
