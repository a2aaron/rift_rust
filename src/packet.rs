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
// Note that the contents of the security fingerprint are not verified--the only checking done here
// is that the data starts with the correct magic bytes, the major version matches, and that all of
// the fields are actually present. Additionally, the `ProtocolPacket` data itself is unparsed and
// may be invalid.
pub fn parse_security_envelope(
    bytes: &[u8],
) -> Result<
    (
        OuterSecurityEnvelopeHeader,
        Option<TIEOriginSecurityEnvelopeHeader>,
        &[u8],
    ),
    ParsingError,
> {
    let (outer_security_header, bytes) = OuterSecurityEnvelopeHeader::parse_packet(bytes)?;

    let (tie_origin_security_header, bytes) =
        if outer_security_header.remaining_tie_lifetime.is_none() {
            (None, bytes)
        } else {
            let (header, bytes) = TIEOriginSecurityEnvelopeHeader::parse_packet(bytes)?;
            (Some(header), bytes)
        };
    Ok((outer_security_header, tie_origin_security_header, bytes))
}

#[derive(Debug)]
pub struct OuterSecurityEnvelopeHeader<'a> {
    pub packet_number: PacketNumber,
    pub major_version: u8,
    pub outer_key_id: OuterKeyID,
    pub security_fingerprint: &'a [u8],
    pub weak_nonce_local: u16,
    pub weak_nonce_remote: u16,
    pub remaining_tie_lifetime: Option<u32>,
}

impl<'a> OuterSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(OuterSecurityEnvelopeHeader<'a>, &'a [u8]), ParsingError> {
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

        Ok((header, &bytes[fingerprint_end + 8..]))
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
#[derive(Debug)]
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

#[derive(Debug)]
pub enum OuterKeyID {
    Invalid,
    Value(u8),
}

impl From<u8> for OuterKeyID {
    fn from(number: u8) -> OuterKeyID {
        if number == INVALID_KEY_VALUE_KEY as u8 {
            OuterKeyID::Invalid
        } else {
            OuterKeyID::Value(number)
        }
    }
}

#[derive(Debug)]
pub struct TIEOriginSecurityEnvelopeHeader<'a> {
    pub tie_origin_key_id: u32, // this is actually only 24 bits long
    pub fingerprint_length: u8,
    pub security_fingerprint: &'a [u8],
}

impl<'a> TIEOriginSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(TIEOriginSecurityEnvelopeHeader<'a>, &'a [u8]), ParsingError> {
        let tie_origin_key_id = {
            let b0 = *bytes.get(0).ok_or(ParsingError::OutOfRange)?;
            let b1 = *bytes.get(1).ok_or(ParsingError::OutOfRange)?;
            let b2 = *bytes.get(2).ok_or(ParsingError::OutOfRange)?;
            u32::from_be_bytes([b0, b1, b2, 0])
        };
        let fingerprint_length = get_u8(bytes, 3)?;

        let fingerprint_end = 4 + fingerprint_length as usize * 4;
        let security_fingerprint = bytes
            .get(4..fingerprint_end)
            .ok_or(ParsingError::OutOfRange)?;

        let header = TIEOriginSecurityEnvelopeHeader {
            tie_origin_key_id,
            fingerprint_length,
            security_fingerprint,
        };
        Ok((header, &bytes[fingerprint_end..]))
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
    ThriftError(thrift::Error),
    OutOfRange,
}
