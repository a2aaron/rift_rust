use thrift::{
    protocol::{TBinaryInputProtocol, TBinaryOutputProtocol, TSerializable},
    transport::ReadHalf,
};

use crate::models::encoding::{ProtocolPacket, PROTOCOL_MAJOR_VERSION};

fn parse_packet(
    bytes: &[u8],
) -> Result<
    (
        OuterSecurityEnvelopeHeader,
        Option<TIEOriginSecurityEnvelopeHeader>,
        ProtocolPacket,
    ),
    ParsingError,
> {
    let (outer_security_header, bytes) = OuterSecurityEnvelopeHeader::parse_packet(bytes)?;

    let (tie_origin_security_header, bytes) =
        if outer_security_header.remaining_tie_lifetime == 0xFFFFFFFF {
            (None, bytes)
        } else {
            let (header, bytes) = TIEOriginSecurityEnvelopeHeader::parse_packet(bytes)?;
            (Some(header), bytes)
        };

    // TODO: Should this be in "strict mode"?
    let mut binary_protocol = TBinaryInputProtocol::new(ReadHalf::new(bytes), true);
    let protocol_packet = ProtocolPacket::read_from_in_protocol(&mut binary_protocol)
        .map_err(ParsingError::ThriftError)?;

    Ok((
        outer_security_header,
        tie_origin_security_header,
        protocol_packet,
    ))
}

struct OuterSecurityEnvelopeHeader<'a> {
    packet_number: u16,
    major_version: u8,
    outer_key_id: u8,
    fingerprint_length: u8,
    security_fingerprint: &'a [u8],
    weak_nonce_local: u16,
    weak_nonce_remote: u16,
    remaining_tie_lifetime: u32,
}

impl<'a> OuterSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(OuterSecurityEnvelopeHeader<'a>, &'a [u8]), ParsingError> {
        // Check RIFT_MAGIC bytes (RIFT_MAGIC value is expected to equal 0xA1F7)
        let rift_magic = u16::from_be_bytes([bytes[0], bytes[1]]);
        if rift_magic != 0xA1F7 {
            return Err(ParsingError::NotMagical);
        }

        let packet_number = u16::from_be_bytes([bytes[2], bytes[3]]);

        let _reserved = bytes[4];

        let major_version = bytes[5];
        if major_version != PROTOCOL_MAJOR_VERSION as u8 {
            return Err(ParsingError::WrongMajorVersion);
        }

        let outer_key_id = bytes[6];
        let fingerprint_length = bytes[7];

        let fingerprint_end = 8 + fingerprint_length as usize * 4;
        let security_fingerprint = &bytes[8..fingerprint_end];

        let weak_nonce_local =
            u16::from_be_bytes([bytes[fingerprint_end], bytes[fingerprint_end + 1]]);

        let weak_nonce_remote =
            u16::from_be_bytes([bytes[fingerprint_end + 2], bytes[fingerprint_end + 3]]);

        let remaining_tie_lifetime = u32::from_be_bytes([
            bytes[fingerprint_end + 4],
            bytes[fingerprint_end + 5],
            bytes[fingerprint_end + 6],
            bytes[fingerprint_end + 7],
        ]);

        let header = OuterSecurityEnvelopeHeader {
            packet_number,
            major_version,
            outer_key_id,
            fingerprint_length,
            security_fingerprint,
            weak_nonce_local,
            weak_nonce_remote,
            remaining_tie_lifetime,
        };

        Ok((header, &bytes[fingerprint_end + 8..]))
    }
}

struct TIEOriginSecurityEnvelopeHeader<'a> {
    tie_origin_key_id: u32, // this is actually only 24 bits long
    fingerprint_length: u8,
    security_fingerprint: &'a [u8],
}

impl<'a> TIEOriginSecurityEnvelopeHeader<'a> {
    fn parse_packet(
        bytes: &'a [u8],
    ) -> Result<(TIEOriginSecurityEnvelopeHeader<'a>, &'a [u8]), ParsingError> {
        let tie_origin_key_id = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], 0]);
        let fingerprint_length = bytes[3];

        let fingerprint_end = 4 + fingerprint_length as usize * 4;
        let security_fingerprint = &bytes[4..fingerprint_end];

        let header = TIEOriginSecurityEnvelopeHeader {
            tie_origin_key_id,
            fingerprint_length,
            security_fingerprint,
        };
        Ok((header, &bytes[fingerprint_end..]))
    }
}

enum ParsingError {
    NotMagical,
    WrongMajorVersion,
    ThriftError(thrift::Error),
}
