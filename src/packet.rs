use crate::models::encoding::PROTOCOL_MAJOR_VERSION;

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
        if outer_security_header.remaining_tie_lifetime == 0xFFFFFFFF {
            (None, bytes)
        } else {
            let (header, bytes) = TIEOriginSecurityEnvelopeHeader::parse_packet(bytes)?;
            (Some(header), bytes)
        };
    Ok((outer_security_header, tie_origin_security_header, bytes))
}

#[derive(Debug)]
pub struct OuterSecurityEnvelopeHeader<'a> {
    pub packet_number: u16,
    pub major_version: u8,
    pub outer_key_id: u8,
    pub fingerprint_length: u8,
    pub security_fingerprint: &'a [u8],
    pub weak_nonce_local: u16,
    pub weak_nonce_remote: u16,
    pub remaining_tie_lifetime: u32,
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

        let packet_number = get_u16(bytes, 2)?;

        let _reserved = get_u8(bytes, 4)?;

        let major_version = get_u8(bytes, 5)?;
        if major_version != PROTOCOL_MAJOR_VERSION as u8 {
            return Err(ParsingError::WrongMajorVersion);
        }

        let outer_key_id = get_u8(bytes, 6)?;

        let fingerprint_length = get_u8(bytes, 7)?;
        let fingerprint_end = 8 + fingerprint_length as usize * 4;

        let security_fingerprint = &bytes
            .get(8..fingerprint_end)
            .ok_or(ParsingError::OutOfRange)?;

        let weak_nonce_local = get_u16(bytes, fingerprint_end)?;
        let weak_nonce_remote = get_u16(bytes, fingerprint_end + 2)?;
        let remaining_tie_lifetime = get_u32(bytes, fingerprint_end + 4)?;

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
