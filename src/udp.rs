//! Handles parsing of UDP header

use nom::number;
use nom::IResult;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct UdpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

pub fn parse_udp_header(input: &[u8]) -> IResult<&[u8], UdpHeader> {
    let (input, source_port) = number::streaming::be_u16(input)?;
    let (input, dest_port) = number::streaming::be_u16(input)?;
    let (input, length) = number::streaming::be_u16(input)?;
    let (input, checksum) = number::streaming::be_u16(input)?;

    Ok((
        input,
        UdpHeader {
            source_port,
            dest_port,
            length,
            checksum,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{parse_udp_header, UdpHeader};
    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn udp_header_works() {
        let bytes = [
            0x00, 0x12, 0x11, 0x11, // source & destination ports
            0x00, 0x1b, 0x21, 0x0f, // length & checksum
        ];
        let expectation = UdpHeader {
            source_port: 0x12,
            dest_port: 0x1111,
            length: 0x1b,
            checksum: 0x210f,
        };
        assert_eq!(parse_udp_header(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
