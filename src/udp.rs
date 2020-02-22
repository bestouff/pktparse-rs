//! Handles parsing of UDP header

use nom::number::streaming::be_u16;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub struct UdpHeader {
    pub source_port: u16,
    pub dest_port: u16,
    pub length: u16,
    pub checksum: u16,
}

named!(pub parse_udp_header<&[u8], UdpHeader>, do_parse!(
        source_port: be_u16 >>
        dest_port: be_u16 >>
        length: be_u16 >>
        checksum: be_u16 >>
    (
        UdpHeader{source_port: source_port, dest_port: dest_port, length: length, checksum: checksum}
    )
));

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
