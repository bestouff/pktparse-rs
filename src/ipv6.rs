//! Handles parsing of IPv6 headers

use crate::ip::{self, IPProtocol};
use nom::bits;
use nom::bytes;
use nom::error::ErrorKind;
use nom::number;
use nom::IResult;
use std::convert::TryFrom;
use std::net::Ipv6Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IPv6Header {
    pub version: u8,
    pub ds: u8,
    pub ecn: u8,
    pub flow_label: u32,
    pub length: u16,
    pub next_header: IPProtocol,
    pub hop_limit: u8,
    pub source_addr: Ipv6Addr,
    pub dest_addr: Ipv6Addr,
}

pub(crate) fn address(input: &[u8]) -> IResult<&[u8], Ipv6Addr> {
    let (input, ipv6) = bytes::streaming::take(16u8)(input)?;

    Ok((input, Ipv6Addr::from(<[u8; 16]>::try_from(ipv6).unwrap())))
}

/*
let (input, ds): (_, u8) =
    bits::bits::<_, _, (_, ErrorKind), _, _>(bits::streaming::take(6u8))(input)?;
let (input, ecn): (_, u8) =
    bits::bits::<_, _, (_, ErrorKind), _, _>(bits::streaming::take(2u8))(input)?;
let (input, flow_label): (_, u32) =
    bits::bits::<_, _, (_, ErrorKind), _, _>(bits::streaming::take(20u8))(input)?;
*/
pub fn parse_ipv6_header(input: &[u8]) -> IResult<&[u8], IPv6Header> {
    let (input, ver_tc) = ip::two_nibbles(input)?;
    let (input, tc_fl) = ip::two_nibbles(input)?;
    let (input, fl): (_, u32) =
        bits::bits::<_, _, (_, ErrorKind), _, _>(bits::streaming::take(16u8))(input)?;
    let (input, length) = number::streaming::be_u16(input)?;
    let (input, next_header) = ip::protocol(input)?;
    let (input, hop_limit) = number::streaming::be_u8(input)?;
    let (input, source_addr) = address(input)?;
    let (input, dest_addr) = address(input)?;

    Ok((
        input,
        IPv6Header {
            version: ver_tc.0,
            ds: (ver_tc.1 << 2) + ((tc_fl.0 & 0b1100) >> 2),
            ecn: tc_fl.0 & 0b11,
            flow_label: (u32::from(tc_fl.1) << 16) + fl,
            length,
            next_header,
            hop_limit,
            source_addr,
            dest_addr,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{ip::protocol, parse_ipv6_header, IPProtocol, IPv6Header};
    use std::net::Ipv6Addr;

    const EMPTY_SLICE: &'static [u8] = &[];
    macro_rules! mk_protocol_test {
        ($func_name:ident, $bytes:expr, $correct_proto:expr) => {
            #[test]
            fn $func_name() {
                let bytes = $bytes;
                assert_eq!(protocol(&bytes), Ok((EMPTY_SLICE, $correct_proto)));
            }
        };
    }

    mk_protocol_test!(protocol_gets_icmp_correct, [1], IPProtocol::ICMP);
    mk_protocol_test!(protocol_gets_tcp_correct, [6], IPProtocol::TCP);
    mk_protocol_test!(protocol_gets_udp_correct, [17], IPProtocol::UDP);

    #[test]
    fn ipparse_gets_packet_correct() {
        let bytes = [
            0x60, /* IP version and differentiated services */
            0x20, /* Differentiated services,
                  explicit congestion notification and
                  partial flow label */
            0x01, 0xff, /* Flow label */
            0x05, 0x78, /* Payload length */
            0x3a, /* Next header */
            0x05, /* Hop limit */
            0x20, 0x01, 0x0d, 0xb8, 0x5c, 0xf8, 0x1a, 0xa8, 0x24, 0x81, 0x61, 0xe6, 0x5a, 0xc6,
            0x03, 0xe0, /* source IP */
            0x20, 0x01, 0x0d, 0xb8, 0x78, 0x90, 0x2a, 0xe9, 0x90, 0x8f, 0xa9, 0xf4, 0x2f, 0x4a,
            0x9b, 0x80, /* destination IP */
        ];

        let expectation = IPv6Header {
            version: 6,
            ds: 0,
            ecn: 2,
            flow_label: 511,
            length: 1400,
            next_header: IPProtocol::ICMP6,
            hop_limit: 5,
            source_addr: Ipv6Addr::new(
                0x2001, 0xdb8, 0x5cf8, 0x1aa8, 0x2481, 0x61e6, 0x5ac6, 0x3e0,
            ),
            dest_addr: Ipv6Addr::new(
                0x2001, 0xdb8, 0x7890, 0x2ae9, 0x908f, 0xa9f4, 0x2f4a, 0x9b80,
            ),
        };
        assert_eq!(parse_ipv6_header(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
