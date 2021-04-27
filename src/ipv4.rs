//! Handles parsing of IPv4 headers

use crate::ip::{self, IPProtocol};
use nom::bits;
use nom::bytes;
use nom::error::Error;
use nom::number;
use nom::sequence;
use nom::IResult;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub length: u16,
    pub id: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: IPProtocol,
    pub chksum: u16,
    pub source_addr: Ipv4Addr,
    pub dest_addr: Ipv4Addr,
}

fn flag_frag_offset(input: &[u8]) -> IResult<&[u8], (u8, u16)> {
    bits::bits::<_, _, Error<_>, _, _>(sequence::pair(
        bits::streaming::take(3u8),
        bits::streaming::take(13u16),
    ))(input)
}

pub(crate) fn address(input: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (input, ipv4) = bytes::streaming::take(4u8)(input)?;

    Ok((input, Ipv4Addr::from(<[u8; 4]>::try_from(ipv4).unwrap())))
}

pub fn parse_ipv4_header(input: &[u8]) -> IResult<&[u8], IPv4Header> {
    let (input, verihl) = ip::two_nibbles(input)?;
    let (input, tos) = number::streaming::be_u8(input)?;
    let (input, length) = number::streaming::be_u16(input)?;
    let (input, id) = number::streaming::be_u16(input)?;
    let (input, flag_frag_offset) = flag_frag_offset(input)?;
    let (input, ttl) = number::streaming::be_u8(input)?;
    let (input, protocol) = ip::protocol(input)?;
    let (input, chksum) = number::streaming::be_u16(input)?;
    let (input, source_addr) = address(input)?;
    let (input, dest_addr) = address(input)?;

    Ok((
        input,
        IPv4Header {
            version: verihl.0,
            ihl: verihl.1 << 2,
            tos,
            length,
            id,
            flags: flag_frag_offset.0,
            fragment_offset: flag_frag_offset.1,
            ttl,
            protocol,
            chksum,
            source_addr,
            dest_addr,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{ip::protocol, parse_ipv4_header, IPProtocol, IPv4Header};
    use std::net::Ipv4Addr;

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
            0x45, /* IP version and length = 20 */
            0x00, /* Differentiated services field */
            0x05, 0xdc, /* Total length */
            0x1a, 0xe6, /* Identification */
            0x20, 0x00, /* flags and fragment offset */
            0x40, /* TTL */
            0x01, /* protocol */
            0x22, 0xed, /* checksum */
            0x0a, 0x0a, 0x01, 0x87, /* source IP */
            0x0a, 0x0a, 0x01, 0xb4, /* destination IP */
        ];

        let expectation = IPv4Header {
            version: 4,
            ihl: 20,
            tos: 0,
            length: 1500,
            id: 0x1ae6,
            flags: 0x01,
            fragment_offset: 0,
            ttl: 64,
            protocol: IPProtocol::ICMP,
            chksum: 0x22ed,
            source_addr: Ipv4Addr::new(10, 10, 1, 135),
            dest_addr: Ipv4Addr::new(10, 10, 1, 180),
        };
        assert_eq!(parse_ipv4_header(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
