//! Handles parsing of IPv4 headers

use crate::ip::{self, IPProtocol};
use nom::number::streaming::be_u8;
use nom::number::Endianness::Big;
use nom::IResult;
use std::convert::TryFrom;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
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

pub fn to_ipv4_address(i: &[u8]) -> Ipv4Addr {
    Ipv4Addr::from(<[u8; 4]>::try_from(i).unwrap())
}

named!(two_nibbles<&[u8], (u8, u8)>, bits!(pair!(take_bits!(4u8), take_bits!(4u8))));
named!(flag_frag_offset<&[u8], (u8, u16)>, bits!(pair!(take_bits!(3u8), take_bits!(13u16))));
named!(protocol<&[u8], IPProtocol>, map!(be_u8, ip::to_ip_protocol));
named!(address<&[u8], Ipv4Addr>, map!(take!(4), to_ipv4_address));

named!(ipparse<&[u8], IPv4Header>,
       do_parse!(verihl : two_nibbles >>
              tos : be_u8 >>
              length : u16!(Big) >>
              id : u16!(Big) >>
              flagfragoffset : flag_frag_offset >>
              ttl : be_u8 >>
              proto : protocol >>
              chksum : u16!(Big) >>
              src_addr : address >>
              dst_addr : address >>
              ({ IPv4Header {
                  version: verihl.0,
                  ihl: verihl.1 << 2,
                  tos: tos,
                  length: length,
                  id: id,
                  flags: flagfragoffset.0,
                  fragment_offset: flagfragoffset.1,
                  ttl: ttl,
                  protocol: proto,
                  chksum: chksum,
                  source_addr: src_addr,
                  dest_addr : dst_addr,
              }})));

pub fn parse_ipv4_header(i: &[u8]) -> IResult<&[u8], IPv4Header> {
    ipparse(i)
}

#[cfg(test)]
mod tests {
    use super::{ipparse, protocol, IPProtocol, IPv4Header};
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
        assert_eq!(ipparse(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
