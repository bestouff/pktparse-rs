//! Handles parsing of Arp pakets

use nom::number::streaming::be_u8;
use nom::number::Endianness::Big;
use nom::IResult;

use std::net::Ipv4Addr;

use crate::ethernet::{to_mac_address, MacAddress};
use crate::ipv4::to_ipv4_address;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub enum HardwareAddressType {
    Ethernet,
    Other(u16),
}

fn to_hw_addr_type(i: u16) -> Option<HardwareAddressType> {
    match i {
        0x0001 => Some(HardwareAddressType::Ethernet),
        other => Some(HardwareAddressType::Other(other)),
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolAddressType {
    IPv4,
    Other(u16),
}

fn to_proto_addr_type(i: u16) -> Option<ProtocolAddressType> {
    match i {
        0x0800 => Some(ProtocolAddressType::IPv4),
        other => Some(ProtocolAddressType::Other(other)),
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub enum Operation {
    Request,
    Reply,
    Other(u16),
}

fn to_operation(i: u16) -> Option<Operation> {
    match i {
        0x0001 => Some(Operation::Request),
        0x0002 => Some(Operation::Reply),
        other => Some(Operation::Other(other)),
    }
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub struct ArpPacket {
    pub hw_addr_type: HardwareAddressType,
    pub proto_addr_type: ProtocolAddressType,

    pub hw_addr_size: u8,
    pub proto_addr_size: u8,

    pub operation: Operation,

    pub src_mac: MacAddress,
    pub src_addr: Ipv4Addr,

    pub dest_mac: MacAddress,
    pub dest_addr: Ipv4Addr,
}

named!(hw_addr_type<&[u8], HardwareAddressType>, map_opt!(u16!(Big), to_hw_addr_type));
named!(proto_addr_type<&[u8], ProtocolAddressType>, map_opt!(u16!(Big), to_proto_addr_type));
named!(operation<&[u8], Operation>, map_opt!(u16!(Big), to_operation));
named!(mac_address<&[u8], MacAddress>, map!(take!(6), to_mac_address));
named!(address<&[u8], Ipv4Addr>, map!(take!(4), to_ipv4_address));
named!(arp_packet<&[u8], ArpPacket>, do_parse!(
    hw_addr_type: hw_addr_type >>
    proto_addr_type: proto_addr_type >>

    hw_addr_size:  be_u8 >>
    proto_addr_size: be_u8 >>

    operation: operation >>

    src_mac: mac_address >>
    src_addr: address >>

    dest_mac: mac_address >>
    dest_addr: address >>

    ({ ArpPacket{
        hw_addr_type: hw_addr_type,
        proto_addr_type: proto_addr_type,

        hw_addr_size: hw_addr_size,
        proto_addr_size: proto_addr_size,

        operation: operation,

        src_mac: src_mac,
        src_addr: src_addr,

        dest_mac: dest_mac,
        dest_addr: dest_addr,
    }})
));

pub fn parse_arp_pkt(i: &[u8]) -> IResult<&[u8], ArpPacket> {
    arp_packet(i)
}

#[cfg(test)]
mod tests {
    use super::{
        arp_packet, ArpPacket, HardwareAddressType, MacAddress, Operation, ProtocolAddressType,
    };
    use std::net::Ipv4Addr;

    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn arp_packet_works() {
        let bytes = [
            0, 1, // hardware type
            8, 0, // proto type
            6, 4, // sizes
            0, 1, // arp operation
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, // src mac
            10, 10, 1, 135, // src ip
            0xde, 0xad, 0xc0, 0x00, 0xff, 0xee, // dest mac
            192, 168, 1, 253, // dest ip
        ];

        let expectation = ArpPacket {
            hw_addr_type: HardwareAddressType::Ethernet,
            proto_addr_type: ProtocolAddressType::IPv4,

            hw_addr_size: 6,
            proto_addr_size: 4,

            operation: Operation::Request,

            src_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            src_addr: Ipv4Addr::new(10, 10, 1, 135),

            dest_mac: MacAddress([0xde, 0xad, 0xc0, 0x00, 0xff, 0xee]),
            dest_addr: Ipv4Addr::new(192, 168, 1, 253),
        };
        assert_eq!(arp_packet(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
