//! Handles parsing of Arp pakets

use nom::number;
use nom::IResult;
use std::net::Ipv4Addr;

use crate::ethernet;
use crate::ethernet::MacAddress;
use crate::ipv4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum HardwareAddressType {
    Ethernet,
    Other(u16),
}

impl From<u16> for HardwareAddressType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0001 => Self::Ethernet,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ProtocolAddressType {
    IPv4,
    Other(u16),
}

impl From<u16> for ProtocolAddressType {
    fn from(raw: u16) -> Self {
        match raw {
            0x0800 => Self::IPv4,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Operation {
    Request,
    Reply,
    Other(u16),
}

impl From<u16> for Operation {
    fn from(raw: u16) -> Self {
        match raw {
            0x0001 => Self::Request,
            0x0002 => Self::Reply,
            other => Self::Other(other),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

fn parse_hw_addr_type(input: &[u8]) -> IResult<&[u8], HardwareAddressType> {
    let (input, hw_addr_type) = number::streaming::be_u16(input)?;

    Ok((input, hw_addr_type.into()))
}

fn parse_proto_addr_type(input: &[u8]) -> IResult<&[u8], ProtocolAddressType> {
    let (input, proto_addr_type) = number::streaming::be_u16(input)?;

    Ok((input, proto_addr_type.into()))
}

fn parse_operation(input: &[u8]) -> IResult<&[u8], Operation> {
    let (input, operation) = number::streaming::be_u16(input)?;

    Ok((input, operation.into()))
}

pub fn parse_arp_pkt(input: &[u8]) -> IResult<&[u8], ArpPacket> {
    let (input, hw_addr_type) = parse_hw_addr_type(input)?;
    let (input, proto_addr_type) = parse_proto_addr_type(input)?;
    let (input, hw_addr_size) = number::streaming::be_u8(input)?;
    let (input, proto_addr_size) = number::streaming::be_u8(input)?;
    let (input, operation) = parse_operation(input)?;
    let (input, src_mac) = ethernet::mac_address(input)?;
    let (input, src_addr) = ipv4::address(input)?;
    let (input, dest_mac) = ethernet::mac_address(input)?;
    let (input, dest_addr) = ipv4::address(input)?;

    Ok((
        input,
        ArpPacket {
            hw_addr_type,
            proto_addr_type,
            hw_addr_size,
            proto_addr_size,
            operation,
            src_mac,
            src_addr,
            dest_mac,
            dest_addr,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_arp_pkt, ArpPacket, HardwareAddressType, MacAddress, Operation, ProtocolAddressType,
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
        assert_eq!(parse_arp_pkt(&bytes), Ok((EMPTY_SLICE, expectation)));
    }
}
