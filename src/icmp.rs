//! Handles parsing of ICMP

use crate::ipv4::{address, parse_ipv4_header, IPv4Header};
use nom::{bytes::streaming::take, number, IResult};
use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Unreachable {
    DestinationNetworkUnreachable,
    DestinationHostUnreachable,
    DestinationProtocolUnreachable,
    DestinationPortUnreachable,
    FragmentationRequired,
    SourceRouteFailed,
    DestinationNetworkUnknown,
    DestinationHostUnknown,
    SourceHostIsolated,
    NetworkAdministrativelyProhibited,
    HostAdministrativelyProhibited,
    NetworkUnreachableForTos,
    HostUnreachableForTos,
    CommunicationAdministrativelyProhibited,
    HostPrecedenceViolation,
    PrecedentCutoffInEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Redirect {
    Network,
    Host,
    TosAndNetwork,
    TosAndHost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TimeExceeded {
    TTL,
    FragmentReassembly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParameterProblem {
    Pointer,
    MissingRequiredOption,
    BadLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExtendedEchoReply {
    NoError,
    MalformedQuery,
    NoSuchInterface,
    NoSuchTableEntry,
    MupltipleInterfacesStatisfyQuery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IcmpCode {
    EchoReply,
    Reserved,
    DestinationUnreachable(Unreachable),
    SourceQuench,
    Redirect(Redirect),
    EchoRequest,
    RouterAdvertisment,
    RouterSolicication,
    TimeExceeded(TimeExceeded),
    ParameterProblem(ParameterProblem),
    Timestamp,
    TimestampReply,
    ExtendedEchoRequest,
    ExtendedEchoReply(ExtendedEchoReply),
    Other(u16),
}

impl From<u16> for IcmpCode {
    fn from(raw: u16) -> Self {
        let [t, c] = raw.to_be_bytes();
        match t {
            0x00 => Self::EchoReply,
            0x01 => Self::Reserved,
            0x02 => Self::Reserved,
            0x03 => match c {
                0x00 => Self::DestinationUnreachable(Unreachable::DestinationNetworkUnreachable),
                0x01 => Self::DestinationUnreachable(Unreachable::DestinationHostUnreachable),
                0x02 => Self::DestinationUnreachable(Unreachable::DestinationProtocolUnreachable),
                0x03 => Self::DestinationUnreachable(Unreachable::DestinationPortUnreachable),
                0x04 => Self::DestinationUnreachable(Unreachable::FragmentationRequired),
                0x05 => Self::DestinationUnreachable(Unreachable::SourceRouteFailed),
                0x06 => Self::DestinationUnreachable(Unreachable::DestinationNetworkUnknown),
                0x07 => Self::DestinationUnreachable(Unreachable::DestinationHostUnknown),
                0x08 => Self::DestinationUnreachable(Unreachable::SourceHostIsolated),
                0x09 => {
                    Self::DestinationUnreachable(Unreachable::NetworkAdministrativelyProhibited)
                }
                0x0A => Self::DestinationUnreachable(Unreachable::HostAdministrativelyProhibited),
                0x0B => Self::DestinationUnreachable(Unreachable::NetworkUnreachableForTos),
                0x0C => Self::DestinationUnreachable(Unreachable::HostUnreachableForTos),
                0x0D => Self::DestinationUnreachable(
                    Unreachable::CommunicationAdministrativelyProhibited,
                ),
                0x0E => Self::DestinationUnreachable(Unreachable::HostPrecedenceViolation),
                0x0F => Self::DestinationUnreachable(Unreachable::PrecedentCutoffInEffect),
                _ => Self::Other(raw),
            },
            0x04 => match c {
                0x00 => Self::SourceQuench,
                _ => Self::Other(raw),
            },
            0x05 => match c {
                0x00 => Self::Redirect(Redirect::Network),
                0x01 => Self::Redirect(Redirect::Host),
                0x02 => Self::Redirect(Redirect::TosAndNetwork),
                0x03 => Self::Redirect(Redirect::TosAndHost),
                _ => Self::Other(raw),
            },
            0x07 => Self::Reserved,
            0x08 => Self::EchoRequest,
            0x09 => Self::RouterAdvertisment,
            0x0A => Self::RouterSolicication,
            0x0B => match c {
                0x00 => Self::TimeExceeded(TimeExceeded::TTL),
                0x01 => Self::TimeExceeded(TimeExceeded::FragmentReassembly),
                _ => Self::Other(raw),
            },
            0x0C => match c {
                0x00 => Self::ParameterProblem(ParameterProblem::Pointer),
                0x01 => Self::ParameterProblem(ParameterProblem::MissingRequiredOption),
                0x02 => Self::ParameterProblem(ParameterProblem::BadLength),
                _ => Self::Other(raw),
            },
            0x0D => Self::Timestamp,
            0x0E => Self::TimestampReply,
            0x2A => Self::ExtendedEchoRequest,
            0x2B => match c {
                0x00 => Self::ExtendedEchoReply(ExtendedEchoReply::NoError),
                0x01 => Self::ExtendedEchoReply(ExtendedEchoReply::MalformedQuery),
                0x02 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchInterface),
                0x03 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchTableEntry),
                0x04 => {
                    Self::ExtendedEchoReply(ExtendedEchoReply::MupltipleInterfacesStatisfyQuery)
                }
                _ => Self::Other(raw),
            },
            _ => Self::Other(raw),
        }
    }
}

fn parse_icmp_code(input: &[u8]) -> IResult<&[u8], IcmpCode> {
    let (input, code) = number::streaming::be_u16(input)?;

    Ok((input, code.into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct IcmpPayloadPacket([u8; 8]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IcmpData {
    Unreachable {
        nexthop_mtu: u16,
        header: IPv4Header,
        packet: IcmpPayloadPacket,
    },
    Redirect {
        gateway: Ipv4Addr,
        header: IPv4Header,
        packet: IcmpPayloadPacket,
    },
    TimeExceeded {
        header: IPv4Header,
        packet: IcmpPayloadPacket,
    },
    None,
}

fn parse_ipv4_header_and_packet(input: &[u8]) -> IResult<&[u8], (IPv4Header, IcmpPayloadPacket)> {
    let (input, header) = parse_ipv4_header(input)?;
    let mut packet: [u8; 8] = Default::default();
    let (input, data) = take(8usize)(input)?;
    packet.copy_from_slice(data);

    Ok((input, (header, IcmpPayloadPacket(packet))))
}

fn parse_icmp_unreachable_data(input: &[u8]) -> IResult<&[u8], IcmpData> {
    let (input, _) = number::streaming::be_u16(input)?;
    let (input, nexthop_mtu) = number::streaming::be_u16(input)?;
    let (input, (header, packet)) = parse_ipv4_header_and_packet(input)?;

    Ok((
        input,
        IcmpData::Unreachable {
            nexthop_mtu,
            header,
            packet,
        },
    ))
}

fn parse_icmp_redirect_data(input: &[u8]) -> IResult<&[u8], IcmpData> {
    let (input, gateway) = address(input)?;
    let (input, (header, packet)) = parse_ipv4_header_and_packet(input)?;

    Ok((
        input,
        IcmpData::Redirect {
            gateway,
            header,
            packet,
        },
    ))
}

fn parse_icmp_timeexceeded_data(input: &[u8]) -> IResult<&[u8], IcmpData> {
    let (input, _) = number::streaming::be_u32(input)?;
    let (input, (header, packet)) = parse_ipv4_header_and_packet(input)?;

    Ok((input, IcmpData::TimeExceeded { header, packet }))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct IcmpHeader {
    pub code: IcmpCode,
    pub checksum: u16,
    pub data: IcmpData,
}

pub fn parse_icmp_header(input: &[u8]) -> IResult<&[u8], IcmpHeader> {
    let (input, code) = parse_icmp_code(input)?;
    let (input, checksum) = number::streaming::be_u16(input)?;

    let (input, data) = match code {
        IcmpCode::DestinationUnreachable(_) => parse_icmp_unreachable_data(input)?,
        IcmpCode::Redirect(_) => parse_icmp_redirect_data(input)?,
        IcmpCode::TimeExceeded(_) => parse_icmp_timeexceeded_data(input)?,
        _ => (input, IcmpData::None),
    };

    Ok((
        input,
        IcmpHeader {
            code,
            checksum,
            data,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        parse_icmp_header, IcmpCode, IcmpData, IcmpHeader, IcmpPayloadPacket, Redirect, Unreachable,
    };
    use crate::ip::IPProtocol;
    use crate::ipv4::IPv4Header;
    use nom::{Err, Needed};
    use std::net::Ipv4Addr;

    const EMPTY_SLICE: &'static [u8] = &[];

    fn get_icmp_ipv4_header_and_packet() -> (IPv4Header, IcmpPayloadPacket) {
        (
            IPv4Header {
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
            },
            IcmpPayloadPacket([0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8]),
        )
    }

    fn get_icmp_redirect_data() -> (Vec<u8>, IcmpHeader) {
        let bytes = [
            5, // type
            1, // code
            0xaa, 0xbb, // checksum
            0x0a, 0x0a, 0x01, 0x86, // gateway addr
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
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        ];

        let (header, packet) = get_icmp_ipv4_header_and_packet();

        let expected = IcmpHeader {
            code: IcmpCode::Redirect(Redirect::Host),
            checksum: 0xaabb,
            data: IcmpData::Redirect {
                gateway: Ipv4Addr::new(10, 10, 1, 134),
                header: header,
                packet: packet,
            },
        };

        (bytes.to_vec(), expected)
    }

    fn get_icmp_unreachable_data() -> (Vec<u8>, IcmpHeader) {
        let bytes = [
            3, // type
            1, // code
            0xaa, 0xbb, // checksum
            0x00, 0x00, // unused
            0x00, 0x7,  // Next-hop MTU
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
            0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        ];

        let (header, packet) = get_icmp_ipv4_header_and_packet();

        let expected = IcmpHeader {
            code: IcmpCode::DestinationUnreachable(Unreachable::DestinationHostUnreachable),
            checksum: 0xaabb,
            data: IcmpData::Unreachable {
                nexthop_mtu: 7,
                header: header,
                packet: packet,
            },
        };

        (bytes.to_vec(), expected)
    }

    #[test]
    fn icmp_unreachable() {
        let (bytes, expected) = get_icmp_unreachable_data();
        assert_eq!(parse_icmp_header(&bytes), Ok((EMPTY_SLICE, expected)))
    }

    #[test]
    fn icmp_unreachable_incomplete() {
        let (mut bytes, _) = get_icmp_unreachable_data();
        bytes.pop();

        assert_eq!(
            parse_icmp_header(&bytes),
            Err(Err::Incomplete(Needed::new(1)))
        )
    }

    #[test]
    fn icmp_redirect() {
        let (bytes, expected) = get_icmp_redirect_data();
        assert_eq!(parse_icmp_header(&bytes), Ok((EMPTY_SLICE, expected)))
    }

    #[test]
    fn icmp_redirect_incomplete() {
        let (mut bytes, _) = get_icmp_redirect_data();
        bytes.pop();

        assert_eq!(
            parse_icmp_header(&bytes),
            Err(Err::Incomplete(Needed::new(1)))
        )
    }
}
