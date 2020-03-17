//! Handles parsing of Ethernet headers

use nom::bytes;
use nom::number;
use nom::IResult;
use std::convert::TryFrom;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacAddress(pub [u8; 6]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum EtherType {
    LANMIN,
    LANMAX,
    IPv4,
    ARP,
    WOL,
    TRILL,
    DECnet,
    RARP,
    AppleTalk,
    AARP,
    VLAN,
    IPX,
    Qnet,
    IPv6,
    FlowControl,
    CobraNet,
    MPLSuni,
    MPLSmulti,
    PPPoEdiscovery,
    PPPoEsession,
    HomePlug,
    EAPOL,
    PROFINET,
    HyperSCSI,
    ATAOE,
    EtherCAT,
    QinQ,
    Powerlink,
    GOOSE,
    GSE,
    LLDP,
    SERCOS,
    HomePlugAV,
    MRP,
    MACsec,
    PBB,
    PTP,
    PRP,
    CFM,
    FCoE,
    FCoEi,
    RoCE,
    TTE,
    HSR,
    CTP,
    VLANdouble,
    Other(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EthernetFrame {
    pub source_mac: MacAddress,
    pub dest_mac: MacAddress,
    pub ethertype: EtherType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct VlanEthernetFrame {
    pub source_mac: MacAddress,
    pub dest_mac: MacAddress,
    pub ethertype: EtherType,
    pub vid: Option<u16>,
}

/// The VID and actual ethertype that comes after the VLAN identifier 0x8100
struct VidEthertype {
    vid: u16,
    ethertype: EtherType,
}

impl From<u16> for EtherType {
    fn from(raw: u16) -> Self {
        match raw {
            0x002E => Self::LANMIN,         // 802.3 Min data length
            0x05DC => Self::LANMAX,         // 802.3 Max data length
            0x0800 => Self::IPv4,           // Internet Protocol version 4 (IPv4)
            0x0806 => Self::ARP,            // Address Resolution Protocol (ARP)
            0x0842 => Self::WOL,            // Wake-on-LAN[4]
            0x22F3 => Self::TRILL,          // IETF TRILL Protocol
            0x6003 => Self::DECnet,         // DECnet Phase IV
            0x8035 => Self::RARP,           // Reverse Address Resolution Protocol
            0x809B => Self::AppleTalk,      // AppleTalk (Ethertalk)
            0x80F3 => Self::AARP,           // AppleTalk Address Resolution Protocol (AARP)
            0x8100 => Self::VLAN, // VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[5]
            0x8137 => Self::IPX,  // IPX
            0x8204 => Self::Qnet, // QNX Qnet
            0x86DD => Self::IPv6, // Internet Protocol Version 6 (IPv6)
            0x8808 => Self::FlowControl, // Ethernet flow control
            0x8819 => Self::CobraNet, // CobraNet
            0x8847 => Self::MPLSuni, // MPLS unicast
            0x8848 => Self::MPLSmulti, // MPLS multicast
            0x8863 => Self::PPPoEdiscovery, // PPPoE Discovery Stage
            0x8864 => Self::PPPoEsession, // PPPoE Session Stage
            0x887B => Self::HomePlug, // HomePlug 1.0 MME
            0x888E => Self::EAPOL, // EAP over LAN (IEEE 802.1X)
            0x8892 => Self::PROFINET, // PROFINET Protocol
            0x889A => Self::HyperSCSI, // HyperSCSI (SCSI over Ethernet)
            0x88A2 => Self::ATAOE, // ATA over Ethernet
            0x88A4 => Self::EtherCAT, // EtherCAT Protocol
            0x88A8 => Self::QinQ, // Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[5]
            0x88AB => Self::Powerlink, // Ethernet Powerlink[citation needed]
            0x88B8 => Self::GOOSE, // GOOSE (Generic Object Oriented Substation event)
            0x88B9 => Self::GSE,  // GSE (Generic Substation Events) Management Services
            0x88CC => Self::LLDP, // Link Layer Discovery Protocol (LLDP)
            0x88CD => Self::SERCOS, // SERCOS III
            0x88E1 => Self::HomePlugAV, // HomePlug AV MME[citation needed]
            0x88E3 => Self::MRP,  // Media Redundancy Protocol (IEC62439-2)
            0x88E5 => Self::MACsec, // MAC security (IEEE 802.1AE)
            0x88E7 => Self::PBB,  // Provider Backbone Bridges (PBB) (IEEE 802.1ah)
            0x88F7 => Self::PTP,  // Precision Time Protocol (PTP) over Ethernet (IEEE 1588)
            0x88FB => Self::PRP,  // Parallel Redundancy Protocol (PRP)
            0x8902 => Self::CFM, // IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
            0x8906 => Self::FCoE, // Fibre Channel over Ethernet (FCoE)
            0x8914 => Self::FCoEi, // FCoE Initialization Protocol
            0x8915 => Self::RoCE, // RDMA over Converged Ethernet (RoCE)
            0x891D => Self::TTE, // TTEthernet Protocol Control Frame (TTE)
            0x892F => Self::HSR, // High-availability Seamless Redundancy (HSR)
            0x9000 => Self::CTP, // Ethernet Configuration Testing Protocol[6]
            0x9100 => Self::VLANdouble, // VLAN-tagged (IEEE 802.1Q) frame with double tagging
            other => Self::Other(other),
        }
    }
}

pub(crate) fn mac_address(input: &[u8]) -> IResult<&[u8], MacAddress> {
    let (input, mac) = bytes::streaming::take(6u8)(input)?;

    Ok((input, MacAddress(<[u8; 6]>::try_from(mac).unwrap())))
}

fn parse_ethertype(input: &[u8]) -> IResult<&[u8], EtherType> {
    let (input, ether) = number::streaming::be_u16(input)?;

    Ok((input, ether.into()))
}

fn vid_ethertype(input: &[u8]) -> IResult<&[u8], VidEthertype> {
    let (input, vid) = number::streaming::be_u16(input)?;
    let (input, ethertype) = parse_ethertype(input)?;

    Ok((input, VidEthertype { vid, ethertype }))
}

fn vlan_ethernet_frame(input: &[u8]) -> IResult<&[u8], VlanEthernetFrame> {
    let (input, dest_mac) = mac_address(input)?;
    let (input, source_mac) = mac_address(input)?;
    let (input, ethertype) = parse_ethertype(input)?;

    Ok((
        input,
        VlanEthernetFrame {
            source_mac,
            dest_mac,
            ethertype,
            vid: None,
        },
    ))
}

pub fn parse_ethernet_frame(input: &[u8]) -> IResult<&[u8], EthernetFrame> {
    let (input, dest_mac) = mac_address(input)?;
    let (input, source_mac) = mac_address(input)?;
    let (input, ethertype) = parse_ethertype(input)?;

    Ok((
        input,
        EthernetFrame {
            source_mac,
            dest_mac,
            ethertype,
        },
    ))
}

/// Similar to `parse_ethernet_frame` but returns a `VlanEthernetFrame` on success. This uses more
/// CPU cycles but handles both tagged and untagged ethernet traffic.
pub fn parse_vlan_ethernet_frame(i: &[u8]) -> IResult<&[u8], VlanEthernetFrame> {
    let (mut frame_content, mut frame) = vlan_ethernet_frame(i)?;
    if frame.ethertype == EtherType::VLAN {
        let (fc, vid_et) = vid_ethertype(frame_content)?;
        frame.vid = Some(vid_et.vid);
        frame.ethertype = vid_et.ethertype;
        frame_content = fc;
    }
    Ok((frame_content, frame))
}

#[cfg(test)]
mod tests {
    use super::{
        mac_address, parse_ethernet_frame, parse_ethertype, EtherType, EthernetFrame, MacAddress,
    };

    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn mac_address_works() {
        let bytes = [0x9c, 0x5c, 0x8e, 0x90, 0xca, 0xfc];
        assert_eq!(mac_address(&bytes), Ok((EMPTY_SLICE, MacAddress(bytes))));
    }

    macro_rules! mk_ethertype_test {
        ($func_name:ident, $bytes:expr, $correct_ethertype:expr) => {
            #[test]
            fn $func_name() {
                let bytes = $bytes;
                assert_eq!(
                    parse_ethertype(&bytes),
                    Ok((EMPTY_SLICE, $correct_ethertype))
                );
            }
        };
    }

    mk_ethertype_test!(ethertype_gets_ipv4_correct, [0x08, 0x00], EtherType::IPv4);
    mk_ethertype_test!(ethertype_gets_arp_correct, [0x08, 0x06], EtherType::ARP);
    mk_ethertype_test!(ethertype_gets_ipv6_correct, [0x86, 0xDD], EtherType::IPv6);
    mk_ethertype_test!(ethertype_gets_vlan_correct, [0x81, 0x00], EtherType::VLAN);

    #[test]
    fn ethernet_frame_works() {
        let bytes = [
            0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, /* src MAC */
            0x08, 0x00, // Ethertype
        ];
        let expectation = EthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4,
        };
        assert_eq!(parse_ethernet_frame(&bytes), Ok((EMPTY_SLICE, expectation)));
    }

    #[test]
    fn parse_vlan_ethernet_frame_works() {
        use super::{parse_vlan_ethernet_frame, VlanEthernetFrame};
        let bytes = [
            0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, /* src MAC */
            0x81, 0x00, 0x04, 0xd2, // VLAN
            0x08, 0x00, // Ethertype
        ];
        let expectation = VlanEthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4,
            vid: Some(1234),
        };
        assert_eq!(
            parse_vlan_ethernet_frame(&bytes),
            Ok((EMPTY_SLICE, expectation))
        );

        let bytes = [
            0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
            0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, /* src MAC */
            0x08, 0x00, // Ethertype
        ];
        let expectation = VlanEthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4,
            vid: None,
        };
        assert_eq!(
            parse_vlan_ethernet_frame(&bytes),
            Ok((EMPTY_SLICE, expectation))
        );
    }
}
