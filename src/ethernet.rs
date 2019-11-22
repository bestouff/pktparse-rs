//! Handles parsing of Ethernet headers

use nom::IResult;
use nom::Endianness::Big;
use std::convert::TryFrom;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
pub struct MacAddress(pub [u8; 6]);
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
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
#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
pub struct EthernetFrame {
    pub source_mac: MacAddress,
    pub dest_mac: MacAddress,
    pub ethertype: EtherType,
}

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(Serialize, Deserialize))]
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

fn to_ethertype(i: u16) -> Option<EtherType> {
    match i {
        0x002E => Some(EtherType::LANMIN),    // 802.3 Min data length
        0x05DC => Some(EtherType::LANMAX),    // 802.3 Max data length
        0x0800 => Some(EtherType::IPv4),    // Internet Protocol version 4 (IPv4)
        0x0806 => Some(EtherType::ARP),    // Address Resolution Protocol (ARP)
        0x0842 => Some(EtherType::WOL),    // Wake-on-LAN[4]
        0x22F3 => Some(EtherType::TRILL),    // IETF TRILL Protocol
        0x6003 => Some(EtherType::DECnet),    // DECnet Phase IV
        0x8035 => Some(EtherType::RARP),    // Reverse Address Resolution Protocol
        0x809B => Some(EtherType::AppleTalk),    // AppleTalk (Ethertalk)
        0x80F3 => Some(EtherType::AARP),    // AppleTalk Address Resolution Protocol (AARP)
        0x8100 => Some(EtherType::VLAN),    // VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq[5]
        0x8137 => Some(EtherType::IPX),    // IPX
        0x8204 => Some(EtherType::Qnet),    // QNX Qnet
        0x86DD => Some(EtherType::IPv6),    // Internet Protocol Version 6 (IPv6)
        0x8808 => Some(EtherType::FlowControl),    // Ethernet flow control
        0x8819 => Some(EtherType::CobraNet),    // CobraNet
        0x8847 => Some(EtherType::MPLSuni),    // MPLS unicast
        0x8848 => Some(EtherType::MPLSmulti),    // MPLS multicast
        0x8863 => Some(EtherType::PPPoEdiscovery),    // PPPoE Discovery Stage
        0x8864 => Some(EtherType::PPPoEsession),    // PPPoE Session Stage
        0x887B => Some(EtherType::HomePlug),    // HomePlug 1.0 MME
        0x888E => Some(EtherType::EAPOL),    // EAP over LAN (IEEE 802.1X)
        0x8892 => Some(EtherType::PROFINET),    // PROFINET Protocol
        0x889A => Some(EtherType::HyperSCSI),    // HyperSCSI (SCSI over Ethernet)
        0x88A2 => Some(EtherType::ATAOE),    // ATA over Ethernet
        0x88A4 => Some(EtherType::EtherCAT),    // EtherCAT Protocol
        0x88A8 => Some(EtherType::QinQ),    // Provider Bridging (IEEE 802.1ad) & Shortest Path Bridging IEEE 802.1aq[5]
        0x88AB => Some(EtherType::Powerlink),    // Ethernet Powerlink[citation needed]
        0x88B8 => Some(EtherType::GOOSE),    // GOOSE (Generic Object Oriented Substation event)
        0x88B9 => Some(EtherType::GSE),    // GSE (Generic Substation Events) Management Services
        0x88CC => Some(EtherType::LLDP),    // Link Layer Discovery Protocol (LLDP)
        0x88CD => Some(EtherType::SERCOS),    // SERCOS III
        0x88E1 => Some(EtherType::HomePlugAV),    // HomePlug AV MME[citation needed]
        0x88E3 => Some(EtherType::MRP),    // Media Redundancy Protocol (IEC62439-2)
        0x88E5 => Some(EtherType::MACsec),    // MAC security (IEEE 802.1AE)
        0x88E7 => Some(EtherType::PBB),    // Provider Backbone Bridges (PBB) (IEEE 802.1ah)
        0x88F7 => Some(EtherType::PTP),    // Precision Time Protocol (PTP) over Ethernet (IEEE 1588)
        0x88FB => Some(EtherType::PRP),    // Parallel Redundancy Protocol (PRP)
        0x8902 => Some(EtherType::CFM),    // IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation Y.1731 (OAM)
        0x8906 => Some(EtherType::FCoE),    // Fibre Channel over Ethernet (FCoE)
        0x8914 => Some(EtherType::FCoEi),    // FCoE Initialization Protocol
        0x8915 => Some(EtherType::RoCE),    // RDMA over Converged Ethernet (RoCE)
        0x891D => Some(EtherType::TTE),    // TTEthernet Protocol Control Frame (TTE)
        0x892F => Some(EtherType::HSR),    // High-availability Seamless Redundancy (HSR)
        0x9000 => Some(EtherType::CTP),    // Ethernet Configuration Testing Protocol[6]
        0x9100 => Some(EtherType::VLANdouble),    // VLAN-tagged (IEEE 802.1Q) frame with double tagging
        other => Some(EtherType::Other(other)),
    }
}

pub fn to_mac_address(i: &[u8]) -> MacAddress {
    MacAddress(<[u8; 6]>::try_from(i).unwrap())
}

named!(mac_address<&[u8], MacAddress>, map!(take!(6), to_mac_address));
named!(ethertype<&[u8], EtherType>, map_opt!(u16!(Big), to_ethertype));
named!(ethernet_frame<&[u8], EthernetFrame>, do_parse!(
    dest_mac: mac_address >>
    src_mac: mac_address >>
    et: ethertype >>
    (EthernetFrame{source_mac: src_mac, dest_mac: dest_mac, ethertype: et})
));
named!(vid_ethertype<&[u8], VidEthertype>, do_parse!(
    vid: u16!(Big) >>
    et: ethertype >>
    (VidEthertype{vid, ethertype: et})
));
named!(vlan_ethernet_frame<&[u8], VlanEthernetFrame>, do_parse!(
    dest_mac: mac_address >>
    src_mac: mac_address >>
    et: ethertype >>
    (VlanEthernetFrame{source_mac: src_mac, dest_mac: dest_mac, ethertype: et, vid: None})
));


pub fn parse_ethernet_frame(i: &[u8]) -> IResult<&[u8], EthernetFrame> {
    ethernet_frame(i)
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
    use super::{mac_address, ethertype, ethernet_frame, MacAddress, EtherType, EthernetFrame};

    const EMPTY_SLICE: &'static [u8] = &[];

    #[test]
    fn mac_address_works() {
        let bytes = [0x9c, 0x5c, 0x8e, 0x90, 0xca, 0xfc];
        assert_eq!(mac_address(&bytes), Ok((EMPTY_SLICE, MacAddress(bytes))));
    }

    macro_rules! mk_ethertype_test {
        ($func_name:ident, $bytes:expr, $correct_ethertype:expr) => (
            #[test]
            fn $func_name() {
                let bytes = $bytes;
                assert_eq!(ethertype(&bytes), Ok((EMPTY_SLICE, $correct_ethertype)));
            }
        )
    }

    mk_ethertype_test!(ethertype_gets_ipv4_correct, [0x08, 0x00], EtherType::IPv4);
    mk_ethertype_test!(ethertype_gets_arp_correct, [0x08, 0x06], EtherType::ARP);
    mk_ethertype_test!(ethertype_gets_ipv6_correct, [0x86, 0xDD], EtherType::IPv6);
    mk_ethertype_test!(ethertype_gets_vlan_correct, [0x81, 0x00], EtherType::VLAN);

    #[test]
    fn ethernet_frame_works() {
        let bytes = [0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, /* dest MAC */
                     0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, /* src MAC */ 
                     0x08, 0x00 // Ethertype
                    ];
        let expectation = EthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4,
        };
        assert_eq!(ethernet_frame(&bytes), Ok((EMPTY_SLICE, expectation)));
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
