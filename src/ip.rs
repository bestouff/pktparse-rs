//! Handles parsing of Internet Protocol fields (shared between ipv4 and ipv6)

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "derive", derive(serde::Serialize, serde::Deserialize))]
pub enum IPProtocol {
    HOPOPT,
    ICMP,
    IGMP,
    GGP,
    IPINIP,
    ST,
    TCP,
    CBT,
    EGP,
    IGP,
    BBNRCCMON,
    NVPII,
    PUP,
    ARGUS,
    EMCON,
    XNET,
    CHAOS,
    UDP,
    IPV6,
    ICMP6,
    Other(u8),
}

impl From<u8> for IPProtocol {
    fn from(raw: u8) -> Self {
        to_ip_protocol(raw)
    }
}

pub fn to_ip_protocol(i: u8) -> IPProtocol {
    match i {
        0 => IPProtocol::HOPOPT,
        1 => IPProtocol::ICMP,
        2 => IPProtocol::IGMP,
        3 => IPProtocol::GGP,
        4 => IPProtocol::IPINIP,
        5 => IPProtocol::ST,
        6 => IPProtocol::TCP,
        7 => IPProtocol::CBT,
        8 => IPProtocol::EGP,
        9 => IPProtocol::IGP,
        10 => IPProtocol::BBNRCCMON,
        11 => IPProtocol::NVPII,
        12 => IPProtocol::PUP,
        13 => IPProtocol::ARGUS,
        14 => IPProtocol::EMCON,
        15 => IPProtocol::XNET,
        16 => IPProtocol::CHAOS,
        17 => IPProtocol::UDP,
        41 => IPProtocol::IPV6,
        58 => IPProtocol::ICMP6,
        other => IPProtocol::Other(other),
    }
}
