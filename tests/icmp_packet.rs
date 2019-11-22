extern crate nom;
extern crate pktparse;

mod tests {
    use std::net::Ipv4Addr;
    use pktparse::{ethernet, ipv4};
    use pktparse::ip::IPProtocol;
    use pktparse::ipv4::IPv4Header;
    use pktparse::ethernet::{EthernetFrame, MacAddress, EtherType};

    #[test]
    fn ipfrag_packet() {
        let bytes =
            [
                0x00, 0x23, 0x54, 0x07, 0x93, 0x6c, // Ethernet destination MAC
                0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b, // Ethernet source MAC
                0x08, 0x00, // Ethernet ethertype
                0x45, // IP version and IHL
                0x00, // IP Differentiated Services Field
                0x05, 0xdc, // IP total length
                0x1a, 0xe6, // IP id
                0x20, 0x00, // IP flags and fragment offset
                0x40, // IP TTL
                0x01, // IP protocol
                0x22, 0xed, // IP header checksum
                0x0a, 0x0a, 0x01, 0x87, // IP source address
                0x0a, 0x0a, 0x01, 0xb4, // IP dest address
            ];
        let eth_expectation = EthernetFrame {
            source_mac: MacAddress([0x00, 0x1b, 0x21, 0x0f, 0x91, 0x9b]),
            dest_mac: MacAddress([0x00, 0x23, 0x54, 0x07, 0x93, 0x6c]),
            ethertype: EtherType::IPv4
        };
        let ip_expectation = IPv4Header {
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
            dest_addr: Ipv4Addr::new(10, 10, 1, 180)
        };
        let parsed_eth_frame = ethernet::parse_ethernet_frame(&bytes);
        if let Ok((remaining_data, eth_frame)) = parsed_eth_frame {
            assert_eq!(eth_frame, eth_expectation);
            let parsed_ip_hdr = ipv4::parse_ipv4_header(&remaining_data);
            if let Ok((_remaining_data, ip_hdr)) = parsed_ip_hdr {
                assert_eq!(ip_hdr, ip_expectation);
            } else {
                assert!(false);
            }
        } else {
            assert!(false);
        }
    }
}
