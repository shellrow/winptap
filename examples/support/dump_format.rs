use nex::packet::{
    arp::ArpPacket,
    ethernet::{EtherType, EthernetPacket},
    icmp::IcmpPacket,
    icmpv6::Icmpv6Packet,
    ip::IpNextProtocol,
    ipv4::Ipv4Packet,
    ipv6::{Ipv6ExtensionHeader, Ipv6Packet},
    packet::Packet as _,
    parse::ParseError,
    tcp::TcpPacket,
    udp::UdpPacket,
    vlan::VlanPacket,
};
use winptap::{Direction, LinkType, Packet};

pub fn format_packet(packet: &Packet) -> String {
    let m = packet.metadata();
    let ticks = m.timestamp_100ns.rem_euclid(86400 * 10_000_000);
    let seconds = ticks / 10_000_000;
    let direction = match m.direction {
        Direction::Receive => "RX",
        Direction::Transmit => "TX",
        _ => "?",
    };
    let summary = summarize(packet.data(), m.link_type)
        .unwrap_or_else(|e| format!("malformed/truncated: {e}"));
    format!(
        "{:02}:{:02}:{:02}.{:06} UTC {direction} {summary}, captured {} bytes, {:?}",
        seconds / 3600,
        (seconds / 60) % 60,
        seconds % 60,
        ticks % 10_000_000 / 10,
        m.captured_len,
        m.truncation
    )
}

pub fn summarize(bytes: &[u8], link: LinkType) -> Result<String, ParseError> {
    match link {
        LinkType::Ethernet => {
            let ethernet = EthernetPacket::try_from_buf(bytes)?;
            let mut kind = ethernet.header.ethertype;
            let mut payload = ethernet.payload;
            let mut tags = String::new();
            while matches!(kind.value(), 0x8100 | 0x88a8 | 0x9100) {
                let vlan = VlanPacket::try_from_buf(&payload)?;
                tags.push_str(&format!("VLAN {} ", vlan.header.vlan_id));
                kind = vlan.header.ethertype;
                payload = vlan.payload;
            }
            let network = match kind {
                EtherType::Ipv4 => ipv4(&payload)?,
                EtherType::Ipv6 => ipv6(&payload)?,
                EtherType::Arp => {
                    let arp = ArpPacket::try_from_buf(&payload)?.header;
                    format!(
                        "ARP {:?} {} ({}) > {} ({})",
                        arp.operation,
                        arp.sender_proto_addr,
                        arp.sender_hw_addr,
                        arp.target_proto_addr,
                        arp.target_hw_addr
                    )
                }
                _ => format!(
                    "Ethernet {} > {}, ethertype 0x{:04x}",
                    ethernet.header.source,
                    ethernet.header.destination,
                    kind.value()
                ),
            };
            Ok(format!("{tags}{network}"))
        }
        LinkType::RawIp => match bytes.first().map(|b| b >> 4) {
            Some(4) => ipv4(bytes),
            Some(6) => ipv6(bytes),
            _ => Ok("unrecognized raw IP header".into()),
        },
        other => Ok(format!("unsupported link type {other:?}")),
    }
}

fn ipv4(bytes: &[u8]) -> Result<String, ParseError> {
    let packet = Ipv4Packet::try_from_buf(bytes)?;
    let h = packet.header;
    if h.fragment_offset != 0 || h.flags & 1 != 0 {
        return Ok(format!(
            "IP {} > {}: fragment id {}, offset {}, more {}",
            h.source,
            h.destination,
            h.identification,
            h.fragment_offset * 8,
            h.flags & 1 != 0
        ));
    }
    transport(
        "IP",
        &h.source.to_string(),
        &h.destination.to_string(),
        h.next_level_protocol,
        &packet.payload,
    )
}

fn ipv6(bytes: &[u8]) -> Result<String, ParseError> {
    let packet = Ipv6Packet::try_from_buf(bytes)?;
    let h = packet.header;
    for ext in &packet.extensions {
        if let Ipv6ExtensionHeader::Fragment {
            offset, more, id, ..
        } = ext
            && (*offset != 0 || *more)
        {
            return Ok(format!(
                "IP6 {} > {}: fragment id {id}, offset {}, more {more}",
                h.source,
                h.destination,
                offset * 8
            ));
        }
    }
    let protocol = packet
        .extensions
        .last()
        .map_or(h.next_header, |e| e.next_protocol());
    transport(
        "IP6",
        &format!("[{}]", h.source),
        &format!("[{}]", h.destination),
        protocol,
        &packet.payload,
    )
}

fn transport(
    family: &str,
    source: &str,
    destination: &str,
    protocol: IpNextProtocol,
    bytes: &[u8],
) -> Result<String, ParseError> {
    Ok(match protocol {
        IpNextProtocol::Tcp => {
            let tcp = TcpPacket::try_from_buf(bytes)?;
            let h = tcp.header;
            let flags: String = [
                (0x01, 'F'),
                (0x02, 'S'),
                (0x04, 'R'),
                (0x08, 'P'),
                (0x10, '.'),
                (0x20, 'U'),
                (0x40, 'E'),
                (0x80, 'W'),
            ]
            .into_iter()
            .filter(|(mask, _)| h.flags & mask != 0)
            .map(|(_, c)| c)
            .collect();
            format!(
                "{family} {source}:{} > {destination}:{}: TCP Flags [{flags}], seq {}, ack {}, win {}, length {}",
                h.source,
                h.destination,
                h.sequence,
                h.acknowledgement,
                h.window,
                tcp.payload.len()
            )
        }
        IpNextProtocol::Udp => {
            let udp = UdpPacket::try_from_buf(bytes)?;
            format!(
                "{family} {source}:{} > {destination}:{}: UDP, length {}",
                udp.header.source,
                udp.header.destination,
                udp.payload.len()
            )
        }
        IpNextProtocol::Icmp => {
            let h = IcmpPacket::try_from_buf(bytes)?.header;
            format!(
                "{family} {source} > {destination}: ICMP {:?}, code {:?}",
                h.icmp_type, h.icmp_code
            )
        }
        IpNextProtocol::Icmpv6 => {
            let h = Icmpv6Packet::try_from_buf(bytes)?.header;
            format!(
                "{family} {source} > {destination}: ICMP6 {:?}, code {:?}",
                h.icmpv6_type, h.icmpv6_code
            )
        }
        _ => format!(
            "{family} {source} > {destination}: {protocol:?}, length {}",
            bytes.len()
        ),
    })
}
