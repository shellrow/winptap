use crate::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Conjunction of header predicates. Missing or truncated fields never match.
#[derive(Clone, Debug, Default)]
pub struct Filter {
    pub ether_type: Option<u16>,
    pub source_mac: Option<[u8; 6]>,
    pub destination_mac: Option<[u8; 6]>,
    pub vlan_id: Option<u16>,
    pub ip_version: Option<u8>,
    pub source_ip: Option<IpAddr>,
    pub destination_ip: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub direction: Option<Direction>,
}
fn be16(b: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        b.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
impl Filter {
    pub fn validate(&self) -> Result<()> {
        if self.vlan_id.is_some_and(|v| v > 4095) {
            return Err(Error::InvalidConfig("VLAN ID exceeds 4095"));
        }
        if self.ip_version.is_some_and(|v| v != 4 && v != 6) {
            return Err(Error::InvalidConfig("IP version must be 4 or 6"));
        }
        let version = |ip: IpAddr| if ip.is_ipv4() { 4 } else { 6 };
        let v = self
            .ip_version
            .or(self.source_ip.map(version))
            .or(self.destination_ip.map(version));
        if self.source_ip.is_some_and(|ip| Some(version(ip)) != v)
            || self.destination_ip.is_some_and(|ip| Some(version(ip)) != v)
        {
            return Err(Error::InvalidConfig("mixed IP versions"));
        }
        Ok(())
    }
    pub fn matches(&self, packet: &Packet) -> bool {
        self.evaluate(packet).unwrap_or(false)
    }
    fn evaluate(&self, p: &Packet) -> Option<bool> {
        if self.direction.is_some_and(|d| d != p.metadata().direction) {
            return Some(false);
        }
        let b = p.data();
        let mut offset = 0;
        let mut ether = None;
        let mut vlan_match = false;
        if p.metadata().link_type == LinkType::Ethernet {
            if self
                .destination_mac
                .is_some_and(|v| b.get(..6) != Some(v.as_slice()))
                || self
                    .source_mac
                    .is_some_and(|v| b.get(6..12) != Some(v.as_slice()))
            {
                return Some(false);
            }
            let mut t = be16(b, 12)?;
            offset = 14;
            while t == 0x8100 || t == 0x88a8 {
                let vlan = be16(b, offset)? & 0x0fff;
                vlan_match |= self.vlan_id == Some(vlan);
                t = be16(b, offset + 2)?;
                offset += 4;
            }
            ether = Some(t);
        } else if self.source_mac.is_some() || self.destination_mac.is_some() {
            return Some(false);
        }
        if self.ether_type.is_some() && self.ether_type != ether {
            return Some(false);
        }
        if self.vlan_id.is_some() && !vlan_match {
            return Some(false);
        }
        let needs_ip = self.ip_version.is_some()
            || self.source_ip.is_some()
            || self.destination_ip.is_some()
            || self.protocol.is_some()
            || self.source_port.is_some()
            || self.destination_port.is_some();
        if !needs_ip {
            return Some(true);
        }
        if let LinkType::Other(kind @ (5 | 6)) = p.metadata().link_type {
            if self.ip_version.is_some()
                || self.source_ip.is_some()
                || self.destination_ip.is_some()
            {
                return Some(false);
            }
            let proto = if kind == 5 { 6 } else { 17 };
            if self.protocol.is_some_and(|v| v != proto) {
                return Some(false);
            }
            if let Some(port) = self.source_port {
                if be16(b, 0)? != port {
                    return Some(false);
                }
            }
            if let Some(port) = self.destination_port {
                if be16(b, 2)? != port {
                    return Some(false);
                }
            }
            return Some(true);
        }
        if p.metadata().link_type != LinkType::RawIp && !matches!(ether, Some(0x0800 | 0x86dd)) {
            return Some(false);
        }
        let b = b.get(offset..)?;
        let version = *b.first()? >> 4;
        if self.ip_version.is_some_and(|v| v != version) {
            return Some(false);
        }
        let (source, dest, mut proto, mut transport, end, fragmented) = match version {
            4 => {
                let h = usize::from(b[0] & 15) * 4;
                if h < 20 {
                    return Some(false);
                }
                let total = usize::from(be16(b, 2)?);
                if total < h {
                    return Some(false);
                }
                b.get(..h)?;
                (
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(12..16)?).ok()?)),
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(b.get(16..20)?).ok()?)),
                    *b.get(9)?,
                    h,
                    total.min(b.len()),
                    be16(b, 6)? & 0x1fff != 0,
                )
            }
            6 => {
                b.get(..40)?;
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(8..24)?).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(b.get(24..40)?).ok()?)),
                    b[6],
                    40,
                    (40 + usize::from(be16(b, 4)?)).min(b.len()),
                    false,
                )
            }
            _ => return Some(false),
        };
        if self.source_ip.is_some_and(|v| v != source)
            || self.destination_ip.is_some_and(|v| v != dest)
        {
            return Some(false);
        }
        if self.protocol.is_none() && self.source_port.is_none() && self.destination_port.is_none()
        {
            return Some(true);
        }
        let b = b.get(..end)?;
        let mut fragmented = fragmented;
        if version == 6 {
            for _ in 0..16 {
                let size = match proto {
                    0 | 43 | 60 => (usize::from(*b.get(transport + 1)?) + 1) * 8,
                    51 => (usize::from(*b.get(transport + 1)?) + 2) * 4,
                    44 => {
                        fragmented |= be16(b, transport + 2)? & 0xfff8 != 0;
                        8
                    }
                    _ => break,
                };
                let next = *b.get(transport)?;
                b.get(transport..transport + size)?;
                transport += size;
                proto = next;
                if fragmented {
                    break;
                }
            }
        }
        if self.protocol.is_some_and(|v| v != proto) {
            return Some(false);
        }
        if self.source_port.is_some() || self.destination_port.is_some() {
            if fragmented || (proto != 6 && proto != 17) {
                return Some(false);
            }
            let src = be16(b, transport)?;
            let dst = be16(b, transport + 2)?;
            if self.source_port.is_some_and(|v| v != src)
                || self.destination_port.is_some_and(|v| v != dst)
            {
                return Some(false);
            }
        }
        Some(true)
    }
}

/// Serialize the documented 216-byte protocol constraint with initialized padding.
pub fn encode_constraint(filter: &Filter) -> Result<[u8; 216]> {
    filter.validate()?;
    let mut c = [0u8; 216];
    c[..14].copy_from_slice(&[119, 0, 105, 0, 110, 0, 112, 0, 116, 0, 97, 0, 112, 0]);
    let mut flags = 0u32;
    for (value, offset, bit) in [
        (filter.source_mac, 132, 0),
        (filter.destination_mac, 138, 1),
    ] {
        if let Some(v) = value {
            c[offset..offset + 6].copy_from_slice(&v);
            flags |= 1 << bit;
        }
    }
    for (value, offset, bit) in [
        (filter.vlan_id, 144, 2),
        (filter.ether_type, 146, 3),
        (filter.source_port, 186, 11),
        (filter.destination_port, 188, 12),
    ] {
        if let Some(v) = value {
            c[offset..offset + 2].copy_from_slice(&v.to_le_bytes());
            flags |= 1 << bit;
        }
    }
    if let Some(v) = filter.protocol {
        c[150] = v;
        flags |= 1 << 5;
    }
    for (value, offset, bit) in [(filter.source_ip, 152, 6), (filter.destination_ip, 168, 7)] {
        if let Some(ip) = value {
            flags |= 1 << bit;
            match ip {
                std::net::IpAddr::V4(ip) => c[offset..offset + 4].copy_from_slice(&ip.octets()),
                std::net::IpAddr::V6(ip) => {
                    c[offset..offset + 16].copy_from_slice(&ip.octets());
                    flags |= 1 << 8;
                }
            }
        }
    }
    c[128..132].copy_from_slice(&flags.to_le_bytes());
    Ok(c)
}
