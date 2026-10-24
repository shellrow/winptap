use crate::{CaptureDevice, Error, Result};

/// OS adapter identity, independent of any particular interface discovery crate.
///
/// Supply the adapter GUID as `name` on Windows (for example, `netdev`'s
/// `Interface::name`). Packet Monitor component IDs are not OS interface indices.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceIdentity<'a> {
    pub name: &'a str,
    pub description: Option<&'a str>,
    /// Current adapter MAC address. Duplicate or zero addresses cannot identify a NIC.
    pub mac_address: Option<[u8; 6]>,
}

fn guid(name: &str) -> Option<[u8; 16]> {
    let name = name
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(name);
    if name.len() != 36 || ![8, 13, 18, 23].iter().all(|&i| name.as_bytes()[i] == b'-') {
        return None;
    }
    let hex: String = name.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = u128::from_str_radix(&hex, 16).ok()?.to_be_bytes();
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    Some(bytes)
}

impl CaptureDevice {
    /// Select a NIC from an enumerated device list using its OS identity.
    ///
    /// GUID matches take priority, followed by a MAC unique in both lists.
    /// If a component has neither usable identity, description
    /// matching is allowed only when unique in both lists. Pass a complete OS
    /// interface snapshot including `interface`; missing or ambiguous identities
    /// return an error rather than selecting another adapter. No capture is opened.
    pub fn for_interface(
        interface: InterfaceIdentity<'_>,
        interfaces: &[InterfaceIdentity<'_>],
        devices: &[Self],
    ) -> Result<Self> {
        let identity = guid(interface.name);
        let mut by_guid = devices.iter().filter(|d| {
            d.network_interface
                && identity.is_some_and(|g| d.guid.or_else(|| guid(&d.name)) == Some(g))
        });
        if let Some(first) = by_guid.next() {
            if by_guid.next().is_some() {
                return Err(Error::InvalidConfig("ambiguous capture interface GUID"));
            }
            return Ok(first.clone());
        }
        if let Some(mac) = interface
            .mac_address
            .filter(|m| *m != [0; 6] && m[0] & 1 == 0)
        {
            let mut os_matches = interfaces.iter().filter(|i| i.mac_address == Some(mac));
            let unique_os = os_matches
                .next()
                .is_some_and(|i| i.name.eq_ignore_ascii_case(interface.name))
                && os_matches.next().is_none();
            if unique_os {
                let mut matches = devices.iter().filter(|d| {
                    d.network_interface
                        && d.guid.or_else(|| guid(&d.name)).is_none()
                        && d.mac_address == Some(mac)
                });
                if let Some(first) = matches.next() {
                    if matches.next().is_some() {
                        return Err(Error::InvalidConfig("ambiguous capture interface MAC"));
                    }
                    return Ok(first.clone());
                }
            }
        }
        let description =
            interface
                .description
                .filter(|s| !s.is_empty())
                .ok_or(Error::InvalidConfig(
                    "interface has no matching GUID or description",
                ))?;
        let mut os_matches = interfaces.iter().filter(|i| {
            i.description
                .is_some_and(|d| d.eq_ignore_ascii_case(description))
        });
        if !os_matches
            .next()
            .is_some_and(|i| i.name.eq_ignore_ascii_case(interface.name))
            || os_matches.next().is_some()
        {
            return Err(Error::InvalidConfig(
                "missing or ambiguous OS interface description",
            ));
        }
        let mut matches = devices.iter().filter(|d| {
            d.network_interface
                && d.guid.or_else(|| guid(&d.name)).is_none()
                && !matches!((interface.mac_address, d.mac_address), (Some(a), Some(b)) if a != b)
                && d.description.eq_ignore_ascii_case(description)
        });
        let first = matches
            .next()
            .ok_or(Error::InvalidConfig("no matching capture interface"))?;
        if matches.next().is_some() {
            return Err(Error::InvalidConfig(
                "ambiguous capture interface description",
            ));
        }
        Ok(first.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Backend;
    fn device(guid: Option<[u8; 16]>) -> CaptureDevice {
        CaptureDevice(winptap_core::Device {
            mac_address: None,
            backend: Backend::Pktmon,
            id: 9,
            secondary_id: 0,
            parent_id: 0,
            name: "driver.sys".into(),
            description: "Adapter".into(),
            network_interface: true,
            guid,
        })
    }
    const OS: InterfaceIdentity<'static> = InterfaceIdentity {
        mac_address: None,
        name: "{00112233-4455-6677-8899-AABBCCDDEEFF}",
        description: Some("Adapter"),
    };
    #[test]
    fn guid_precedes_description_and_uses_windows_byte_order() {
        let bytes = [
            0x33, 0x22, 0x11, 0, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff,
        ];
        assert_eq!(guid(OS.name), Some(bytes));
        let devices = [device(None), device(Some(bytes))];
        assert_eq!(
            CaptureDevice::for_interface(OS, &[], &devices)
                .unwrap()
                .guid,
            Some(bytes)
        );
        assert!(CaptureDevice::for_interface(OS, &[OS], &[device(Some([0; 16]))]).is_err());
    }
    #[test]
    fn description_requires_uniqueness_on_both_sides() {
        let devices = [device(None)];
        assert!(CaptureDevice::for_interface(OS, &[OS], &devices).is_ok());
        assert!(CaptureDevice::for_interface(OS, &[], &devices).is_err());
        assert!(CaptureDevice::for_interface(OS, &[OS, OS], &devices).is_err());
        assert!(CaptureDevice::for_interface(OS, &[OS], &[device(None), device(None)]).is_err());
        let mut conflicting = device(None);
        conflicting.0.name = "{11112233-4455-6677-8899-AABBCCDDEEFF}".into();
        assert!(CaptureDevice::for_interface(OS, &[OS], &[conflicting]).is_err());
    }

    #[test]
    fn mac_mapping_requires_unique_identity_and_respects_conflicts() {
        let os = InterfaceIdentity {
            mac_address: Some([2, 1, 2, 3, 4, 5]),
            ..OS
        };
        let mut target = device(None);
        target.0.description = "different driver label".into();
        target.0.mac_address = os.mac_address;
        assert!(CaptureDevice::for_interface(os, &[os], &[target.clone()]).is_ok());
        assert!(CaptureDevice::for_interface(os, &[os, os], &[target.clone()]).is_err());
        assert!(
            CaptureDevice::for_interface(os, &[os], &[target.clone(), target.clone()]).is_err()
        );
        target.0.guid = Some([0; 16]);
        assert!(CaptureDevice::for_interface(os, &[os], &[target]).is_err());
        let mut conflicting = device(None);
        conflicting.0.mac_address = Some([2; 6]);
        assert!(CaptureDevice::for_interface(os, &[os], &[conflicting]).is_err());
    }
}
