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

/// Select one capture point for an identity-equivalent component hierarchy.
/// Unrelated roots, duplicate IDs, missing intermediate parents, and cycles are
/// ambiguous. Driver names are deliberately not used to infer relationships.
fn unique_component<'a>(devices: &[&'a CaptureDevice]) -> Option<&'a CaptureDevice> {
    let first = *devices.first()?;
    if devices.len() == 1 {
        return Some(first);
    }
    for (index, device) in devices.iter().enumerate() {
        if device.backend != first.backend
            || device.guid != first.guid
            || device.mac_address != first.mac_address
            || !device.description.eq_ignore_ascii_case(&first.description)
            || devices[..index].iter().any(|other| other.id == device.id)
        {
            return None;
        }
    }
    let mut roots = devices.iter().copied().filter(|device| {
        device.parent_id == 0 || !devices.iter().any(|parent| parent.id == device.parent_id)
    });
    let root = roots.next()?;
    if roots.next().is_some() {
        return None;
    }
    for device in devices {
        let mut current = *device;
        for _ in 0..devices.len() {
            if current.id == root.id {
                break;
            }
            current = *devices
                .iter()
                .find(|parent| parent.id == current.parent_id)?;
        }
        if current.id != root.id {
            return None;
        }
    }
    Some(root)
}

impl CaptureDevice {
    /// Select a NIC from an enumerated device list using its OS identity.
    ///
    /// GUID matches take priority, followed by a MAC unique in both lists.
    /// Multiple capture components sharing a MAC can be distinguished by a
    /// description unique in both lists. Otherwise, description matching is a
    /// fallback for components without a conflicting identity. Pass a complete OS
    /// interface snapshot including `interface`; missing or ambiguous identities
    /// return an error rather than selecting another adapter. No capture is opened.
    /// Identity-equivalent parent/child NIC components select their common parent
    /// capture point; independent components are never merged by MAC alone.
    pub fn for_interface(
        interface: InterfaceIdentity<'_>,
        interfaces: &[InterfaceIdentity<'_>],
        devices: &[Self],
    ) -> Result<Self> {
        let identity = guid(interface.name);
        let by_guid: Vec<_> = devices
            .iter()
            .filter(|d| {
                d.network_interface
                    && identity.is_some_and(|g| d.guid.or_else(|| guid(&d.name)) == Some(g))
            })
            .collect();
        if !by_guid.is_empty() {
            return unique_component(&by_guid)
                .cloned()
                .ok_or(Error::InvalidConfig("ambiguous capture interface GUID"));
        }
        let mut ambiguous_mac = None;
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
                let matches: Vec<_> = devices
                    .iter()
                    .filter(|d| {
                        d.network_interface
                            && d.guid.or_else(|| guid(&d.name)).is_none()
                            && d.mac_address == Some(mac)
                    })
                    .collect();
                if !matches.is_empty() {
                    if let Some(selected) = unique_component(&matches) {
                        return Ok(selected.clone());
                    } else {
                        // A physical NIC and virtual capture components may share
                        // a MAC. Keep this candidate set for description matching.
                        ambiguous_mac = Some(mac);
                    }
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
        let matches: Vec<_> = devices.iter().filter(|d| {
            d.network_interface
                && d.guid.or_else(|| guid(&d.name)).is_none()
                && ambiguous_mac.is_none_or(|mac| d.mac_address == Some(mac))
                && !matches!((interface.mac_address, d.mac_address), (Some(a), Some(b)) if a != b)
                && d.description.eq_ignore_ascii_case(description)
        }).collect();
        if matches.is_empty() {
            return Err(Error::InvalidConfig("no matching capture interface"));
        }
        unique_component(&matches)
            .cloned()
            .ok_or(Error::InvalidConfig(
                "ambiguous capture interface description",
            ))
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

    #[test]
    fn shared_mac_is_resolved_by_a_unique_description() {
        let os = InterfaceIdentity {
            mac_address: Some([2, 1, 2, 3, 4, 5]),
            ..OS
        };
        let mut target = device(None);
        target.0.mac_address = os.mac_address;
        let mut virtual_component = target.clone();
        virtual_component.0.id = 10;
        virtual_component.0.description = "Virtual component".into();
        for candidates in [
            [target.clone(), virtual_component.clone()],
            [virtual_component.clone(), target.clone()],
        ] {
            assert_eq!(
                CaptureDevice::for_interface(os, &[os], &candidates)
                    .unwrap()
                    .id,
                target.id
            );
        }
        // Equal descriptions do not distinguish two capture points.
        virtual_component.0.description = target.description.clone();
        assert!(
            CaptureDevice::for_interface(os, &[os], &[target.clone(), virtual_component.clone()])
                .is_err()
        );
        // Nor can a duplicate OS description establish which adapter was selected.
        let other_os = InterfaceIdentity {
            name: "another-adapter",
            mac_address: None,
            ..os
        };
        virtual_component.0.description = "Virtual component".into();
        assert!(
            CaptureDevice::for_interface(os, &[os, other_os], &[target, virtual_component])
                .is_err()
        );
    }

    #[test]
    fn ambiguous_mac_does_not_select_an_unrelated_description_match() {
        let os = InterfaceIdentity {
            mac_address: Some([2, 1, 2, 3, 4, 5]),
            ..OS
        };
        let mut candidate = device(None);
        candidate.0.mac_address = os.mac_address;
        candidate.0.description = "Unmapped driver label".into();
        let unrelated = device(None);
        assert!(
            CaptureDevice::for_interface(os, &[os], &[candidate.clone(), candidate, unrelated])
                .is_err()
        );
    }

    #[test]
    fn netadapter_parent_and_child_select_the_parent_in_either_order() {
        let os = InterfaceIdentity {
            mac_address: Some([2, 1, 2, 3, 4, 5]),
            ..OS
        };
        let mut parent = device(None);
        parent.0.id = 182;
        parent.0.name = "vendor-driver.sys".into();
        parent.0.mac_address = os.mac_address;
        let mut child = parent.clone();
        child.0.id = 13;
        child.0.parent_id = parent.id;
        child.0.name = "netadaptercx.sys".into();
        for candidates in [
            [parent.clone(), child.clone()],
            [child.clone(), parent.clone()],
        ] {
            assert_eq!(
                CaptureDevice::for_interface(os, &[os], &candidates)
                    .unwrap()
                    .id,
                182
            );
        }
        child.0.parent_id = 0;
        assert!(CaptureDevice::for_interface(os, &[os], &[parent.clone(), child.clone()]).is_err());
        child.0.parent_id = parent.id;
        parent.0.parent_id = child.id;
        assert!(CaptureDevice::for_interface(os, &[os], &[parent, child]).is_err());
    }

    #[test]
    fn hierarchy_requires_consistent_identity_and_complete_parent_chain() {
        let mut parent = device(None);
        let mut child = parent.clone();
        child.0.id = 10;
        child.0.parent_id = parent.id;
        let mut grandchild = child.clone();
        grandchild.0.id = 11;
        grandchild.0.parent_id = child.id;
        assert_eq!(
            unique_component(&[&grandchild, &parent, &child])
                .unwrap()
                .id,
            parent.id
        );
        assert!(unique_component(&[&parent, &grandchild]).is_none());
        child.0.mac_address = Some([2; 6]);
        assert!(unique_component(&[&parent, &child]).is_none());
        child.0.mac_address = None;
        parent.0.guid = Some([1; 16]);
        assert!(unique_component(&[&parent, &child]).is_none());
    }
}
