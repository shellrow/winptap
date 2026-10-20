#[allow(dead_code)]
#[path = "../../../examples/support/dump_format.rs"]
mod dump_format;
#[allow(dead_code)]
#[path = "../../../examples/support/mod.rs"]
mod support;

use netdev::Interface;
use winptap::{Backend, LinkType};
use winptap_core::Device;

fn interface(index: u32, name: &str, description: &str) -> Interface {
    let mut interface = Interface::dummy();
    interface.index = index;
    interface.name = name.into();
    interface.description = Some(description.into());
    interface
}

fn device(id: u32, description: &str) -> Device {
    Device {
        backend: Backend::NativeIoctl,
        id,
        secondary_id: id,
        parent_id: 0,
        name: format!("NIC{id}"),
        description: description.into(),
        network_interface: true,
        guid: None,
    }
}

#[test]
fn interface_guid_uses_windows_byte_order_and_precedes_descriptions() {
    let interface = interface(42, "{00112233-4455-6677-8899-aabbccddeeff}", "same model");
    let mut target = device(9, "different label");
    target.guid = Some([
        0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]);
    let devices = [device(42, "same model"), target];
    assert_eq!(
        support::match_interface(&interface, std::slice::from_ref(&interface), &devices).unwrap(),
        1
    );
}

#[test]
fn native_description_mapping_requires_uniqueness_on_both_sides() {
    let interface = interface(42, "adapter-a", "Example NIC");
    let devices = [device(9, "Example NIC")];
    assert_eq!(
        support::match_interface(&interface, std::slice::from_ref(&interface), &devices).unwrap(),
        0
    );
    let mut second = interface.clone();
    second.index = 43;
    second.name = "adapter-b".into();
    assert!(support::match_interface(&interface, &[interface.clone(), second], &devices).is_err());
    assert!(
        support::match_interface(
            &interface,
            std::slice::from_ref(&interface),
            &[devices[0].clone(), device(10, "Example NIC")]
        )
        .is_err()
    );
    assert!(
        support::match_interface(
            &interface,
            std::slice::from_ref(&interface),
            &[device(42, "Other NIC")]
        )
        .is_err()
    );
}

#[test]
fn conflicting_guid_cannot_fall_back_to_description() {
    let interface = interface(1, "{00112233-4455-6677-8899-aabbccddeeff}", "Example NIC");
    let mut device = device(9, "Example NIC");
    device.guid = Some([0; 16]);
    assert!(
        support::match_interface(&interface, std::slice::from_ref(&interface), &[device]).is_err()
    );
}

#[test]
fn command_line_validation_does_not_open_capture() {
    for args in [
        vec!["--interface"],
        vec!["--count", "0"],
        vec!["--unknown"],
        vec!["-i", "Ethernet", "--component", "9"],
    ] {
        assert!(
            support::Options::from_args(args.into_iter().map(str::to_owned), Backend::Auto, None)
                .is_err()
        );
    }
    let options = support::Options::from_args(
        ["--native", "-c", "2", "--help"].map(str::to_owned),
        Backend::Auto,
        None,
    )
    .unwrap();
    assert_eq!(options.backend, Backend::NativeIoctl);
    assert_eq!(options.count, Some(2));
    assert!(options.select().unwrap().is_none());
}

fn ipv4_udp() -> Vec<u8> {
    let mut bytes = vec![0; 28];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 17;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
    bytes[20..22].copy_from_slice(&1234u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
    bytes[24..26].copy_from_slice(&8u16.to_be_bytes());
    bytes
}

#[test]
fn dump_udp_and_vlan_preserve_endpoints() {
    let ip = ipv4_udp();
    assert!(
        dump_format::summarize(&ip, LinkType::RawIp)
            .unwrap()
            .contains("192.0.2.1:1234 > 198.51.100.2:53: UDP")
    );
    let mut ethernet = vec![0; 18];
    ethernet[12..18].copy_from_slice(&[0x81, 0, 0, 42, 8, 0]);
    ethernet.extend(ip);
    assert!(
        dump_format::summarize(&ethernet, LinkType::Ethernet)
            .unwrap()
            .starts_with("VLAN 42 IP 192.0.2.1:1234")
    );
}

#[test]
fn dump_does_not_invent_ports_for_fragments() {
    let mut ip = ipv4_udp();
    ip[7] = 1;
    let text = dump_format::summarize(&ip, LinkType::RawIp).unwrap();
    assert!(text.contains("fragment"));
    assert!(!text.contains(":1234"));
    let mut ip6 = vec![0; 56];
    ip6[0] = 0x60;
    ip6[5] = 16;
    ip6[6] = 44;
    ip6[40] = 17;
    ip6[43] = 8;
    ip6[48..].copy_from_slice(&ipv4_udp()[20..]);
    let text = dump_format::summarize(&ip6, LinkType::RawIp).unwrap();
    assert!(text.contains("fragment"));
    assert!(!text.contains(":1234"));
}

#[test]
fn dump_tcp_flags_and_ipv6_extensions() {
    let mut ip = ipv4_udp();
    ip.resize(40, 0);
    ip[3] = 40;
    ip[9] = 6;
    ip[32] = 0x50;
    ip[33] = 0x12;
    assert!(
        dump_format::summarize(&ip, LinkType::RawIp)
            .unwrap()
            .contains("TCP Flags [S.]")
    );
    let mut ip6 = vec![0; 56];
    ip6[0] = 0x60;
    ip6[5] = 16;
    ip6[6] = 0;
    ip6[40] = 17;
    ip6[48..].copy_from_slice(&ipv4_udp()[20..]);
    assert!(
        dump_format::summarize(&ip6, LinkType::RawIp)
            .unwrap()
            .contains("[::]:1234 > [::]:53: UDP")
    );
}

#[test]
fn dump_handles_truncated_and_unsupported_packets() {
    for size in 0..14 {
        assert!(dump_format::summarize(&vec![0; size], LinkType::Ethernet).is_err());
    }
    assert!(
        dump_format::summarize(&[], LinkType::Wifi)
            .unwrap()
            .contains("unsupported")
    );
    let ip = ipv4_udp();
    for size in 1..28 {
        assert!(dump_format::summarize(&ip[..size], LinkType::RawIp).is_err());
    }
}
