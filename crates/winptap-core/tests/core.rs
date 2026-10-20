use std::{net::Ipv4Addr, time::Duration};
use winptap_core::*;
fn frame(vlan: bool) -> Vec<u8> {
    let mut b = vec![0; 14 + if vlan { 4 } else { 0 } + 20 + 8 + 4];
    b[..6].copy_from_slice(&[255; 6]);
    b[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    let ip = if vlan {
        b[12..18].copy_from_slice(&[0x81, 0, 0, 7, 8, 0]);
        18
    } else {
        b[12..14].copy_from_slice(&[8, 0]);
        14
    };
    b[ip] = 0x45;
    b[ip + 2..ip + 4].copy_from_slice(&32u16.to_be_bytes());
    b[ip + 9] = 17;
    b[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 1]);
    b[ip + 16..ip + 20].copy_from_slice(&[192, 0, 2, 2]);
    b[ip + 20..ip + 28].copy_from_slice(&[0x12, 0x34, 0xab, 0xcd, 0, 12, 0, 0]);
    b[ip + 28..].copy_from_slice(&[1, 2, 3, 4]);
    b
}
fn packet(bytes: &[u8], kind: u16) -> Packet {
    let mut b = vec![0; 40];
    b[12..14].copy_from_slice(&3u16.to_le_bytes());
    b[14..16].copy_from_slice(&kind.to_le_bytes());
    b.extend_from_slice(bytes);
    wire::decode_stream(&b, 0, 40, bytes.len() as u32, 9000, Backend::Pktmon).unwrap()
}
#[test]
fn fidelity_and_metadata() {
    let data = frame(true);
    let p = packet(&data, 1);
    assert_eq!(p.data(), data);
    assert_eq!(p.metadata().original_len, None);
    assert_eq!(p.metadata().direction, Direction::Receive);
    assert_eq!(p.metadata().link_type, LinkType::Ethernet);
}
#[test]
fn all_payload_types_are_preserved() {
    for kind in 0..=u16::MAX {
        let p = packet(&[1, 2, 3], kind);
        assert_eq!(p.metadata().packet_type, kind);
        assert_eq!(p.metadata().link_type == LinkType::Ethernet, kind == 1);
    }
}
#[test]
fn malformed_descriptors() {
    let data = vec![0; 100];
    for offset in [61, 100, u32::MAX] {
        assert!(wire::decode_stream(&data, offset, 0, 10, 9000, Backend::Pktmon).is_err());
    }
    assert!(wire::decode_stream(&data, 0, u32::MAX, 2, 9000, Backend::Pktmon).is_err());
    assert!(wire::decode_stream(&data, 0, 20, 10, 9000, Backend::Pktmon).is_err());
    assert!(wire::decode_stream(&data, 0, 48, 52, 51, Backend::Pktmon).is_err());
}
#[test]
fn metadata_packed_offsets() {
    let mut data = vec![0; 41];
    data[22..26].copy_from_slice(&204u32.to_le_bytes());
    data[26..30].copy_from_slice(&0xe0001007u32.to_le_bytes());
    data[30..32].copy_from_slice(&3u16.to_le_bytes());
    data[32..40].copy_from_slice(&123456i64.to_le_bytes());
    let p = wire::decode_stream(&data, 0, 40, 1, 1, Backend::NativeIoctl).unwrap();
    let m = p.metadata();
    assert_eq!(
        (
            m.drop_reason,
            m.drop_location,
            m.processor,
            m.timestamp_100ns
        ),
        (204, 0xe0001007, 3, 123456)
    );
    assert_eq!(m.truncation, Truncation::CaptureLimitReached);
}
#[test]
fn metadata_aligned_offsets() {
    let mut data = vec![0; 49];
    data[24..28].copy_from_slice(&123u32.to_le_bytes());
    data[40..48].copy_from_slice(&987i64.to_le_bytes());
    let p = wire::decode_stream(&data, 0, 48, 1, 9000, Backend::Pktmon).unwrap();
    assert_eq!(p.metadata().drop_reason, 123);
    assert_eq!(p.metadata().timestamp_100ns, 987);
}
#[test]
fn conjunctive_filter() {
    let f = Filter {
        ether_type: Some(0x0800),
        source_mac: Some([2, 0, 0, 0, 0, 1]),
        destination_mac: Some([255; 6]),
        vlan_id: Some(7),
        ip_version: Some(4),
        source_ip: Some(Ipv4Addr::new(192, 0, 2, 1).into()),
        destination_ip: Some(Ipv4Addr::new(192, 0, 2, 2).into()),
        protocol: Some(17),
        source_port: Some(0x1234),
        destination_port: Some(0xabcd),
        direction: Some(Direction::Receive),
    };
    assert!(f.matches(&packet(&frame(true), 1)));
    assert!(!f.matches(&packet(&frame(false), 1)));
    for i in 0..42 {
        assert!(!f.matches(&packet(&frame(true)[..i], 1)));
    }
}
#[test]
fn raw_ip_does_not_gain_ethernet() {
    let data = frame(false);
    let p = packet(&data[14..], 3);
    assert!(
        Filter {
            ip_version: Some(4),
            source_port: Some(0x1234),
            ..Default::default()
        }
        .matches(&p)
    );
    assert!(
        !Filter {
            ether_type: Some(0x0800),
            ..Default::default()
        }
        .matches(&p)
    );
}
#[test]
fn ipv4_noninitial_fragments_have_no_ports() {
    let mut data = frame(false);
    data[20..22].copy_from_slice(&1u16.to_be_bytes());
    let p = packet(&data, 1);
    assert!(
        Filter {
            protocol: Some(17),
            ..Default::default()
        }
        .matches(&p)
    );
    assert!(
        !Filter {
            source_port: Some(0x1234),
            ..Default::default()
        }
        .matches(&p)
    );
}
#[test]
fn padding_cannot_supply_ports() {
    let mut data = frame(false);
    data[16..18].copy_from_slice(&20u16.to_be_bytes());
    assert!(
        !Filter {
            source_port: Some(0x1234),
            ..Default::default()
        }
        .matches(&packet(&data, 1))
    );
}
#[test]
fn ipv6_extensions() {
    let mut b = vec![0; 56];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&16u16.to_be_bytes());
    b[6] = 0;
    b[40] = 17;
    b[48..52].copy_from_slice(&[0x12, 0x34, 0xab, 0xcd]);
    let f = Filter {
        ip_version: Some(6),
        protocol: Some(17),
        source_port: Some(0x1234),
        ..Default::default()
    };
    assert!(f.matches(&packet(&b, 3)));
    b[41] = 255;
    assert!(!f.matches(&packet(&b, 3)));
}
#[test]
fn ipv6_noninitial_fragments() {
    let mut b = vec![0; 56];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&16u16.to_be_bytes());
    b[6] = 44;
    b[40] = 17;
    b[43] = 8;
    b[48..52].copy_from_slice(&[0x12, 0x34, 0xab, 0xcd]);
    assert!(
        !Filter {
            source_port: Some(0x1234),
            ..Default::default()
        }
        .matches(&packet(&b, 3))
    );
}
#[test]
fn queue_drop_policies() {
    for policy in [OverflowPolicy::DropNewest, OverflowPolicy::DropOldest] {
        let q = PacketQueue::new(1, policy);
        q.push(packet(&[1], 1));
        q.push(packet(&[2], 1));
        let p = q.receive(Some(Duration::ZERO)).unwrap().unwrap();
        assert_eq!(
            p.data(),
            if matches!(policy, OverflowPolicy::DropNewest) {
                &[1]
            } else {
                &[2]
            }
        );
        assert_eq!(q.stats().queue_overflow, 1);
        assert_eq!(q.receive(Some(Duration::ZERO)).unwrap_err(), Error::Timeout);
    }
}
#[test]
fn close_drains_and_error_does_not() {
    let q = PacketQueue::new(2, OverflowPolicy::DropNewest);
    q.push(packet(&[1], 1));
    q.close(Ok(()));
    assert!(q.receive(None).unwrap().is_some());
    assert!(q.receive(None).unwrap().is_none());
    let q = PacketQueue::new(2, OverflowPolicy::DropNewest);
    q.push(packet(&[1], 1));
    q.close(Err(Error::Cancelled));
    assert_eq!(q.receive(None).unwrap_err(), Error::Cancelled);
}
#[test]
fn cancellation_wakes_blocked_thread() {
    let q = PacketQueue::new(1, OverflowPolicy::DropNewest);
    let token = CancellationToken(q.clone());
    let join = std::thread::spawn(move || q.receive(None));
    token.cancel();
    assert_eq!(join.join().unwrap().unwrap_err(), Error::Cancelled);
}
#[test]
fn config_and_error_validation() {
    for snaplen in [0, 9001, u16::MAX] {
        assert!(
            Config {
                snaplen,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    assert!(
        Config {
            queue_capacity: 0,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            ring_multiplier: 11,
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert_eq!(
        hresult("test", 0x80070005u32 as i32),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        hresult("test", 0x80070519u32 as i32),
        Err(Error::RevisionMismatch)
    );
    assert!(hresult("test", 1).is_ok());
}
#[test]
fn invalid_filter_combinations() {
    assert!(
        Filter {
            vlan_id: Some(4096),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        Filter {
            ip_version: Some(6),
            source_ip: Some(Ipv4Addr::LOCALHOST.into()),
            ..Default::default()
        }
        .validate()
        .is_err()
    );
}
#[test]
fn arbitrary_short_packets_never_panic() {
    for len in 0..256 {
        let bytes: Vec<_> = (0..len).map(|n| ((n * 73 + len) % 256) as u8).collect();
        for kind in [1, 2, 3, 99] {
            let p = packet(&bytes, kind);
            let _ = Filter {
                source_port: Some(53),
                ..Default::default()
            }
            .matches(&p);
        }
    }
}
#[test]
fn standalone_transport_payloads() {
    for (kind, protocol) in [(5, 6), (6, 17)] {
        let p = packet(&[0, 53, 0x12, 0x34], kind);
        assert!(
            Filter {
                protocol: Some(protocol),
                source_port: Some(53),
                ..Default::default()
            }
            .matches(&p)
        );
        assert!(
            !Filter {
                ip_version: Some(4),
                ..Default::default()
            }
            .matches(&p)
        );
    }
}
#[test]
fn packet_length_invariants() {
    let p = packet(&[1, 2, 3], 1);
    assert!(p.clone().with_original_len(2).is_err());
    assert_eq!(
        p.with_original_len(4).unwrap().metadata().truncation,
        Truncation::Known
    );
}
#[test]
fn constraint_encoding_initializes_padding_and_uses_documented_offsets() {
    let b = encode_constraint(&Filter {
        source_mac: Some([1, 2, 3, 4, 5, 6]),
        source_port: Some(53),
        protocol: Some(17),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(
        u32::from_le_bytes(b[128..132].try_into().unwrap()),
        1 | (1 << 5) | (1 << 11)
    );
    assert_eq!(&b[132..138], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(b[150], 17);
    assert_eq!(&b[186..188], &53u16.to_le_bytes());
    for offset in [151, 191, 198, 199] {
        assert_eq!(b[offset], 0);
    }
    assert_eq!(&b[200..], &[0; 16]);
}
