//! Run explicitly on an isolated administrator VM; never in ordinary CI.
use std::time::{Duration, Instant};
use winptap::*;
fn config(backend: Backend, snaplen: u16) -> CaptureConfig {
    config_with_capacity(backend, snaplen, 1024, OverflowPolicy::DropNewest)
}
fn config_with_capacity(
    backend: Backend,
    snaplen: u16,
    capacity: usize,
    policy: OverflowPolicy,
) -> CaptureConfig {
    let name = std::env::var("WINPTAP_TEST_INTERFACE")
        .expect("set WINPTAP_TEST_INTERFACE to the driver name");
    let device = CaptureDevice::list_with_backend(backend)
        .unwrap()
        .into_iter()
        .find(|d| d.network_interface && d.name == name)
        .expect("test interface");
    CaptureConfig::builder()
        .backend(backend)
        .device(device)
        .snaplen(snaplen)
        .queue_capacity(capacity)
        .overflow_policy(policy)
        .link_type(LinkType::Ethernet)
        .capture_filter(Filter {
            protocol: Some(17),
            destination_port: Some(48931),
            ..Default::default()
        })
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap()
}
fn receive(c: &mut Capture) -> Packet {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(15) {
        match c.next_packet() {
            Ok(Some(p))
                if p.data()
                    .windows(b"winptap-controlled-frame-".len())
                    .any(|b| b == b"winptap-controlled-frame-") =>
            {
                println!(
                    "controlled frame via {:?}: length={}, group={}",
                    p.metadata().backend,
                    p.data().len(),
                    p.metadata().group_id
                );
                return p;
            }
            Ok(Some(_)) | Err(Error::Timeout) => (),
            result => panic!("unexpected capture result: {result:?}"),
        }
    }
    panic!(
        "no controlled UDP frame received; stats={:?}",
        c.statistics()
    );
}
#[test]
#[ignore = "requires an isolated administrator VM and external controlled UDP traffic"]
fn live_backend_parity() {
    let _receiver = std::net::UdpSocket::bind("0.0.0.0:48931").unwrap();
    let mut official = Capture::open(config(Backend::Pktmon, 9000)).unwrap();
    let mut native = Capture::open(config(Backend::NativeIoctl, 9000)).unwrap();
    official.start().unwrap();
    native.start().unwrap();
    let packet = receive(&mut native);
    assert_eq!(packet.metadata().direction, Direction::Receive);
    assert_eq!(packet.metadata().backend, Backend::NativeIoctl);
    let start = Instant::now();
    let counterpart = loop {
        let p = receive(&mut official);
        if p.data() == packet.data() {
            break p;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "no exact byte match"
        );
    };
    // Group IDs are session observations, not globally unique frame identities.
    assert_eq!(
        packet.metadata().component_id,
        counterpart.metadata().component_id
    );
    assert_eq!(
        packet.metadata().timestamp_100ns,
        counterpart.metadata().timestamp_100ns
    );
    assert!(packet.data().len() >= 66);
    assert_eq!(&packet.data()[12..14], &[8, 0]);
    assert_eq!(packet.data()[23], 17);
    assert_eq!(
        u16::from_be_bytes([packet.data()[36], packet.data()[37]]),
        48931
    );
    official.stop().unwrap();
    native.stop().unwrap();
    assert_eq!(official.statistics().parse_errors, 0);
    assert_eq!(native.statistics().parse_errors, 0);
    println!(
        "byte-identical Ethernet frame: {} bytes; official={:?}; native={:?}",
        packet.data().len(),
        official.statistics(),
        native.statistics()
    );
}
#[test]
#[ignore = "requires an isolated administrator VM"]
fn live_lifecycle() {
    for backend in [Backend::Pktmon, Backend::NativeIoctl] {
        // Warm up runtime and DLL caches before measuring owned OS handles.
        {
            let mut c = Capture::open(config(backend, 128)).unwrap();
            c.start().unwrap();
            c.stop().unwrap();
        }
        let before = handle_count();
        for _ in 0..100 {
            let mut capture = Capture::open(config(backend, 128)).unwrap();
            assert_eq!(capture.next_packet().unwrap_err(), Error::InvalidState);
            capture.start().unwrap();
            assert_eq!(capture.start().unwrap_err(), Error::InvalidState);
            capture.stop().unwrap();
            capture.stop().unwrap();
            capture.start().unwrap();
            capture.stop().unwrap();
        }
        let after = handle_count();
        assert!(after <= before + 2, "handle growth: {before} -> {after}");
        println!("{backend:?}: process handles {before} -> {after}");
        println!("{backend:?}: 100 start/stop/drop cycles passed");
    }
}

#[test]
#[ignore = "requires an isolated administrator VM"]
fn live_movable_receiver_lifecycle() {
    let backends = [
        #[cfg(feature = "pktmon")]
        Backend::Pktmon,
        #[cfg(feature = "native")]
        Backend::NativeIoctl,
    ];
    for backend in backends {
        drop(PacketReceiver::open(config(backend, 128)).unwrap());
        let before = handle_count();
        for iteration in 0..100 {
            let receiver = PacketReceiver::open(config(backend, 128)).unwrap();
            std::thread::spawn(move || {
                let mut receiver = receiver;
                if iteration % 2 == 0 {
                    receiver.cancellation_token().cancel();
                    assert_eq!(receiver.next_packet().unwrap_err(), Error::Cancelled);
                } else {
                    receiver.stop().unwrap();
                    receiver.stop().unwrap();
                }
            })
            .join()
            .unwrap();
        }
        let after = handle_count();
        assert!(after <= before + 2, "handle growth: {before} -> {after}");
        println!("{backend:?}: 100 movable receiver cycles, handles {before} -> {after}");
    }
}

#[test]
#[ignore = "requires an isolated administrator VM and external controlled UDP traffic"]
fn live_movable_receiver_capture() {
    let _socket = std::net::UdpSocket::bind("0.0.0.0:48931").unwrap();
    let backends = [
        #[cfg(feature = "pktmon")]
        Backend::Pktmon,
        #[cfg(feature = "native")]
        Backend::NativeIoctl,
    ];
    for backend in backends {
        let receiver = PacketReceiver::open(config(backend, 9000)).unwrap();
        std::thread::spawn(move || {
            let mut receiver = receiver;
            let start = Instant::now();
            loop {
                assert!(
                    start.elapsed() < Duration::from_secs(15),
                    "controlled traffic timed out"
                );
                match receiver.next_packet() {
                    Ok(Some(packet))
                        if packet
                            .data()
                            .windows(b"winptap-controlled-frame-".len())
                            .any(|b| b == b"winptap-controlled-frame-") =>
                    {
                        assert_eq!(packet.metadata().backend, backend);
                        assert_eq!(packet.metadata().link_type, LinkType::Ethernet);
                        break;
                    }
                    Ok(Some(_)) | Err(Error::Timeout) => (),
                    other => panic!("unexpected receive: {other:?}"),
                }
            }
            receiver.stop().unwrap();
            assert_eq!(receiver.statistics().parse_errors, 0);
        })
        .join()
        .unwrap();
    }
}

#[test]
#[ignore = "requires an isolated administrator VM and controlled UDP traffic at 1000 packets/s"]
fn live_queue_backpressure() {
    let _socket = std::net::UdpSocket::bind("0.0.0.0:48931").unwrap();
    let backends = [
        #[cfg(feature = "pktmon")]
        Backend::Pktmon,
        #[cfg(feature = "native")]
        Backend::NativeIoctl,
    ];
    for backend in backends {
        for policy in [OverflowPolicy::DropNewest, OverflowPolicy::DropOldest] {
            let mut receiver =
                PacketReceiver::open(config_with_capacity(backend, 9000, 8, policy)).unwrap();
            // Deliberately stall the application while the bounded producer runs.
            std::thread::sleep(Duration::from_secs(1));
            receiver.stop().unwrap();
            let mut drained = 0;
            while receiver.next_packet().unwrap().is_some() {
                drained += 1;
            }
            let stats = receiver.statistics();
            assert_eq!(drained, 8);
            assert!(
                stats.queue_overflow > 0,
                "traffic did not exercise backpressure: {stats:?}"
            );
            assert_eq!(stats.parse_errors, 0);
            assert_eq!(stats.delivered, drained);
            println!("{backend:?} {policy:?}: {stats:?}");
        }
    }
}
fn handle_count() -> u32 {
    #[cfg(windows)]
    {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
            fn GetProcessHandleCount(process: *mut std::ffi::c_void, count: *mut u32) -> i32;
        }
        let mut count = 0;
        // SAFETY: current-process pseudo handle and a valid DWORD output pointer.
        let result = unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) };
        assert_ne!(result, 0);
        count
    }
    #[cfg(not(windows))]
    {
        0
    }
}
#[test]
#[ignore = "requires an isolated administrator VM and external controlled UDP traffic"]
fn live_truncation() {
    let _receiver = std::net::UdpSocket::bind("0.0.0.0:48931").unwrap();
    for backend in [Backend::Pktmon, Backend::NativeIoctl] {
        let mut capture = Capture::open(config(backend, 100)).unwrap();
        capture.start().unwrap();
        let packet = receive(&mut capture);
        assert_eq!(packet.data().len(), 100);
        if backend == Backend::NativeIoctl {
            assert_eq!(packet.metadata().truncation, Truncation::Known);
            assert!(packet.metadata().original_len.unwrap() > 100);
        } else {
            assert_eq!(
                packet.metadata().truncation,
                Truncation::CaptureLimitReached
            );
            assert_eq!(packet.metadata().original_len, None);
        }
        capture.stop().unwrap();
        println!("{backend:?} truncation verified");
    }
}
#[cfg(feature = "tokio")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires an isolated administrator VM"]
async fn live_async_cancellation() {
    for backend in [Backend::Pktmon, Backend::NativeIoctl] {
        let mut capture = Capture::open(
            CaptureConfig::builder()
                .backend(backend)
                .application_filter(Filter {
                    destination_port: Some(65001),
                    ..Default::default()
                })
                .build()
                .unwrap(),
        )
        .unwrap();
        capture.start().unwrap();
        let token = capture.cancellation_token();
        let cancel = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            token.cancel();
        });
        let error = tokio::time::timeout(Duration::from_secs(5), capture.next_packet_async())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error, Error::Cancelled);
        cancel.join().unwrap();
        capture.stop().unwrap();
    }
}
#[test]
#[ignore = "requires an isolated administrator VM and external controlled UDP traffic"]
fn live_native_independent() {
    let _receiver = std::net::UdpSocket::bind("0.0.0.0:48931").unwrap();
    let mut capture = Capture::open(config(Backend::NativeIoctl, 9000)).unwrap();
    capture.start().unwrap();
    let packet = receive(&mut capture);
    assert_eq!(packet.metadata().backend, Backend::NativeIoctl);
    assert_eq!(packet.metadata().direction, Direction::Receive);
    capture.stop().unwrap();
    assert_eq!(capture.statistics().parse_errors, 0);
    println!(
        "native-only capture: {} bytes; {:?}",
        packet.data().len(),
        capture.statistics()
    );
}
