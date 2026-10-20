use crate::{buffer::Ring, device::DeviceHandle, protocol::parse_session_reply};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::JoinHandle,
};
use winptap_core::*;
static NEXT: AtomicU64 = AtomicU64::new(1);
pub(crate) struct NativeSession {
    handle: DeviceHandle,
    id: u64,
    stream: u64,
    ring: Arc<Mutex<Ring>>,
    reader: Option<JoinHandle<()>>,
    queue: Arc<PacketQueue>,
    config: Config,
    stop: Arc<AtomicBool>,
    started: bool,
    stopped: bool,
}
impl NativeSession {
    pub fn open(config: Config) -> Result<Self> {
        if config
            .application_filter
            .as_ref()
            .is_some_and(|f| f.direction == Some(Direction::Transmit))
        {
            return Err(Error::InvalidConfig("native backend is receive-only"));
        }
        if config
            .capture_filter
            .as_ref()
            .is_some_and(|f| f.direction == Some(Direction::Transmit))
        {
            return Err(Error::InvalidConfig("native backend is receive-only"));
        }
        let handle = DeviceHandle::open()?;
        if let Some(f) = &config.capture_filter {
            crate::filter::encode(0, f)?;
        }
        if let Some(d) = &config.device {
            if d.backend != Backend::NativeIoctl {
                return Err(Error::InvalidConfig(
                    "native capture needs a native component identity",
                ));
            }
            if !crate::discovery::enumerate(&handle)?
                .iter()
                .any(|v| v.id == d.id && v.name == d.name)
            {
                return Err(Error::InvalidConfig("native component disappeared"));
            }
        }
        let ring = Ring::new(config.ring_multiplier)?;
        let mut input = [0u8; 512];
        let name = format!(
            "winptap-native-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        for (i, c) in name.encode_utf16().enumerate() {
            input[i * 2..i * 2 + 2].copy_from_slice(&c.to_le_bytes());
        }
        let mut output = [0u8; 528];
        let returned = handle.ioctl(crate::ioctl::Control::CreateSession, &input, &mut output)?;
        let id = parse_session_reply(&output[..returned])?.identifier;
        let mut result = Self {
            handle,
            id,
            stream: 0,
            ring: Arc::new(Mutex::new(ring)),
            reader: None,
            queue: PacketQueue::new(config.queue_capacity, config.overflow),
            config,
            stop: Arc::new(AtomicBool::new(false)),
            started: false,
            stopped: false,
        };
        if let Some(f) = &result.config.capture_filter {
            result.handle.ioctl(
                crate::ioctl::Control::AddConstraint,
                &crate::filter::encode(id, f)?,
                &mut [],
            )?;
        }
        if let Some(d) = &result.config.device {
            let mut selection = [0u8; 20];
            selection[..8].copy_from_slice(&id.to_le_bytes());
            selection[8..12].copy_from_slice(&3u32.to_le_bytes());
            selection[12..14].copy_from_slice(&1u16.to_le_bytes());
            selection[16..20].copy_from_slice(&d.id.to_le_bytes());
            result
                .handle
                .ioctl(crate::ioctl::Control::SelectComponents, &selection, &mut [])?;
        }
        let ring = result.ring.lock().unwrap_or_else(|p| p.into_inner());
        let mut attach = [0u8; 40];
        attach[..8].copy_from_slice(&id.to_le_bytes());
        attach[8..16].copy_from_slice(&ring.packets.address().to_le_bytes());
        attach[16..20].copy_from_slice(&(ring.packets.size as u32).to_le_bytes());
        attach[24..32].copy_from_slice(&ring.control.address().to_le_bytes());
        attach[32..36].copy_from_slice(&(ring.control.size as u32).to_le_bytes());
        attach[36..38].copy_from_slice(&result.config.snaplen.to_le_bytes());
        let mut output = [0u8; 8];
        let returned =
            result
                .handle
                .ioctl(crate::ioctl::Control::AttachStream, &attach, &mut output)?;
        if returned != 8 {
            return Err(Error::InvalidData("stream identifier size"));
        }
        result.stream = u64::from_le_bytes(output);
        drop(ring);
        Ok(result)
    }
}
impl Session for NativeSession {
    fn start(&mut self) -> Result<()> {
        if self.started {
            return Err(Error::InvalidState);
        }
        self.queue.reopen()?;
        self.stop.store(false, Ordering::Release);
        self.handle.ioctl(
            crate::ioctl::Control::Activate,
            &self.id.to_le_bytes(),
            &mut [],
        )?;
        self.started = true;
        self.stopped = false;
        let shared_ring = self.ring.clone();
        let stop = self.stop.clone();
        let queue = self.queue.clone();
        let config = self.config.clone();
        self.reader = Some(
            std::thread::Builder::new()
                .name("winptap-native-reader".into())
                .spawn(move || {
                    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        let mut ring = shared_ring.lock().unwrap_or_else(|p| p.into_inner());
                        while !stop.load(Ordering::Acquire) && !queue.is_closed() {
                            let bytes = match ring.read() {
                                Ok(Some(b)) => b,
                                Ok(None) => {
                                    std::thread::sleep(std::time::Duration::from_millis(1));
                                    continue;
                                }
                                Err(e) => {
                                    queue.close(Err(e));
                                    break;
                                }
                            };
                            if u32::from_le_bytes(bytes[8..12].try_into().unwrap()) != 40 {
                                queue.close(Err(Error::InvalidData("native metadata version")));
                                break;
                            }
                            let missed = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                            queue.update_stats(|s| s.missed_writes += u64::from(missed));
                            let packet = match winptap_core::wire::decode_stream(
                                &bytes,
                                24,
                                64,
                                (bytes.len() - 64) as u32,
                                config.snaplen,
                                Backend::NativeIoctl,
                            )
                            .and_then(|p| {
                                p.with_original_len(u32::from_le_bytes(
                                    bytes[..4].try_into().unwrap(),
                                ))
                            }) {
                                Ok(p) => p,
                                Err(_) => {
                                    queue.update_stats(|s| s.parse_errors += 1);
                                    continue;
                                }
                            };
                            let m = packet.metadata();
                            queue.update_stats(|s| {
                                s.received += 1;
                                if m.truncation == Truncation::CaptureLimitReached {
                                    s.capture_limit_reached += 1;
                                }
                                if m.truncation == Truncation::Known {
                                    s.known_truncations += 1;
                                }
                            });
                            let component_ok = match config.duplicates {
                                DuplicatePolicy::PreserveAll => true,
                                DuplicatePolicy::Component(id) => m.component_id == id,
                            };
                            if m.direction != Direction::Receive
                                || !component_ok
                                || config.link_type.is_some_and(|v| v != m.link_type)
                                || config
                                    .capture_filter
                                    .as_ref()
                                    .is_some_and(|f| !f.matches(&packet))
                                || config
                                    .application_filter
                                    .as_ref()
                                    .is_some_and(|f| !f.matches(&packet))
                            {
                                queue.update_stats(|s| s.filtered += 1);
                                continue;
                            }
                            queue.push(packet);
                        }
                    }));
                    if outcome.is_err() {
                        queue.close(Err(Error::StreamFailed(1359)));
                    }
                })
                .map_err(|_| Error::Windows {
                    operation: "spawn native reader",
                    code: 8,
                })?,
        );
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        if self.started {
            self.handle.ioctl(
                crate::ioctl::Control::Deactivate,
                &self.id.to_le_bytes(),
                &mut [],
            )?;
        }
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            reader.join().map_err(|_| Error::StreamFailed(1359))?;
        }
        self.started = false;
        self.stopped = true;
        self.queue.close(Ok(()));
        Ok(())
    }
    fn queue(&self) -> Arc<PacketQueue> {
        self.queue.clone()
    }
}
impl Drop for NativeSession {
    fn drop(&mut self) {
        let _ = self.stop();
        self.stop.store(true, Ordering::Release);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if self.stream != 0 {
            let _ = self.handle.ioctl(
                crate::ioctl::Control::DetachStream,
                &self.stream.to_le_bytes(),
                &mut [],
            );
        }
        let _ = self.handle.ioctl(
            crate::ioctl::Control::DeleteSession,
            &self.id.to_le_bytes(),
            &mut [],
        );
        // Field order closes the device before freeing shared allocations, even
        // if an explicit detach failed. File cleanup releases driver mappings.
    }
}
