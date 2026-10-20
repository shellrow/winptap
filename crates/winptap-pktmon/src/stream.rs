#[cfg(windows)]
use crate::ffi;
#[cfg(windows)]
use std::{ffi::c_void, sync::Arc};
use winptap_core::*;
pub fn decode(
    bytes: &[u8],
    metadata_offset: u32,
    packet_offset: u32,
    packet_length: u32,
    snaplen: u16,
) -> Result<Packet> {
    winptap_core::wire::decode_stream(
        bytes,
        metadata_offset,
        packet_offset,
        packet_length,
        snaplen,
        Backend::Pktmon,
    )
}
#[cfg(windows)]
pub(crate) struct Callback {
    pub queue: Arc<PacketQueue>,
    pub config: Config,
    pub missed_reads: std::sync::atomic::AtomicU32,
}
#[cfg(windows)]
impl Callback {
    fn accept(&self, packet: Packet) {
        let component = u32::from(packet.metadata().component_id);
        let guid = self
            .config
            .device
            .as_ref()
            .filter(|d| d.network_interface && (d.id == component || d.secondary_id == component))
            .and_then(|d| d.guid);
        let packet = packet.with_interface_guid(guid);
        let m = packet.metadata();
        self.queue.update_stats(|s| {
            s.received += 1;
            if m.truncation == Truncation::CaptureLimitReached {
                s.capture_limit_reached += 1;
            }
        });
        let component_ok = match self.config.duplicates {
            DuplicatePolicy::PreserveAll => true,
            DuplicatePolicy::Component(id) => m.component_id == id,
        };
        if !component_ok
            || self.config.link_type.is_some_and(|l| l != m.link_type)
            || self
                .config
                .capture_filter
                .as_ref()
                .is_some_and(|f| !f.matches(&packet))
            || self
                .config
                .application_filter
                .as_ref()
                .is_some_and(|f| !f.matches(&packet))
        {
            self.queue.update_stats(|s| s.filtered += 1);
            return;
        }
        self.queue.push(packet);
    }
}
#[cfg(windows)]
pub(crate) unsafe extern "system" fn data(
    context: *mut c_void,
    descriptor: *const ffi::Descriptor,
) {
    if context.is_null() || descriptor.is_null() {
        return;
    }
    // SAFETY: the owning session keeps Callback pinned until the stream closes.
    let c = unsafe { &*context.cast::<Callback>() };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: the API supplies a valid Descriptor for the callback duration.
        let d = unsafe { descriptor.read_unaligned() };
        let previous_reads = c
            .missed_reads
            .swap(d.missed_reads, std::sync::atomic::Ordering::Relaxed);
        c.queue.update_stats(|s| {
            s.missed_reads += u64::from(d.missed_reads.wrapping_sub(previous_reads));
            s.missed_writes += u64::from(d.missed_writes);
        });
        if d.data.is_null() || d.size > 256 * 1024 * 10 {
            return Err(Error::InvalidData("invalid stream buffer"));
        }
        // SAFETY: Windows owns d.data for this callback; documented size is capped above.
        let bytes = unsafe { std::slice::from_raw_parts(d.data, d.size as usize) };
        c.accept(decode(
            bytes,
            d.metadata_offset,
            d.packet_offset,
            d.packet_length,
            c.config.snaplen,
        )?);
        Ok(())
    }));
    match result {
        Ok(Ok(())) => (),
        Ok(Err(_)) => c.queue.update_stats(|s| s.parse_errors += 1),
        Err(_) => c.queue.close(Err(Error::StreamFailed(1359))),
    }
}
#[cfg(windows)]
pub(crate) unsafe extern "system" fn event(
    context: *mut c_void,
    info: *const ffi::EventInfo,
    kind: u32,
) {
    if context.is_null() || info.is_null() {
        return;
    }
    // SAFETY: session owns context until stream close returns.
    let c = unsafe { &*context.cast::<Callback>() };
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match kind {
        1 | 2 => {
            // SAFETY: these event kinds select the stop union member.
            let stop = unsafe { (*info).stop };
            if kind == 2 || stop.fatal != 0 {
                c.queue.close(Err(Error::StreamFailed(stop.reason)));
            } else {
                c.queue.close(Ok(()));
            }
        }
        3 => {
            // SAFETY: process-info kind selects the process member.
            let process = unsafe { (*info).process };
            c.queue.update_stats(|s| {
                s.stream_warnings += 1;
                if process.reason == 122 {
                    s.oversized_packets += 1;
                }
            });
        }
        _ => (),
    }));
}
