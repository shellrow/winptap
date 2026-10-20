use std::{
    ptr::NonNull,
    sync::atomic::{AtomicU32, Ordering},
};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};
use winptap_core::*;
/// Page-aligned memory pinned by the driver only while an attached stream exists.
pub(crate) struct Allocation {
    pointer: NonNull<u8>,
    pub size: usize,
}
impl Allocation {
    pub fn new(size: usize) -> Result<Self> {
        // SAFETY: requests a fresh zero-filled, page-aligned allocation.
        let p = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        Ok(Self {
            pointer: NonNull::new(p.cast()).ok_or(Error::Windows {
                operation: "VirtualAlloc",
                code: 8,
            })?,
            size,
        })
    }
    pub fn address(&self) -> u64 {
        self.pointer.as_ptr() as usize as u64
    }
    fn atomic(&self, offset: usize) -> &AtomicU32 {
        assert!(offset % 4 == 0 && offset + 4 <= self.size);
        // SAFETY: page alignment and checked offset provide aligned atomic storage.
        // Kernel accesses these counters through aligned loads and lock-prefixed RMW.
        unsafe { &*self.pointer.as_ptr().add(offset).cast::<AtomicU32>() }
    }
    fn word(&self, offset: usize) -> Result<u32> {
        if offset + 4 > self.size || offset % 4 != 0 {
            return Err(Error::InvalidData("ring word outside allocation"));
        }
        // SAFETY: checked alignment/bounds; producer ownership was acquired first.
        Ok(unsafe {
            self.pointer
                .as_ptr()
                .add(offset)
                .cast::<u32>()
                .read_volatile()
        })
    }
}
// SAFETY: ownership can move to the sole reader thread. Kernel access follows the
// published counter protocol. No Rust slice aliases the shared allocation.
unsafe impl Send for Allocation {}
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: callers must detach/close the device before releasing allocations.
        unsafe {
            VirtualFree(self.pointer.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}
pub(crate) struct Ring {
    pub control: Allocation,
    pub packets: Allocation,
    entries: u32,
    read_index: u32,
}
impl Ring {
    pub fn new(multiplier: u16) -> Result<Self> {
        let entries = u32::from(multiplier) * 1000;
        Ok(Self {
            control: Allocation::new(0x94 + entries as usize * 8)?,
            packets: Allocation::new(256 * 1024 * usize::from(multiplier))?,
            entries,
            read_index: 0,
        })
    }
    pub fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let count = self.control.atomic(0x8c).load(Ordering::Acquire);
        if count == 0 {
            return Ok(None);
        }
        if count > self.entries {
            return Err(Error::InvalidData("invalid ring occupancy"));
        }
        let index = self.read_index;
        let offset = self.control.word(0x94 + index as usize * 8)? as usize;
        let length = self.control.word(0x98 + index as usize * 8)? as usize;
        if offset >= self.packets.size || length < 64 || length > self.packets.size || length > 9064
        {
            return Err(Error::InvalidData("invalid ring packet extent"));
        }
        let used = self.control.atomic(0x90).load(Ordering::Acquire);
        if used < length as u32 || used > self.packets.size as u32 {
            return Err(Error::InvalidData("invalid ring byte occupancy"));
        }
        let mut bytes = Vec::with_capacity(length);
        for i in 0..length {
            let address = (offset + i) % self.packets.size;
            // SAFETY: the acquired entry owns these bytes until both counters are
            // released below; modulo bounds each volatile access within the ring.
            bytes.push(unsafe { self.packets.pointer.as_ptr().add(address).read_volatile() });
        }
        self.read_index = (index + 1) % self.entries;
        self.control
            .atomic(4)
            .store(self.read_index, Ordering::Release);
        self.control
            .atomic(0x90)
            .fetch_sub(length as u32, Ordering::AcqRel);
        self.control.atomic(0x8c).fetch_sub(1, Ordering::AcqRel);
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn put(a: &Allocation, offset: usize, value: u32) {
        // SAFETY: tests own the allocation exclusively; no kernel mapping exists.
        unsafe {
            a.pointer
                .as_ptr()
                .add(offset)
                .cast::<u32>()
                .write_unaligned(value);
        }
    }
    #[test]
    fn wrapped_record_and_release_accounting() {
        let mut ring = Ring::new(1).unwrap();
        let offset = ring.packets.size - 32;
        for i in 0..64 {
            // SAFETY: bounded writes into exclusively test-owned storage.
            unsafe {
                ring.packets
                    .pointer
                    .as_ptr()
                    .add((offset + i) % ring.packets.size)
                    .write(i as u8);
            }
        }
        put(&ring.control, 0x94, offset as u32);
        put(&ring.control, 0x98, 64);
        put(&ring.control, 0x90, 64);
        put(&ring.control, 0x8c, 1);
        assert_eq!(ring.read().unwrap().unwrap(), (0u8..64).collect::<Vec<_>>());
        assert!(ring.read().unwrap().is_none());
        assert_eq!(ring.control.atomic(0x90).load(Ordering::Acquire), 0);
    }
    #[test]
    fn corrupted_ring_is_rejected_without_reading_payload() {
        let mut ring = Ring::new(1).unwrap();
        put(&ring.control, 0x94, u32::MAX);
        put(&ring.control, 0x98, 64);
        put(&ring.control, 0x90, 64);
        put(&ring.control, 0x8c, 1);
        assert!(ring.read().is_err());
        put(&ring.control, 0x8c, 1001);
        assert!(ring.read().is_err());
    }
}
