use crate::{ffi::Source, loader::Context};
use winptap_core::*;
pub(crate) fn sources(context: &Context, hidden: bool) -> Result<Vec<Source>> {
    let mut needed = 0;
    // SAFETY: documented size query with no output allocation.
    let hr = unsafe {
        (context.api.enumerate)(
            context.handle,
            0,
            hidden.into(),
            0,
            &mut needed,
            std::ptr::null_mut(),
        )
    };
    if hr < 0 && hr as u32 != 0x8007007a && hr as u32 != 0x800700ea {
        hresult("PacketMonitorEnumDataSources", hr)?;
    }
    for _ in 0..8 {
        if needed == 0 {
            return Ok(Vec::new());
        }
        if needed > 64 * 1024 * 1024 {
            return Err(Error::InvalidData("source list exceeds limit"));
        }
        // Eight-byte alignment covers the pointer array and Source.
        let mut storage = vec![0u64; needed.div_ceil(8)];
        let capacity = storage.len() * 8;
        // SAFETY: writable aligned output allocation of capacity bytes.
        let hr = unsafe {
            (context.api.enumerate)(
                context.handle,
                0,
                hidden.into(),
                capacity,
                &mut needed,
                storage.as_mut_ptr().cast(),
            )
        };
        if hr as u32 == 0x8007007a || hr as u32 == 0x800700ea {
            continue;
        }
        hresult("PacketMonitorEnumDataSources", hr)?;
        let base = storage.as_ptr() as usize;
        let length = needed.min(capacity);
        if length < 8 {
            return Err(Error::InvalidData("source list header"));
        }
        let count = storage[0] as u32 as usize;
        let pointers = count
            .checked_mul(std::mem::size_of::<usize>())
            .and_then(|n| n.checked_add(8))
            .ok_or(Error::InvalidData("source count overflow"))?;
        if pointers > length {
            return Err(Error::InvalidData("source pointer table"));
        }
        let mut result = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: table extent checked; each pointer-sized element is aligned.
            let address = unsafe { *((base + 8) as *const usize).add(index) };
            let offset = address
                .checked_sub(base)
                .ok_or(Error::InvalidData("source pointer before allocation"))?;
            if offset
                .checked_add(std::mem::size_of::<Source>())
                .is_none_or(|end| end > length)
            {
                return Err(Error::InvalidData("source pointer outside allocation"));
            }
            // SAFETY: Source contains only integer fields and lies inside the live allocation.
            result.push(unsafe { (address as *const Source).read_unaligned() });
        }
        return Ok(result);
    }
    Err(Error::InvalidData("source list kept changing"))
}
pub(crate) fn device(s: &Source) -> Device {
    fn string(s: &[u16]) -> String {
        String::from_utf16_lossy(&s[..s.iter().position(|c| *c == 0).unwrap_or(s.len())])
    }
    let mut detail = [0; 16];
    detail[..8].copy_from_slice(&s.detail[0].to_ne_bytes());
    detail[8..].copy_from_slice(&s.detail[1].to_ne_bytes());
    Device {
        backend: Backend::Pktmon,
        id: s.id,
        secondary_id: s.secondary_id,
        parent_id: s.parent_id,
        name: string(&s.name),
        description: string(&s.description),
        network_interface: s.kind == 1,
        // Detail is a union. Some Windows builds set both GUID and MAC flags
        // but overwrite the first six GUID bytes with the MAC. Never expose
        // that mixed value as an interface GUID.
        guid: (s.present == 1).then_some(detail),
        mac_address: matches!(s.present, 8 | 9).then(|| detail[..6].try_into().unwrap()),
    }
}
pub(crate) fn enumerate(context: &Context, hidden: bool) -> Result<Vec<Device>> {
    Ok(sources(context, hidden)?.iter().map(device).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overwritten_union_is_not_reported_as_a_guid() {
        let mut source = Source {
            kind: 1,
            name: [0; 64],
            description: [0; 128],
            id: 9,
            secondary_id: 9,
            parent_id: 0,
            present: 9,
            detail: [u64::from_le_bytes([0, 12, 41, 188, 70, 255, 152, 67]), 0],
        };
        let parsed = device(&source);
        assert_eq!(parsed.guid, None);
        assert_eq!(parsed.mac_address, Some([0, 12, 41, 188, 70, 255]));
        source.present = 1;
        assert!(device(&source).guid.is_some());
        assert!(device(&source).mac_address.is_none());
        source.present = 3;
        assert!(device(&source).guid.is_none());
        assert!(device(&source).mac_address.is_none());
    }
}
