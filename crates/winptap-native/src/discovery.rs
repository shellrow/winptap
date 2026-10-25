use crate::device::DeviceHandle;
use winptap_core::*;
pub(crate) fn enumerate(handle: &DeviceHandle) -> Result<Vec<Device>> {
    let mut header = [0u8; 4];
    match handle.ioctl(crate::ioctl::Control::EnumerateComponents, &[], &mut header) {
        Ok(_) | Err(Error::Windows { code: 234, .. }) => (),
        Err(e) => return Err(e),
    }
    let mut size = u32::from_le_bytes(header) as usize;
    for _ in 0..8 {
        if !(8..=64 * 1024 * 1024).contains(&size) {
            return Err(Error::InvalidData("component list size"));
        }
        let mut bytes = vec![0; size];
        match handle.ioctl(crate::ioctl::Control::EnumerateComponents, &[], &mut bytes) {
            Ok(returned) => {
                if returned < 8 {
                    return Err(Error::InvalidData("component header"));
                }
                let count = u16::from_le_bytes(bytes[4..6].try_into().unwrap()) as usize;
                if 8 + count * 0x13b0 > returned {
                    return Err(Error::InvalidData("component list extent"));
                }
                let mut result = Vec::new();
                for i in 0..count {
                    let b = &bytes[8 + i * 0x13b0..8 + (i + 1) * 0x13b0];
                    fn text(b: &[u8]) -> String {
                        let v: Vec<_> = b
                            .chunks_exact(2)
                            .map(|p| u16::from_le_bytes([p[0], p[1]]))
                            .take_while(|c| *c != 0)
                            .collect();
                        String::from_utf16_lossy(&v)
                    }
                    let id = u32::from_le_bytes(b[0x184..0x188].try_into().unwrap());
                    let kind = u32::from_le_bytes(b[0x180..0x184].try_into().unwrap());
                    result.push(Device {
                        backend: Backend::NativeIoctl,
                        id,
                        secondary_id: id,
                        parent_id: 0,
                        name: text(&b[..128]),
                        description: text(&b[128..384]),
                        network_interface: kind == 2,
                        guid: None,
                        mac_address: None,
                    });
                }
                return Ok(result);
            }
            Err(Error::Windows { code: 234, .. }) => {
                size = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::InvalidData("component list kept changing"))
}
