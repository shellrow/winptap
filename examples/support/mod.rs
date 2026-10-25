use netdev::Interface;
use winptap::{Backend, CaptureDevice};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Options {
    pub backend: Backend,
    pub count: Option<usize>,
    interface: Option<String>,
    component: Option<u32>,
    list: bool,
    help: bool,
}

impl Options {
    pub fn parse(backend: Backend, count: Option<usize>) -> Result<Self> {
        Self::from_args(std::env::args().skip(1), backend, count)
    }

    pub fn from_args(
        args: impl IntoIterator<Item = String>,
        backend: Backend,
        count: Option<usize>,
    ) -> Result<Self> {
        let mut options = Self {
            backend,
            count,
            interface: None,
            component: None,
            list: false,
            help: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-i" | "--interface" => {
                    if options.interface.is_some() {
                        return Err("--interface may only be supplied once".into());
                    }
                    options.interface = Some(args.next().ok_or("missing interface name or index")?);
                }
                "--component" => {
                    options.component = Some(args.next().ok_or("missing component ID")?.parse()?);
                }
                "-c" | "--count" => {
                    let count = args.next().ok_or("missing packet count")?.parse()?;
                    if count == 0 {
                        return Err("packet count must be positive".into());
                    }
                    options.count = Some(count);
                }
                "--native" => options.backend = Backend::NativeIoctl,
                "-l" | "--list" => options.list = true,
                "-h" | "--help" => options.help = true,
                _ => return Err(format!("unknown argument: {arg}; use --help").into()),
            }
        }
        if options.interface.is_some() && options.component.is_some() {
            return Err("--interface and --component cannot be combined".into());
        }
        Ok(options)
    }

    /// Return None for help/list operations, without starting capture.
    pub fn select(&self) -> Result<Option<CaptureDevice>> {
        if self.help {
            println!(
                "Options:\n  -i, --interface NAME|INDEX|GUID  OS interface (default: netdev default)\n      --component ID             Explicit Packet Monitor NIC component\n      --native                   Use the native receive backend\n  -l, --list                     List OS interfaces and capture components\n  -c, --count N                  Stop after N packets\n  -h, --help                     Show help"
            );
            return Ok(None);
        }
        let interfaces = netdev::get_interfaces();
        if self.list {
            println!("OS interfaces (use --interface):");
            for interface in &interfaces {
                println!(
                    "  {}: {}  {}  {}",
                    interface.index,
                    interface.friendly_name.as_deref().unwrap_or(""),
                    interface.name,
                    interface.description.as_deref().unwrap_or("")
                );
            }
        }
        let devices = CaptureDevice::list_with_backend(self.backend)?;
        if self.list {
            println!("Packet Monitor NIC components (use --component):");
            for device in devices.iter().filter(|d| d.network_interface) {
                println!(
                    "  {}: {}  {}  {:?}",
                    device.id, device.name, device.description, device.backend
                );
            }
            return Ok(None);
        }
        let device = if let Some(id) = self.component {
            unique(
                devices.iter().filter(|d| d.network_interface && d.id == id),
                "capture component",
            )?
            .clone()
        } else {
            let interface = match &self.interface {
                Some(selector) => unique(
                    interfaces.iter().filter(|i| {
                        selector.parse::<u32>().ok() == Some(i.index)
                            || selector.eq_ignore_ascii_case(&i.name)
                            || i.friendly_name
                                .as_ref()
                                .is_some_and(|n| selector.eq_ignore_ascii_case(n))
                            || guid(selector).is_some_and(|g| Some(g) == guid(&i.name))
                    }),
                    "OS interface",
                )?
                .clone(),
                None => netdev::get_default_interface().map_err(|e| {
                    format!("cannot determine default interface: {e}; use --interface")
                })?,
            };
            let index = match_interface(
                &interface,
                &interfaces,
                &devices.iter().map(|d| (**d).clone()).collect::<Vec<_>>(),
            ).map_err(|error| format!(
                "cannot map OS interface {} to a capture component: {error}; use --list and select --component ID explicitly",
                interface.name,
            ))?;
            devices[index].clone()
        };
        eprintln!(
            "Capturing on {} ({}, component {}, {:?})",
            device.name, device.description, device.id, device.backend
        );
        Ok(Some(device))
    }
}

fn unique<'a, T>(mut items: impl Iterator<Item = &'a T>, kind: &str) -> Result<&'a T> {
    let first = items
        .next()
        .ok_or_else(|| format!("no matching {kind}; use --list"))?;
    if items.next().is_some() {
        return Err(
            format!("ambiguous {kind}; use --list and specify --component explicitly").into(),
        );
    }
    Ok(first)
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
    // Windows stores the first three GUID fields in little-endian order.
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    Some(bytes)
}

/// Prefer GUID identity. Native enumeration may expose only an adapter description;
/// accept that fallback only when unique among both OS interfaces and components.
pub fn match_interface(
    interface: &Interface,
    interfaces: &[Interface],
    devices: &[winptap_core::Device],
) -> Result<usize> {
    fn identity(i: &Interface) -> winptap::InterfaceIdentity<'_> {
        winptap::InterfaceIdentity {
            name: &i.name,
            description: i.description.as_deref(),
            mac_address: i.mac_addr.map(|m| m.octets()),
        }
    }
    let identities: Vec<_> = interfaces.iter().map(identity).collect();
    let candidates: Vec<_> = devices.iter().cloned().map(CaptureDevice).collect();
    let selected = CaptureDevice::for_interface(identity(interface), &identities, &candidates)?;
    devices
        .iter()
        .position(|d| d == &selected.0)
        .ok_or_else(|| "selected capture device disappeared".into())
}
