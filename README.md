# winptap

A Rust packet capture library for Windows, built on Packet Monitor. No Npcap or
additional driver is required.

winptap provides synchronous and optional async capture, interface selection,
packet filters, and capture statistics. Packet data includes the link type,
timestamp, direction, and source component.

## Requirements

- Windows and an administrator terminal for capture.
- Windows x64 for the native backend.
- Rust 1.88 or newer to build the examples and run tests.

Both backends have been tested on Windows 11 build 26200.9457. See
[compatibility](docs/compatibility.md) for backend requirements and known limits.

## Usage

```toml
[dependencies]
winptap = { path = "path/to/winptap/crates/winptap" }
netdev = "0.46.3"
```

```rust,no_run
use winptap::{Capture, CaptureConfig, CaptureDevice, LinkType};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface = netdev::get_default_interface()?;
    let description = interface.description.as_deref()
        .filter(|s| !s.is_empty())
        .ok_or("default interface has no adapter description")?;

    // Match the adapter description, not the OS interface index.
    if netdev::get_interfaces().iter().any(|other| {
        other.index != interface.index
            && other.description.as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(description))
    }) {
        return Err("adapter description is ambiguous; select a component explicitly".into());
    }
    let mut devices = CaptureDevice::list()?
        .into_iter()
        .filter(|d| d.network_interface && d.description.eq_ignore_ascii_case(description));
    let device = devices.next().ok_or("default interface is not available for capture")?;
    if devices.next().is_some() {
        return Err("multiple capture components match the default interface".into());
    }

    let mut capture = Capture::open(
        CaptureConfig::builder()
            .device(device)
            .link_type(LinkType::Ethernet)
            .build()?,
    )?;
    capture.start()?;
    while let Some(packet) = capture.next_packet()? {
        println!("{} bytes: {:?}", packet.data().len(), packet.metadata());
    }
    capture.stop()?;
    Ok(())
}
```

This snippet matches the default interface by its adapter description and rejects
ambiguous matches. The command-line examples also support GUID matching and
explicit component selection.

## Examples

Run from the repository root in an administrator PowerShell terminal:

```powershell
# List OS interfaces and Packet Monitor components.
cargo run -p winptap --example capture -- --list

# Capture on the default interface, or select one by name or OS index.
cargo run -p winptap --example capture
cargo run -p winptap --example capture -- -i "Ethernet"
cargo run -p winptap --example capture_native -- -i 12

# Print live packet summaries. Press Ctrl+C to stop.
cargo run -p winptap --example dump
cargo run -p winptap --example dump -- --native -i "Wi-Fi" --count 100

# Build and run with only the native backend.
cargo run -p winptap --no-default-features --features native --example capture_native
```

`capture`, `capture_native`, and `dump` accept `--interface` (`-i`) with an OS
index, friendly name, or adapter GUID. When omitted, they use
`netdev::get_default_interface()`. If the interface cannot be mapped uniquely,
use `--list` and select a Packet Monitor NIC with `--component ID`. Component IDs
and OS interface indices are different; `--component` and `--interface` are
mutually exclusive.

`capture` and `capture_native` stop after ten packets or a five-second receive
timeout. `--count N` changes the packet limit. `dump` runs until Ctrl+C or its
optional packet limit, and prints UTC timestamps, direction, addresses, ports,
TCP flags, and protocol details using [nex](https://github.com/shellrow/nex).
Interface discovery uses [netdev](https://github.com/shellrow/netdev). Both are
example dependencies, not library dependencies.

## Backends and features

| Backend | Capture | Interface |
|---|---|---|
| `Backend::Pktmon` | Receive and transmit | Documented `Pktmonapi.dll` streaming API |
| `Backend::NativeIoctl` | Receive only | Direct access to `PktMonDev` on Windows x64 |

`Backend::Auto` prefers the official API and falls back to native capture when
exports are missing or the API version is incompatible. Permission errors are
returned to the caller. When a device is supplied, `Auto` uses that device's
backend. Enumerate native devices with
`CaptureDevice::list_with_backend(Backend::NativeIoctl)`.

The default Cargo features are `pktmon` and `native`. Add `tokio` for
`next_packet_async`:

```powershell
cargo run -p winptap --features tokio --example capture_async
```

A capture stays on its owning thread. Use a current-thread Tokio runtime or a
`LocalSet`; cancellation tokens can be sent to other threads.

## Capture behavior

The defaults are a 9000-byte snaplen, a ring multiplier of 1 (256 KiB), and a
1024-packet application queue. Choose `DropNewest` or `DropOldest` to control
queue overflow.

`next_packet` waits for a packet; `try_next_packet` polls. A receive timeout
returns `Error::Timeout`. After `stop`, queued packets remain readable, followed
by `Ok(None)`. A stopped capture can restart. Fatal errors and cancellation are
terminal; call `stop` or drop the capture to release active resources.

`capture_filter` applies supported constraints in the driver and checks the full
predicate in Rust. `application_filter` runs only in Rust. Filters support MAC
addresses, EtherType, VLAN ID, IP addresses, protocol, ports, and direction.

Packet bytes are copied from Windows without modification. Prefer NIC capture
points when Ethernet headers matter. Offloading, truncation, and upper-stack
capture points affect what Windows reports.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE),
at your option.
