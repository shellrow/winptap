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

See [compatibility](docs/compatibility.md) for backend requirements and known limits,
and [validation](docs/validation.md) for tested environments and results.

## Usage

The following example targets the unreleased v0.2.0 API from this checkout.
The published v0.1.0 remains available on crates.io.

```toml
[dependencies]
winptap = { path = "path/to/winptap/crates/winptap" }
netdev = "0.46.3"
```

```rust,no_run
use winptap::{CaptureConfig, CaptureDevice, InterfaceIdentity, LinkType, PacketReceiver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interface = netdev::get_default_interface()?;
    let interfaces = netdev::get_interfaces();
    let identities: Vec<_> = interfaces.iter().map(|i| InterfaceIdentity {
        name: &i.name,
        description: i.description.as_deref(),
        mac_address: i.mac_addr.map(|m| m.octets()),
    }).collect();
    let device = CaptureDevice::for_interface(
        InterfaceIdentity {
            name: &interface.name,
            description: interface.description.as_deref(),
            mac_address: interface.mac_addr.map(|m| m.octets()),
        },
        &identities,
        &CaptureDevice::list()?,
    )?;

    // PacketReceiver opens and starts capture on its dedicated owner thread.
    let mut capture = PacketReceiver::open(
        CaptureConfig::builder()
            .device(device)
            .link_type(LinkType::Ethernet)
            .build()?,
    )?;
    while let Some(packet) = capture.next_packet()? {
        println!("{} bytes: {:?}", packet.data().len(), packet.metadata());
    }
    capture.stop()?;
    Ok(())
}
```

Interface matching prefers the adapter GUID, then a MAC address or description unique among
both OS interfaces and capture components. Conflicting GUIDs are never matched
by description. The command-line examples also support explicit component selection.

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

| Backend | Traffic observed | Interface |
|---|---|---|
| `Backend::Pktmon` | Receive and transmit | Documented `Pktmonapi.dll` streaming API |
| `Backend::NativeIoctl` | Receive only | Direct access to `PktMonDev` on Windows x64 |

Neither backend injects or sends packets. Observing transmit traffic means
capturing packets sent by other applications. Packet Monitor does not request
promiscuous mode or provide a replacement for every Npcap feature.

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

`Capture` stays on its owning thread; use a current-thread Tokio runtime or a
`LocalSet`. `PacketReceiver` owns a dedicated session thread and can move across
threads, including into a multithreaded Tokio task. Both expose cancellation tokens.

## Capture behavior

The defaults are a 9000-byte snaplen, a ring multiplier of 1 (256 KiB), and a
1024-packet application queue. Choose `DropNewest` or `DropOldest` to control
queue overflow.

`next_packet` waits for a packet; `try_next_packet` polls. A receive timeout
returns `Error::Timeout`. After `stop`, queued packets remain readable, followed
by `Ok(None)`. A stopped capture can restart. Fatal errors and cancellation are
terminal; call `stop` or drop the capture to release active resources.

`PacketReceiver` starts during `open` and cannot restart. It shares the backend's
bounded queue without a second queue or extra packet copy. Cancellation and fatal
errors wake its owner to release resources automatically; `stop` and `Drop` join
the owner. Stopping normally preserves queued packets.

Capture errors convert to `std::io::Error`, preserving the typed source and
mapping timeouts to `TimedOut` and cancellation to `Interrupted`.

`capture_filter` applies supported constraints in the driver and checks the full
predicate in Rust. `application_filter` runs only in Rust. Filters support MAC
addresses, EtherType, VLAN ID, IP addresses, protocol, ports, and direction.

Packet bytes are copied from Windows without modification. Prefer NIC capture
points when Ethernet headers matter. Offloading, truncation, and upper-stack
capture points affect what Windows reports.

See [nex integration](docs/nex-integration.md) for the receive-only adapter and
[validation](docs/validation.md) for checks and outstanding live qualification.

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache License 2.0](LICENSE-APACHE),
at your option.
