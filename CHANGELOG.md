# Changelog

## 0.2.0 (unreleased)

### Added

- `PacketReceiver`: a `Send` receiver with a dedicated session owner, synchronous
  startup errors, cancellation cleanup, and optional Send-compatible async receive.
- `InterfaceIdentity` and `CaptureDevice::for_interface` for dependency-independent
  GUID matching and unambiguous MAC/description fallback.
- Typed capture error conversion to `std::io::Error`.
- An opt-in adapter fixture compiled against the adjacent nex dev checkout.

### Fixed

- Empty and direction-only filters now accept short captured frames.
- IP predicates reject EtherType/version mismatches.
- Async queue termination wakes all registered consumers.
- Native reader creation failure deactivates the session immediately.
- Configuration rejects mismatched backend/device identities before opening a backend.
- Packet Monitor's overlapping GUID/MAC detail is no longer exposed as a corrupted
  GUID. NIC selection can use a unique MAC when driver and OS descriptions differ.

### Compatibility

- `winptap_core::Device` has a new optional `mac_address` field; callers constructing
  device literals must supply it. Normal enumeration callers need no migration.
- Error display text now describes failures; use typed variants for program logic.
- Removed the unused `UnsupportedWindowsBuild` error and native compatibility
  module's `VALIDATED_BUILDS`, `VALIDATED_REVISIONS`, and `current_build` APIs.
  Tested Windows versions are documentation-only records.

## 0.1.0

### Added

- Windows packet capture through the official Packet Monitor API and an
  independent native receive backend.
- Interface selection, packet metadata, filters, bounded queues, and capture
  statistics.
- Synchronous receive and optional Tokio support, with timeout and cancellation.
- Capture examples with netdev interface discovery and a nex-based packet dump.
- Offline tests, Windows integration tests, and CI checks.
