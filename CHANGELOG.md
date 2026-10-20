# Changelog

## Unreleased

### Added

- Windows packet capture through the official Packet Monitor API and an
  independent native receive backend.
- Interface selection, packet metadata, filters, bounded queues, and capture
  statistics.
- Synchronous receive and optional Tokio support, with timeout and cancellation.
- Capture examples with netdev interface discovery and a nex-based packet dump.
- Offline tests, Windows integration tests, and CI checks.
