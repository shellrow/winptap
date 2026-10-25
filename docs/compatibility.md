# Compatibility

## Requirements

Capture requires Windows and administrator privileges. The official backend
loads the streaming exports from `Pktmonapi.dll` at runtime; the presence of
`pktmon.exe` alone does not establish API availability.

The native backend uses an undocumented driver protocol and requires Windows x64.
Availability is determined by the platform, API availability, permissions, and
driver responses, not a Windows build allowlist. Tested environments are recorded
in [validation](validation.md). The official backend remains the preferred path.
Neither backend sends packets or requests promiscuous mode.

## Interface identity

The official API can report multiple presence flags for its shared identity union.
On the tested build, the GUID/MAC combination contains MAC bytes overwriting part
of the GUID. winptap leaves `guid` unset in this case and exposes the MAC instead.
`CaptureDevice::for_interface` prefers a valid GUID, then a MAC unique on both
sides, then a unique description. A conflicting known identity is never ignored.
NIC components with identical identity information in one parent/child hierarchy
select the common parent capture point. This handles drivers that also expose a
NetAdapterCx child. Independent components sharing a MAC still require a unique
description or explicit component selection; enumeration order never breaks ties.
The native enumerator supplies no MAC or GUID, so differing OS/driver descriptions
can still require explicit component selection.

The union layout is documented by Microsoft's
[PacketMonitorEnumDataSources reference](https://learn.microsoft.com/en-us/windows/win32/pktmon/packetmonitor/nf-packetmonitor-packetmonitorenumdatasources);
the mixed-field behavior above was observed on the validation VM.

## Troubleshooting

| Symptom | Check |
|---|---|
| `PermissionDenied` | Run from an administrator terminal. |
| `MissingApi` or `RevisionMismatch` | Check the enabled Cargo features and available Packet Monitor API. `Auto` can fall back to native on Windows x64. |
| No matching interface | Use the example's `--list` option. OS indices differ from Packet Monitor component IDs. |
| Ambiguous interface mapping | Select a NIC explicitly with `--component ID` from `--list`. |
| Receive timeout | Check the selected interface, filters, and traffic direction. Native capture delivers receive packets only. |
| Native device or IOCTL error | Record the Windows build and error code. The installed driver may use a different protocol. |
