# Compatibility

## Requirements

Capture requires Windows and administrator privileges. The official backend
loads the streaming exports from `Pktmonapi.dll` at runtime; the presence of
`pktmon.exe` alone does not establish API availability.

## Troubleshooting

| Symptom | Check |
|---|---|
| `PermissionDenied` | Run from an administrator terminal. |
| `MissingApi` or `RevisionMismatch` | Check the enabled Cargo features and available Packet Monitor API. `Auto` can fall back to native on Windows x64. |
| No matching interface | Use the example's `--list` option. OS indices differ from Packet Monitor component IDs. |
| Ambiguous interface mapping | Select a NIC explicitly with `--component ID` from `--list`. |
| Receive timeout | Check the selected interface, filters, and traffic direction. Native capture delivers receive packets only. |
| Native device or IOCTL error | Record the Windows build and error code. The installed driver may use a different protocol. |
