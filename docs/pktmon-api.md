# Official Packet Monitor API

## Loading and sessions

The backend loads `Pktmonapi.dll` with `LOAD_LIBRARY_SEARCH_SYSTEM32` and resolves
all required exports before initialization. `PacketMonitorInitialize` requests
version `0x00010000` with a null reserved argument. The DLL stays loaded until
all sessions and callbacks have been released.

Each capture owns a monitor, live session, and real-time stream. Activation and
deactivation affect that session only; cleanup does not call global `PktmonStop`.
See the [Microsoft API reference](https://learn.microsoft.com/en-us/windows/win32/pktmon/pktmon-reference)
for the session and stream functions.

The source list contains a pointer array, not an inline array of structures.
Allocation sizes and every returned source pointer are checked before copying.
Enumeration retries up to eight times if the list grows. Source structs are
424 bytes on x64; ID offset is 388. Filter constraints are 216 bytes. ABI layout assertions
cover these values. Sources are re-enumerated and checked when opening a session.
There is no assumed mapping from a component ID to an interface index.

## Documented ABI discrepancy

Microsoft's stream page declares metadata that naturally occupies 48 bytes.
The tested 26200.9457 driver and DLL deliver a packed 40-byte record.
The decoder supports the 40-byte wire layout when the payload immediately
follows it, and the documented 48-byte layout otherwise. The latter has offline
tests, not live validation on a different Windows build.

Packed offsets are group ID 0, count 8, appearance 10, direction 12, payload type
14, component 16, edge 18, reserved 20, drop reason 22, drop location 26,
processor 30, and system timestamp 32. The timestamp uses 100-nanosecond Windows
system-time units, not QPC ticks. The reference's natural offsets for drop reason,
drop location, processor, and timestamp are 24, 28, 32, and 40.

The observed DLL returns `0x80070519` for an unsupported API version; the reference
mentions `0x8007051A`. Both are handled as revision mismatch.

The DLL's missed-read descriptor counter is cumulative; the library records
wrapping deltas. Missed-write counts are per-record and accumulated separately.
Fatal events close the queue with their reason code. Oversize process warnings,
malformed records, and application queue overflow have independent statistics.

## Cleanup and capture limits

The official stream reader is joined by `PacketMonitorCloseRealtimeStream`.
The stream must close before the session, because its destructor removes its
entry from the session's output collection. Callback context and DLL ownership
remain alive throughout this sequence.

The requested default snaplen is 9000. Static inspection also found a 9000-byte
internal staging allocation for the entire stream record in this DLL; near-limit
payloads can therefore trigger an oversize warning before reaching the requested
payload length. Jumbo-frame behavior has not been verified. The official
descriptor does not include the original packet length.
