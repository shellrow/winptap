# Architecture

| Crate | Responsibility |
|---|---|
| `winptap` | Public configuration, device selection, and capture lifecycle |
| `winptap-core` | Packet types, decoding, filters, and bounded queues |
| `winptap-pktmon` | Official API bindings, DLL loading, sessions, streams, and callbacks |
| `winptap-native` | Native device access, sessions, shared buffers, and polling reader |

The native backend has no dependency on the official backend. Both implement a
session interface with `start`, `stop`, and access to the receive queue.

## Packet delivery

Packets own their bytes. Official callbacks check descriptor bounds and copy
the payload before returning. The native reader copies a ring record while
holding its entry and byte reservations, then decodes the record and copies its
payload into a packet. Driver-owned memory is never exposed to callers.

A mutex protects the bounded queue. Overflow drops either the incoming packet
or the oldest queued packet. Producers may wait briefly for the mutex but do
not wait for queue capacity. A condition variable serves synchronous receivers;
Tokio `Notify` serves async receivers. Normal stop allows the queue to drain.
Fatal errors and cancellation take precedence over queued packets.

Repeated observations are preserved by default. `DuplicatePolicy::Component`
restricts capture to a component; it does not deduplicate by packet contents.
Group IDs identify observations and should not be used to match packets across
sessions.

## Resource ownership

Capture handles stay on the owning thread. Constructors release resources on
partial failure. The official backend loads the DLL from System32 and keeps it
and the callback context alive until the stream closes. The stream closes before
the session.

The native session retains its buffer allocations even if the reader panics.
`stop` deactivates the session and joins the reader; the session can restart.
Dropping it detaches the stream, deletes the session, closes the device, and
releases the buffers. Device close precedes buffer release so the driver's
file-close cleanup can remove mappings if explicit detachment fails.

Each capture manages its own session. The library does not stop global Packet
Monitor capture. Native device access can start the existing Windows `PktMon`
service but does not install or stop it.

## Performance

Official delivery copies each payload once. Native delivery currently copies
the ring record and then its payload. The native reader sleeps for 1 ms when
idle. Changes to these paths must preserve buffer ownership and publication
ordering.
