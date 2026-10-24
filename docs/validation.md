# v0.2.0 validation

Earlier v0.1.0 validation covered Windows 11 build 26200.9457. Build numbers here
record test environments; they do not define a runtime support allowlist.

## Environment and scope

Validated on 2026-10-25 (Asia/Tokyo) using an owner-provided Windows 11 25H2 VM,
build 26200.9711, Windows x64 MSVC, and an administrator SSH session. The NIC
capture point was `kdnic.sys` (Microsoft Kernel Debug Network Adapter).
Neither `npcap`/`npf` services nor Packet.dll in System32 or System32/Npcap were
found. The controlled IPv4/UDP fixture was sent from a second machine to port
48931. No system-wide capture was stopped or driver installed.

## Results

| Check | Result |
|---|---|
| Offline workspace tests, all features | 46 passed; live tests ignored |
| Formatting, warnings-denied Clippy | Passed |
| Feature combinations | None, pktmon, native, tokio, pktmon+tokio, native+tokio, all passed |
| Rust 1.85 library MSRV | All workspace libraries and features checked |
| Rust 1.88 examples/tests | All targets and features checked |
| Non-Windows compilation | FreeBSD x64 cross-check passed; no runtime claim |
| Official/native parity | Identical 203-byte Ethernet frame, component and timestamp |
| Truncation | Both returned 100 bytes; native supplied original length |
| Original Capture lifecycle | 100 cycles per backend including restart; handles 100 to 100 |
| PacketReceiver lifecycle | 100 cycles per backend with thread migration, stop/cancel/drop; handles 100 to 100 |
| Async cancellation | Both backends passed |
| Native-only executable | Receive and 100 movable receiver cycles passed; handles 93 to 93 |
| Bounded queue under traffic | Both policies and both backends retained exactly 8 packets and recorded overflow |
| nex-datalink compatibility | Receive-only trait/Send check and actual default-interface Ethernet receive passed |

The main seven-test live run passed in 22.93 seconds. The additional backpressure
test passed in 4.23 seconds, with a nominal sender rate of 1000 datagrams/s.
Actual sender throughput was lower; these are observation counts, not throughput
benchmarks. Each one-second stalled-consumer case observed more than 1300 records,
recorded queue overflow, and drained exactly eight packets. Parse errors and driver
missed-read/write counters were zero. Multiple observations per datagram are
preserved. Statistics need not sum to a datagram count, especially during shutdown.

Receive-only integration with nex-datalink was verified against nex dev revision
`cec99308f25d8dc44fd3eaf54db6335c5141fe79` using a temporary adapter. That validation
code is not retained in this repository; the nex working tree was not modified.
Live interface selection uncovered the mixed GUID/MAC union issue documented in
[compatibility](compatibility.md). A regression test covers that record shape,
and the normal capture example and nex receiver both succeeded after the fix.

## Reproduce

Ordinary checks never open capture:

```powershell
./scripts/validate.ps1
cargo +1.85.0 check --workspace --lib --all-features --locked
cargo +1.88.0 check --workspace --all-targets --all-features --locked
```

Build the live executable, then run it sequentially in a controlled administrator
Windows environment with `WINPTAP_TEST_INTERFACE` set to the enumerated driver
name. Start controlled traffic on another machine before the test run:

```powershell
cargo test -p winptap --test live --all-features --no-run
$env:WINPTAP_TEST_INTERFACE = "kdnic.sys"
# Use the executable path printed by Cargo:
# live-<hash>.exe --ignored --test-threads=1 --nocapture
python scripts/send-test-traffic.py <VM-IP> --seconds 60 --rate 1000
```

For independence, build with `--no-default-features --features native` and run only
`live_native_independent`, `live_movable_receiver_capture`,
`live_movable_receiver_lifecycle`, and `live_queue_backpressure`. The older parity
and truncation tests require both backends. Run suites separately so their
process-wide handle measurements and UDP listeners do not interfere.

## Remaining qualification

This evidence covers one VM adapter and current Windows build. Physical Ethernet,
Wi-Fi, VLAN/offload/jumbo variants, additional Windows releases and Server,
adapter removal, sleep/resume, multi-hour saturation, full memory-leak analysis,
and quantitative CPU/latency benchmarks remain unverified. Do not infer those
results from offline CI or the short controlled traffic tests. Publishing and
release decisions remain manual.
