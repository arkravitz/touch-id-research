# Milestones 1 and 2 — current status

The user's full objective remains active: recover and reproduce the protocol as far as possible without new hardware.

## Verified progress

- Recovered the host header, small-command buffer allocation, trusted-accessory recognition, entitlement gate, HID request/response correlation, pairing and session operations, chunked transfer, secure intent, and several SEP wrappers.
- Implemented standard-library Python encoders/decoders for the recovered trusted-accessory structures and recovered pairing/session SEP wrapper formats.
- Implemented a scripted peer, command-line tools, and synthetic discovery/pairing/session/intent transcripts.
- 65 automated tests passed, including malformed lengths, fixed offsets, wrong reply IDs, stale counters, duplicate/out-of-order transfers, native trust refusal, and CLI errors.
- Compared 111 complete buffers with Apple's original host serializer: all matched. Native allocations are 16384 bytes for small inputs, then at least payload length + 8 for larger inputs.
- Inspected local SEP firmware packaging: an IM4P `sepi` payload is available, but its sampled payload is high entropy and no recognizable Mach-O/LZFSE header or `stac`/`sbio` text was found. Encryption is an inference, not established by entropy alone. Inventory is saved in `evidence/sep-firmware-inventory.json`.

## Current research frontier

A separate `AppleMesaAccessory` implementation in `AppleMesaSEPDriver` exposes sensor-operation reports beyond the pairing interface. Located so far:

- Set command mode: report ID is `0x78 | mode`, mode < 5, with a one-byte descriptor.
- Sensor info: GetReport `0xa0`, 91-byte descriptor.
- Finger state: GetReport `0xa1`.
- Calibration: GetReport `0xab` then `0xac`.
- Interrupt processing names include image metadata/data, finger state, and button-state reports.

Four interrupt report layouts (`b4`–`b7`) now have encoders/decoders, along with capture buffer and identity wrappers; see [SENSOR-REPORTS.md](SENSOR-REPORTS.md). The 17-byte image region is verified as capture metadata with button/wake/count getters. Packed capture buffers reach SBIO transaction `0x74`, followed on the observed success path by UID + metadata transaction `0x75`. Their contents remain partly opaque, and no runtime sensor traffic has been captured. Selector0 command dispatch and payloads are now modeled. Selectors1/2 inputs, four manager output formats, initial pairing SEP structures, and intent notification bodies now have codecs and source annotations. Remaining property/sensor semantics, opaque outputs and full state behavior need analysis and review. The remaining scope has not been reduced to the existing passing tests.

## Interpretation corrections made during implementation

- Protocol negotiation: the observed driver accepts a nonzero advertisement and sends a fixed selection of version 1. This is now reflected in the helper; the advertised integer's complete semantics remain unknown.
- Cancel uses counter + zero + zero, while starting secure intent uses counter + one + one. The wrong initial assumption was caught against disassembly and corrected with a failing fixture first.
- Apple's serializer returns an initial 16 KB buffer. Comparing only the logical header would have missed this; native verification now compares complete buffers.

## Remaining external limits

No genuine external Touch ID device is available for Bluetooth/report-descriptor or pairing captures. No enclave acceptance, cryptography, or native compatibility has been demonstrated. More host-side static work is still available, so this is currently incomplete work rather than a terminal hardware blocker.

The consolidated docs/PROTOCOL-REFERENCE.md now links the operation inventory, layer namespaces, observed success path, sensor layouts, and verification limits. Unpair GetReport `0x44` has a four-byte status codec, verified statically without running an unpair operation.

Feature follow-up: `0xab` calibration status/length and `0xa1` nonzero finger presence now have codecs. Repeated `0xac` reads and mode ID mapping 78–7c are documented with source addresses. Calibration contents and mode meanings remain unresolved. Partial verification audit: evidence/verification.json.

Host/session increment: docs/HOST-AND-SESSION.md and evidence/host-dispatch-table.json cover all 14 selector0 table entries. New modules manager.py and stac.py reproduce their recovered input structures and session wrappers. Static code explicitly tests duplicate challenge rejection on the accessory and enclave, but no real replay test was performed.

Current stac coverage:22 opcodes across32 direct generic-transfer call sites, indexed in evidence/stac-call-sites.json. All recovered input structures route through offline codecs; only established response structures decode. docs/SECURE-INTENT.md and docs/STAC-MATRIX.md document the limits.
