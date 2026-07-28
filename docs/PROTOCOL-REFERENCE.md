# Recovered protocol reference

Scope: host-visible external Touch ID structures on macOS build 26A434.
All HID and enclave layouts here are **seen in static driver code**. The
host serializer additionally has native differential evidence. No Bluetooth
capture, real external pairing, or enclave acceptance has been obtained.

## Layers and namespaces

1. `TAManagerProxy` packs host commands as `<uint16 magic=0x4154, command,
   version, in_value>` plus opaque payload. Small native allocations are 16 KB.
   No general payload length exists in that header. Complete host command
   selector0 dispatch and payloads are documented in [HOST-AND-SESSION.md](HOST-AND-SESSION.md);
   selectors1/2 and notification bodies are documented in [SECURE-INTENT.md](SECURE-INTENT.md).
2. `AppleTrustedAccessory` uses feature GetReport/SetReport operations and
   interrupt replies. An interrupt pairing reply begins with byte report ID,
   then a little-endian uint32 request counter. Feature replies do not share
   this envelope. GetReport has no recovered outbound body in this model.
3. The manager forwards pairing/session material to enclave endpoint `stac`.
   Enclave validation is opaque; framing does not establish trust.
4. `AppleMesaAccessory` receives sensor reports `b4`–`b7`, which start with a
   report ID but do not use the pairing counter envelope. Capture data passes
   through `AppleMesaSEPDriver` to endpoint `sbio`.

Numbers at different layers are separate namespaces. The following sizes
are driver buffers, not Bluetooth packet lengths. Capacity is an allocation
size, not proof of the exact size returned by a device.

## Trusted-accessory operation inventory

| Operation | Feature operation / ID | Outbound bytes | Interrupt reply ID | Reply bytes / interpretation |
| --- | --- | ---: | --- | --- |
| `protocol_info` | get 0x4b | — | feature result | 8 descriptor_capacity |
| `select_protocol` | set 0x68 | 8 | — | —  |
| `uid` | get 0x41 | — | feature result | 16 descriptor_capacity |
| `nonce` | get 0x4c | — | feature result | 16 descriptor_capacity |
| `public_key` | set 0x67 | 4 | 0x40 | 74 minimum |
| `query_pairing` | set 0x60 | 137 | 0x42 | 8 minimum |
| `generate_key` | set 0x66 | 8 | 0x47 | 74 minimum |
| `transfer` | set 0x6a | 532 | — | —  |
| `pair_prepare` | set 0x6b | 137 | 0x49 | 9 minimum |
| `pair` | set 0x61 | 202 | 0x43 | 3601 exact |
| `unpair` | get 0x44 | — | feature result | 4 descriptor_capacity |
| `manifest` | get 0x45 | — | feature result | 2564 descriptor_capacity |
| `compute_session` | set 0x62 | 329 | 0x46 | 1549 minimum |
| `issue_challenge` | get 0x48 | — | feature result | 60 descriptor_capacity |
| `verify_challenge` | set 0x63 | 64 | 0x49 | 9 minimum |
| `start_intent` | set 0x64 | 12 | 0x49 | 9 minimum |
| `secure_intent_nonce` | set 0x65 | 48 | — | —  |
| `cancel` | set 0x64 | 12 | 0x49 | 9 minimum |

The machine-readable inventory provides the symbol and instruction addresses
for each row: [operations.json](../evidence/operations.json). `unpair` is modeled
only as a four-byte status reply; no live unpair operation is performed.

## Field layouts and boundaries

- Query/prepare: counter32, identity length32, reserved identity region129;
  identity is 1–129 bytes. Main pair appends a fixed 65-byte key.
- Generate key: counter32, key type32; observed callers use type1 for pairing,
  type2 for a session. Public-key request contains the counter alone.
- Key replies: envelope5, status32, key65. These are key-shaped opaque bytes;
  the codecs do not validate curve points.
- Pair reply: exactly3601 bytes, status at5, lengthA at9, A at13 in a1536-byte
  region; lengthB at1549, B at1553 in a2048-byte region. Success requires A1–1536;
  B0–2048. The session reply shares the first1549 bytes.
- Compute session request: counter32, key65, challenge length32, reserved
  challenge region256. Challenge length1–256.
- Transfer: counter32, type32, total32, offset32, chunk length32, reserved
  chunk region512. Observed types1/2. Chunks use the same counter; the offline
  reassembler rejects overlaps, gaps, duplicates, mixed transfers, and truncation.
- Verify challenge: counter32 + opaque60; issue challenge returns raw60.
- Start intent: counter32 + uint32(1) + uint32(1). Cancel: counter32 +0 +0.
- Secure intent nonce: opaque48, no counter. Async report `4a` carries a report
  ID plus48 bytes forwarded to the manager, outside the normal reply queue.
- Manifest: length32 + up to2560 bytes. Its content and attestation semantics
  remain unresolved. Nonzero status values do not establish their error meanings.

All multibyte integers above are little-endian. Reserved padding is retained
when decoded; encoders use canonical zero padding unless supplied explicitly.
That does not establish that every real scratch buffer is zero-filled.

## Pairing and session sequence

The observed new-pairing success path checks readiness and cached query state,
transfers type1 material, performs prepare `6b`/`49`, transfers type2 material,
and performs main pair `61`/`43`. Those two stages occur sequentially on that
path; early exits and previously-paired state are separate branches. The
manager then performs enclave completion transaction `0x15`, submits the
manifest with transaction5, and publishes readiness after successful results.

Known `stac` wrappers and source anchors are in [PROTOCOL.md](../PROTOCOL.md).
Session setup crosses `stac` transactions6 and7; their wrappers now have codecs
and [source annotations](HOST-AND-SESSION.md), together with transaction0x0e's
challenge validation input. Complete failure/state behavior still needs analysis.
A simulated success is never reported as native trust.

## Sensor capture path

See [SENSOR-REPORTS.md](SENSOR-REPORTS.md) for fixed sensor report layouts,
metadata getter semantics, packed image buffers, and `sbio` transactions
`0x74`/`0x75`. These have offline encoders/decoders and malformed-input fixtures.

## Evidence strength and remaining work

- Native host serializer:111 complete fresh-object buffers matched, including
  16 KB allocation boundaries and65 KB inputs; saved comparison JSON.
- HID/SEP/sensor codecs: static instruction evidence plus independent synthetic
  fixtures. They have not been differentially tested against live hardware.
- Scripted peer: deterministic framing/order checks using opaque fixtures; no
  cryptographic implementation or hardware transport.
- Outstanding accessible analysis: opaque enclave outputs, manager properties,
  full lifecycle/state behavior, sensor mode/calibration semantics,
  per-capture status values, and a
  complete source-to-codec coverage review.
- External limits: no genuine Bluetooth reference device; protected enclave
  implementation and required device credentials remain unavailable. No working
  entirely third-party native Touch ID implementation is claimed.
