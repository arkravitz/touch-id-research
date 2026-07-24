# External Touch ID: further analysis without hardware

This continues [FINDINGS.md](FINDINGS.md) using the saved macOS 27.0.1 kernel disassembly. Everything below is **seen in static code** unless marked inferred. No external keyboard, Arduino, new authentication attempt, or live pairing operation was used. These are driver-visible structures and call arguments; Bluetooth packet encapsulation remains unverified.

## Replies are matched to requests

`AppleTrustedAccessory::waitForInterruptReport` starts at `0xfffffe000a0877e0`. Its queue scanner checks that a descriptor has at least five bytes, then reads:

| Offset | Size | Meaning established by use |
| --- | --- | --- |
| `0` | 1 | Report ID |
| `1` | 4 | Request counter, little-endian on this target |
| `5` onward | variable | Operation-specific reply |

The comparisons at `0xfffffe000a0879a4..0xfffffe000a0879b8` require both the expected report ID and request counter. This is message correlation, not by itself cryptographic replay protection. The enclosing requests increment an accessory object's counter at offset `0x1fc`.

The crypto-challenge path reads a nine-byte reply and treats the 32-bit value at reply offset 5 as its result: a nonzero value branches to failure. See `0xfffffe000a08cff0..0xfffffe000a08d014`.

## Additional report operations

The earlier report already identifies query-pairing, key-generation, and session-key operations. Further recovered operations are:

| Driver operation | Request report ID | Expected interrupt reply |
| --- | --- | --- |
| Preliminary exchange within `pair` | SetReport `0x6b` | `0x49` |
| Main exchange within `pair` | SetReport `0x61` | `0x43` |
| `verifyCryptoChallengeGated` | SetReport `0x63` | `0x49` |
| `getManifestGated` | GetReport `0x45` | Synchronous GetReport result |

All listed calls use report-type argument `2`. SetReport uses the vtable slot resolved in FINDINGS.md; GetReport uses the adjacent preceding slot. Further annotation establishes that both stages occur sequentially on the observed new-pairing success path, after cached query state and readiness guards. Early exits and already-paired state remain separate paths. See [the consolidated reference](docs/PROTOCOL-REFERENCE.md).

Selected evidence addresses:

- Preliminary pairing request/reply: `0xfffffe000a089dbc`, `0xfffffe000a089de4`.
- Main pairing request/reply: `0xfffffe000a089f8c`, `0xfffffe000a089fb0`.
- Crypto challenge request/reply: `0xfffffe000a08cf68`, `0xfffffe000a08cf8c`.
- Manifest request: `0xfffffe000a08b25c`.

## The manifest has an explicit length

`getManifestGated` allocates a `0xa04`-byte descriptor and issues GetReport `0x45`. In the resulting buffer it reads a 32-bit length at offset zero, rejects values greater than `0xa00` (2560), and copies that many bytes from offset 4. This establishes a bounded, length-prefixed opaque blob. **Unknown:** its internal format, signing, and policy semantics.

`sendAccessoryManifestToSEP` packages the blob and submits enclave transaction `5`. Its driver-created buffer is:

| Offset | Size | Content |
| --- | --- | --- |
| `0` | 16 | Accessory identifier bytes |
| `0x10` | 1 | Boolean argument supplied to the method |
| `0x11` | 4 | Manifest length |
| `0x15` | variable | Manifest bytes |

The identifier's semantic label is inferred from the accessory getter and its use elsewhere; the copy size and offsets are explicit. Evidence: `0xfffffe000a098b5c..0xfffffe000a098bc4`.

## Pairing completion reaches the enclave

After `AppleTrustedAccessory::pair` returns output blobs, the manager constructs a separate enclave request and submits transaction **`0x15`**, at `0xfffffe000a0965f8..0xfffffe000a096614`. This is distinct from the HID report IDs above and the host framework command numbers.

The constructed enclave input contains:

| Offset | Content |
| --- | --- |
| `0` | 16-byte accessory identifier |
| `0x10` | 65-byte key-shaped input copied by the manager |
| `0x51` | 32-bit length A |
| `0x55` | Blob A, in a reserved region of `0x600` bytes |
| `0x655` | 32-bit length B |
| `0x659` | Blob B |

The manager rejects length A of `0x601` or greater. Total allocation is `0x659 + length B`. Calling the 65-byte field a specific elliptic-curve encoding, or assigning certificate/signature meanings to A and B, would require further evidence.

The success path checks transaction `0x15`, sends the manifest with transaction `5`, checks that result, and then calls `publishReadiness`. **Inferred:** successful host report parsing alone does not complete pairing; the enclave transactions are further gates. Their internal validation logic is not visible in this host kernel disassembly.

## What we can do without purchasing anything

We can continue annotating the branch conditions, initial device discovery, public-key retrieval, HID descriptors, remaining report layouts, and the structures crossing into `stac`. We can also model those formats entirely offline to check consistency. Such a model would validate our interpretation, not prove that the real enclave accepts a fabricated sensor.

The central unresolved question is what the enclave requires for pairing acceptance, and whether there is any supported way for independently provisioned hardware to satisfy it. Fully understanding host framing will not create the hardware-held credentials. No bypass or working third-party native Touch ID implementation is demonstrated here.

Evidence excerpts: [focused functions](evidence/pairing-deep-dive-functions.txt). For the manager's complete pairing function, use [the full driver disassembly](evidence/AppleTrustedAccessory-kernel-disassembly.txt), symbol `__ZN28AppleTrustedAccessoryManager13pairAccessoryEPKhPKvm`.
