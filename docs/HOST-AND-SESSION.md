# Host dispatch and session wrappers

Everything below is **seen in static code** in the local build, unless marked
inferred. No manager operation was invoked. Cryptographic fields remain opaque.
Focused source: `evidence/host-session-functions.txt`.

## Request routing

`performRequestGated` checks an input length >=8 and magic `0x4154`
(`fffffe000a094ad8..fffffe000a094aec`). The eight-byte host header is followed
by the remainder of the mapped buffer; there is no general payload-length
field. The framework's 16 KB allocation can therefore appear as trailing
padding to operation-specific fields.

The IOKit selector is separate from the header command. Selector0 calls
`performCommand`; selectors1/2 call `performOperation` with different boolean
arguments. Evidence: `fffffe000a094b54..fffffe000a094bd4`. Thus command numbers
below describe **selector0**, not every operation available through the client.
The command codecs do not execute IOKit requests or model entitlement acceptance.

## Selector0 dispatch table

`performCommand` subtracts2 from header.command and dispatches an inclusive
14-entry table for commands2–15; every handler checks header.version==1.
The table is at `fffffe000a096080`, with signed32 relative offsets based at
`fffffe000a095094`. Raw and annotated entries are in
`evidence/host-dispatch-table.json`.

| Command | Lab name | Input payload structure | Downstream / output |
| --- | --- | --- | --- |
| 2 | `enclave_0b` | No fields consumed | stac `0x0b` output to IOMD |
| 3 | `enclave_0a` | No fields consumed | stac `0x0a` output to IOMD |
| 4 | `pair` | UID16, opaque36, length32, blob | `pairAccessory` |
| 5 | `unpair` | UID16 | `unpairAccessory` |
| 6 | `unpair_all` | No fields consumed | `unpairAllAccessories` |
| 7 | `is_connected` | UID16 | Boolean: accessory object found |
| 8 | `query_pairing` | UID16 | stac2 + optional accessory query, five-byte output |
| 9 | `find_accessories` | count32, records72[] | count32 + matched UID16[] |
| 10 | `test_session` | UID16 | Challenge/replay checks described below |
| 11 | `authorize` | type32, UID16, length32, reserved32, optional extra length32/blob | `authorizeAccessory`, stac `0x14` |
| 12 | `get_property` | UID16, property32 | property32, length32, reserved64 |
| 13 | `inject_input` | UID16, input type32 | `injectInput` |
| 14 | `command_14` | No fields consumed | Two unresolved virtual methods on manager object at `0x140` |
| 15 | `enclave_16` | UID16 | stac `0x16` output to IOMD |

All integers here are little-endian. Commands2/3/14 retain neutral names because
downstream meaning is unresolved. Command9's records are property32, length32,
reserved data64, and the codec conservatively rejects length>64. Command11's
primary authorization length is bounded to32 by `authorizeAccessory` at
`fffffe000a0973c8`. A 56-byte input can omit the extra field; inputs >=60 bytes
can provide an extra length at56, with data at60.

Command4's 36-byte region is retained without assigning a meaning. Its length
is at52 and data at56 (`fffffe000a09522c..fffffe000a09523c`). The manager codec
validates that declared variable lengths fit the supplied bytes. It is a
bounded structural model, not a promise to reproduce all native handling of
malformed buffers. Successful outputs for connection presence, pairing flags,
property data, and UID lists now have dedicated offline codecs via
`encode/decode manager_result`. Other outputs remain opaque.

Example (synthetic, memory only):

```sh
python3 -m touchid_lab encode manager find_accessories '{"records":[{"property":7,"data":"414243"}]}'
```

`encode manager` includes the eight-byte host header. `decode manager command
HEX` reads the command from that header. These tools always remain offline.

## stac session setup

`establishSessionWithAccessory` first submits the manifest with flag false,
asks the accessory for a type2 key, then sends transaction6:

```
UID[16] | accessory_key[65]                       # 81 bytes
```

Evidence: `fffffe000a098ed8..fffffe000a098f14`. Its response is interpreted as
key65, length32 at65, and challenge bytes at69. The driver checks outer length
>=69 (`fffffe000a098f1c..fffffe000a098f30`) then delegates to the accessory's
`computeSessionKey`, which enforces challenge length1–256. The lab decoder also
checks that the declared length fits the actual response; this is a structural
bound, not evidence that the enclave itself accepts synthetic keys.

The accessory returns a nonempty blob of at most1536 bytes. The manager then
submits transaction7 with a zero-initialized fixed1556-byte buffer:

```
UID[16] | uint32_le blob_length | blob[blob_length] | unused[1536-blob_length]
```

Evidence: zeroing at `fffffe000a098e7c..fffffe000a098e84`, length guard and
assembly at `fffffe000a098fa4..fffffe000a098fc8`, submission at
`fffffe000a098fd4..fffffe000a098fe8`. Successful transaction7 precedes publishing
readiness. That order supports the inference that host framing alone cannot
complete session establishment.

Codecs: `touchid_lab.stac`, also exposed as `encode/decode sep session_begin`,
`session_material`, and `session_completion`. They do not derive session keys.

## Explicit duplicate-challenge rejection checks

`testSecureSessionWithAccessory` requests a challenge from stac transaction
`0x0d` using UID16, requiring a response of at least60 bytes. It calls the
accessory's `verifyCryptoChallenge` **twice with the same buffer**, requiring
success first and a nonzero result on the second call. Source:
`fffffe000a097d84..fffffe000a097dc0`.

It then asks the accessory to issue a challenge and packages:

```
UID[16] | opaque_challenge[60]                    # 76 bytes
```

The manager submits this identical input to stac transaction `0x0e` twice,
requiring first success and then a nonzero result. Source:
`fffffe000a097dd4..fffffe000a097e48`. The wrapper is available as
`encode/decode sep challenge_validation`.

**Seen:** the host explicitly tests duplicate rejection in both directions.
**Inferred:** this exercises cryptographic replay resistance beyond the HID
reply-counter correlation. **Unknown:** the enclave/accessory algorithm,
state representation, rejection codes, and real device behavior for this test.
Static test logic is not an observed successful live replay test.

## Remaining accessible work

Selector1/2 operation payloads and manager notification bodies now have codecs
and [source annotations](SECURE-INTENT.md). Initial pairing wrappers and other
enclave inputs are indexed in [STAC-MATRIX.md](STAC-MATRIX.md). Property meanings,
command14's object type, opaque outputs, and complete failure/state transitions
still need analysis and coverage.
Native third-party trust and Bluetooth encapsulation remain unverified.

Follow-up static evidence for selectors1/2 is saved in
`evidence/secure-intent-operation-functions.txt`. Selector1 requires header
command1/version1 and payload length>=41 (`fffffe000a096140..fffffe000a09616c`).
`startSecureIntent` reads a uint32 at0, a length32 at4 bounded to32, context at8
in a32-byte region, and a flag byte at40. It submits the first40 bytes in a
zero-initialized buffer to stac transaction `0x10`
(`fffffe000a098294..fffffe000a0982d8`); byte40 affects later operation state
(`fffffe000a098444..fffffe000a098450`). Precise field semantics are unresolved.
Selector2 checks version1 and cancels for the calling IOService; this branch
does not check header.command (`fffffe000a096184..fffffe000a09619c`). These
operation inputs have dedicated codecs in `touchid_lab.intent`.
