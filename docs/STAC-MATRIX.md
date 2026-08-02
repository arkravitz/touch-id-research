# stac transaction structure coverage

The saved trusted-accessory disassembly contains32 direct calls to
`AppleSEPGenericTransfer::transact` or `transactToIOMD`, using opcodes1–22.
`evidence/stac-call-sites.json` retains each caller, call address, and instruction
window. `tools/index_stac_calls.py` reproduces that index. Its opcode candidate
is a bounded last-immediate search, so the index is a discovery aid; the layouts
below are based on reading the callers. This is not proof that no other driver,
firmware, or indirect path can issue additional operations.

| Opcode | Host-created input | Host-consumed output |
| --- | --- | --- |
| `01` | Empty | length32 + identity region129; outer size>=133 |
| `02` | UID16 | At least2 bytes, two flags |
| `03` | UID16 + static key65 + generated pairing key65 | key65 + length32 + variable pairing material |
| `04` | UID16 | No returned buffer |
| `05` | UID16 + flag8 + length32 + manifest | No returned buffer |
| `06` | UID16 + generated session key65 | key65 + length32 + variable session material |
| `07` | UID16 + length32 + reserved blob1536 | No returned buffer |
| `08` | UID16 | No returned buffer |
| `09` | UID16 + presence byte | No returned buffer |
| `0a` | Empty | Opaque IOMD output |
| `0b` | Empty | Opaque IOMD output; analytics consumers need further study |
| `0c` | Empty | No returned buffer |
| `0d` | UID16 | At least60 opaque challenge bytes |
| `0e` | UID16 + challenge60 | No returned buffer |
| `0f` | uint32 value | No returned buffer |
| `10` | type32 + context length32 + reserved context32 | No returned buffer |
| `11` | Empty | No returned buffer |
| `12` | UID16 | At least48 opaque nonce bytes |
| `13` | UID16 + opaque intent48 | No returned buffer |
| `14` | type32 + UID16 + length32 + reserved authorization32 + extra length32/blob | No returned buffer |
| `15` | UID16 + static key65 + lengthA32 + reserved A1536 + lengthB32 + B | No returned buffer |
| `16` | UID16 | Opaque IOMD output |

"No returned buffer" means the caller passes null output pointers. The integer
transaction result is returned separately; the table does not assert success
or assign meanings to failure codes. Opcodes are arguments to the enclave
transfer API, not prefixes of these buffers, HID IDs, or host command numbers.

All input shapes above have offline `stac.encode_request`/`decode_request`
routing. Output codecs cover only the recovered structures for opcodes1,2,3,6,
0d,12. Opaque outputs and null-output transactions are rejected by the generic
response decoder instead of being presented as synthetic acceptance.

## Pairing input and authorization evidence

Transaction3 is assembled at `fffffe000a0964a0..fffffe000a0964f4`: UID at0,
static accessory public-key-shaped bytes at16, and the type1 generated key at81,
total146 bytes. Its response is checked for outer size>=69 and enough bytes
for the length at65 (`fffffe000a0964fc..fffffe000a096518`). The variable material
then reaches the accessory's pairing operation.

Transaction1's consumer checks response size>=133, reads length at0, and copies
from4 (`fffffe000a094e58..fffffe000a094ea8`). The lab models a129-byte region
and rejects larger declared lengths. That bound reflects the fixed wrapper and
later HID identity capacity; it is **not an upper-bound check seen in this cache
function**. The parser deliberately does not imitate potential out-of-bounds
native behavior. Identity bytes, key material, certificates, and signatures
remain opaque rather than interchangeable credentials.

Transaction0x14 is assembled at `fffffe000a09746c..fffffe000a0974f0`, with the
authorization length bounded to32 at `fffffe000a0973c8`. The manager sets its
accessory authorization flag only after a successful transaction result
(`fffffe000a0974f4..fffffe000a097508`). This is another enclave gate after host
payload parsing.

Detailed session and replay evidence: [HOST-AND-SESSION.md](HOST-AND-SESSION.md).
Detailed intent and notification evidence: [SECURE-INTENT.md](SECURE-INTENT.md).

The matrix is structural coverage, not an implementation of enclave logic,
attestation, image encryption, key derivation, or fingerprint matching. Further
accessible work remains in sensor metadata/device information, property and
mode meanings, lifecycle conditions, opaque outputs, and the overall review.
