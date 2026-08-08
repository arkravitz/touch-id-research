# Progress — protocol-lab plan

Plan: docs/superpowers/plans/2026-10-19-protocol-lab.md
Spec: docs/superpowers/specs/2026-10-19-protocol-lab.md

- Task 1 in progress: existing artifacts re-read; recovered additional discovery/report operations.
- Ruling: use standard-library Python; no third-party dependencies required.
- Ruling: reproduce driver buffers and host command packing; Bluetooth encapsulation and enclave cryptographic acceptance stay unknown until independently established.
- Pre-flight: Task 2 consumes Task 1 schemas; Task 3 consumes Task 2 codecs. Types and bounds will be pinned by evidence and independent fixtures.

- Task 2 substantial implementation: 14 codec tests passing; 111 complete buffers matched native serializer. Decoder/encoder bounds derive from independent fixtures and instruction offsets.
- Task 3 substantial implementation: scripted peer + CLI + synthetic transcript; full suite 27 tests passing.
- Ruling: native serialization checks compare fresh-object full buffers; cache reuse is explicitly uncharacterized.
- Ruling: version negotiation follows observed nonzero check then fixed selection 1; do not infer advertised-mask semantics.
- Evidence correction: cancel's final two words are zero, not 0/1; corrected fixture failed then codec was fixed.
- Task 1 remains in progress: discovered AppleMesaAccessory sensor stream/control/calibration path; saved report candidates. Next annotate its report classes and add field-level codecs.
- Task 4 not complete: do not mark goal done while sensor path and protocol coverage audit remain.

- Sensor report increment: confirmed b4 minimum is six bytes (although the copied error consumes bytes 1–4); added b4/b5/b6/b7 decoder, five independent field/bounds tests, and docs/SENSOR-REPORTS.md. Full suite: 27 passed. Next trace capture-data packing and enclave submission; native acceptance remains unverified.

- Capture increment: resolved OSData and driver virtual calls; recovered image/metadata/extra packing and SBIO transactions 0x74/0x75. Added codecs, metadata getter model, CLI commands, independent malformed/boundary fixtures, and focused evidence. Current full suite: 34 passing.
- Inventory increment: unpair raw status decoded from static code; distinguished descriptor capacity from minimum/exact lengths. Added docs/PROTOCOL-REFERENCE.md. Task 1 and coverage audit remain active for calibration, command modes, host dispatch and remaining stac wrappers.

- Feature increment: recovered calibration status/length header (0xab), repeated opaque-data reads (0xac), nonzero finger presence (0xa1), and mode-to-report mapping. Added header/state codecs and tests. Current suite: 36 passing. Evidence reference audit confirms all 18 inventory report-address anchors lie within their named functions; audit remains explicitly partial.

- Host/session increment: decoded actual 14-entry signed-relative dispatch table, mapped selector0 commands 2–15, and recovered payload lengths/fields. Added manager.py, stac.py, 13 additional tests including CLI integration, and docs/HOST-AND-SESSION.md. Current suite: 49 passed.
- Evidence: testSecureSessionWithAccessory explicitly repeats identical challenges in both directions and requires the second call to fail. Recorded as static test logic, not observed runtime replay resistance.
- Ruling: manager codecs model bounded structures and preserve padding; they do not attempt to duplicate native out-of-bounds behavior or invoke privileged handlers. Cost if wrong: a malformed-buffer compatibility edge differs; no native trust claim depends on it.
- Next accessible work: selector1/2 secure-intent operation input, manager outputs and notifications, initial pairing wrappers, property meanings, unresolved command14 object, and coverage review. Both milestones remain active.

- Selector1/2 follow-up: performOperation confirms selector1 accepts header command1/version1 and at least41 payload bytes; payload words at0 and4, up-to32-byte context at8, byte40 controls a later operation flag. stac0x10 receives only first40 bytes. Selector2 checks version1 and cancels for the calling IOService without checking header.command. Saved focused source; operation codecs and notification semantics remain next.

- Intent/coverage increment: intent.py encodes selector1/2 operations, stac context and detected-intent wrappers, and notification bodies. Added four manager output codecs, initial pairing/authorization wrappers, and generic stac routing for all22 observed opcodes. Saved32 direct call sites with reproducible index tool and coverage matrix. Full suite:65 passing.
- Evidence: successful secure-intent notification follows stac0x13 validation of UID16+opaque48. Notification bodies are16 bytes; Mach headers/port rights remain outside the model. Native status-body reserved bytes are unknown and preserved rather than assumed zero.
- Ruling: transaction1 identity decoder models the fixed129-byte region and later HID capacity, while explicitly documenting that cacheDirectAttestationKey lacks that upper-bound check. This conservative parsing boundary is not claimed as exact native malformed-input behavior.
- Next: review manager properties/command14, sensor info/metadata, opaque outputs and lifecycle; integrate boundary transcripts and run full source/code coverage review. No hardware/enclave compatibility claim.
