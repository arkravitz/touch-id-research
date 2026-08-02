# Sensor reports recovered without hardware

These layouts are **seen in static code**, not captured Bluetooth packets. Source:
`evidence/AppleMesaSEPDriver-kernel-disassembly.txt`, classes
`MesaAccessoryIntReportError`, `MesaAccessoryIntReportFingerState`,
`MesaAccessoryIntReportImage`, and `MesaAccessoryIntReportImageInfo`.
The report ID occupies byte zero. The base `processReportMD` checks a minimum
length, so extra bytes are allowed. These reports do not use the pairing
reply's four-byte counter envelope.

| ID | Minimum bytes | Fields copied by the driver |
| --- | ---: | --- |
| `b4` | 6 | Little-endian 32-bit error at offset 1; byte 5's meaning unknown |
| `b5` | 10 | State byte at 1, opaque eight-byte field at 2 |
| `b6` | 10818 | 10752-byte image-related blob at 1, 17 bytes at `0x2a01`, 48 bytes at `0x2a12` |
| `b7` | 308 | Marker at 1, 306 bytes of metadata at 2; marker `ff` enables derived metadata |

Evidence anchors (kernel virtual addresses for this build):

- Error minimum: `fffffe00099ba5b4`; copy: `fffffe00099ba668`.
- Finger minimum: `fffffe00099ba9d0`; copies: `fffffe00099baa84`, `fffffe00099baa8c`.
- Image minimum: `fffffe00099bafec`; regions: `fffffe00099bb0bc..fffffe00099bb11c`.
- ImageInfo minimum: `fffffe00099bb5d0`; copy and marker: `fffffe00099bb69c..fffffe00099bb6b4`.

The image-related blob is **not established as plaintext pixels**. Timestamp,
nonce, authentication tag, image dimensions, and encryption algorithm remain
unknown for these specific regions. Further tracing establishes that the
17-byte region is passed as `ma_image_metadata`; it is not justified to call
the entire region an IV.

`touchid_lab.sensor` encodes and decodes the observed fixed fields and rejects
truncated buffers. The report decoder retains ImageInfo's raw 306-byte region;
a separate typed decoder now exposes its fixed records, as described below.

## Capture metadata and enclave submission

**Seen:** `accessoryIntReportHandlerGated` passes the image object's three regions
to `IOMesaCaptureDataAccessory::create` at `fffffe00099b3718..fffffe00099b3728`.
Its typed signature identifies the middle argument as `ma_image_metadata*`.
The constructor copies 17 bytes to object offset `0x38`.

Named native getters establish these uses within that metadata:

| Metadata offset | Observed use |
| --- | --- |
| `0..1` | Flags, read as little-endian uint16 |
| Flags bits `0..1` | `getButtonState` maps 0,1,2,3 to return values 1,3,4,2 |
| Flags bit `3` | `getWakeOnMenuPinUsed` returns the mask value 0 or 8 |
| `2..9` | Opaque eight-byte field; also used by `bioDeviceFromCaptureData` |
| `10` | Meaning unresolved |
| `11` | Count; `getCaptureCounter` returns count−1 when nonzero, otherwise zero |
| `12..16` | Five bytes consumed as per-capture values; meanings unresolved |

Getter anchors: `fffffe000998e798`, `fffffe000998ee6c`, `fffffe000998ee84`.
No semantic names are assigned to button-state enum values without tracing
their consumers. Other consumers use flags bits 4–6; their meanings need study.

For non-null image and extra OSData objects, the constructor builds:

```
uint32_le image_length
uint32_le metadata_length = 17
uint32_le extra_length
image_bytes[image_length]
metadata[17]
extra_bytes[extra_length]
```

For the fixed `b6` report, lengths are 10752, 17, 48; the packed result is
10829 bytes. Evidence: `fffffe000998e33c..fffffe000998e40c` establishes lengths
and capacity; `fffffe000998e45c..fffffe000998e500` appends header, image, metadata,
then extra. Resolved OSData vtable slots `0x160`, `0x188`, `0x190` are
`getLength`, `appendBytes(void*, uint32)`, and `appendBytes(OSData*)`, respectively.
Resolution data is saved in `evidence/capture-vtable-resolution.json`.

In the accessory branch of `asyncCaptureHandler`, the buffer is submitted via
`sepTransact(0x74, bytes, length, ...)` at `fffffe0009991b54..fffffe0009991b74`.
On that path, successful submission is followed by transaction `0x75` with
exactly 33 bytes: the accessory UID (16) followed by metadata (17), assembled
at `fffffe0009991bb4..fffffe0009991bc4` and submitted at `fffffe0009991bf0..fffffe0009991c14`.
The UID comes from the accessory object at offset `0x98`.

Driver vtable slot `0x9b8` resolves to `AppleMesaSEPDriver::sepTransact` at
`fffffe00099b3074`; its body forwards arguments to
`AppleSEPGenericTransfer::transact` at `fffffe00099b3130..fffffe00099b314c`.
Apple's `enumSBIOCommandToString` table labels `0x74` and `0x75` as `Unknown`;
we retain the numbers. Table extraction: `evidence/sbio-command-names.json`.
The complete focused source is `evidence/capture-submission-functions.txt`.

These are **SBIO transactions**, distinct from similarly numbered HID report
IDs or `stac` pairing transactions. The observed accessory path also handles
metadata-only `b7` reports; not every report necessarily submits a nonempty
image buffer. A null image skips buffer construction in the constructor.

CLI examples (all synthetic and offline):

```sh
python3 -m touchid_lab decode sensor report b5020001020304050607
python3 -m touchid_lab decode sensor metadata 0000000000000000000000000000000000
python3 -m touchid_lab encode sensor capture '{"image_blob":"414243","metadata":"0000000000000000000000000000000000","extra":"5859"}'
```

This advances the sensor-to-enclave boundary reconstruction. It does not
demonstrate enclave acceptance, fingerprint matching, Bluetooth transport,
or a working third-party Touch ID device. Remaining questions include
calibration, command-mode semantics, the per-capture values, and cryptographic
validation inside the enclave.

## Feature operations: calibration, state, and command modes

**Seen:** `AppleMesaAccessory::getCalibrationData` reads GetReport `0xab`
into an eight-byte descriptor. Offset0 is uint32 status (nonzero aborts);
offset4 is uint32 total length. The total must fit the caller's output
capacity before an intermediate buffer of that capacity is allocated.
Evidence: `fffffe00099b7f40..fffffe00099b7fb8`.

It then repeatedly calls GetReport `0xac`, copying the returned descriptor
bytes into the destination at a running offset until that offset reaches
the advertised total. There is no host-supplied chunk offset in the observed
GetReport arguments. Evidence: `fffffe00099b7fd0..fffffe00099b80fc`.
The data itself is opaque. No live chunk sizes, reset behavior, checksums,
or complete data schema have been observed. The model encodes/decodes only
the verified status/total header; it does not fabricate calibration contents
or assume an offset protocol.

**Seen:** `readFingerState` uses a one-byte descriptor and GetReport `0xa1`.
Its asynchronous completion reads that byte and invokes the callback with
`byte != 0`. Evidence: `fffffe00099b845c..fffffe00099b8464`,
`fffffe00099b8568`, `fffffe00099b86dc..fffffe00099b86e8`.
This is distinct from the ten-byte `b5` interrupt report.

**Seen:** `setCommandMode` rejects mode >=5, allocates a one-byte descriptor,
and issues SetReport with report ID `0x78 | mode` (78–7c).
Evidence: `fffffe00099b6e18..fffffe00099b6e30`,
`fffffe00099b6f10..fffffe00099b6f2c`.
The observed function does not explicitly write the descriptor's one-byte
body. Its actual initialized contents and the meanings of modes0–4 are
unresolved, so only the ID mapping is reproduced by `command_mode_report_id`.
The boolean method argument is captured for completion behavior; the code
does not establish that it is serialized as that byte.

Focused source: `evidence/sensor-feature-functions.txt`.

## Typed image-info records

**Seen:** biometrickitd's `accessoryImageInfo:` Objective-C method encoding
describes a packed message containing a 20-byte biodevice identity, a 306-byte
image-info region, and a final uint64. The driver independently copies 306 bytes
and sends 334 bytes at `fffffe00099b392c..fffffe00099b3974`.
Saved type evidence: `evidence/accessory-method-types.json`.

The 306-byte region comprises two uint64 values, five bytes, and five 57-byte
records. Byte20 is the active record count. The raw codec preserves all five
records and the count; `active_image_info_records` rejects counts above five
before selecting records. This safety bound does not emulate native out-of-bounds
reads. Multibyte fields are unaligned and little-endian.

The daemon's `+[MesaCAImageInfo imageInfoFromAccessoryImageInfo:souceBioDevice:]`
at `0x10002732c` names several fields through its property setters:

| Record offset | Type | Observed consumer |
| --- | --- | --- |
| 0 | uint16 | Flags: bits0–1 map to button state 1,3,4,2; bit3 wake-on-menu-pin; bit6 image problem class |
| 2 | uint8 | Feedback |
| 3 | uint8 | Assessment |
| 4 | uint16 | Image bad blocks |
| 6 | three bytes | First byte used in gain normalization; remaining two unresolved |
| 9 | float32 | Image contrast; analytics multiplies by1000 before unsigned conversion |
| 13 | float32 | Image brightness; analytics multiplies by1000 before unsigned conversion |
| 17 | float32 | Image feature strength; analytics applies a separate scale |
| 21 | uint32 | Image pixel outlier count |
| 25 | four uint64 | Further event timing computations; exact meanings unresolved |

Source: `evidence/image-record-conversion-excerpt.txt`, with resolved selector
names; `evidence/image-info-analytics-excerpt.txt` shows the count and record
stride. These are names used by Apple's analytics consumer, not a recovered
pixel format or fingerprint matcher. Codecs keep neutral offset names and
preserve float bit patterns, including NaNs and signed zero.

**Seen:** sensor-info GetReport `0xa0` forwards 91 bytes through driver command
`0x55`. biometrickitd's `accessorySensorInfo:` at `0x100021708` allocates91 bytes
and returns NSData, checking the returned length. That method does not decode
the fields. `encode_device_info`/`decode_device_info` preserve them as opaque.

CLI operations `sensor image_info` and `sensor device_info` support both encode
and decode. Their inputs are metadata/feature buffers without report IDs.

## Service modes versus accessory modes

**Seen:** `IOBiometricService::enumCommandModeToString` at
`fffffe000aa4f8ec` maps service modes0–6 to None, Idle, Match, Enroll,
PresenceDetect, BgPresenceDetect, Count. Table:
`evidence/service-command-modes.json`.

These are not identical to accessory mode numbers. The accessory-state handler
at `fffffe00099b3b88..fffffe00099b3c48` conditionally maps service Enroll to
accessory4 and PresenceDetect to accessory1, with a suppression flag selecting0.
Match involves additional flags and the previous accessory mode. The one-byte
SetReport body remains uncharacterized. Thus a service-mode name alone does not
establish a complete sensor-control command.
