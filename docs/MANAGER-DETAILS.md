# Manager properties and command14

All findings below are from static code on local build26A434. They have not
been exercised against a real external accessory.

`AppleTrustedAccessory::getPropertyData` resolves property enums as follows:

| Enum | IORegistry property | Representation |
| --- | --- | --- |
| 1 | VendorID | uint32 |
| 2 | ProductID | uint32 |
| 3 | SerialNumber | string bytes |
| 4 | Transport | string bytes |
| 5 | SerialNumber when Transport is exactly Bluetooth | string bytes; otherwise empty |
| 6 | LocationID | uint32 |

The relevant block is
`____ZN21AppleTrustedAccessory15getPropertyDataE25atam_accessory_property_tPvPm_block_invoke`
in `evidence/AppleTrustedAccessory-kernel-disassembly.txt`.
String references resolve to `evidence/property-strings.json`; anchors include
`fffffe000a08bfe0` (serial), `fffffe000a08c0b4` (location),
`fffffe000a08c138` (vendor), `fffffe000a08c1ac` (transport),
`fffffe000a08c290` (product), and `fffffe000a08c318..fffffe000a08c370`
(Bluetooth condition). These are discovery properties; assigning them does
not demonstrate trusted-device acceptance.

Selector0 command14 operates on a timer, rather than forwarding new credential
material. Manager startup creates an IOTimerEventSource for
`analyticsDailyUpdateHandler` at `fffffe000a09d8b0` and stores it in member0x140
at `fffffe000a09d8dc`. Command14 calls its vtable slot0x1f0 with argument0,
then slot0x170. Those resolve to `setTimeoutMS(0)` and `enable()` using the
kernel timer vtable. Evidence: `evidence/command14-timer-resolution.json` and
`evidence/timer-resolution-symbols.txt`.

**Inferred from that call chain:** command14 schedules an immediate analytics
update. The codec retains its existing numeric name `command_14` for stability.
No live timer invocation was performed.
