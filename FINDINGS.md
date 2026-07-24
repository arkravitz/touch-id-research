# Touch ID investigation — 2026-10-19

## Result and scope

The requested target is a Bluetooth fingerprint peripheral made entirely from third-party parts, accepted by native macOS Touch ID. No working implementation or demonstrated route through Apple's accessory attestation was found in this investigation. This is a substantial unresolved trust problem, beyond decoding Bluetooth or implementing a fingerprint matcher.

The local investigation recovered concrete host interfaces, driver matching rules, and a command header. One live authentication succeeded on the connected laptop. No Bluetooth Touch ID exchange was captured: there is no Magic Keyboard with Touch ID available. The built-in sensor uses SPI, so touching it cannot produce the missing Bluetooth reference trace.

Evidence labels:

- **Seen / live**: observed in IORegistry or an executed experiment.
- **Seen / static**: present in shipped code, metadata, or plists; not proof that a particular operation succeeds.
- **Documented**: supported by a linked external source.
- **Inferred**: interpretation of evidence, with the remaining gap stated.
- **Unknown**: not established here. None of these observations is claimed to be a first-ever discovery.

## Machine and reproducibility

Local environment: MacBookPro17,1, Apple M1, macOS 27.0.1 build 26A434, arm64. Addresses below refer to the arm64e slice where applicable. Shared-cache runtime addresses depend on the system's cache mapping; framework-relative offsets are preferable for reuse.

Inspected standalone binaries were copied with APFS clone semantics to `$TMPDIR/re/touchid-26A434` before inspection. SHA-256:

| Binary | SHA-256 |
| --- | --- |
| biometrickitd | `f7415d75e03523370cb341d069f3d5da53661ce3484cfaf25b5bae3226f343c8` |
| AppleMesaLib | `e9dda510c3583d8c36539dd245f59f6d7b98967f6ceb075f0512952601d88791` |
| MechTouchId | `432ad7a0d2bf961b696557cfaad81a0ac4d573549cf7ab67cd1faf6a4f637597` |

Tools used: `ioreg`, `plutil`, `file`, `otool`, `nm`, `strings`, Objective-C runtime metadata, Swift LocalAuthentication, unified logging, and LLDB on our own helper process. No system daemon was attached to or patched. No pairing, provisioning, enrollment, deletion, PAM installation, or security-setting change was requested by our tools. Ordinary successful matching can trigger Apple's own adaptive template maintenance; the log contains a template-list update.

## Locally recovered implementation details

### 1. Built-in sensor and enclave are distinct interfaces

**Seen / live:** the sensor is `AppleSandDollar`, with `IOProviderClass=AppleARMSPIDevice`, `IONameMatch=biosensor,mesa`, `spi-freq=8000000`, `spi-clock-phase=3`, `SensorID=13138`, and `patch-version=22`. Its user client is `AppleMesaUserClient`.

Separately, `AppleMesaSEPDriver` matches `sep-endpoint,sbio`; `AppleBiometricServices` exposes `AppleBiometricServicesUserClient`, opened by `biometrickitd`. Calibration is reported as `MesaCalBlobSource=FDR`.

Evidence: [sensor registry](evidence/sensor-ioreg.txt), [SEP registry](evidence/sep-ioreg.txt). Frequency and phase are reported configuration properties, not measurements with a logic analyzer.

### 2. Sensor plug-in user-client selectors

**Seen / static:** `AppleMesaLib` supplies the following IOKit selectors. Addresses identify the instructions assigning `w1` immediately before the corresponding IOKit call. These are host user-client selectors, **not SPI command bytes or Bluetooth opcodes**.

| Operation | Selector | Address in AppleMesaLib |
| --- | --- | --- |
| Open | `0x03` | `0x1140` |
| Close | `0x04` | `0x129c` |
| Reset | `0x05` | `0x141c` |
| StartCapture | `0x06` | `0x16b4` |
| StopCapture | `0x07` | `0x17ec` |
| PauseCapture | `0x08` | `0x1924` |
| GetStatus | `0x09` | `0x1a5c` |
| LoadPatch | `0x0e` | `0x20c4` |
| Provision | `0x0f` | `0x2204` |
| SetPower | `0x10` | `0x2940` |
| SetParameters | `0x11` | `0x2a88` |
| Idle | `0x17` | `0x157c` |
| StartFingerDetect | `0x19` | `0x2f30` |

`Provision` passes a 32-byte input structure to `IOConnectCallStructMethod` (`w3=0x20` at `0x220c`). **Unknown:** the structure's semantics and acceptance requirements. Its name is not evidence of a usable third-party enrollment route. We did not invoke these selectors.

Evidence: [call-site excerpts](evidence/mesa-userclient-call-sites.txt), [disassembly](evidence/AppleMesaLib-disassembly.txt).

### 3. External accessory driver matching

**Seen / static:** `AppleTrustedAccessory.kext` declares an `IOHIDInterface` personality with:

| Property | Value |
| --- | --- |
| VendorID | `1452 = 0x05ac` |
| ProductIDArray | `666, 671, 801, 802 = 0x029a, 0x029f, 0x0321, 0x0322` |
| DeviceUsagePage | `65280 = 0xff00` |
| DeviceUsage | `77 = 0x4d` |
| Driver class | `AppleTrustedAccessory` |

**Inferred:** these describe an entry point for recognition experiments with a HID peripheral. Matching these values would not establish trusted identity or guarantee successful driver attachment. This plist does not establish the Bluetooth profile, report IDs, report descriptor, packet framing, or cryptographic exchange.

Evidence: [driver personalities](evidence/trusted-accessory-personalities.txt).

### 4. The trusted accessory path has its own enclave endpoint

**Seen / live:** `AppleTrustedAccessoryManager` matches `sep-endpoint,stac`, exposes `AppleTrustedAccessoryManagerUserClient`, and has user-client instances owned by `coreauthd`.

Evidence: [manager registry](evidence/trusted-accessory-manager-ioreg.txt). This independently confirms the local `stac` driver mapping; the general endpoint association is already discussed in [Asahi's SEP notes](https://github.com/AsahiLinux/docs/blob/main/docs/hw/soc/sep.md).

### 5. Private pairing and authorization interfaces

**Seen / static metadata:** `TrustedAccessory.framework` contains:

| Class / method | Framework-relative offset |
| --- | --- |
| `TADevice pairingState:error:` | `0x4888` |
| `TADevice pairWithError:` | `0x4de4` |
| `TADevice authorizeWithCredentialSet:error:` | `0x5654` |
| `TADevice generateAuthorizationNonceWithError:` | `0x58f8` |
| `TADevice authorizeWithTicket:error:` | `0x5b4c` |
| `TADevice testSecureSessionWithError:` | `0x5ed8` |
| `TAManagerProxyDirect initializeConnection` | `0x3910` |
| `TAManagerProxy prepareCommand:version:inValue:inData:inSize:command:` | `0x3374` |

`TADevice` also exposes transport and Bluetooth-address properties. `TADeviceManager` exposes connected devices, paired devices, and available pairing slots. The connection initializer references `AppleTrustedAccessoryManager` directly.

**Unknown:** which operations an ordinary third-party process can successfully invoke, their entitlement checks, and the full pairing state machine. We enumerated metadata and disassembled methods; we did not call private pairing or authorization methods. A method called `injectSecureIntentWithError:` also exists, but its name alone proves neither an accessible bypass nor software-forgeable secure intent.

Evidence: [runtime metadata](evidence/framework-metadata.txt), [pairing and connection disassembly](evidence/trusted-accessory-disassembly.txt).

### 6. Recovered host command header

**Seen / static; field interpretation inferred from ABI and stores:** the command preparation method adds 8 to the payload size and writes four 16-bit fields followed by the payload:

```c
// Host-side TrustedAccessory command buffer; NOT an established Bluetooth frame.
struct TAHostCommand {
    uint16_t magic;       // 0x4154; little-endian bytes 54 41 ("TA")
    uint16_t command;     // method's command argument
    uint16_t version;     // method's version argument
    uint16_t inValue;     // method's inValue argument
    uint8_t payload[];    // copied at offset 8
};
```

Evidence: `prepareCommand...` at framework offset `0x3374`; instructions at method offsets `+96` and `+256..+292` in [command disassembly](evidence/trusted-accessory-command-disassembly.txt). The method checks that input pointer and input size are either both zero or both nonzero, and checks size addition overflow.

This is a useful artifact for further host-interface analysis. It supplies no attestation credentials and has not been validated against a real external device.

### 7. Kernel-side access gate and partial HID protocol

**Seen / static:** the local boot kernelcache was located, cloned, decoded from IMG4/LZFSE using the system `libcompression`, and its Mach-O fileset entries inspected. The compressed artifact SHA-256 is `9188e1bbf516a7d954d9704437d1c1b71bb1118097a2f107a5074d3bf5f0c1cb`. Kext views preserve the original segment file offsets; they are analysis views, not installable rebuilt kexts.

`AppleTrustedAccessoryManagerUserClient::initWithTask` calls `IOUserClient::copyClientEntitlement` with **`com.apple.private.appletamanager.allow`** at `0xfffffe000a0a029c..0xfffffe000a0a02a8`, then checks the returned object before continuing initialization. **Inferred:** loading the private framework alone does not grant an ordinary application access to its kernel manager. The exact gate should be validated with a controlled connection probe before making a broader claim about every calling context.

The kernel also exposes substantially more than the framework header. These values are recovered from the accessory report paths, with the set-report target resolved through the class vtable:

| Operation | Outgoing report ID argument | Expected interrupt report ID | Selected code addresses |
| --- | --- | --- | --- |
| Query pairing | `0x60` | `0x42` | `0xfffffe000a088b0c`, `0xfffffe000a088b30` |
| Generate key pair | `0x66` | `0x47` | `0xfffffe000a0891e4`, `0xfffffe000a089208` |
| Compute session key | `0x62` | `0x46` | `0xfffffe000a08b868`, `0xfffffe000a08b88c` |

All three pass report-type argument `2`. Outgoing descriptors contain a monotonically incremented 32-bit request counter; the response wait receives that counter too. Generate-key-pair supplies an 8-byte descriptor containing counter and key-pair type. Query-pairing constructs a 137-byte descriptor beginning with counter, 32-bit input length, and input bytes; its input-size check rejects lengths of 130 or more. These are **static code paths**, not Bluetooth packets observed over the air. HID transport framing and any implicit report-ID bytes remain to be validated.

The vtable verification is explicit: `__ZTV21AppleTrustedAccessory = 0xfffffe0008326ff8`; the object-vtable slot at `+16+0x890` contains chained pointer `0x801159590308b774`. Its image-relative target `0x0308b774` plus collection base `0xfffffe0007004000` resolves to `0xfffffe000a08f774`, the symbol for `AppleTrustedAccessory::setReport`.

**Seen / static:** `AppleTrustedAccessoryManager::pairAccessory` interleaves accessory operations with `AppleSEPGenericTransfer::transact`: it requests an accessory key pair of type `1`, then submits enclave transaction `3` with a `0x92`-byte input. Session establishment requests accessory key-pair type `2`, submits enclave transaction `6` with `0x51` bytes, calls the accessory's `computeSessionKey`, then submits enclave transaction `7` with `0x614` bytes. This supports a protocol spanning both the accessory and enclave, rather than a host-only pairing flag. It does not reveal the enclave's implementation of those commands.

Evidence: [fileset inventory](evidence/kernel-fileset-inventory.txt), [kernel symbols](evidence/AppleTrustedAccessory-kernel-symbols.txt), [kernel disassembly](evidence/AppleTrustedAccessory-kernel-disassembly.txt), [focused functions](evidence/trusted-accessory-kernel-targets.txt). The separate sensor and SEP-driver symbol/disassembly inventories are also saved under `evidence/`.

## Live authentication experiment

**Seen / live:** the first availability probe reported closed-clamshell mode. After the user opened the lid, availability became true. A biometric-only LocalAuthentication request succeeded:

| Local time, America/Los_Angeles | Observation |
| --- | --- |
| 13:27:47.558 onward | LocalAuthentication request from our probe |
| 13:27:48.090 | `biometrickitd match:withOptions:withClient:` |
| 13:27:49.661 | status `63`, 36-byte data; log identifies finger-on |
| 13:27:50.069 | status `64`, 36-byte data; log identifies finger-off |
| 13:27:50.095 | successful match reported |
| 13:27:50.099 | LocalAuthentication evaluation returns |

The finger-on to logged match interval is approximately 434 ms for this single trial. It includes software scheduling and logging; it is not an isolated sensor or matcher benchmark. Other status numbers remain undecoded here.

Evidence: [probe result](evidence/authentication-probe.txt), [logs with UUIDs/database hash redacted](evidence/authentication-log.txt), [probe source](tools/auth-probe.swift). The application received success/error, not a fingerprint image. The trace does not expose or reproduce the underlying cryptographic protocol.

## Existing work and its relevance

1. **Apple's documented trust architecture:** external Touch ID pairs the keyboard's hardware PKA with the Mac's Secure Enclave using Apple-rooted attestation and hardware-held keys. The sensor also has a factory-established secure channel to its PKA. The host channel uses AES-256-GCM and ephemeral ECDH. This accounts for why a generic reader cannot become native Touch ID merely by reporting a successful match. [Apple Platform Security](https://support.apple.com/guide/security/magic-keyboard-with-touch-id-secf60513daa/web).
2. **Built-in sensor channel:** Apple documents SPI forwarding and factory-keyed authenticated encryption between sensor and enclave. This is consistent with the local SPI driver topology. [Biometric security](https://support.apple.com/guide/security/biometric-security-sec067eb0c9e/web).
3. **Standalone donor builds:** Jeff Geerling's build keeps both the Apple sensor and keyboard logic board. It demonstrates rehousing, not a third-party implementation. [Original build write-up](https://www.jeffgeerling.com/blog/2025/why-doesnt-apple-make-standalone-touch-id/).
4. **Hardware reverse engineering:** Limentic's Magicanical project reports mapping the Touch ID ribbon with probes and a microscope, while retaining Apple's motherboard. It does not demonstrate replacement of the trusted electronics. [Builder's thread](https://geekhack.org/index.php?topic=120964.0).
5. **Actual low-level tracing code:** Asahi's `trace_mesa.py` instruments SPI, SIO, interrupts, and DMA. Its opening comment reports encrypted command buffers after power-on. It is a substantial starting point for built-in sensor research, not a completed Bluetooth peripheral implementation. [Source](https://github.com/AsahiLinux/m1n1/blob/main/proxyclient/hv/trace_mesa.py).
6. **Linux T2 progress:** `t2-touchid-linux` reports experimental matching through bridgeOS BiometricKit/BridgeXPC on specified Intel Macs. It still uses Apple's existing T2, sensor, and enclave. Its authors' hardware claims were not reproduced here and do not establish compatibility with the connected M1. [Repository and status](https://github.com/jmurth1234/t2-touchid-linux).
7. **Recent Apple Silicon research:** a Sapporo issue reports missing biometric endpoints under its Linux boot, while a separate M2 Pro gist claims later successful bring-up. These are different setups and claims, not proof of a replacement external sensor. Their relevance requires inspecting the actual artifacts and reproducing results. [Sapporo discussion](https://github.com/stevederico/Sapporo/issues/48), [M2 Pro findings](https://gist.github.com/JJRPF/2b34f7f369d0887352c0218bea33ed7c).
8. **Custom authentication alternative:** UnTouchID/TouchBridge uses a companion device and a Mac daemon/PAM path. Its README distinguishes verified sudo support from planned surfaces and excludes native keychain biometric items and Apple Pay. Some comparison claims in that README conflict with Apple's documentation, so it should be evaluated as unverified implementation work, not authoritative platform guidance. [Repository](https://github.com/HMAKT99/UnTouchID).

Targeted web searches for the recovered method names and HID values did not reveal a detailed matching implementation write-up. This is not proof of novelty or an exhaustive literature search.

## Feasibility and next work

**Inferred:** an entirely third-party native Touch ID peripheral needs a way to satisfy or change the Apple-rooted hardware trust requirement, in addition to reproducing transport and sensor behavior. No such capability was demonstrated here. Captured certificates alone would not supply the corresponding private keys. Writing Bluetooth firmware should wait until this central requirement has a credible solution.

The next focused research step is completing the accessory report/response layouts and enclave command structures around the recovered pairing sequence, particularly which evidence is checked inside `stac`. A real reference keyboard would permit runtime pairing traces, but is not available and was not purchased. Driver recognition is only an early milestone; it must not be reported as authentication success. The kernel transport decoding above already goes beyond the initial host-only inventory.

If the practical requirement can be narrowed to specific actions such as sudo or a custom app, a third-party fingerprint sensor plus a BLE controller and a separate Mac authentication component is a different feasible research direction. It would not automatically satisfy native Touch ID dialogs, protected keychain operations, or Apple Pay. No such component has been designed or installed during this investigation.

Remaining unknowns include Bluetooth transport/profile and complete report layouts, runtime external-device handshake bytes, enclave-side certificate policy, sensor image format, third-party image compatibility, and any legitimate third-party provisioning program. The project has a verified starting point, not a completed Touch ID clone.
