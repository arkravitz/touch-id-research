# Touch ID protocol research lab

This project investigates native macOS Touch ID using local shipped code and reproduces recovered message structures offline. No Arduino or external sensor is needed to run it. No third-party native Touch ID compatibility is demonstrated.

The research covers the host/daemon protocol stack end to end: the host command and reply framing in `touchid_lab/codec.py` (bounds, version negotiation, transfer chunking, SEP manifest and pairing-completion wrappers), sensor report and image-info metadata codecs in `touchid_lab/sensor.py`, secure-intent structures in `touchid_lab/intent.py`, manager discovery properties in `touchid_lab/manager.py`, and stac opcode routing in `touchid_lab/stac.py`. `touchid_lab/simulator.py` replays scripted exchanges against the real codecs. All structures were recovered from saved disassembly and registry evidence in `evidence/`, and each claim in `docs/` points back to it.

## Requirements

Python 3.10 or newer, standard library only. The native comparison additionally needs Xcode command-line tools and a macOS installation carrying `TrustedAccessory.framework`.

## Run the offline tools

From this directory:

```sh
python3 -m unittest discover -s tests -v
python3 -m touchid_lab demo --scenario all
python3 -m touchid_lab encode request generate_key '{"counter":1,"key_type":2}'
python3 -m touchid_lab decode reply query_pairing 4201000000010005
python3 -m touchid_lab decode sensor report b5020001020304050607
python3 -m touchid_lab encode host command '{"command":4,"version":1,"in_value":0,"payload":"dead"}'
```

Byte fields in encode JSON are hexadecimal. Decoded byte fields are also hexadecimal. Use `buffer_size:16384` to request a zero-padded host buffer matching Apple's fresh-object small-command allocation. The host header has no general payload-length field, so a raw padded buffer alone cannot reveal the semantic payload length.

`demo` uses explicitly synthetic, opaque cryptographic fixtures. It exercises real codecs, report/counter matching, and ordered scripted exchanges. It always reports `native_compatible:false`; successful parsing is not evidence that an enclave trusts these fixtures. The simulator never opens Bluetooth, IOKit, LocalAuthentication, a socket, or a system authentication configuration.

## Compare with Apple's original serializer

On the investigated macOS installation, with Xcode command-line tools:

```sh
python3 tools/compare_native.py
```

This compiles a small helper in a temporary directory, loads `TrustedAccessory.framework`, and calls only the base object's initializer and its memory-only command preparation method. It does not call the manager/proxy factory, connect to drivers, or pair anything. The recorded run compared 111 **entire buffers**, including the 16 KB boundary and 65 KB inputs. This verifies host serialization on this build; HID and SEP structures are currently checked against static code and synthetic fixtures.

## Repo layout

- `touchid_lab/` — Python package: codecs, simulator, and the `python3 -m touchid_lab` CLI.
- `tools/` — analysis scripts (`inspect_functions.py`, `index_objc_methods.py`, `index_stac_calls.py`, `resolve_vtable.py`, `compare_native.py`) and native helpers (`native_pack_oracle.m`, `framework-metadata.m`, `auth-probe.swift`).
- `evidence/` — saved disassembly, metadata, registry excerpts, test records, native comparison output, and a labeled synthetic transcript.
- `docs/` — per-topic protocol notes and the consolidated reference.
- `tests/` — unit tests, runnable with the standard `unittest` runner.

## Read the evidence

- [Initial findings](FINDINGS.md): local topology, driver selectors, trust boundary, successful built-in authentication trace, and external sources.
- [Further protocol recovery](PROTOCOL.md): response correlation, pairing stages, manifest and enclave wrappers.
- [Consolidated reference](docs/PROTOCOL-REFERENCE.md): operation inventory, layer distinctions, field bounds, and remaining coverage.
- [Sensor reports and capture submission](docs/SENSOR-REPORTS.md): report layouts, metadata getters, and recovered SBIO buffers.
- [Host dispatch and session setup](docs/HOST-AND-SESSION.md): selector0 commands 2–15, payload codecs, stac wrappers, and explicit replay-test logic.
- [Manager details](docs/MANAGER-DETAILS.md): recovered discovery-property meanings and command14's timer target.
- [Secure intent](docs/SECURE-INTENT.md): selector1/2 structures, enclave validation, and client notification bodies.
- [stac coverage matrix](docs/STAC-MATRIX.md): indexed transfer call sites and recovered input/output structures for opcodes1–22.
- [Current work status](docs/STATUS.md): completed checks and remaining research.
- `tools/inspect_functions.py` extracts named functions from the saved disassembly, for example:

```sh
python3 tools/inspect_functions.py getPublicKeyGated --start 30 --count 100
python3 tools/inspect_functions.py AppleMesaAccessory --file evidence/AppleMesaSEPDriver-kernel-disassembly.txt --calls --count 30
```

## Limits that matter

The recovered driver buffers are not established Bluetooth wire captures. Apple attestation, sensor image processing, image encryption, template matching, and enclave implementation remain opaque. Unused driver buffer bytes may differ from the lab's canonical zero padding. The native serializer comparison uses a fresh object per command and does not characterize cache reuse. No enrollment, real external pairing, or authentication installation is performed by the lab.

## License

MIT — see [LICENSE](LICENSE).
