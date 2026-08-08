# Touch ID Protocol Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the locally accessible protocol and reproduce its known messages offline.
**Architecture:** Evidence-indexed schemas feed explicit binary codecs and a scripted simulation. Native serialization comparison remains separate from simulated cryptographic endpoints.
**Tech Stack:** Python standard library, Objective-C/Foundation runtime, existing Mach-O and kernel disassembly.
**Spec:** docs/superpowers/specs/2026-10-19-protocol-lab.md

## Global Constraints
- No external hardware or purchases; no live pairing/enrollment or authentication installation.
- Unknown cryptography stays opaque; no fabricated native-compatibility claims.
- Use the local build and record evidence addresses for recovered fields.

## Review Focus
- Length fields cannot read past supplied buffers; reject truncation and overflow.
- Reserved fixed-size regions must preserve their offsets at boundary lengths.
- Duplicate/stale/wrong-operation replies cannot advance simulation state.
- Unknown protocol versions must be surfaced rather than guessed compatible.
- Native serializer comparisons must execute only memory packing, not manager connection methods.

### Task 1: Evidence and schema
**Files:** tools/inspect_functions.py; evidence/operations.json; docs/PROTOCOL-REFERENCE.md
**Interfaces:** ordered operation definitions, input/reply layouts, exact evidence references.
- [ ] Extract and annotate protocol version, identity, public key, pair, challenge, session, data transfer, secure intent, and asynchronous report dispatch.
- [ ] Recover conditional pairing stages, host command dispatch, SEP boundaries; check firmware availability.
- [ ] Record interpretations and bounds; validate evidence references.

### Task 2: Codecs
**Files:** touchid_lab/codec.py; tests/test_codec.py
**Interfaces:** encode/decode host commands, request/reply envelopes, operation bodies, and SEP wrappers.
- [ ] Write independent hexadecimal fixtures and malformed/boundary tests; run and observe failure.
- [ ] Implement codecs with explicit limits and opaque fields; run suite.
- [x] Compile a memory-only native serializer oracle and compare normal/boundary/random cases.

### Task 3: Simulation and tools
**Files:** touchid_lab/simulator.py; touchid_lab/__main__.py; tests/test_simulator.py; tests/test_cli.py; README.md
**Interfaces:** scripted transport exchanges through real codecs; explicit unavailable trust gate.
- [x] Write failing transcript/state/error/CLI tests.
- [x] Implement scripted exchanges and CLI encode/decode/demo without hardware I/O.
- [x] Run tests and demonstrations; record provenance of every example and limitation.

### Task 4: Verification and scope audit
**Files:** docs/STATUS.md; evidence/verification.json
- [ ] Compare implementation coverage with the entire recovered operation inventory.
- [ ] Audit source/fixtures/native evidence and address remaining accessible gaps.
- [ ] Review all code and report actual tested scope and remaining hardware/enclave limits.

Ruling: the workspace is an existing projectless directory, not a Git repository. Keep changes here and use a local progress ledger; no worktree/commit machinery applies. The user explicitly authorized completing both milestones, so execute without another plan approval stop.
