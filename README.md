# Kirin / Xray

Xray is a model-independent, read-only device evidence and verification core.
The repository began as Huawei Kirin recovery evidence, but Xray is intentionally
cross-brand and cross-mode. Android, Apple, UNISOC, MediaTek, Qualcomm, Samsung,
Huawei and unknown devices can all enter through the same evidence contract.

The first usable runtime is now included. It does not need Hunter, ChatGPT, a
local model or internet access to inspect a captured device log, run the Xray
Corps review, preserve evidence provenance and refuse unsupported conclusions.

## First run

```bash
python -m pip install -e ".[test]"
xray doctor
xray selftest
xray inspect device-log.txt
```

JSON output for Hunter, automation or later UI work:

```bash
xray inspect device-log.txt --format json --output xray-report.json
```

External information can be supplied without turning it into device truth:

```bash
xray inspect unisoc-log.txt \
  --claim "hardware.marketed_soc=UNISOC T7250|specialist_online|Infinix X6725B"
```

Xray then checks the claim against the model actually reported by the device,
keeps loader compatibility separate from exact silicon identity, lists missing
proof, and returns `CONFLICTED`, `INFERRED`, `CERTIFIED`, `BLOCKED`, or another
explicit evidence state.

## SRG operating structure

The runtime uses the SRG **20-for-2** force method: two governed waves of twenty
private workers. Permanent officers then review the combined evidence:

- Scout — discovery and mode detection
- Mechanic — transport and handshake health
- Quartermaster — artifact custody and hashes
- Engineer — firmware, board, partition and storage structure
- Medic — preservation and safety gates
- Analyst — typed claims and confidence
- Challenger — attacks the leading interpretation
- Judge — applies frozen deterministic proof policy
- Governor — issues the final verdict

Models are optional borrowed brains. They can explain or suggest another safe
probe, but they cannot certify identity or authorize writes.

## Current safety boundary

Xray 0.2 is deliberately read-only. It cannot authorize flashing, erase,
unlock, relock, formatting, identity repair or partition writes. Repair engines
remain separate from the evidence authority.

## Xray Live provider and session core

The second milestone adds live host-side device perception without changing the
read-only authority boundary:

- cross-platform USB/PnP snapshot-diff watcher
- stable physical-device session IDs across mode changes
- persistent hashed-identifier correlation with guarded topology continuity
- versioned provider interface and capability registry
- ADB, Fastboot, Apple Recovery and Apple DFU providers
- raw evidence envelopes with timestamps, topology and SHA-256 custody
- append-only evidence journal with replay self-consistency and corruption checks
- dedicated SRG 20-for-2 live review corps
- simulated Huawei P30 Pro and Apple Recovery/DFU verification

```bash
xray-live doctor
xray-live providers
xray-live simulate all
xray-live watch --once
```

A provider-observed Apple ECID or protocol serial can merge a newly enumerated
endpoint back into its earlier physical-device session. Reusing the same USB port
with a different strong identity creates a new session rather than inheriting the
old device history. Sensitive correlation anchors are hashed in the session
registry. Persisted session summaries redact protocol identifiers and instance
paths into SHA-256 references. Live event reports and raw evidence journals can
still contain device identifiers, command arguments and protocol output; treat
those files as sensitive and protect them with operating-system access controls
or encrypted storage.

## Apple readiness

The core understands Apple USB family evidence, DFU/recovery mode signatures,
CPID/BDID/ECID/product-type fields and includes live Recovery/DFU providers using
`irecovery` query mode. The same report and officer structure is used for Apple
and Android-family devices.

Future Apple depth can add normal-mode usbmux/MobileDevice providers, SEP/baseband
readback and richer board/product resolution without redesigning the session or
evidence contracts.

## Commands

```text
xray doctor             Verify the core and optional provider tools
xray selftest           Run UNISOC, Huawei and Apple proof cases
xray inspect FILE       Inspect a captured tool/device log
xray scan               Run available read-only host discovery providers
xray knowledge-verify   Validate the local knowledge pack

xray-live doctor        Verify live providers and command availability
xray-live providers     List provider manifests and capabilities
xray-live simulate      Run P30 Pro and Apple simulated live proof
xray-live watch         Watch USB/PnP events and write evidence reports
xray-live journal-verify Verify an evidence JSONL journal
```

## Repository map

- `src/xray/` — Python evidence, corps, live session/provider and CLI runtimes
- `src/xray/data/base.json` — packaged model-free rules and USB knowledge
- `knowledge/base.json` — source-tree knowledge-pack copy
- `rust/` — deterministic policy spine and authority-boundary tests
- `tests/` — regression, simulation and proof tests
- `tools/review_live_core.py` — independent local SRG 20-for-2 reviewer
- `docs/xray/` — Huawei evidence, handoffs and frozen milestone records

Firmware binaries are not stored in this repository. Evidence is referenced by
local path, package name, file size and hash where useful.
