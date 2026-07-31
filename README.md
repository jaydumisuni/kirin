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
python -m pip install -e .
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

The runtime uses the SRG **10-for-2** force method: two governed waves of ten
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

Xray 0.1 is deliberately read-only. It cannot authorize flashing, erase,
unlock, relock, formatting, identity repair or partition writes. Repair engines
remain separate from the evidence authority.

## Apple readiness

The core already understands Apple USB family evidence, DFU/recovery mode
signatures, CPID/BDID/ECID/product-type fields and expects future providers for:

- Apple USB
- usbmux / MobileDevice
- `ideviceinfo`
- `irecovery`
- DFU

The same report and officer structure is used for Apple and Android-family
devices. Apple-specific recovery depth can be added without redesigning Xray.

## Commands

```text
xray doctor             Verify the core and optional provider tools
xray selftest           Run UNISOC, Huawei and Apple proof cases
xray inspect FILE       Inspect a captured tool/device log
xray scan               Run available read-only host discovery providers
xray knowledge-verify   Validate the local knowledge pack
```

## Repository map

- `src/xray/` — usable Python evidence, corps and CLI runtime
- `knowledge/base.json` — model-free rules and hardware/USB knowledge
- `rust/` — deterministic policy spine and authority-boundary tests
- `tests/` — regression and proof tests
- `docs/xray/first-run.md` — first-run design, limitations and proof record
- `docs/xray/` — existing Huawei recovery evidence and handoff notes

Firmware binaries are not stored in this repository. Evidence is referenced by
local path, package name, file size and hash where useful.
