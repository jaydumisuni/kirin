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
xray revive-plan        Build an audit-only reusable device revive plan
xray firmware-list      Refresh the model-based local firmware catalog
xray firmware-add-model Add a model folder to the firmware library
xray revive-workflow    Carry a proven staged workflow into a model profile
xray update-app-list    List Huawei UPDATE.APP payloads without extracting
xray update-app-extract Extract one named payload with checksum verification
xray huawei-usb-boot    Load signed images through Huawei USB COM mode
xray huawei-recovery-build Build a target-based temporary recovery image
xray huawei-oeminfo-build Build a verified VOG-L29 C185 OEMINFO image
xray huawei-package-verify Fully verify the matched VOG-L29 C185 package

xray-live doctor        Verify live providers and command availability
xray-live providers     List provider manifests and capabilities
xray-live simulate      Run P30 Pro and Apple simulated live proof
xray-live watch         Watch USB/PnP events and write evidence reports
xray-live journal-verify Verify an evidence JSONL journal
```

## Revive planning

Xray can now map a known-safe revive pattern to a target device package without
authorizing writes. The first profile uses the `P10Revive` layout as a template
for a P30 Pro `VOG-L29 hw/meafnaf C185` plan while rejecting direct reuse of
`VTR-*` payloads:

```bash
xray revive-plan vog-l29-c185 \
  --package-root "D:\projects\Huawei kirin\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP" \
  --template-root "D:\projects\Huawei kirin\P10Revive\P10 Revive" \
  --output vog-l29-c185-revive-plan.json \
  --script-output vog-l29-c185-revive-audit.bat
```

The generated batch file is audit-only and exits before any write. The P30
workflow can build and verify `VOG-L29C185.bin` from the 96 MiB board template
and exact base, CUST and PRELOAD metadata. A live
`/dev/block/by-name/oeminfo` target and full post-write hash are still mandatory
before the target firmware stage.

```bash
xray huawei-oeminfo-build \
  --template "firmware/p 30 pro/BOARD_PACKAGE/fastbootimage/oeminfo.mbn" \
  --base-version "TARGET_PACKAGE/revive-extracted/metadata/BASE_VER.mbn" \
  --cust-version "TARGET_PACKAGE/revive-extracted/metadata/CUST_VER.mbn" \
  --preload-version "TARGET_PACKAGE/revive-extracted/metadata/PRELOAD_VER.mbn" \
  --output "firmware/p 30 pro/VOG-L29C185.bin" \
  --manifest "firmware/p 30 pro/VOG-L29C185.bin.manifest.json"
```

This corrects the old `verlist.img` assumption. The P10 reference launchers
continue after missing verlist-related files; their effective identity repair
is the model-specific OEMINFO write. P30 therefore receives a generated v8
OEMINFO image and never a copied P10 payload.

The USB loader command is an explicit recovery transport for Huawei devices
already enumerated in USB COM mode. It requires signed, model-matched loader
images and an address for every image; Xray does not infer addresses or firmware:

```bash
xray huawei-usb-boot --port COM117 \
  --image "0x00022000=sec_usb_xloader.img" \
  --image "0x60049000=sec_usb_xloader2.img" \
  --image "0x1A400000=sec_fastboot.img"
```

## Firmware library

Firmware is organized by model so a later UI can consume the same JSON catalog.
Each immediate folder below the library is one model. Dropped packages appear on
the next scan; known package signatures are classified as `READY`,
`NEEDS_EXTRACTION`, or `INCOMPLETE`, while new generic models remain
`UNVERIFIED` until a package profile is added.

```bash
xray firmware-add-model --library-root firmware --folder "p 30 pro" --preset p30-pro
xray firmware-list --library-root firmware --catalog-output firmware/available-firmware.json
xray firmware-add-model --library-root firmware --folder "mate 20 pro" \
  --name "Mate 20 Pro" --manufacturer Huawei --variant LYA-L29
xray revive-workflow p30-pro --model-root "firmware/p 30 pro" \
  --output plans/p30-pro-workflow.json
```

The P30 workflow verifies all 63 internal UPDATE.APP entries, keeps the board
service Fastboot stage through the OEMINFO repair, withholds the board recipe's
final normal reboot, and restores target Fastboot only during the matched target
firmware stage. It remains audit-only until the live device gates are satisfied.

## Repository map

- `src/xray/` — Python evidence, corps, live session/provider and CLI runtimes
- `src/xray/data/base.json` — packaged model-free rules and USB knowledge
- `knowledge/base.json` — source-tree knowledge-pack copy
- `rust/` — deterministic policy spine and authority-boundary tests
- `tests/` — regression, simulation and proof tests
- `tools/review_live_core.py` — independent local SRG 20-for-2 reviewer
- `docs/xray/` — Huawei evidence, handoffs and frozen milestone records
- `templates/revive-workspace/` — local firmware-library launchers

Firmware binaries are not stored in this repository. Evidence is referenced by
local path, package name, file size and hash where useful.
