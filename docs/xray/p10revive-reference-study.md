# P10Revive reference study

## Purpose

`P10Revive` is evidence for the shape of a revive workflow. It is not a safe
device profile and none of its VTR payloads or hard-coded partition paths may be
reused for VOG/P30 Pro.

Reference root inspected on Athena:

`D:\projects\Huawei kirin\P10Revive\P10 Revive`

## Workflow found

The package exposes five small launchers around a large P10-specific payload:

1. `UNPACKER_RUN_ME.bat` invokes `splitupdate.exe UPDATE.app`.
2. `1. revive flasher.bat` performs a base partition flash, then selects
   VTR-L29 or VTR-L09 regional images.
3. `2. TWRP Recovery.bat` flashes a P10 TWRP image to `recovery_ramdisk`.
4. `3a. OEMINFO Flash VTR-L29C432.bat` pushes a VTR-L29 OEMINFO binary and
   writes it with `dd`.
5. `3b. OEMINFO Flash VTR-L09C432.bat` does the same for VTR-L09.

The main launcher contains 42 flash commands, four erase commands and 37 unique
partition names. Four referenced base artifacts are absent from the local
package: `curver.img`, `package_type.img`, `sha256rsa.img`, and `verlist.img`.

## Unsafe assumptions that must not be inherited

- no connected-device identity or board verification
- no explicit Fastboot or ADB serial selection
- no artifact hash, signature, size, or package-family verification
- no check that a command succeeded before continuing
- immediate GPT, boot-chain, modem, system, userdata, CUST and version writes
- hard-coded `/dev/block/sdd5` for OEMINFO
- P10-only `VTR-*` payloads and `twrp_p10_0.1.img`
- bundled old tools with no embedded product or file version metadata
- a generic Ubuntu/VirtualBox appliance with no declared role in the launchers

The old `adb.exe`, `fastboot.exe`, `splitupdate.exe`, OEMINFO binaries and
launcher hashes were captured during the local study. They remain outside the
repository and are not trusted runtime dependencies.

| Reference file | SHA-256 |
| --- | --- |
| `1. revive flasher.bat` | `3F9D1F180C5C3F968F742A9480F0C9A6390A8B04E17D2C2CB4B8C5D33E7D6150` |
| `2. TWRP Recovery.bat` | `204EA7FD211C589724787625805BFBE76AC692B60D24D23980D7C5F2FBC706DB` |
| `3a. OEMINFO Flash VTR-L29C432.bat` | `CC0A1EB1DF5D896547B54AB6873FE365276CC95C2D09C911F083F637DC000D2B` |
| `3b. OEMINFO Flash VTR-L09C432.bat` | `7C2EFF9FCDC3296E1936A4A41CB5A501CECD94E98B7A43B00457F235B964B470` |
| `adb.exe` | `CF86C753E03372ED044F4021E91828B077055B38A0DE40CE36AFAA2A7E6E75FA` |
| `fastboot.exe` | `46E3B7DF2A1B3E2960A6815F28791BD274572889C258509B43E4BABDC707B479` |
| `splitupdate.exe` | `A1BD43BC03D994BCD454263D4120DEE1F2AEA9F0EC7CA904FC4DC3B430B00702` |
| `VTR-L29C432.bin` | `DFDFC47308A7125B7CB1AC2134BEB8ABD3BFC330BDF8489D9A0B9E03FC90E65D` |
| `VTR-L09C432.bin` | `F5D88138795A97B65970E7933269717DBA82322BED7A20EA4E98638218343571` |

## Universal design extracted from the reference

The reusable concept is a staged recipe, with device-specific data removed:

1. Discover and bind exactly one physical device.
2. Certify model, board, mode, bootloader state and current partition evidence.
3. Inventory and verify all package artifacts before any operation.
4. Build a model recipe from named artifacts and named target partitions.
5. Require a verified partition map; never carry a block path across models.
6. Execute one operation at a time with stop-on-error and an evidence journal.
7. Re-read device identity and firmware state after each stage.

Python owns model registration, package discovery, manifests and report
generation. Rust owns deterministic package states and write-gate policy. A
later UI must consume these same schemas instead of embedding model logic.

## Current implementation boundary

The first universal layer is the model-based firmware catalog:

- `model.json` defines model variants and known package signatures.
- dropped firmware is discovered without executing it.
- known packages become `READY`, `NEEDS_EXTRACTION`, or `INCOMPLETE`.
- firmware for a newly added generic model appears as `UNVERIFIED` until a
  model-specific signature is supplied.
- catalog state does not authorize a device write.

P30 Pro uses a VOG-L29 three-part dload signature. Its future repair recipe
remains blocked until the VOG OEMINFO payload and live OEMINFO target are proven.
