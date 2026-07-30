# Kirin

Field notes and evidence indexes for Huawei Kirin recovery and conversion work.

This repository is structured around **Xray**, a documentation layer for capturing
what was observed during a repair, which files were present, which writes
succeeded or failed, and what still needs direct verification on the device.

## Xray structure

- `docs/xray/README.md` - how Xray entries are organized.
- `xray/` - read-only multi-mode Android, fastboot, Huawei rescue, and Windows
  USB/COM evidence collector.
- `docs/xray/collector.md` - collector behavior, safety boundary, and limits.
- `docs/xray/vog-al00-to-vog-l29-c185.md` - current VOG-AL00 to VOG-L29 C185
  conversion notes.
- `docs/xray/vog-l29-c185-firmware-readout.md` - readout from the local Huawei
  release docs, package tags, CUST/PRELOAD metadata, and AL00 board XML.
- `docs/xray/unlocktool-static-kirin980-observations-2026-07-31.md` - sanitized
  static evidence for the Kirin 980 test-point, patched-fastboot, and OEMINFO
  workflow observed in the local UnlockTool installation.
- `evidence/xray/2026-07-30-vog-fastboot-final/` - reviewed raw JSON and text
  from the Xray live-device capture. The earlier sibling folder is retained as
  preliminary evidence.
- `docs/xray/handoff-current-state.md` - pickup note for continuing the case
  from another chat.

Firmware binaries are not stored in this repository. Evidence is referenced by
local path, package name, file size, and hash where useful.
