HUAWEI REVIVE FIRMWARE LIBRARY

Open "Huawei Revive.bat" to list firmware, add a model, build the P30 Pro
workflow, or generate its verified OEMINFO identity file from the official
board template and matched regional metadata.

"Verify P30 Pro firmware package" reads all three official archives, checks
their ZIP CRCs, matches each extracted UPDATE.APP back to its archive, and saves
the current proof in plans\p30-pro-package-proof.json.

Firmware layout:

  firmware\
    p 30 pro\
      model.json
      YOUR DOWNLOADED FIRMWARE FOLDER OR FILE
    another model\
      model.json
      YOUR DOWNLOADED FIRMWARE FOLDER OR FILE

The list is refreshed into firmware\available-firmware.json. A known complete
package is READY. A package with archives but missing extracted metadata is
NEEDS_EXTRACTION. A partial known package is INCOMPLETE. Files for a newly added
model are UNVERIFIED until that model receives a package signature.

READY means the expected files are present. It does not authorize flashing.
The P10Revive folder is a reference only and is never used as P30 Pro firmware.
The carried P30 workflow is saved to plans\p30-pro-workflow.json.
For P30 Pro, VOG-L29C185.bin is generated as a v8 96 MiB image. The system
does not use the missing P10 verlist file and does not copy a VTR OEMINFO image.
