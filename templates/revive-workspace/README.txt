HUAWEI REVIVE FIRMWARE LIBRARY

Open "Huawei Revive.bat" to list firmware or add a model.

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
