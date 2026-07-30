# Next fix plan

Date: 2026-07-30

## Confidence level

We have enough information to avoid blind file hunting. We do not yet have enough
information to guarantee the phone is fixed without a live read.

Current confidence:

- High: the target package is correct for `VOG-L29 hw/meafnaf C185E8R5P1`.
- High: the failed CUST/PRELOAD metadata exists inside the package.
- High: `VBMETA_HW_PRODUCT` must be written and was a real blocker.
- Medium-high: the remaining blocker is the flashing path/tool mode, not missing
  firmware.
- Not proven: the live phone's current state after the last write.

## Key evidence pulled from package internals

The failed labels are embedded inside each package's `PTABLE.APP`.

CUST package:

```text
Software\dload\update_sd_cust_VOG-L29_hw_meafnaf\PTABLE.APP
```

Contains:

```text
CUST_VERLIST
CUST_VER
PACKAGE_TYPE
PTABLE_CUST
```

Important values:

```text
CUST_VER:    VOG-Global-CUST 10.0.0(C185)
PTABLE_CUST: version=603979776
PACKAGE_TYPE: OFFLINE_UPDATE
```

PRELOAD package:

```text
Software\dload\update_sd_preload_VOG-L29_hw_meafnaf_R5\PTABLE.APP
```

Contains:

```text
PRELOAD_VERLIST
PRELOAD_VER
PACKAGE_TYPE
PTABLE_PRELOAD
```

Important values:

```text
PRELOAD_VER:    VOG_GLOBAL_PRELOAD 10.0.0(C185)
PTABLE_PRELOAD: preload=1199570944
PACKAGE_TYPE:   OFFLINE_UPDATE
```

The base package update binary contains Huawei handlers and labels for the same
operations:

```text
cust_version_list_write_func
cust_version_write_func
preload_version_list_write_func
preload_version_write_func
ptable_cust_write_func
ptable_preload_write_func
PTABLE_CUST
PTABLE_PRELOAD
CUST_VER
PRELOAD_VER
CUST_VERLIST
PRELOAD_VERLIST
VBMETA_HW_PRODUCT
VBMETA_CUST
```

It also contains this important string:

```text
not allow update verlist
```

Working interpretation: the six failed entries are controlled writes performed
by Huawei's update logic. A service tool that writes images individually may not
enter the same path or may be blocked by device/package state.

## Best next action after charging

Do not start by flashing random single files.

First, charge the phone enough for update work. Huawei's local upgrade guideline
requires battery above 30% at the start of the upgrade.

Then do this sequence:

1. Read phone info with the service tool and save a photo/log before writing:
   model, build, vendor/country, OEMINFO, boot mode, baseband, and any CUST or
   PRELOAD version fields the tool can show.
2. If the phone can enter EMUI 10 recovery update mode, use the complete official
   `dload` set through SD/OTG force upgrade:

   ```text
   dload\
   |--update_sd_base.zip
   |--update_sd_cust_VOG-L29_hw_meafnaf.zip
   |--update_sd_preload_VOG-L29_hw_meafnaf_R5.zip
   ```

   This is preferred because Huawei's own `update-binary` knows how to process
   `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`, `PRELOAD_VERLIST`, `PRELOAD_VER`,
   and `PTABLE_PRELOAD` from the matched package.
3. If recovery SD/OTG update is not accessible, use a service-tool mode that
   flashes the whole three-part dload/offline update package, not only extracted
   individual partitions.
4. If using an individual-partition tool, do not point `CUST_VERLIST` or
   `PRELOAD_VERLIST` at random files from another build. The matching source is:

   ```text
   CUST_VERLIST    <- update_sd_cust_VOG-L29_hw_meafnaf\SOFTWARE_VER_LIST.mbn
   CUST_VER        <- VOG-Global-CUST 10.0.0(C185), embedded in CUST PTABLE.APP
   PTABLE_CUST     <- update_sd_cust_VOG-L29_hw_meafnaf\PTABLE_CUST.mbn
   PRELOAD_VERLIST <- update_sd_preload_VOG-L29_hw_meafnaf_R5\SOFTWARE_VER_LIST.mbn
   PRELOAD_VER     <- VOG_GLOBAL_PRELOAD 10.0.0(C185), embedded in PRELOAD PTABLE.APP
   PTABLE_PRELOAD  <- update_sd_preload_VOG-L29_hw_meafnaf_R5\PTABLE_PRELOAD.mbn
   ```

## Stop conditions

Stop and do not continue flashing if any of these happen:

- the phone readback no longer shows `VOG-L29 / hw / meafnaf`;
- the tool asks to downgrade security/rollback level without showing the exact
  current and target values;
- `VBMETA_HW_PRODUCT` fails again;
- the tool reports `not allow update verlist`;
- the tool reports partition size/layout mismatch for CUST or PRELOAD;
- battery is below the service tool's safe threshold.

## Why this plan is safer

The package itself is internally consistent. The six failed labels are not absent
files; they are package metadata records. The official dload/offline update path
is the path most likely to run Huawei's own handlers for these records.

The service-tool path that succeeded for `VBMETA_HW_PRODUCT` may still be useful,
but the next attempt should prefer a mode that processes the whole CUST/PRELOAD
package rather than trying to patch the failed labels one by one.

## What to capture when the PC is back

Before any write:

```text
Phone info/read screen
Current model
Current build
Current vendor/country
Current boot mode
Current OEMINFO values
Current CUST/PRELOAD values, if shown
Exact tool name and version
Complete operation log
```

After any write:

```text
Final status screen
Any failed labels
First boot result
About Phone version
Baseband
IMEI 1 / IMEI 2
SIM slot test
Wi-Fi and camera test
```

