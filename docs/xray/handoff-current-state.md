# Current handoff state

Date: 2026-07-30

## Repository state

- GitHub repo: `https://github.com/jaydumisuni/kirin`
- Local repo: `D:\projects\kirin`
- Branch: `main`
- Current commit before this handoff note was first written:
  `3b16ad6 Document VOG-L29 C185 conversion notes`
- Remote status after push: clean, `main` tracks `origin/main`

Xray now also has an executable read-only collector under `xray/`. Its first
raw live capture is preserved under:

```text
evidence\xray\2026-07-30-vog-fastboot-final
```

## Local evidence state

Firmware evidence is on Athena at:

```text
D:\projects\Huawei kirin
```

The target VOG-L29 C185 package is extracted at:

```text
D:\projects\Huawei kirin\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP
```

Important package parts:

```text
Software\dload\update_sd_base.zip
Software\dload\update_sd_cust_VOG-L29_hw_meafnaf.zip
Software\dload\update_sd_preload_VOG-L29_hw_meafnaf_R5.zip
```

Important extracted metadata files:

```text
Software\dload\update_sd_cust_VOG-L29_hw_meafnaf\SOFTWARE_VER_LIST.mbn
Software\dload\update_sd_cust_VOG-L29_hw_meafnaf\PTABLE_CUST.mbn
Software\dload\update_sd_preload_VOG-L29_hw_meafnaf_R5\SOFTWARE_VER_LIST.mbn
Software\dload\update_sd_preload_VOG-L29_hw_meafnaf_R5\PTABLE_PRELOAD.mbn
```

## Phone conversion state from chat evidence

Target identity:

```text
Device Model:  VOG-L29
Build Version: VOGUE-L29D 10.0.0.186(C185E8R5P1)
Vendor:        hw
Country:       meafnaf
```

Do not use `VOG-L29D` as the repaired model. Use `VOG-L29`.

Known successful flash entries from the conversation:

```text
SUPER
VBMETA_SYSTEM
VBMETA_VENDOR
VBMETA_ODM
VBMETA_HW_PRODUCT
VBMETA_CUST
PRELOAD
VERSION
```

Known problem entries:

```text
CUST_VERLIST
CUST_VER
PTABLE_CUST
PRELOAD_VERLIST
PRELOAD_VER
PTABLE_PRELOAD
```

Important interpretation:

- `VBMETA_HW_PRODUCT` could not be skipped. Skipping it caused the verified-boot
  recovery warning.
- A later tool wrote `VBMETA_HW_PRODUCT` successfully.
- The CUST/PRELOAD verlist problem is not because the files are absent. The
  extracted firmware contains the matching CUST/PRELOAD metadata.
- The likely issue is the flashing mode/tool path rejecting CUST/PRELOAD
  version-table and partition-table metadata on an AL00 to L29 conversion.
- A newer full Xray read proves that the phone currently has no fastboot-visible
  main version and cannot return vendor/country or Huawei OEMINFO version items.

## What to solve before using the phone battery again

1. Identify the exact flashing tool and mode that can write:
   `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`, `PRELOAD_VERLIST`, `PRELOAD_VER`,
   and `PTABLE_PRELOAD`.
2. Find whether the tool expects these names directly or maps them from:
   `SOFTWARE_VER_LIST.mbn`, `PTABLE_CUST.mbn`, and `PTABLE_PRELOAD.mbn`.
3. Avoid mixing metadata from another firmware version.
4. Treat the OEMINFO/main-version state as damaged or incomplete. Do not write a
   guessed AL00 or L29 OEMINFO image until the exact service-tool operation,
   backup path, and expected readback are established.
5. Do not relock the bootloader/security state before final boot verification.

## Additional firmware readout

Read `docs/xray/vog-l29-c185-firmware-readout.md` before choosing the next live
phone action. It confirms from local Huawei documents that:

- the release notes target `VOG-L29 10.0.0.186(C185E8R5P1)`;
- the upgrade guideline requires the three `dload` files: base, CUST, PRELOAD;
- `05016EUP` is a VOG-L29 C185E8R5P1 delivery variant;
- CUST/PRELOAD metadata exists locally and is not simply missing from the
  package;
- the next phone step should be a read/log capture, not a blind write.

Also read `docs/xray/next-fix-plan.md`. It adds the stronger finding that
`CUST_VER`, `PRELOAD_VER`, `CUST_VERLIST`, `PRELOAD_VERLIST`, `PTABLE_CUST`, and
`PTABLE_PRELOAD` are embedded in the package `PTABLE.APP` records, and it
recommends using the complete official three-part dload/offline update path after
charging and live phone readback.

Also read `docs/xray/live-fastboot-readout-2026-07-30.md`. The phone is visible
in fastboot as `5T5PUB194L059785`, bootloader reports `unlocked`, but fastboot
reports `rescue_phoneinfo: NO MAIN VERSION` and cannot read vendor/country from
OEMINFO. This moves OEMINFO/main-version repair ahead of another CUST/PRELOAD
write attempt.

Also read `docs/xray/xray-live-capture-2026-07-30.md` and
`docs/xray/external-tool-readout-2026-07-30.md`. They compare the user's second
tool with the new Xray collector and preserve the complete raw command evidence.

## What remains unverified

- Final boot result after `VBMETA_HW_PRODUCT` succeeded.
- Whether About Phone reports `VOG-L29` and C185 after boot.
- Whether both IMEIs, baseband, SIM slots, Wi-Fi, and camera work.
- Whether CUST/PRELOAD show a valid regional state or fall back to `C900`.
- Whether OTA validation works.
- The exact service tool and operation that can restore a valid
  `VOG-L29 / hw / meafnaf` main-version identity without reverting the device to
  AL00 or damaging security data.
- A backup of the phone's current OEMINFO/security-sensitive state.
- Whether the original IMEIs and calibration data are still present; fastboot
  cannot read them in the current state.

## Next chat pickup prompt

Continue from the latest `jaydumisuni/kirin` `main` plus
`docs/xray/handoff-current-state.md`. We need to solve the Huawei P30 Pro
`VOG-AL00` to `VOG-L29 C185` CUST/PRELOAD metadata write problem before touching
the phone again. First establish a backup-capable service path that restores and
reads back the missing `VOG-L29 / hw / meafnaf` OEMINFO/main-version identity.
Then process `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`, `PRELOAD_VERLIST`,
`PRELOAD_VER`, and `PTABLE_PRELOAD` from the matching
`VOGUE-L29D 10.0.0.186(C185E8R5P1)` package without mixing firmware.
