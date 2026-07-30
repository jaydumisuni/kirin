# Current handoff state

Date: 2026-07-30

## Repository state

- GitHub repo: `https://github.com/jaydumisuni/kirin`
- Local repo: `D:\projects\kirin`
- Branch: `main`
- Current commit: `3b16ad6 Document VOG-L29 C185 conversion notes`
- Remote status after push: clean, `main` tracks `origin/main`

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

## What to solve before using the phone battery again

1. Identify the exact flashing tool and mode that can write:
   `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`, `PRELOAD_VERLIST`, `PRELOAD_VER`,
   and `PTABLE_PRELOAD`.
2. Find whether the tool expects these names directly or maps them from:
   `SOFTWARE_VER_LIST.mbn`, `PTABLE_CUST.mbn`, and `PTABLE_PRELOAD.mbn`.
3. Avoid mixing metadata from another firmware version.
4. Do not rewrite OEMINFO again unless the current values are proven wrong.
5. Do not relock the bootloader/security state before final boot verification.

## What remains unverified

- Final boot result after `VBMETA_HW_PRODUCT` succeeded.
- Whether About Phone reports `VOG-L29` and C185 after boot.
- Whether both IMEIs, baseband, SIM slots, Wi-Fi, and camera work.
- Whether CUST/PRELOAD show a valid regional state or fall back to `C900`.
- Whether OTA validation works.

## Next chat pickup prompt

Continue from `jaydumisuni/kirin` commit `3b16ad6` plus
`docs/xray/handoff-current-state.md`. We need to solve the Huawei P30 Pro
`VOG-AL00` to `VOG-L29 C185` CUST/PRELOAD metadata write problem before touching
the phone again. Focus on how to write `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`,
`PRELOAD_VERLIST`, `PRELOAD_VER`, and `PTABLE_PRELOAD` from the matching
`VOGUE-L29D 10.0.0.186(C185E8R5P1)` package without mixing firmware.
