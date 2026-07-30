# VOG-AL00 to VOG-L29 C185 conversion

## Scope

- Source device: Huawei P30 Pro, `VOG-AL00`.
- Target device identity: `VOG-L29`.
- Target firmware: `VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP`.
- Target vendor/country: `hw/meafnaf`.
- Target region: `C185`.
- Target build string used in tool: `VOGUE-L29D 10.0.0.186(C185E8R5P1)`.

Do not set the repaired device model to `VOG-L29D`. `VOG-L29` is the retail model;
`VOGUE-L29D` is the firmware/product package identifier.

## Local evidence recovered

Local evidence root:

```text
D:\projects\Huawei kirin
```

Extracted target firmware:

```text
D:\projects\Huawei kirin\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP
```

The target firmware is present as a three-part dload set:

| Package | Size | Role |
| --- | ---: | --- |
| `Software\dload\update_sd_base.zip` | 4,308,716,151 bytes | Base firmware |
| `Software\dload\update_sd_cust_VOG-L29_hw_meafnaf.zip` | 37,292 bytes | CUST package for `hw/meafnaf` |
| `Software\dload\update_sd_preload_VOG-L29_hw_meafnaf_R5.zip` | 251,722,738 bytes | PRELOAD package for `hw/meafnaf_R5` |

Extracted CUST/PRELOAD metadata files are present locally:

| File | Size | SHA-256 |
| --- | ---: | --- |
| `update_sd_cust_VOG-L29_hw_meafnaf\SOFTWARE_VER_LIST.mbn` | 299 | `69B01EDE929810A427B016E9AF535D89E01E01FB8E864C3D32B3112EC6F75436` |
| `update_sd_cust_VOG-L29_hw_meafnaf\PTABLE_CUST.mbn` | 18 | `D32F78514C10CAD8A74BAC82FA52D6F5F748D1BD7687DEC687B4111937388881` |
| `update_sd_preload_VOG-L29_hw_meafnaf_R5\SOFTWARE_VER_LIST.mbn` | 408 | `68D2092C0D996F3444E5DD8C55DB5AD0FCE00E391C231CB5EB48FA7364E6C8FD` |
| `update_sd_preload_VOG-L29_hw_meafnaf_R5\PTABLE_PRELOAD.mbn` | 19 | `A9D26BFC4B608BE6759AA2D08FD0C032EBD7378E5D55B8AE49457D230225477A` |

The CUST verlist contains C185 entries:

```text
VOG-Global-CUST 9.1.0(C185)
VOG-Global-CUST 10.0.0(C185)
```

The PRELOAD verlist contains C185 entries:

```text
VOG-L29-PRELOAD 9.1.0(C185R1)
VOG_GLOBAL_PRELOAD 9.1.0(C185)
VOG_GLOBAL_PRELOAD 10.0.0(C185)
```

## Observed workflow

OEMINFO/service-tool values used for the aligned target:

```text
Device Model:  VOG-L29
Build Version: VOGUE-L29D 10.0.0.186(C185E8R5P1)
Vendor:        hw
Country:       meafnaf
```

Earlier notes mentioned `VOG-L29 10.0.0.185(C185)`. That is not aligned with the
firmware package and should not be kept as the target build for this conversion.

The flash initially failed when `VBMETA_HW_PRODUCT` was skipped. The device then
showed the recovery/verified-boot warning. A later attempt with another tool
wrote `VBMETA_HW_PRODUCT` successfully.

Known successful writes from the field notes:

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

Problem entries observed during the CUST/PRELOAD stage:

```text
CUST_VERLIST
CUST_VER
PTABLE_CUST
PRELOAD_VERLIST
PRELOAD_VER
PTABLE_PRELOAD
```

## Interpretation

The missing verlist issue is not evidence that the firmware archive lacks CUST or
PRELOAD metadata. The extracted package contains both CUST and PRELOAD verlist
and ptable metadata files.

The stronger interpretation is that the flashing mode or tool path rejected the
CUST/PRELOAD version-table and partition-table metadata while accepting the main
images. Because the source device is `VOG-AL00` and the target is `VOG-L29 C185`,
these failures should not be treated as harmless until the device boots and
reports the expected regional build.

`VBMETA_HW_PRODUCT` is required for this conversion path. Skipping it caused a
verified-boot recovery warning, and writing it later was a necessary recovery
step.

## Recovery checklist

1. Preserve the original `VOG-AL00` OEMINFO/security evidence before writing.
2. Set model/vendor/country to `VOG-L29 / hw / meafnaf`.
3. Use the aligned build string `VOGUE-L29D 10.0.0.186(C185E8R5P1)`.
4. Flash the complete three-part firmware set from one extraction: base, CUST,
   and PRELOAD.
5. Confirm `VBMETA_HW_PRODUCT` writes successfully. Do not skip it.
6. If the tool reports failures for `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`,
   `PRELOAD_VERLIST`, `PRELOAD_VER`, or `PTABLE_PRELOAD`, do not substitute
   random metadata from another build. Use the matching files from the same
   `.186(C185E8R5P1)` extraction or a flashing mode that can write them.
7. After flashing completes, boot recovery/eRecovery first only if required, then
   test normal boot.

## Verification targets

After a successful boot, confirm:

```text
Model: VOG-L29
Build: 10.0.0.186(C185E8R5P1) or equivalent C185 reporting
Vendor/Country: hw/meafnaf
Baseband: present
IMEI 1 and IMEI 2: present
SIM slots: working
CUST/PRELOAD: not C900 unless expected by the package's compatibility layer
```

## Still unverified

- Final boot result after `VBMETA_HW_PRODUCT` succeeded.
- Whether the phone reports the full `C185E8R5P1` suffix after the CUST/PRELOAD
  metadata failures.
- Exact flashing tool names and exact error lines for the six failed metadata
  entries.
- Whether a different service mode can write `CUST_VERLIST`, `CUST_VER`,
  `PTABLE_CUST`, `PRELOAD_VERLIST`, `PRELOAD_VER`, and `PTABLE_PRELOAD` on this
  converted `VOG-AL00`.
- Whether OTA validation works after the conversion.
