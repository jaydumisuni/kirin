# VOG-L29 C185 firmware readout

Date read: 2026-07-30

## Source

Local package:

```text
D:\projects\Huawei kirin\VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP
```

This note records what was read from the local package and Huawei release
documents. It does not include a live read from the phone.

## Huawei release notes

File read:

```text
ReleaseDoc\HUAWEI VOG-L29 10.0.0.186(C185E8R5P1) Software Release Notes.docx
```

Important fields:

| Field | Value |
| --- | --- |
| Model | `VOG-L29` |
| Current version | `10.0.0.186(C185E8R5P1)` |
| Previous version | `10.0.0.178(C185E8R5P1)` |
| IMEI SV | `22` |
| Android version | `10` |
| EMUI version | `10.0.0` |
| CPU | `Huawei Kirin 980` |
| Android security patch | `January 1, 2020` |
| Baseband version | `21C20B377S000C000,21C20B377S000C000` |
| Version type | `Google Patch MR` |

This supports the target identity as `VOG-L29 10.0.0.186(C185E8R5P1)`.

## Huawei upgrade guideline

Files read:

```text
ReleaseDoc\HUAWEI VOG-L29 hw-meafnaf Software Upgrade Guideline.docx
ReleaseDoc\HUAWEI VOG-L29 hw-meafnaf 升级指导书_用服.docx
```

The upgrade guideline confirms the required `dload` package structure:

```text
dload\
|--update_sd_base.zip
|--update_sd_cust_VOG-L29_hw_meafnaf.zip
|--update_sd_preload_VOG-L29_hw_meafnaf_R5.zip
```

Relevant guidance:

- The package is applicable to `HUAWEI VOG-L29` phones.
- Huawei warns that using other country custom versions can fail or introduce
  unknown problems.
- Upgrade begins with battery above 30%.
- The guideline describes SD/OTG force upgrade and says force upgrade can be
  used when the phone cannot power on or needs restoration.
- The guideline says the package directory must be intact.
- The guideline says to verify the version from Settings/About Phone after boot.

This reinforces that base, CUST, and PRELOAD must be treated as one matched set.

## Factory delivery documents

Files read under `ReleaseDoc\toFactory`:

```text
HUAWEI VOG-L29 10.0.0.186(C185E8R5P1) 版本描述文件和版本配套表 05016EUP.docx
HUAWEI VOG-L29 10.0.0.186(C185E8R5P1) 版本描述文件和版本配套表 05015WJK.docx
HUAWEI VOG-L29 10.0.0.186(C185E8R5P1) 版本描述文件和版本配套表 05015XPG.docx
HUAWEI VOG-L29 10.0.0.186(C185E8R5P1) 版本描述文件和版本配套表 05015SNU.docx
```

The `05016EUP` factory document identifies:

| Field | Value |
| --- | --- |
| Product name | `HUAWEI VOG-L29` |
| Product version | `VOG-L29 10.0.0.186(C185E8R5P1)` |
| Area/site restriction | Middle East and Africa |
| Delivery/BOM line | `05016EUP` / `VOGUE-L29C` channel package |
| Version shown in BOM | `VOG-L29 10.0.0.186 (C185 E8R5P1)` |

The other factory documents list the same software version for related
`05015*` delivery variants. This matters because the package folder ends in
`05016EUP`, and the document confirms that delivery is part of the same
`VOG-L29 10.0.0.186(C185E8R5P1)` family.

## Package tags

Read from extracted package tag files:

| Package | `UPT_VER.tag` | `SD_update.tag` |
| --- | --- | --- |
| `update_sd_base` | `UPT_VER5.0` | `SD_PACKAGE_BASEPKG` |
| `update_sd_cust_VOG-L29_hw_meafnaf` | `UPT_VER5.0` | `SD_PACKAGE_CUSTPKG` |
| `update_sd_preload_VOG-L29_hw_meafnaf_R5` | `UPT_VER5.0` | `SD_PACKAGE_PRELOADPKG` |

This confirms the three extracted packages identify themselves as base, CUST,
and PRELOAD packages.

## CUST/PRELOAD metadata files

The small ptable metadata files are plain text:

```text
PTABLE_CUST.mbn:    version=603979776
PTABLE_PRELOAD.mbn: preload=1199570944
```

The corresponding verlist files are present:

```text
update_sd_cust_VOG-L29_hw_meafnaf\SOFTWARE_VER_LIST.mbn
update_sd_preload_VOG-L29_hw_meafnaf_R5\SOFTWARE_VER_LIST.mbn
```

Working interpretation:

- Tool label `CUST_VERLIST` likely maps to the CUST `SOFTWARE_VER_LIST.mbn`.
- Tool label `PRELOAD_VERLIST` likely maps to the PRELOAD `SOFTWARE_VER_LIST.mbn`.
- Tool label `PTABLE_CUST` maps to `PTABLE_CUST.mbn`.
- Tool label `PTABLE_PRELOAD` maps to `PTABLE_PRELOAD.mbn`.
- Tool labels `CUST_VER` and `PRELOAD_VER` may map to package version/tag
  metadata rather than a separately named extracted file. This is still
  unverified.

## Original AL00 board software evidence

File read:

```text
D:\projects\Huawei kirin\VOGUE-AL00A-BD 1.0.0.82_Board Software_general_9.1.0_r1_EMUI9.1.0_05022MXS\Software\VOG-AL00-BD_1.0.0.82_Download.xml
```

Relevant fields:

| Field | Value |
| --- | --- |
| AP platform | `kirin980` |
| Product ID | `VOG` |
| Board software version | `VOG-AL00-BD 1.0.0.82` |

The board XML includes erase entries for:

```text
OEMINFO
CUST
PRODUCT
VERSION
USERDATA
```

It also includes fastboot image handling for `preload`, `product`, `version`,
`vbmeta`, `oeminfo`, and many low-level Kirin980 partitions.

This confirms the source evidence is AL00 board software and the target evidence
is L29 C185 service firmware. It does not prove the live phone's current state.

## Decision impact

The additional document read strengthens these points:

1. The target package is a complete three-part `VOG-L29 hw/meafnaf` dload set.
2. The missing CUST/PRELOAD metadata entries are present locally in the package.
3. The conversion problem is likely not "find a missing file"; it is "find a
   flashing path that will write the matched CUST/PRELOAD metadata to this
   converted AL00 device."
4. The phone should not be flashed with mixed CUST/PRELOAD metadata from another
   build.
5. The next live action should be a phone read/log capture, not another blind
   write.

## Still not read

- Live phone partition table.
- Live phone OEMINFO after write.
- Live phone current CUST/PRELOAD reported values.
- Exact service-tool log lines for `CUST_VER`, `PRELOAD_VER`, and the two
  verlist failures.
- Any screenshots attached in the source ChatGPT conversation; their image bytes
  were not available in this Codex thread.
