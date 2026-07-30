# UnlockTool static Kirin 980 observations

Date: 2026-07-31

Status: static, sanitized evidence only

Source root: `C:\UnlockTool`

## Scope and safety boundary

This note records Huawei-relevant facts found during a read-only inspection of a
local proprietary service-tool installation. UnlockTool and its bundled helpers
were not launched. No device command was issued.

The inspection did not copy or attempt to extract proprietary payloads, OEMINFO
images, security data, raw logs, account artifacts, certificates, serial numbers,
IMEIs, or other device identifiers. Saved evidence is limited to filenames,
sizes, hashes, container headers, and sanitized workflow facts.

The observations do not establish source provenance, licences, payload
correctness, or independent proof that a reported write persisted on the phone.

## Local Huawei containers

Two files were present under `DataFiles\Huawei`:

| Relative path | Bytes | SHA-256 |
|---|---:|---|
| `KIRIN_980_UNLOCKED.uhw` | 4,780,788 | `60a4309d278c5cc18c292b698a4c24556260af960748af01329d5af618173482` |
| `STK-L21M__hw__meafnaf__STK-L21M_9.1.0.341C185E2R2P1.oeminfo` | 414,930 | `3f62ebfd06c833522e4759f21d4405d9d900f8f34141ad7cb88ab16778a5ddef` |

Both start with the six-byte header:

```text
61 5C 04 05 14 41
```

The same header appears on UnlockTool's inspected Apple `.rd`, `.drv`, and
selected `.utl` containers. It identifies a shared proprietary wrapper, not a
known raw Huawei image format. The contents, compression, encryption, signatures,
and internal file list remain unknown because the containers were not unpacked.

The standalone OEMINFO file targets `STK-L21M`, not `VOG-AL00` or `VOG-L29`.
It must not be used for the P30 Pro recovery.

## Sanitized Kirin 980 test-point workflow

Six `[USB 1.0] UNLOCK FASTBOOT` logs selected:

```text
Selected model: HiSilicon Kirin 980
Code name: Hi980_Unlocked
Operation: Kirin Testpoint [2]
```

Four logs reached the end of the full workflow. One attempt failed when the
reconnected port was already in use, and one stopped because `HUAWEI USB COM 1.0`
was not found.

The complete observed sequence was:

```text
authenticate
-> retrieve approximately 4.56 MiB of server data
-> discover HUAWEI USB COM 1.0
-> connect through HUAWEI HSPL_usbvcom 2.0.7.1
-> initialize
-> write patch1
-> write patch2
-> write patch3
-> read a partition map
-> search for a bootloader key
-> patch bootloader
-> require disconnect and test-point re-entry
-> reconnect through HUAWEI USB COM 1.0
-> write sec_usb_xloader
-> write sec_usb_xloader2
-> write unlock1
-> write unlock2
-> write sec_fastboot
```

The successful logs reported partition-map counts of 68 or 69. The bootloader-key
search reported the same opaque tuple:

```text
3:10485760:5242880
```

The tuple's fields and units are not exposed by the log and must not be guessed.

This sequence shows that the later Android Bootloader Interface is not necessarily
the stock retail fastboot environment. A generic `kirin980` product, placeholder
serial, unusual USB manufacturer, undefined retail properties, and an unlocked
boot result can be consistent with the service tool's patched `sec_fastboot`
stage. That is an inference from the ordered logs and later Xray readout, not
proof of the patched image's implementation.

## Sanitized OEMINFO attempt

One `[FB] CHANGE OEMINFO` log reported:

```text
Fastboot lock state: unlocked
Model: VOG-L29
Vendor/Country: hw/meafnaf
Build version: VOGUE-L29D 10.0.0.186(C185E8R5P1)
Initialize: OK
Writing OEMINFO: OK
```

This confirms the exact values supplied to the service tool and that the tool
acknowledged its write operation. It does not prove that:

- the intended OEMINFO slots were updated;
- both copies or checksummed regions were valid;
- the main-version record was regenerated;
- the write survived reboot;
- vendor/country became readable;
- the target partition layout matched the original VOG-AL00 device.

The later live Xray read is stronger current-state evidence: fastboot reported
`rescue_phoneinfo: NO MAIN VERSION` and could not return the Huawei OEMINFO
vendor/country/version values. The OEMINFO event must therefore be recorded as an
attempted and tool-acknowledged write, not a successful identity repair.

## Implications for Xray

Xray should distinguish at least these Kirin states:

```text
stock Huawei fastboot
service-tool patched fastboot
Huawei USB COM 1.0 test-point transport
OEMINFO write acknowledged
OEMINFO/main-version independently read back
```

Recommended evidence fields:

- selected service-tool model and operation;
- transport and driver identity;
- partition-map count;
- whether the test-point reconnect occurred;
- ordered payload-role acknowledgments;
- fastboot implementation classification;
- OEMINFO input values;
- immediate post-write readback;
- post-reboot readback;
- raw and normalized `rescue_phoneinfo` state;
- explicit distinction between tool acknowledgment and independent proof.

The current collector should continue preserving undefined and unsupported
properties rather than converting them to empty strings. For this device, a
generic fastboot identity is itself evidence that retail Huawei identity reads
cannot yet be trusted.

## Recovery relevance

These findings tighten the next repair decision:

1. Treat the current fastboot environment as possibly patched and generic.
2. Do not infer a valid VOG-L29 identity from `product: kirin980` or
   `bootloader: unlocked`.
3. Do not repeat the same OEMINFO write merely because the prior tool said `OK`.
4. Require a backup-capable path and immediate plus post-reboot readback.
5. Keep the target values bound to
   `VOG-L29 / hw / meafnaf / VOGUE-L29D 10.0.0.186(C185E8R5P1)`.
6. Keep `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`, `PRELOAD_VERLIST`,
   `PRELOAD_VER`, and `PTABLE_PRELOAD` bound to the same complete C185 package.
7. Never substitute the unrelated STK-L21M OEMINFO container.

## Unverified

The static evidence does not establish:

- the contents of `KIRIN_980_UNLOCKED.uhw`;
- which logged role maps to which bytes inside the container;
- source code, source commits, licences, signatures, or reproducible builds;
- whether the server data is device-specific or generic;
- the meaning of the bootloader-key tuple;
- whether the patched fastboot can safely read or write every VOG partition;
- the exact OEMINFO copy/checksum/main-version repair procedure;
- a valid post-write or post-reboot OEMINFO readback;
- a successful Android boot after the C185 conversion;
- working baseband, IMEIs, SIM slots, Wi-Fi, camera, C185 customization, or OTA.

No device action should be authorized from this note alone.
