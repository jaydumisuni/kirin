# Live VOG-L29 repair record

Date: 2026-08-02

## Device and access path

Expected serial:

```text
5T5PUB194L059785
```

The working Kirin 980 service Fastboot was loaded by this physical sequence:

1. Enter Huawei USB COM 1.0 with the test point and Harmony cable.
2. The service tool detects `COM117`, loads its first stage, and asks for USB
   COM 1.0 again.
3. Disconnect and reconnect the Harmony cable at the computer side.
4. `COM117` appears again and the tool loads the temporary Fastboot stage.
5. Windows exposes `USB\VID_18D1&PID_D00D` as Android Bootloader Interface.

The temporary loader reported `FB LockState: UNLOCKED` while the persistent
`USER LockState` remained locked.

## Verified target artifacts

All files came from the exact matched package:

```text
VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP
```

Important live-write hashes:

```text
VOG-L29C185.bin
740414511acbb3a3b3a03750456ff760a19cb17f98c160b7d041f5167824e491

VERSION.img
e411878ea5e35365d98d74221b69ba144259002ece12cbb845e0832f6bf97339

PRELOAD.img
2e0b606d9abf653d8e64717f547e5a3aa20a020a6f06b988f8fc021eae99a52e

RECOVERY_RAMDISK.img
49f84677a3a344fc318ab4c55a4eea205c96a68bc49f97cda3e7ead1e7ee6edf

RECOVERY_VENDOR.img
8d1ed9e3ccd15f7dcd7f230b490290bc2563989e09b846a4841a5a5a225d9c33

RECOVERY_VBMETA.img
78ec491d85cdd350c3a287b894cf7504ba5427cd0062649db943b0300a7a0347

FASTBOOT.img
44569838999a3adaa23c30c3eb5a39e38526e8c50669a26bc1d1966c4216c9ce
```

Xray verified the three archive CRCs, the three extracted UPDATE.APP files,
all 63 expected UPDATE.APP entries, and each extracted payload checksum used
in the live stage.

## Live results

The 96 MiB OEMINFO image wrote twice with full Fastboot send/write `OKAY`.
The second write followed `oeminfoerase-disablewp`.

Readback after the OEMINFO write:

```text
rescue_phoneinfo: VOG-L29 10.0.0.186(C185E8R5P1)
SYSTEM_VERSION:  VOG-L29 10.0.0.186(C185E8R5P1)
BASE_VERSION:    VOG-LGRP2-OVS 10.0.0.1
CUSTOM_VERSION:  VOG-Global-CUST 10.0.0(C185)
PRELOAD_VERSION: VOG_GLOBAL_PRELOAD 10.0.0(C185)
```

The exact `CUST_VERLIST` update record was rejected as a Fastboot target:

```text
Writing 'cust_verlist' FAILED (remote: 'partition length get error')
```

This did not write a partition. `CUST_VERLIST`, `CUST_VER`, `PTABLE_CUST`,
`PRELOAD_VERLIST`, `PRELOAD_VER`, and `PTABLE_PRELOAD` are Huawei update
control records on this device, not GPT partitions.

The real CUST and PRELOAD storage writes completed:

```text
Writing 'version' OKAY
Writing 'preload' OKAY
```

The exact target recovery trio and target Fastboot were then restored, all with
send/write `OKAY`. No relock command was used.

## Remaining blocker

After a stock bootloader reload, all four target version records still read
correctly, but:

```text
getvar:vendorcountry FAILED
remote: cannot get vendorcountry in oeminfo
```

Vendor/country is legacy OEMINFO item 18, mapped to v8 record 1502. Record 1502
is in the root-WP OEMINFO area. The live evidence shows that a successful raw
Fastboot partition write can update none-WP records while leaving this record
unavailable. Future workflows must treat root-WP readback as a separate gate.

## Persistent unlock result

The service-token OEM unlock command returned `OKAY`, rebooted, and reset user
data. The stock target bootloader then reported:

```text
FB LockState: LOCKED
USER LockState: LOCKED
```

Therefore that command is not persistent on this phone. The local Huawei
unlock source identifies the persistent factory unlock as NVME property
`FBLOCK` with binary value `1`, with Huawei hwdog/backdoor commands as older
fallbacks. This must be attempted only in a temporary service session and must
be proven by a bootloader reload before it is trusted.

## Next controlled stage

1. Load the same temporary Kirin 980 service Fastboot.
2. Set NVME `FBLOCK` to binary `1` and read it back before reboot.
3. Reload the target bootloader and require persistent `FB LockState: UNLOCKED`.
4. Install the verified target-based root recovery.
5. Read the live 96 MiB OEMINFO and preserve it as the device-specific source.
6. Patch only v8 record 1502 in both OEMINFO copies to `hw/meafnaf`.
7. Write and hash the complete OEMINFO readback.
8. Restore the exact target recovery trio.
9. Require model, all version records, `vendorcountry: hw/meafnaf`, baseband,
   serial, and IMEI evidence before normal boot or any relock decision.
