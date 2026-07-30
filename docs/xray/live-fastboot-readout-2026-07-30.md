# Live fastboot readout

Date: 2026-07-30

## Scope

This is a read-only capture from the currently connected phone. The phone was
visible in fastboot mode through the `P10Revive` platform tools.

No flash, erase, reboot, unlock, or write command was run.

Tool path used:

```text
D:\projects\Huawei kirin\P10Revive\P10 Revive\tools_fw\fastboot.exe
```

## Device detection

```text
fastboot devices -l
5T5PUB194L059785       fastboot
```

Windows detected it as:

```text
Android Bootloader Interface
USB\VID_18D1&PID_D00D
```

ADB did not show an Android userspace device.

## Fastboot variables

`fastboot getvar all` did not work on this device:

```text
all: undefine
Finished. Total time: 0.000s
```

Specific read results:

```text
product: kirin980
serialno: serialv1.0
version: 0.5
max-download-size: 471859200
```

Most common partition and version variables returned `undefine`, including:

```text
version-bootloader
version-baseband
secure
unlocked
current-slot
slot-count
partition-type:system
partition-size:system
partition-type:vendor
partition-size:vendor
partition-type:product
partition-size:product
partition-type:cust
partition-size:cust
partition-type:preload
partition-size:preload
partition-type:version
partition-size:version
partition-type:vbmeta_hw_product
partition-size:vbmeta_hw_product
partition-type:vbmeta_cust
partition-size:vbmeta_cust
```

## Bootloader state

```text
fastboot oem get-bootinfo
(bootloader)  unlocked
OKAY [  0.001s]
Finished. Total time: 0.001s
```

The bootloader reports unlocked.

## OEMINFO/version read failures

Critical result:

```text
fastboot getvar rescue_phoneinfo
(bootloader) main version do not exist in oeminfo!

rescue_phoneinfo: NO MAIN VERSION
Finished. Total time: 0.013s
```

Vendor/country read also failed:

```text
fastboot getvar vendorcountry
getvar:vendorcountry FAILED (remote: 'cannot get vendorcountry in oeminfo')
Finished. Total time: 0.014s
```

Huawei OEMINFO reads failed:

```text
fastboot oem oeminforead-SYSTEM_VERSION
FAILED (remote: 'Read oeminfo failed!')

fastboot oem oeminforead-CUSTOM_VERSION
FAILED (remote: 'Read oeminfo failed!')

fastboot oem oeminforead-PRELOAD_VERSION
FAILED (remote: 'Read oeminfo failed!')

fastboot oem oeminforead-BASE_VERSION
FAILED (remote: 'Read oeminfo failed!')
```

Other item names failed with input item errors:

```text
fastboot oem oeminforead-VENDOR_COUNTRY
FAILED (remote: 'The reason of failed input oem_nv_item error!')

fastboot oem oeminforead-CUST_VERSION
FAILED (remote: 'The reason of failed input oem_nv_item error!')

fastboot oem oeminforead-OEMINFO_CUST_VERSION
FAILED (remote: 'The reason of failed input oem_nv_item error!')

fastboot oem oeminforead-OEMINFO_PRELOAD_VERSION
FAILED (remote: 'The reason of failed input oem_nv_item error!')
```

Common Huawei commands also failed:

```text
fastboot oem get-build-number
FAILED (Device sent unknown status code: get_build_number failed!)

fastboot oem get-product-model
FAILED (remote: 'FAIL')

fastboot oem get-vendorcountry
FAILED (remote: 'invalid command')
```

## P10Revive folder warning

The `P10Revive` scripts are for Huawei P10 `VTR-*`, not P30 Pro `VOG-*`.

Examples from the batch files:

```text
fastboot flash ptable update-L29\HISIUFS_GPT.img
fastboot flash cust update-L29\cust.img
ADB push VTR-L29C432.bin /tmp/oeminfo.bin
ADB shell "dd if=/tmp/oeminfo.bin of=/dev/block/sdd5 bs=1048576"
```

Do not run these scripts on the P30 Pro. The folder is useful only because it
contains working `adb.exe` and `fastboot.exe`.

## Updated diagnosis

The live phone read makes the problem more specific:

```text
main version do not exist in oeminfo
cannot get vendorcountry in oeminfo
```

This means the phone's current fastboot-visible OEMINFO/main-version state is
incomplete or unreadable. That can explain why the previous tool failed at:

```text
CUST_VERLIST
CUST_VER
PTABLE_CUST
PRELOAD_VERLIST
PRELOAD_VER
PTABLE_PRELOAD
```

Working interpretation: the CUST/PRELOAD metadata failure is likely downstream
of missing/incomplete OEMINFO version identity, not only a CUST/PRELOAD package
write problem.

## Next action impact

Before attempting the full dload/offline update, restore or repair the
fastboot-readable VOG-L29 OEMINFO/main-version identity enough that fastboot no
longer reports:

```text
NO MAIN VERSION
cannot get vendorcountry in oeminfo
```

The expected identity remains:

```text
Device Model:  VOG-L29
Build Version: VOGUE-L29D 10.0.0.186(C185E8R5P1)
Vendor:        hw
Country:       meafnaf
```

After that readback is fixed, retry the matched complete three-part
`base + cust + preload` offline update path.

