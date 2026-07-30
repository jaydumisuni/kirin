# Xray live device capture

Date: 2026-07-30

## Evidence files

```text
evidence\xray\2026-07-30-vog-fastboot-final\capture.json
evidence\xray\2026-07-30-vog-fastboot-final\report.txt
```

The JSON file preserves every command, return code, elapsed time, combined raw
output, parsed value, and status. No existing evidence file was overwritten.
The preliminary sibling capture is also retained; the final capture corrects a
host USB filter that had included an unrelated composite device.

## Safety

The collector used only its tested read allowlist. It did not request flash,
erase, reboot, boot, unlock, relock, format, continue, update, or partition
fetch operations.

## Tools and transport

```text
ADB:      1.0.41 / platform-tools 37.0.0-14910828
fastboot: 37.0.0-14910828
Device:   5T5PUB194L059785
Mode:     fastboot
USB:      VID_18D1&PID_D00D
Driver:   LeMobile 11.0.0.0 / oem460.inf / WinUSB
```

The LeMobile name belongs to the Windows driver. It is not accepted as phone
identity.

## Concrete phone responses

```text
product:           kirin980
serialno:          serialv1.0
version:           0.5
max-download-size: 471859200
rescue_phoneinfo:  NO MAIN VERSION
oem get-bootinfo:  unlocked
```

Critical failure:

```text
getvar:vendorcountry FAILED
(remote: 'cannot get vendorcountry in oeminfo')
```

Huawei OEMINFO queries failed consistently:

```text
SYSTEM_VERSION   -> Read oeminfo failed!
CUSTOM_VERSION   -> Read oeminfo failed!
PRELOAD_VERSION  -> Read oeminfo failed!
BASE_VERSION     -> Read oeminfo failed!
VENDOR_COUNTRY   -> failed input oem_nv_item
CUST_VERSION     -> failed input oem_nv_item
OEMINFO_CUST_VERSION    -> failed input oem_nv_item
OEMINFO_PRELOAD_VERSION -> failed input oem_nv_item
```

The collector received 5 concrete fastboot variable values and 109 explicit
`undefine` results. ADB did not expose a device in the current mode.

## Confirmed diagnosis

The fastboot-visible main version is missing and vendor/country cannot be read
from OEMINFO. Model, build, Android version, IMEI, baseband, CUST version,
PRELOAD version, FRP, secure-boot state, anti-rollback, memory, and partition
sizes remain unavailable in this boot stage.

The earlier CUST/PRELOAD metadata failures are consistent with this damaged or
incomplete identity state, but causation is still an inference. A future repair
must prove the OEMINFO/main-version readback before another regional update.

## What this capture does not authorize

This evidence does not identify a safe standalone OEMINFO image to write. The
original AL00 board package contains an AL00 OEMINFO image; writing it during an
L29 conversion could restore the source identity or conflict with already
written L29 partitions. The correct service-tool operation and backup/restore
path must be established first.
