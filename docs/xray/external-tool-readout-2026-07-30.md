# External tool fastboot readout

Date supplied: 2026-07-30

## Source

The user supplied this text from a second service tool while the phone was
connected. It is retained as conversation evidence; Xray did not generate it.

```text
Waiting for device...
Download port: Android Bootloader Interface [SN:5T5PUB194L059785]
Port: Android Bootloader Interface [SN:5T5PUB194L059785]
Manufacturer: LeMobile

Connect to fastboot device... OK
Read device info...
 ● Product Name: kirin980
 ● IMEI: undefine
 ● Serial Number: serialv1.0
 ● Android Version: undefine
 ● Device Codename: undefine
 ● SKU / Model: undefine
 ● Carrier: undefine
 ● Internal Memory Size: undefine
 ● RAM Size: undefine
 ● Secure Boot: undefine
 ● FRP State: undefine
 ● Hardware Revision: undefine
 ● Flash ID: undefine
 ● Variant: undefine
 ● CPU ID: undefine
 ● Security Patch Level: undefine
 ● Bootloader Unlocked: undefine
 ● Boot Mode: undefine
 ● CRC Check: undefine
 ● DP Level: undefine
 ● Unlock Token: undefine
 ● Parallel Download: undefine
 ● Anti-Rollback: undefine
 ● HW Revision: undefine
 ● Off Mode Charging: undefine
 ● Charger Screen Enabled: undefine
 ● Battery Health OK: undefine
 ● Battery Voltage (mV): undefine
 ● Boot Info:  unlocked
Elapsed Time: 388 msecs.
```

## Interpretation

- The tool reached the same fastboot device, `5T5PUB194L059785`.
- Its concrete device values were `kirin980`, `serialv1.0`, and boot info
  `unlocked`.
- `Manufacturer: LeMobile` is the installed Windows driver provider. Windows
  reports driver `oem460.inf`, version `11.0.0.0`, dated 2016-08-28. It is not
  reliable evidence of the phone's manufacturer.
- The tool did not prove the IMEI, model, Android version, carrier, memory,
  security state, FRP, anti-rollback, or battery values. It reported those
  fields as `undefine`.
- It did not show the critical Huawei rescue and OEMINFO errors that Xray
  captured separately.

## Xray comparison

The dated Xray capture in
`evidence/xray/2026-07-30-vog-fastboot-final` independently confirmed the three
concrete values above. It additionally retained:

- `rescue_phoneinfo: NO MAIN VERSION`;
- `cannot get vendorcountry in oeminfo`;
- all failed Huawei OEMINFO read commands and their exact errors;
- 109 explicitly undefined fastboot values, including partition queries;
- ADB absence;
- Windows USB IDs, driver metadata, and serial-port enumeration;
- the exact ADB and fastboot versions used for the read.
