# Xray read-only collector

The Xray collector records what a connected Android device and the Windows host
actually expose. It does not turn an unavailable field into `undefine` and then
present that as a successful read.

## Supported evidence paths

- Android Debug Bridge in Android, recovery, and rescue states.
- Standard fastboot and fastbootd variables.
- Huawei/Kirin rescue variables and known read-only OEMINFO queries.
- Windows USB device, driver, and serial-port metadata.
- Raw JSON evidence plus a compact text report.

The collector is model-independent at the transport layer. Huawei-specific
queries are additional probes; a failure there does not hide standard Android or
fastboot results.

## MIBU reuse

The implementation was compared with the local `jaydumisuni/MIBU` PC helper and
reuses its proven design ideas: explicit tool discovery, hidden Windows helper
processes, merged command output, bounded timeouts, strict device-row parsing,
and serial-specific commands. No MIBU source file was changed, and Xray does not
import MIBU's Xiaomi workflow or device-selection assumptions.

## Safety boundary

The fastboot command list is an allowlist. Tests reject commands containing
flash, erase, reboot, boot, unlock, relock, format, continue, or update actions.
Xray does not fetch partition contents.

Run:

```powershell
python -m xray --output C:\path\to\evidence
```

Python 3.10 or newer is required. The collector has no third-party Python
dependencies.

Optional tool overrides:

```powershell
python -m xray --adb C:\platform-tools\adb.exe `
  --fastboot C:\platform-tools\fastboot.exe `
  --output C:\path\to\evidence
```

## Interpretation

Xray separates these cases:

- `value`: the current protocol returned a concrete value.
- `undefined`: the device explicitly returned `undefine`, `undefined`, or an
  equivalent marker.
- `no_value`: the command completed without a parseable value.
- `error`: the bootloader rejected the query and the raw error was retained.
- `timeout`: the transport did not answer within the bounded read window.

Windows driver provider names are host evidence only. For example, the live
phone appears under a LeMobile driver, but that is not evidence that the phone
was manufactured by LeMobile.

## Limits

No language or library can recover protected OEMINFO, IMEI, security, or
partition data when the active boot stage does not expose a read operation.
Adding Rust or direct USB access can replace the transport implementation later,
but it cannot bypass device permissions. In a proprietary Huawei download mode,
Xray can identify the Windows USB/COM interface until a lawful, documented
protocol adapter is available.
