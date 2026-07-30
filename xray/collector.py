from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

ADB_STATES = {
    "bootloader",
    "device",
    "offline",
    "recovery",
    "rescue",
    "sideload",
    "unauthorized",
}

FASTBOOT_VARIABLES = (
    "product",
    "product-name",
    "device",
    "device-codename",
    "model",
    "sku",
    "variant",
    "hw-revision",
    "serialno",
    "version",
    "version-bootloader",
    "version-baseband",
    "version-os",
    "version-vndk",
    "os-version",
    "android-version",
    "security-patch-level",
    "build-number",
    "build-version",
    "current-slot",
    "slot-count",
    "slot-suffixes",
    "is-userspace",
    "secure",
    "unlocked",
    "lock-state",
    "device-state",
    "frp",
    "frp-state",
    "anti",
    "anti-rollback",
    "rollback-index",
    "battery-voltage",
    "battery-soc-ok",
    "off-mode-charge",
    "charger-screen-enabled",
    "max-download-size",
    "logical-block-size",
    "erase-block-size",
    "page-size",
    "rescue_phoneinfo",
    "vendorcountry",
    "boot-mode",
    "crc",
    "dp-level",
    "unlock-token",
    "parallel-download",
    "cpu-id",
    "flash-id",
    "ram-size",
    "internal-memory-size",
    "imei",
    "imei1",
    "imei2",
)

FASTBOOT_PARTITIONS = (
    "oeminfo",
    "version",
    "cust",
    "preload",
    "product",
    "super",
    "vbmeta",
    "vbmeta_system",
    "vbmeta_vendor",
    "vbmeta_odm",
    "vbmeta_hw_product",
    "vbmeta_cust",
    "system",
    "vendor",
    "odm",
    "boot",
    "ramdisk",
    "recovery_ramdisk",
    "erecovery_ramdisk",
    "userdata",
)

# These OEM subcommands only request values. Commands that write, unlock, erase,
# boot, continue, or reboot are deliberately absent.
GENERIC_OEM_READS = (("device-info",),)

HUAWEI_OEM_READS = (
    ("get-bootinfo",),
    ("get-build-number",),
    ("get-product-model",),
    ("oeminforead-SYSTEM_VERSION",),
    ("oeminforead-CUSTOM_VERSION",),
    ("oeminforead-PRELOAD_VERSION",),
    ("oeminforead-BASE_VERSION",),
    ("oeminforead-VENDOR_COUNTRY",),
    ("oeminforead-CUST_VERSION",),
    ("oeminforead-OEMINFO_CUST_VERSION",),
    ("oeminforead-OEMINFO_PRELOAD_VERSION",),
)

ADB_READS = (
    ("shell", "getprop"),
    ("shell", "dumpsys", "battery"),
    ("shell", "cat", "/proc/cpuinfo"),
    ("shell", "wm", "size"),
    ("shell", "wm", "density"),
    ("shell", "df", "-h"),
)

FORBIDDEN_DEVICE_ACTIONS = {
    "boot",
    "continue",
    "delete-logical-partition",
    "erase",
    "flash",
    "flashing",
    "format",
    "reboot",
    "reboot-bootloader",
    "set_active",
    "snapshot-update",
    "update",
    "wipe-super",
}


@dataclass
class CommandResult:
    command: list[str]
    returncode: int | None
    stdout: str
    status: str
    elapsed_ms: int
    error: str | None = None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def run_command(command: Sequence[str], timeout: int = 15) -> CommandResult:
    started = datetime.now(timezone.utc)
    try:
        proc = subprocess.run(
            list(command),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
            errors="replace",
        )
        output = proc.stdout.strip()
        status = "ok" if proc.returncode == 0 else "error"
        error = None
        returncode: int | None = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = _timeout_output(exc)
        status = "timeout"
        error = f"Timed out after {timeout} seconds"
        returncode = None
    except OSError as exc:
        output = ""
        status = "error"
        error = str(exc)
        returncode = None
    elapsed = datetime.now(timezone.utc) - started
    return CommandResult(
        command=list(command),
        returncode=returncode,
        stdout=output,
        status=status,
        elapsed_ms=max(0, round(elapsed.total_seconds() * 1000)),
        error=error,
    )


def _timeout_output(exc: subprocess.TimeoutExpired) -> str:
    value = exc.stdout or ""
    if isinstance(value, bytes):
        return value.decode(errors="replace").strip()
    return value.strip()


def _candidate_tools(name: str) -> list[Path]:
    executable = f"{name}.exe" if os.name == "nt" else name
    candidates: list[Path] = []
    for variable in (f"XRAY_{name.upper()}", name.upper()):
        value = os.environ.get(variable)
        if value:
            candidates.append(Path(value))
    for root_variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(root_variable)
        if root:
            candidates.append(Path(root) / "platform-tools" / executable)
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            candidates.append(
                Path(local_app_data) / "Android" / "Sdk" / "platform-tools" / executable
            )
        candidates.extend(
            (
                Path("D:/projects/in progress/#MIBU/.build-tools/android-sdk/platform-tools")
                / executable,
                Path("D:/projects/Huawei kirin/P10Revive/P10 Revive/tools_fw")
                / executable,
            )
        )
    resolved = shutil.which(name)
    if resolved:
        candidates.append(Path(resolved))
    return candidates


def find_tool(name: str, explicit: str | None = None) -> str | None:
    candidates = [Path(explicit)] if explicit else []
    candidates.extend(_candidate_tools(name))
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).casefold()
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return str(candidate.resolve())
    return None


def tool_version(tool: str, name: str) -> CommandResult:
    arguments = ["version"] if name == "adb" else ["--version"]
    return run_command([tool, *arguments], timeout=10)


def parse_adb_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("*") or line.lower().startswith("list of devices"):
            continue
        fields = line.split()
        if len(fields) < 2 or fields[1].lower() not in ADB_STATES:
            continue
        device = {"serial": fields[0], "state": fields[1].lower()}
        for field in fields[2:]:
            if ":" in field:
                key, value = field.split(":", 1)
                device[key] = value
        devices.append(device)
    return devices


def parse_fastboot_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if (
            not line
            or line.startswith("<")
            or line.startswith("(")
            or line.lower().startswith("waiting for")
        ):
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1].lower() in {"fastboot", "bootloader"}:
            devices.append({"serial": fields[0], "state": fields[1].lower()})
    return devices


def fastboot_command(tool: str, serial: str, arguments: Sequence[str]) -> list[str]:
    return [tool, "-s", serial, *arguments]


def parse_fastboot_value(output: str, key: str) -> dict[str, str | None]:
    failure = next(
        (
            line.strip()
            for line in output.splitlines()
            if "FAILED" in line or line.strip().startswith("fastboot: error:")
        ),
        None,
    )
    value: str | None = None
    key_prefix = f"{key}:"
    for raw_line in output.splitlines():
        line = re.sub(r"^\(bootloader\)\s*", "", raw_line.strip())
        if line.casefold().startswith(key_prefix.casefold()):
            value = line[len(key_prefix) :].strip()
            break
    if value is None:
        bootloader_lines = [
            re.sub(r"^\(bootloader\)\s*", "", line.strip())
            for line in output.splitlines()
            if line.strip().startswith("(bootloader)")
        ]
        if len(bootloader_lines) == 1 and ":" not in bootloader_lines[0]:
            value = bootloader_lines[0].strip()
    if failure:
        status = "error"
    elif value is None:
        status = "no_value"
    elif value.casefold() in {"undefine", "undefined", "unknown", "n/a"}:
        status = "undefined"
    else:
        status = "value"
    return {"status": status, "value": value, "error": failure}


def _read_adb(tool: str) -> dict[str, Any]:
    listing = run_command([tool, "devices", "-l"], timeout=10)
    devices = parse_adb_devices(listing.stdout)
    result: dict[str, Any] = {
        "listing": asdict(listing),
        "devices": devices,
        "probes": {},
    }
    for device in devices:
        serial = device["serial"]
        if device["state"] not in {"device", "recovery", "rescue"}:
            continue
        probes: dict[str, Any] = {}
        for arguments in ADB_READS:
            name = " ".join(arguments)
            probe = run_command([tool, "-s", serial, *arguments], timeout=20)
            probes[name] = asdict(probe)
        result["probes"][serial] = probes
    return result


def fastboot_read_commands() -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = [("getvar", "all")]
    commands.extend(("getvar", key) for key in FASTBOOT_VARIABLES)
    for partition in FASTBOOT_PARTITIONS:
        commands.extend(
            (
                ("getvar", f"partition-type:{partition}"),
                ("getvar", f"partition-size:{partition}"),
                ("getvar", f"has-slot:{partition}"),
            )
        )
    commands.extend(("oem", *parts) for parts in GENERIC_OEM_READS)
    commands.extend(("oem", *parts) for parts in HUAWEI_OEM_READS)
    return commands


def assert_read_only(arguments: Sequence[str]) -> None:
    lowered = [part.casefold() for part in arguments]
    if any(part in FORBIDDEN_DEVICE_ACTIONS for part in lowered):
        raise ValueError(f"Mutating fastboot command rejected: {' '.join(arguments)}")
    if lowered[:2] == ["oem", "unlock"] or lowered[:2] == ["oem", "relock"]:
        raise ValueError(f"Mutating OEM command rejected: {' '.join(arguments)}")
    allowed = (
        lowered[:1] == ["getvar"]
        or lowered[:2] == ["oem", "device-info"]
        or (
            lowered[:1] == ["oem"]
            and len(lowered) == 2
            and (
                lowered[1].startswith("get-")
                or lowered[1].startswith("oeminforead-")
            )
        )
    )
    if not allowed:
        raise ValueError(f"Command is not on the Xray read allowlist: {' '.join(arguments)}")


def _read_fastboot(tool: str) -> dict[str, Any]:
    listing = run_command([tool, "devices", "-l"], timeout=10)
    devices = parse_fastboot_devices(listing.stdout)
    result: dict[str, Any] = {
        "listing": asdict(listing),
        "devices": devices,
        "probes": {},
    }
    for device in devices:
        serial = device["serial"]
        probes: dict[str, Any] = {}
        variables: dict[str, Any] = {}
        for arguments in fastboot_read_commands():
            assert_read_only(arguments)
            name = " ".join(arguments)
            probe = run_command(fastboot_command(tool, serial, arguments), timeout=10)
            item = asdict(probe)
            if arguments[:1] == ("getvar",) and len(arguments) == 2:
                key = arguments[1]
                parsed = parse_fastboot_value(probe.stdout, key)
                item["parsed"] = parsed
                variables[key] = parsed
            probes[name] = item
        result["probes"][serial] = {"variables": variables, "commands": probes}
    return result


def _read_windows_usb() -> dict[str, Any]:
    if os.name != "nt":
        return {"status": "not_windows", "entities": [], "serial_ports": []}
    script = r"""
$ErrorActionPreference = 'Stop'
$pattern = 'Android|ADB|Bootloader|Fastboot|Huawei|HiSilicon|Kirin|Qualcomm.*9008|MediaTek|PreLoader|USB COM\b|Download Port|LeMobile'
$entities = @(Get-CimInstance Win32_PnPEntity | Where-Object {
  $_.PNPDeviceID -like 'USB\*' -and (
    $_.PNPClass -eq 'AndroidUsbDeviceClass' -or
    $_.Name -match $pattern -or
    $_.Manufacturer -match $pattern
  )
} | Select-Object Name, Manufacturer, Status, PNPClass, Service, DeviceID, HardwareID, CompatibleID)
$drivers = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object {
  $_.DeviceID -like 'USB\*' -and (
    $_.DeviceName -match $pattern -or
    $_.Manufacturer -match $pattern -or
    $_.DriverProviderName -match $pattern
  )
} | Select-Object DeviceName, Manufacturer, DriverProviderName, DriverVersion, DriverDate, InfName, IsSigned, Signer, DeviceID)
$ports = @(Get-CimInstance Win32_SerialPort | Select-Object Name, DeviceID, Description, ProviderType, PNPDeviceID, Status)
@{ entities = $entities; drivers = $drivers; serial_ports = $ports } | ConvertTo-Json -Depth 5 -Compress
"""
    probe = run_command(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=30,
    )
    if probe.status != "ok":
        return {"status": probe.status, "error": probe.error, "raw": probe.stdout}
    try:
        data = json.loads(probe.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "parse_error", "error": str(exc), "raw": probe.stdout}
    data["status"] = "ok"
    data["note"] = (
        "Manufacturer and provider names in this section describe Windows "
        "drivers or USB descriptors; they are not trusted phone identity."
    )
    return data


def _first_fastboot_probe(evidence: dict[str, Any]) -> dict[str, Any] | None:
    probes = evidence.get("fastboot", {}).get("probes", {})
    return next(iter(probes.values()), None)


def derive_findings(evidence: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    fastboot_devices = evidence.get("fastboot", {}).get("devices", [])
    adb_devices = evidence.get("adb", {}).get("devices", [])
    usb = evidence.get("windows_usb", {})
    if fastboot_devices:
        findings.append(
            {
                "level": "info",
                "code": "FASTBOOT_PRESENT",
                "message": f"{len(fastboot_devices)} device(s) answered fastboot.",
            }
        )
    elif adb_devices:
        findings.append(
            {
                "level": "info",
                "code": "ADB_PRESENT",
                "message": f"{len(adb_devices)} device(s) appeared through ADB.",
            }
        )
    elif usb.get("entities") or usb.get("serial_ports"):
        findings.append(
            {
                "level": "warning",
                "code": "HOST_USB_ONLY",
                "message": (
                    "Windows sees a relevant USB/COM device, but neither ADB nor "
                    "fastboot answered. Identity reads require a protocol adapter "
                    "for the current service mode."
                ),
            }
        )
    else:
        findings.append(
            {
                "level": "warning",
                "code": "NO_DEVICE",
                "message": "No Android, fastboot, or relevant USB/COM device was detected.",
            }
        )

    probe = _first_fastboot_probe(evidence)
    if not probe:
        return findings
    variables = probe.get("variables", {})
    product = variables.get("product", {})
    if product.get("status") == "value":
        findings.append(
            {
                "level": "info",
                "code": "FASTBOOT_PRODUCT",
                "message": f"Fastboot product is {product.get('value')}.",
            }
        )
    rescue = variables.get("rescue_phoneinfo", {})
    rescue_value = (rescue.get("value") or "").casefold()
    if "no main version" in rescue_value:
        findings.append(
            {
                "level": "critical",
                "code": "OEMINFO_MAIN_VERSION_MISSING",
                "message": (
                    "Huawei rescue reports NO MAIN VERSION. The main-version "
                    "identity in OEMINFO is absent or unreadable."
                ),
            }
        )
    vendor = variables.get("vendorcountry", {})
    vendor_text = " ".join(
        str(value or "") for value in (vendor.get("value"), vendor.get("error"))
    ).casefold()
    if "cannot get vendorcountry" in vendor_text:
        findings.append(
            {
                "level": "critical",
                "code": "OEMINFO_VENDORCOUNTRY_UNREADABLE",
                "message": "Huawei fastboot cannot read vendor/country from OEMINFO.",
            }
        )
    commands = probe.get("commands", {})
    bootinfo = commands.get("oem get-bootinfo", {}).get("stdout", "")
    bootinfo_value = _single_bootloader_value(bootinfo)
    if bootinfo_value:
        findings.append(
            {
                "level": "info",
                "code": "HUAWEI_BOOTINFO",
                "message": f"Huawei OEM boot info reports {bootinfo_value}.",
            }
        )
    valued = sum(1 for item in variables.values() if item.get("status") == "value")
    undefined = sum(
        1 for item in variables.values() if item.get("status") == "undefined"
    )
    findings.append(
        {
            "level": "info",
            "code": "FASTBOOT_COVERAGE",
            "message": (
                f"Fastboot returned {valued} concrete value(s) and explicitly "
                f"reported {undefined} value(s) as undefined."
            ),
        }
    )
    return findings


def _single_bootloader_value(output: str) -> str | None:
    values = [
        re.sub(r"^\(bootloader\)\s*", "", line.strip())
        for line in output.splitlines()
        if line.strip().startswith("(bootloader)")
    ]
    return values[0] if len(values) == 1 and values[0] else None


def collect_evidence(
    *,
    adb: str | None = None,
    fastboot: str | None = None,
) -> dict[str, Any]:
    started_at = utc_now()
    adb_tool = find_tool("adb", adb)
    fastboot_tool = find_tool("fastboot", fastboot)
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "capture": {
            "started_at": started_at,
            "finished_at": None,
            "host": {
                "platform": platform.platform(),
                "python": sys.version.split()[0],
                "machine": platform.machine(),
            },
        },
        "safety": {
            "mode": "read_only",
            "statement": (
                "Xray did not request flash, erase, reboot, boot, unlock, "
                "relock, format, continue, or partition fetch operations."
            ),
        },
        "tools": {},
        "windows_usb": _read_windows_usb(),
        "adb": {"status": "tool_not_found", "devices": [], "probes": {}},
        "fastboot": {"status": "tool_not_found", "devices": [], "probes": {}},
    }
    if adb_tool:
        version = tool_version(adb_tool, "adb")
        evidence["tools"]["adb"] = {"path": adb_tool, "version": asdict(version)}
        evidence["adb"] = _read_adb(adb_tool)
        evidence["adb"]["status"] = "probed"
    if fastboot_tool:
        version = tool_version(fastboot_tool, "fastboot")
        evidence["tools"]["fastboot"] = {
            "path": fastboot_tool,
            "version": asdict(version),
        }
        evidence["fastboot"] = _read_fastboot(fastboot_tool)
        evidence["fastboot"]["status"] = "probed"
    evidence["findings"] = derive_findings(evidence)
    evidence["capture"]["finished_at"] = utc_now()
    return evidence


def render_report(evidence: dict[str, Any]) -> str:
    lines = [
        "Xray Android Device Readout",
        "===========================",
        "",
        f"Started: {evidence['capture']['started_at']}",
        f"Finished: {evidence['capture']['finished_at']}",
        f"Safety: {evidence['safety']['statement']}",
        "",
        "Findings",
        "--------",
    ]
    for finding in evidence.get("findings", []):
        lines.append(
            f"[{finding['level'].upper()}] {finding['code']}: {finding['message']}"
        )
    lines.extend(("", "Tools", "-----"))
    for name, tool in evidence.get("tools", {}).items():
        version = tool["version"].get("stdout", "").splitlines()
        version_line = version[0] if version else "version unavailable"
        lines.append(f"{name}: {tool['path']} ({version_line})")

    usb = evidence.get("windows_usb", {})
    lines.extend(("", "Windows USB and COM", "-------------------"))
    lines.append(usb.get("note", "No Windows USB metadata was captured."))
    for entity in _as_list(usb.get("entities")):
        lines.append(
            f"- {entity.get('Name')} | provider={entity.get('Manufacturer')} | "
            f"class={entity.get('PNPClass')} | service={entity.get('Service')} | "
            f"id={entity.get('DeviceID')}"
        )
    for port in _as_list(usb.get("serial_ports")):
        lines.append(
            f"- COM: {port.get('Name')} | status={port.get('Status')} | "
            f"id={port.get('PNPDeviceID')}"
        )

    lines.extend(("", "ADB", "---"))
    adb_devices = evidence.get("adb", {}).get("devices", [])
    if not adb_devices:
        lines.append("No ADB device answered.")
    for device in adb_devices:
        lines.append(
            f"- {device.get('serial')} | state={device.get('state')} | "
            f"model={device.get('model', 'not advertised')}"
        )

    lines.extend(("", "Fastboot", "--------"))
    fastboot_devices = evidence.get("fastboot", {}).get("devices", [])
    if not fastboot_devices:
        lines.append("No fastboot device answered.")
    for device in fastboot_devices:
        serial = device["serial"]
        lines.append(f"- {serial} | state={device.get('state')}")
        probe = evidence["fastboot"]["probes"].get(serial, {})
        variables = probe.get("variables", {})
        for key in FASTBOOT_VARIABLES:
            item = variables.get(key)
            if not item:
                continue
            value = item.get("value") or item.get("error") or item.get("status")
            lines.append(f"  {key}: {value} [{item.get('status')}]")
        lines.append("  OEM read probes:")
        for name, command in probe.get("commands", {}).items():
            if not name.startswith("oem "):
                continue
            value = _single_bootloader_value(command.get("stdout", ""))
            if value:
                summary = value
            else:
                summary = next(
                    (
                        line.strip()
                        for line in command.get("stdout", "").splitlines()
                        if line.strip().startswith(("FAILED", "fastboot: error:"))
                    ),
                    command.get("status", "no_value"),
                )
            lines.append(f"    {name}: {summary} [{command.get('status')}]")

    lines.extend(
        (
            "",
            "Interpretation boundary",
            "-----------------------",
            (
                "A field marked undefined was rejected or omitted by the current "
                "device protocol. Xray does not invent a value from the chipset, "
                "USB driver, firmware folder, or target conversion profile."
            ),
            "",
        )
    )
    return "\n".join(lines)


def _as_list(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def write_evidence(evidence: dict[str, Any], output: Path) -> tuple[Path, Path]:
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / "capture.json"
    report_path = output / "report.txt"
    json_path.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
    report_path.write_text(render_report(evidence), encoding="utf-8")
    return json_path, report_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Collect read-only Android, fastboot, Huawei rescue, and Windows "
            "USB/COM evidence."
        )
    )
    parser.add_argument("--adb", help="Path to adb")
    parser.add_argument("--fastboot", help="Path to fastboot")
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory for capture.json and report.txt",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path.cwd() / "xray-evidence" / stamp
    evidence = collect_evidence(adb=args.adb, fastboot=args.fastboot)
    json_path, report_path = write_evidence(evidence, output)
    print(render_report(evidence))
    print(f"JSON evidence: {json_path.resolve()}")
    print(f"Text report: {report_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
