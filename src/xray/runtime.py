from __future__ import annotations

import platform
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Sequence

from .engine import inspect_text
from .knowledge import load_knowledge
from .models import Claim, Status, VERSION, XrayReport

SELFTEST_UNISOC = """Connect phone in BROM mode. Use volume key buttons or testpoint.
Waiting for device... OK
Device found at COM19
Port: USB\\VID_1782&PID_4D00\\5&242A2F40&0&5
Driver: [UNISOC Communications Inc.,sprdvcom,SPRD U2S Diag,sprdvcom.sys,4.19.38.134]
Port type: BROM
Connecting to device... OK
Selected processor: Tiger_T616_64
Connect preloader 1... OK
Connect preloader 2... OK
Connect loader 1... OK
Connect loader 2... OK
Flash Type: EMMC
Read partitions info... OK
Checking A/B state... OK [A]
Read product info... [EROFS] ... OK
Product Brand        : Infinix
Product Manufacturer : INFINIX
Product Model        : Infinix X6725
Product Name         : X6725-OP
Product Device       : Infinix-X6725
Product Board        : Infinix-X6725
Board Platform       : ums9230
Build ID             : TP1A.220624.014
Build Date           : Thu Oct 23 11:24:58 CST 2025
Display ID           : X6725-(BASE001PF001AZ)251023V2806DevT
Security Patch       : 2025-10-01
Version SDK          : 35
Version Release      : 15
Version Codename     : REL
Firmware Version     : 28626
Userdata FS Type     : F2FS
Read IMEI... error(1)
"""

SELFTEST_HUAWEI = """Xray Android Device Readout
FASTBOOT_PRESENT: 1 device(s) answered fastboot.
FASTBOOT_PRODUCT: kirin980
rescue_phoneinfo: NO MAIN VERSION
vendorcountry: cannot get vendorcountry in oeminfo
oem get-bootinfo: unlocked
"""

SELFTEST_APPLE = """Apple Mobile Device (DFU Mode)
Port: USB\\VID_05AC&PID_1227\\CPID8015
MODE: DFU
CPID: 0x8015
BDID: 0x0C
ECID: 0x0011223344556677
PRODUCT: iPhone10,6
"""


def _report_text(report: XrayReport) -> str:
    lines = [
        f"Xray {report.xray_version} — {report.governor_verdict['result']}",
        f"Session: {report.session_id}",
        f"Artifact: {report.artifact['name']} ({report.artifact['bytes']} bytes)",
        f"SHA-256: {report.artifact['sha256']}",
        f"Workforce: {report.workforce['total_privates']} privates in {report.workforce['waves']} waves",
        "",
        "Claims",
        "------",
    ]
    for claim in report.claims:
        value = claim.value if claim.value is not None else "unknown"
        lines.append(f"{claim.name}: {value} [{claim.status.value}, score={claim.score}]")
        if claim.contradictions:
            lines.append(f"  contradictions: {'; '.join(claim.contradictions)}")
        if claim.missing_proof:
            lines.append(f"  missing proof: {', '.join(claim.missing_proof)}")
        if claim.note:
            lines.append(f"  note: {claim.note}")
    lines.extend(["", "Officer reports", "---------------"])
    for officer in report.officers:
        lines.append(f"{officer.officer}: {officer.summary}")
        for blocker in officer.blockers:
            lines.append(f"  blocker: {blocker}")
    lines.extend(
        [
            "",
            "Authority boundary",
            "------------------",
            "Write authorized: NO",
            "Model required: NO",
            "Model used: NO",
        ]
    )
    return "\n".join(lines)


def _safe_command(name: str, argv: Sequence[str], timeout: int = 12) -> dict[str, Any]:
    executable = shutil.which(argv[0])
    if not executable:
        return {"name": name, "available": False, "argv": list(argv), "returncode": None, "stdout": "", "stderr": "not found"}
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            errors="replace",
        )
        return {
            "name": name,
            "available": True,
            "argv": list(argv),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "available": True,
            "argv": list(argv),
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"timeout after {timeout}s",
        }


def doctor() -> dict[str, Any]:
    knowledge = load_knowledge()
    commands = ["adb", "fastboot", "idevice_id", "ideviceinfo", "irecovery", "lsusb", "system_profiler", "powershell"]
    return {
        "xray_version": VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "knowledge_schema": knowledge["schema"],
        "knowledge_version": knowledge["version"],
        "commands": {command: shutil.which(command) for command in commands},
        "write_authorized": False,
        "model_required": False,
    }


def scan_host() -> XrayReport:
    system = platform.system().lower()
    probes: list[tuple[str, list[str]]] = [
        ("adb-list", ["adb", "devices", "-l"]),
        ("fastboot-list", ["fastboot", "devices"]),
        ("apple-usbmux-list", ["idevice_id", "-l"]),
        ("apple-recovery-query", ["irecovery", "-q"]),
    ]
    if system == "linux":
        probes.append(("linux-usb", ["lsusb"]))
    elif system == "darwin":
        probes.append(("macos-usb", ["system_profiler", "SPUSBDataType"]))
    elif system == "windows":
        probes.append(
            (
                "windows-pnp",
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-PnpDevice -PresentOnly | Where-Object {$_.Class -in 'USB','Ports','WPD'} | Format-List",
                ],
            )
        )
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=10, thread_name_prefix="xray-provider") as pool:
        futures = [pool.submit(_safe_command, name, argv) for name, argv in probes]
        for future in as_completed(futures):
            results.append(future.result())
    joined = []
    for result in sorted(results, key=lambda item: item["name"]):
        joined.append(f"### {result['name']}\nreturncode: {result['returncode']}\n{result['stdout']}\n{result['stderr']}")
    return inspect_text("\n".join(joined), artifact_name="live-host-scan.txt")


def _claim(report: XrayReport, name: str) -> Claim:
    for item in report.claims:
        if item.name == name:
            return item
    raise AssertionError(f"Missing claim: {name}")


def run_selftest() -> dict[str, Any]:
    tests: list[dict[str, Any]] = []

    unisoc = inspect_text(
        SELFTEST_UNISOC,
        artifact_name="selftest-unisoc.txt",
        external_claims=[
            {
                "key": "hardware.marketed_soc",
                "value": "UNISOC T7250",
                "source_class": "specialist_online",
                "applies_to_model": "Infinix X6725B",
            }
        ],
    )
    tests.append(
        {
            "name": "unisoc-loader-not-silicon",
            "passed": (
                _claim(unisoc, "device.family").value == "UNISOC"
                and _claim(unisoc, "transport.mode").value == "BROM"
                and _claim(unisoc, "hardware.loader_compatibility").value == "Tiger_T616_64"
                and _claim(unisoc, "hardware.exact_soc").status in {Status.CONFLICTED, Status.INFERRED}
                and _claim(unisoc, "hardware.exact_soc").status != Status.CERTIFIED
            ),
            "verdict": unisoc.governor_verdict["result"],
        }
    )

    huawei = inspect_text(SELFTEST_HUAWEI, artifact_name="selftest-huawei.txt")
    tests.append(
        {
            "name": "huawei-main-version-gate",
            "passed": (
                _claim(huawei, "firmware.main_version").status == Status.BLOCKED
                and huawei.governor_verdict["result"] == "BLOCKED"
            ),
            "verdict": huawei.governor_verdict["result"],
        }
    )

    apple = inspect_text(SELFTEST_APPLE, artifact_name="selftest-apple.txt")
    tests.append(
        {
            "name": "apple-dfu-readiness",
            "passed": (
                _claim(apple, "device.family").value == "Apple"
                and _claim(apple, "transport.mode").value == "DFU"
                and _claim(apple, "apple.cpid").value == "0x8015"
                and "dfu" in apple.provider_expectations["apple"]
            ),
            "verdict": apple.governor_verdict["result"],
        }
    )

    return {
        "xray_version": VERSION,
        "passed": all(item["passed"] for item in tests),
        "tests": tests,
        "write_authorized": False,
        "model_required": False,
    }
