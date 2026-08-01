from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import VERSION


class RevivePlanError(ValueError):
    """Raised when a revive profile cannot be built from local evidence."""


@dataclass(frozen=True)
class ReviveArtifact:
    label: str
    path: Path
    role: str

    def to_dict(self) -> dict[str, Any]:
        digest = hashlib.sha256()
        with self.path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                digest.update(chunk)
        return {
            "label": self.label,
            "path": str(self.path),
            "role": self.role,
            "size": self.path.stat().st_size,
            "sha256": digest.hexdigest().upper(),
        }


@dataclass(frozen=True)
class ReviveProfile:
    name: str
    source_model: str
    target_model: str
    target_build: str
    vendor: str
    country: str
    region: str
    package_root: Path
    template_root: Path | None = None

    @property
    def dload_root(self) -> Path:
        return self.package_root / "Software" / "dload"

    def artifact_map(self) -> tuple[ReviveArtifact, ...]:
        return (
            ReviveArtifact("BASE_PACKAGE", self.dload_root / "update_sd_base.zip", "official dload base package"),
            ReviveArtifact(
                "CUST_PACKAGE",
                self.dload_root / "update_sd_cust_VOG-L29_hw_meafnaf.zip",
                "official dload CUST package",
            ),
            ReviveArtifact(
                "PRELOAD_PACKAGE",
                self.dload_root / "update_sd_preload_VOG-L29_hw_meafnaf_R5.zip",
                "official dload PRELOAD package",
            ),
            ReviveArtifact(
                "BASE_VERLIST",
                self.dload_root / "update_sd_base" / "SOFTWARE_VER_LIST.mbn",
                "base package version list",
            ),
            ReviveArtifact(
                "CUST_VERLIST",
                self.dload_root / "update_sd_cust_VOG-L29_hw_meafnaf" / "SOFTWARE_VER_LIST.mbn",
                "C185 CUST verlist input",
            ),
            ReviveArtifact(
                "CUST_PTABLE",
                self.dload_root / "update_sd_cust_VOG-L29_hw_meafnaf" / "PTABLE_CUST.mbn",
                "C185 CUST ptable input",
            ),
            ReviveArtifact(
                "PRELOAD_VERLIST",
                self.dload_root / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "SOFTWARE_VER_LIST.mbn",
                "C185 PRELOAD verlist input",
            ),
            ReviveArtifact(
                "PRELOAD_PTABLE",
                self.dload_root / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "PTABLE_PRELOAD.mbn",
                "C185 PRELOAD ptable input",
            ),
        )


def vog_l29_c185_profile(package_root: Path, template_root: Path | None = None) -> ReviveProfile:
    return ReviveProfile(
        name="vog-l29-c185-from-p10revive-pattern",
        source_model="VOG-AL00",
        target_model="VOG-L29",
        target_build="VOGUE-L29D 10.0.0.186(C185E8R5P1)",
        vendor="hw",
        country="meafnaf",
        region="C185",
        package_root=package_root,
        template_root=template_root,
    )


def _required_template_files(template_root: Path | None) -> list[dict[str, Any]]:
    if template_root is None:
        return []
    files = [
        "1. revive flasher.bat",
        "3a. OEMINFO Flash VTR-L29C432.bat",
        "tools_fw/fastboot.exe",
        "tools_fw/adb.exe",
    ]
    results: list[dict[str, Any]] = []
    for relative in files:
        path = template_root / relative
        results.append({"path": str(path), "present": path.exists(), "role": "P10Revive pattern/tool reference"})
    return results


def build_revive_plan(profile: ReviveProfile) -> dict[str, Any]:
    missing = [artifact for artifact in profile.artifact_map() if not artifact.path.exists()]
    if missing:
        labels = ", ".join(f"{item.label}={item.path}" for item in missing)
        raise RevivePlanError(f"Missing required revive artifact(s): {labels}")

    template_files = _required_template_files(profile.template_root)
    phases = [
        {
            "phase": "read_only_precheck",
            "purpose": "Confirm the connected phone still reports the known blocker before any repair attempt.",
            "commands": [
                "fastboot devices",
                "fastboot -s <SERIAL> getvar rescue_phoneinfo",
                "fastboot -s <SERIAL> getvar vendorcountry",
                "fastboot -s <SERIAL> oem get-bootinfo",
            ],
            "stop_if": [
                "device is not the expected VOG/P30 Pro target",
                "bootloader is not unlocked",
                "more than one fastboot device is connected",
            ],
        },
        {
            "phase": "oeminfo_identity_repair",
            "purpose": "Create or apply a VOG-L29 hw/meafnaf OEMINFO payload using the P10Revive dd pattern, not the P10 payload.",
            "required_payload": "VOG-L29 C185 hw/meafnaf OEMINFO binary, not present in the current local evidence set",
            "block_path_rule": "Resolve /dev/block/by-name/oeminfo on the connected phone; do not assume /dev/block/sdd5.",
            "target_identity": {
                "model": profile.target_model,
                "build": profile.target_build,
                "vendor": profile.vendor,
                "country": profile.country,
            },
        },
        {
            "phase": "matched_dload_or_service_package",
            "purpose": "Process the complete matched VOG-L29 C185 base+CUST+PRELOAD package after OEMINFO reads cleanly.",
            "packages": ["BASE_PACKAGE", "CUST_PACKAGE", "PRELOAD_PACKAGE"],
            "metadata_inputs": ["CUST_VERLIST", "CUST_PTABLE", "PRELOAD_VERLIST", "PRELOAD_PTABLE"],
        },
        {
            "phase": "post_repair_readback",
            "purpose": "Verify the repair result without trusting the write tool log alone.",
            "must_read": [
                "VOG-L29 model",
                "VOGUE-L29D 10.0.0.186(C185E8R5P1) or equivalent C185 build",
                "hw/meafnaf vendor/country",
                "baseband present",
                "IMEI fields present",
            ],
        },
    ]
    return {
        "schema": "xray-revive-plan-v1",
        "xray_version": VERSION,
        "profile": profile.name,
        "source_model": profile.source_model,
        "target": {
            "model": profile.target_model,
            "build": profile.target_build,
            "vendor": profile.vendor,
            "country": profile.country,
            "region": profile.region,
        },
        "authority": {
            "write_authorized": False,
            "script_mode": "audit-only",
            "reason": "Xray can prepare and verify revive inputs, but does not authorize flashing or OEMINFO writes.",
        },
        "package_root": str(profile.package_root),
        "template_root": str(profile.template_root) if profile.template_root else None,
        "template_reference": template_files,
        "artifacts": [artifact.to_dict() for artifact in profile.artifact_map()],
        "phases": phases,
        "stop_conditions": [
            "NO MAIN VERSION remains after OEMINFO identity repair",
            "vendorcountry remains unreadable after OEMINFO identity repair",
            "tool reports not allow update verlist",
            "CUST/PRELOAD partition size or layout mismatch",
            "VBMETA_HW_PRODUCT fails",
            "the phone reports a non-VOG-L29 identity after repair",
        ],
    }


def guarded_batch_script(plan: dict[str, Any]) -> str:
    target = plan["target"]
    artifacts = {item["label"]: item["path"] for item in plan["artifacts"]}
    return "\r\n".join(
        [
            "@echo off",
            "setlocal EnableExtensions",
            "echo Xray revive scaffold - AUDIT ONLY",
            "echo This file is generated from verified local package paths.",
            "echo Xray write_authorized=false. Review every line before converting to an execution script.",
            "echo.",
            f"echo Target model: {target['model']}",
            f"echo Target build: {target['build']}",
            f"echo Vendor/Country: {target['vendor']}/{target['country']}",
            "echo.",
            "echo Required read-only checks:",
            "echo   fastboot devices",
            "echo   fastboot -s ^<SERIAL^> getvar rescue_phoneinfo",
            "echo   fastboot -s ^<SERIAL^> getvar vendorcountry",
            "echo   fastboot -s ^<SERIAL^> oem get-bootinfo",
            "echo.",
            "echo Matched package inputs:",
            f"echo   BASE_PACKAGE={artifacts['BASE_PACKAGE']}",
            f"echo   CUST_PACKAGE={artifacts['CUST_PACKAGE']}",
            f"echo   PRELOAD_PACKAGE={artifacts['PRELOAD_PACKAGE']}",
            f"echo   CUST_VERLIST={artifacts['CUST_VERLIST']}",
            f"echo   CUST_PTABLE={artifacts['CUST_PTABLE']}",
            f"echo   PRELOAD_VERLIST={artifacts['PRELOAD_VERLIST']}",
            f"echo   PRELOAD_PTABLE={artifacts['PRELOAD_PTABLE']}",
            "echo.",
            "echo Missing before execution: VOG-L29 C185 OEMINFO payload and verified /dev/block/by-name/oeminfo path.",
            "echo Do not use VTR-L29C432.bin or /dev/block/sdd5 by assumption.",
            "exit /b 2",
            "",
        ]
    )


def write_revive_outputs(plan: dict[str, Any], output: Path | None, script_output: Path | None) -> None:
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if script_output:
        script_output.parent.mkdir(parents=True, exist_ok=True)
        script_output.write_text(guarded_batch_script(plan), encoding="utf-8")
