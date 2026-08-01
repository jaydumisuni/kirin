from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree


BOARD_RECIPE_SCHEMA = "xray-huawei-board-recipe-v1"
REVIVE_WORKFLOW_SCHEMA = "xray-revive-workflow-v1"


class HuaweiBoardError(ValueError):
    """Raised when a Huawei board-software recipe cannot be verified."""


def inspect_huawei_board_package(package_root: Path) -> dict[str, Any]:
    """Parse an official Huawei board-software XML without executing it."""

    xml_paths = sorted(package_root.glob("*_Download.xml"), key=lambda path: path.name.casefold())
    if len(xml_paths) != 1:
        raise HuaweiBoardError(
            f"Expected exactly one Huawei *_Download.xml in {package_root}; found {len(xml_paths)}"
        )
    xml_path = xml_paths[0]
    try:
        xml_bytes = xml_path.read_bytes()
        try:
            xml_text = xml_bytes.decode("utf-8")
        except UnicodeDecodeError:
            xml_text = xml_bytes.decode("gb18030")
        configuration = ElementTree.fromstring(xml_text).find("configuration")
    except (ElementTree.ParseError, OSError, UnicodeDecodeError) as exc:
        raise HuaweiBoardError(f"Cannot parse Huawei board XML {xml_path}: {exc}") from exc
    if configuration is None:
        raise HuaweiBoardError(f"Missing configuration element in {xml_path}")

    inventory: list[dict[str, Any]] = []
    image_sections = ("bootloaderimage_ddr", "bootloaderimage", "fastbootimage")
    for section_name in image_sections:
        section = configuration.find(section_name)
        if section is None:
            continue
        for image in section.findall("image"):
            relative = (image.text or "").strip()
            if not relative:
                continue
            path = _artifact_path(package_root, relative)
            inventory.append(
                {
                    "section": section_name,
                    "name": image.get("name"),
                    "identifier": image.get("identifier"),
                    "relative_path": relative,
                    "path": str(path),
                    "present": path.is_file(),
                    "size": path.stat().st_size if path.is_file() else None,
                }
            )

    operation_section = configuration.find("partially_erase_configuration")
    if operation_section is None:
        raise HuaweiBoardError(f"Missing partially_erase_configuration in {xml_path}")
    operations: list[dict[str, Any]] = []
    for index, command in enumerate(operation_section.findall("cmd"), start=1):
        relative = (command.text or "").strip()
        artifact = _artifact_path(package_root, relative) if relative else None
        operation = command.get("command", "")
        operations.append(
            {
                "index": index,
                "transport": command.get("type", "fastboot"),
                "operation": operation,
                "identifier": command.get("identifier"),
                "artifact": str(artifact) if artifact else None,
                "artifact_present": artifact.is_file() if artifact else None,
                "destructive": operation in {"flash", "erase", "oem"},
            }
        )

    missing_inventory = sorted(
        {item["relative_path"] for item in inventory if not item["present"]},
        key=str.casefold,
    )
    missing_operations = sorted(
        {
            str(Path(item["artifact"]).relative_to(package_root))
            for item in operations
            if item["artifact"] and not item["artifact_present"]
        },
        key=str.casefold,
    )
    return {
        "schema": BOARD_RECIPE_SCHEMA,
        "status": "READY" if not missing_operations else "INCOMPLETE",
        "package_root": str(package_root),
        "source_xml": str(xml_path),
        "source_xml_sha256": _sha256(xml_path),
        "platform": configuration.get("ap_platform"),
        "product": configuration.get("product_id"),
        "version": configuration.get("version"),
        "inventory": inventory,
        "inventory_count": len(inventory),
        "operations": operations,
        "operation_count": len(operations),
        "flash_count": sum(item["operation"] == "flash" for item in operations),
        "erase_count": sum(item["operation"] == "erase" for item in operations),
        "oem_count": sum(item["operation"] == "oem" for item in operations),
        "missing_artifacts": missing_operations,
        "optional_inventory_missing": missing_inventory,
        "write_authorized": False,
    }


def build_p30_revive_workflow(model_root: Path) -> dict[str, Any]:
    """Carry the P10Revive stage pattern into verified P30 package data."""

    board_root = _single_board_package(model_root)
    target_root, dload_root = _single_dload_package(model_root)
    board = inspect_huawei_board_package(board_root)
    target_artifacts = _target_dload_artifacts(dload_root)
    target_missing = [item["pattern"] for item in target_artifacts if not item["present"]]
    target_status = "READY" if not target_missing else "INCOMPLETE"
    board_oeminfo = board_root / "fastbootimage" / "oeminfo.mbn"

    return {
        "schema": REVIVE_WORKFLOW_SCHEMA,
        "profile": "huawei-p30-pro-vog-l29-c185",
        "model_root": str(model_root),
        "target": {
            "family": "VOG",
            "model": "VOG-L29",
            "region": "C185",
            "vendor": "hw",
            "country": "meafnaf",
        },
        "authority": {
            "write_authorized": False,
            "mode": "audit-only",
            "reason": "The carried workflow is prepared, but live identity and target OEMINFO gates remain open.",
        },
        "lineage": [
            {
                "p10_stage": "unpack UPDATE.APP",
                "universal_stage": "inventory official package artifacts",
            },
            {
                "p10_stage": "flash base board images",
                "universal_stage": "parse and preserve the official board XML operation order",
            },
            {
                "p10_stage": "apply L09/L29 regional images",
                "universal_stage": "apply the selected model's matched base+CUST+PRELOAD package",
            },
            {
                "p10_stage": "boot recovery and write OEMINFO",
                "universal_stage": "use only a model-certified identity method and partition target",
            },
        ],
        "stages": [
            {
                "id": "board_restore",
                "status": "PREPARED" if board["status"] == "READY" else "INCOMPLETE",
                "source": board["source_xml"],
                "platform": board["platform"],
                "product": board["product"],
                "version": board["version"],
                "operations": board["operations"],
                "operation_count": board["operation_count"],
                "missing": board["missing_artifacts"],
                "optional_inventory_missing": board["optional_inventory_missing"],
            },
            {
                "id": "target_vog_l29_c185",
                "status": "PREPARED" if target_status == "READY" else "INCOMPLETE",
                "package_root": str(target_root),
                "dload_root": str(dload_root),
                "artifacts": target_artifacts,
                "missing": target_missing,
            },
            {
                "id": "target_identity",
                "status": "BLOCKED",
                "board_oeminfo": str(board_oeminfo),
                "board_oeminfo_present": board_oeminfo.is_file(),
                "board_oeminfo_identity": "VOG-AL00 board identity; not proof of VOG-L29 C185 identity",
                "required": [
                    "certified VOG-L29 C185 OEMINFO method or service transition",
                    "live OEMINFO partition target resolved from the P30 Pro",
                    "post-write VOG-L29 and hw/meafnaf readback",
                ],
            },
            {
                "id": "post_repair_verification",
                "status": "PENDING",
                "required": [
                    "main version present",
                    "vendorcountry reads hw/meafnaf",
                    "baseband present",
                    "VOG-L29 identity present",
                ],
            },
        ],
        "ready_for_execution": False,
    }


def write_p30_revive_workflow(workflow: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(workflow, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _single_board_package(model_root: Path) -> Path:
    candidates = sorted(
        {xml.parent for xml in model_root.glob("*/*_Download.xml")},
        key=lambda path: path.name.casefold(),
    )
    if len(candidates) != 1:
        raise HuaweiBoardError(f"Expected one Huawei board package in {model_root}; found {len(candidates)}")
    return candidates[0]


def _single_dload_package(model_root: Path) -> tuple[Path, Path]:
    candidates: dict[str, tuple[Path, Path]] = {}
    for marker in model_root.rglob("update_sd_base.zip"):
        dload_root = marker.parent
        relative = dload_root.relative_to(model_root)
        package_root = model_root / relative.parts[0] if relative.parts else model_root
        candidates[str(package_root).casefold()] = (package_root, dload_root)
    if len(candidates) != 1:
        raise HuaweiBoardError(f"Expected one target dload package in {model_root}; found {len(candidates)}")
    return next(iter(candidates.values()))


def _target_dload_artifacts(dload_root: Path) -> list[dict[str, Any]]:
    patterns = (
        "update_sd_base.zip",
        "update_sd_cust_VOG-L29_*.zip",
        "update_sd_preload_VOG-L29_*.zip",
        "update_sd_base/SOFTWARE_VER_LIST.mbn",
        "update_sd_cust_VOG-L29_*/SOFTWARE_VER_LIST.mbn",
        "update_sd_cust_VOG-L29_*/PTABLE_CUST.mbn",
        "update_sd_preload_VOG-L29_*/SOFTWARE_VER_LIST.mbn",
        "update_sd_preload_VOG-L29_*/PTABLE_PRELOAD.mbn",
    )
    results: list[dict[str, Any]] = []
    for pattern in patterns:
        matches = sorted((path for path in dload_root.glob(pattern) if path.is_file()), key=lambda path: str(path).casefold())
        results.append(
            {
                "pattern": pattern,
                "present": bool(matches),
                "paths": [str(path) for path in matches],
                "size": sum(path.stat().st_size for path in matches),
            }
        )
    return results


def _artifact_path(package_root: Path, relative: str) -> Path:
    relative_path = Path(*PurePosixPath(relative.replace("\\", "/")).parts)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise HuaweiBoardError(f"Unsafe artifact path in board XML: {relative}")
    path = package_root / relative_path
    try:
        path.resolve(strict=False).relative_to(package_root.resolve())
    except ValueError as exc:
        raise HuaweiBoardError(f"Artifact path escapes board package: {relative}") from exc
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()
