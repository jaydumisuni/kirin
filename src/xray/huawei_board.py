from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any
from xml.etree import ElementTree

from .huawei_package import EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES
from .oeminfo import OEMINFO_SCHEMA, OeminfoError, verify_vog_l29_c185_oeminfo
from .update_app import UpdateAppError, parse_update_app


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
    update_apps = _target_update_app_inventory(dload_root)
    package_proof = _target_package_proof(model_root, target_root)
    if update_apps["status"] == "INVALID":
        target_status = "INVALID"
    elif target_status == "READY" and update_apps["status"] == "VERIFIED" and package_proof["status"] == "VERIFIED":
        target_status = "VERIFIED"
    target_stage_status = (
        "VERIFIED" if target_status == "VERIFIED" else "PREPARED" if target_status == "READY" else target_status
    )
    board_oeminfo = board_root / "fastbootimage" / "oeminfo.mbn"
    identity_stage = _target_identity_stage(model_root, board_oeminfo)
    recovery_stage = _target_recovery_stage(model_root)

    board_operations = board["operations"]
    final_normal_reboot = board_operations[-1] if board_operations else None
    service_operations = (
        board_operations[:-1]
        if final_normal_reboot and final_normal_reboot["operation"] == "reboot"
        else board_operations
    )

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
            "reason": (
                "Offline artifacts can be verified, but live device binding, OEMINFO readback, "
                "and final target restoration remain gated."
            ),
        },
        "execution_policy": {
            "device_serial_required": True,
            "stop_on_first_error": True,
            "evidence_journal_required": True,
            "automatic_normal_reboot": False,
            "extract_target_payloads_one_at_a_time": True,
            "reason": "Keep board/service Fastboot available and avoid duplicating the 5.2 GB base UPDATE.APP.",
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
                "service_operations": service_operations,
                "service_operation_count": len(service_operations),
                "withheld_operation": final_normal_reboot,
                "withheld_reason": (
                    "Do not perform the board recipe's final normal reboot before OEMINFO and "
                    "target firmware are restored."
                ),
                "missing": board["missing_artifacts"],
                "optional_inventory_missing": board["optional_inventory_missing"],
            },
            {
                "id": "target_vog_l29_c185",
                "status": target_stage_status,
                "package_root": str(target_root),
                "dload_root": str(dload_root),
                "artifacts": target_artifacts,
                "internal_update_apps": update_apps,
                "offline_package_proof": package_proof,
                "missing": target_missing,
            },
            identity_stage,
            recovery_stage,
            {
                "id": "staged_execution_order",
                "status": (
                    "PREPARED"
                    if board["status"] == "READY"
                    and target_stage_status in {"PREPARED", "VERIFIED"}
                    and identity_stage["status"] == "PREPARED"
                    and recovery_stage["status"] == "PREPARED"
                    else "INCOMPLETE"
                ),
                "steps": [
                    {
                        "order": 1,
                        "action": (
                            "Verify every board, target, recovery, and OEMINFO artifact before "
                            "binding a device."
                        ),
                    },
                    {
                        "order": 2,
                        "action": (
                            "Bind exactly one VOG/P30 Pro by serial and capture read-only identity "
                            "and partition evidence."
                        ),
                    },
                    {
                        "order": 3,
                        "action": (
                            "Run board XML operations only through the final OEMINFO erase; "
                            "withhold the final normal reboot."
                        ),
                    },
                    {
                        "order": 4,
                        "action": (
                            "Install the verified target-based temporary recovery while retaining "
                            "board/service Fastboot."
                        ),
                    },
                    {
                        "order": 5,
                        "action": (
                            "Resolve /dev/block/by-name/oeminfo, require a 96 MiB target, back it "
                            "up, write VOG-L29C185.bin, and hash the full readback."
                        ),
                    },
                    {
                        "order": 6,
                        "action": (
                            "Return to the bootloader without a normal boot and install the matched "
                            "VOG-L29 C185 base, CUST, and PRELOAD packages."
                        ),
                    },
                    {
                        "order": 7,
                        "action": (
                            "Restore target FASTBOOT only inside the verified target-firmware stage, "
                            "then complete final readback before normal boot."
                        ),
                    },
                ],
                "live_gates": [
                    "expected serial and VOG hardware identity",
                    "unlocked/service write state",
                    "resolved OEMINFO by-name path reports exactly 100663296 bytes",
                    "OEMINFO readback SHA-256 equals the prepared image",
                    "all target base+CUST+PRELOAD operations complete without error",
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


def _target_identity_stage(model_root: Path, board_oeminfo: Path) -> dict[str, Any]:
    image_path = model_root / "VOG-L29C185.bin"
    manifest_path = model_root / "VOG-L29C185.bin.manifest.json"
    stage: dict[str, Any] = {
        "id": "target_identity",
        "status": "BLOCKED",
        "image": str(image_path),
        "image_present": image_path.is_file(),
        "manifest": str(manifest_path),
        "manifest_present": manifest_path.is_file(),
        "board_oeminfo": str(board_oeminfo),
        "board_oeminfo_present": board_oeminfo.is_file(),
        "board_oeminfo_identity": "Factory board template only; target identity is generated separately.",
        "required": [
            "verified VOG-L29 C185 OEMINFO image built from exact package metadata",
            "live OEMINFO partition target resolved from the P30 Pro",
            "full 96 MiB post-write hash and VOG-L29 hw/meafnaf readback",
        ],
    }
    if not (image_path.is_file() and manifest_path.is_file() and board_oeminfo.is_file()):
        return stage
    try:
        verification = verify_vog_l29_c185_oeminfo(image_path, board_oeminfo)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("schema") != OEMINFO_SCHEMA or manifest.get("status") != "VERIFIED":
            raise HuaweiBoardError(f"Invalid OEMINFO manifest schema or status: {manifest_path}")
        output = manifest.get("output", {})
        if output.get("size") != verification["image_size"] or output.get("sha256") != verification["image_sha256"]:
            raise HuaweiBoardError(f"OEMINFO manifest does not match the generated image: {manifest_path}")
    except (OSError, json.JSONDecodeError, OeminfoError, HuaweiBoardError) as exc:
        stage["status"] = "INVALID"
        stage["error"] = str(exc)
        return stage
    stage["status"] = "PREPARED"
    stage["verification"] = verification
    stage["remaining_live_gates"] = stage["required"][1:]
    return stage


def _target_recovery_stage(model_root: Path) -> dict[str, Any]:
    revive_root = model_root.parent.parent
    image_path = revive_root / "tools" / "recovery" / "VOG-L29-C185-10.0.0.186-root-adb-recovery.img"
    manifest_path = image_path.with_suffix(".json")
    stage: dict[str, Any] = {
        "id": "target_recovery_bridge",
        "status": "INCOMPLETE",
        "image": str(image_path),
        "image_present": image_path.is_file(),
        "manifest": str(manifest_path),
        "manifest_present": manifest_path.is_file(),
        "purpose": "Temporary target-based root ADB access for an OEMINFO backup, write, and full readback.",
        "normal_boot_allowed": False,
    }
    if not (image_path.is_file() and manifest_path.is_file()):
        return stage
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        digest = _sha256(image_path).casefold()
        if (
            manifest.get("schema") != "xray.huawei.debug-recovery.v1"
            or manifest.get("partition_size") != image_path.stat().st_size
            or str(manifest.get("output_sha256", "")).casefold() != digest
        ):
            raise HuaweiBoardError(f"Temporary recovery manifest does not match its image: {manifest_path}")
    except (OSError, json.JSONDecodeError, HuaweiBoardError) as exc:
        stage["status"] = "INVALID"
        stage["error"] = str(exc)
        return stage
    stage["status"] = "PREPARED"
    stage["sha256"] = digest
    stage["size"] = image_path.stat().st_size
    return stage


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
        matches = sorted(
            (path for path in dload_root.glob(pattern) if path.is_file()),
            key=lambda path: str(path).casefold(),
        )
        results.append(
            {
                "pattern": pattern,
                "present": bool(matches),
                "paths": [str(path) for path in matches],
                "size": sum(path.stat().st_size for path in matches),
            }
        )
    return results


def _target_update_app_inventory(dload_root: Path) -> dict[str, Any]:
    paths = {
        "base": dload_root / "update_sd_base" / "UPDATE.APP",
        "cust": dload_root / "update_sd_cust_VOG-L29_hw_meafnaf" / "UPDATE.APP",
        "preload": dload_root / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "UPDATE.APP",
    }
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        return {
            "status": "NOT_EXTRACTED",
            "reason": (
                "The signed three-part archives are present; internal UPDATE.APP inventory is "
                "optional until preparation."
            ),
            "missing": missing,
            "packages": [],
        }

    packages: list[dict[str, Any]] = []
    try:
        for role, path in paths.items():
            entries = parse_update_app(path)
            names = tuple(entry.name for entry in entries)
            expected = EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES[role]
            if names != expected:
                raise HuaweiBoardError(
                    f"Unexpected {role} UPDATE.APP entry order: found {names!r}; expected {expected!r}"
                )
            packages.append(
                {
                    "role": role,
                    "path": str(path),
                    "size": path.stat().st_size,
                    "entry_count": len(entries),
                    "entries": [entry.to_dict() for entry in entries],
                    "structure": "VERIFIED",
                }
            )
    except (OSError, UpdateAppError, HuaweiBoardError) as exc:
        return {"status": "INVALID", "error": str(exc), "missing": [], "packages": packages}
    return {
        "status": "VERIFIED",
        "missing": [],
        "packages": packages,
        "total_entries": sum(item["entry_count"] for item in packages),
        "target_install_order": ["base", "cust", "preload"],
    }


def _target_package_proof(model_root: Path, target_root: Path) -> dict[str, Any]:
    proof_path = model_root.parent.parent / "plans" / "p30-pro-package-proof.json"
    stage: dict[str, Any] = {
        "status": "NOT_RUN",
        "path": str(proof_path),
        "present": proof_path.is_file(),
    }
    if not proof_path.is_file():
        return stage
    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
        if (
            proof.get("schema") != "xray.huawei.package-proof.v1"
            or proof.get("status") != "VERIFIED"
            or proof.get("profile") != "huawei-p30-pro-vog-l29-c185"
            or proof.get("total_update_app_entries") != 63
            or Path(str(proof.get("package_root", ""))).resolve() != target_root.resolve()
        ):
            raise HuaweiBoardError(f"Package proof metadata does not match the P30 target: {proof_path}")
        roles = [item.get("role") for item in proof.get("packages", [])]
        if roles != ["base", "cust", "preload"]:
            raise HuaweiBoardError(f"Package proof has the wrong install order: {roles!r}")
        for item in proof["packages"]:
            for key in ("archive", "update_app"):
                artifact = item.get(key, {})
                path = Path(str(artifact.get("path", "")))
                if not path.is_file() or path.stat().st_size != artifact.get("size"):
                    raise HuaweiBoardError(f"Package proof artifact is missing or changed size: {path}")
    except (OSError, json.JSONDecodeError, HuaweiBoardError) as exc:
        stage["status"] = "INVALID"
        stage["error"] = str(exc)
        return stage
    stage["status"] = "VERIFIED"
    stage["package_count"] = proof["package_count"]
    stage["total_update_app_entries"] = proof["total_update_app_entries"]
    stage["packages"] = [
        {
            "role": item["role"],
            "archive_sha256": item["archive"]["sha256"],
            "update_app_sha256": item["update_app"]["sha256"],
        }
        for item in proof["packages"]
    ]
    return stage


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
