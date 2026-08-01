from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


MODEL_SCHEMA = "xray-firmware-model-v1"
CATALOG_SCHEMA = "xray-firmware-catalog-v1"


class FirmwareLibraryError(ValueError):
    """Raised when a firmware library or model definition is invalid."""


def p30_pro_model_document() -> dict[str, Any]:
    """Return the reusable Huawei P30 Pro model and package signature."""

    return {
        "schema": MODEL_SCHEMA,
        "id": "huawei-p30-pro",
        "name": "P30 Pro",
        "manufacturer": "Huawei",
        "variants": ["VOG-L09", "VOG-L29", "VOG-AL00"],
        "profiles": [
            {
                "id": "vog-l29-three-part-dload",
                "name": "VOG-L29 three-part dload",
                "marker": "Software/dload/update_sd_base.zip",
                "package_patterns": [
                    "Software/dload/update_sd_base.zip",
                    "Software/dload/update_sd_cust_VOG-L29_*.zip",
                    "Software/dload/update_sd_preload_VOG-L29_*.zip",
                ],
                "verification_patterns": [
                    "Software/dload/update_sd_base/SOFTWARE_VER_LIST.mbn",
                    "Software/dload/update_sd_cust_VOG-L29_*/SOFTWARE_VER_LIST.mbn",
                    "Software/dload/update_sd_cust_VOG-L29_*/PTABLE_CUST.mbn",
                    "Software/dload/update_sd_preload_VOG-L29_*/SOFTWARE_VER_LIST.mbn",
                    "Software/dload/update_sd_preload_VOG-L29_*/PTABLE_PRELOAD.mbn",
                ],
            }
        ],
    }


def generic_model_document(name: str, manufacturer: str, variants: Iterable[str]) -> dict[str, Any]:
    clean_name = name.strip()
    clean_manufacturer = manufacturer.strip()
    clean_variants = sorted({item.strip() for item in variants if item.strip()})
    if not clean_name:
        raise FirmwareLibraryError("Model name cannot be empty")
    if not clean_manufacturer:
        raise FirmwareLibraryError("Manufacturer cannot be empty")
    return {
        "schema": MODEL_SCHEMA,
        "id": _slug(f"{clean_manufacturer}-{clean_name}"),
        "name": clean_name,
        "manufacturer": clean_manufacturer,
        "variants": clean_variants,
        "profiles": [],
    }


def add_firmware_model(
    library_root: Path,
    folder: str,
    *,
    name: str | None = None,
    manufacturer: str = "Unknown",
    variants: Iterable[str] = (),
    preset: str = "generic",
) -> Path:
    """Create one model folder and its definition without overwriting one."""

    folder = folder.strip()
    if not folder or folder in {".", ".."} or Path(folder).name != folder:
        raise FirmwareLibraryError("Model folder must be one local folder name")
    if preset == "p30-pro":
        document = p30_pro_model_document()
    elif preset == "generic":
        document = generic_model_document(name or "", manufacturer, variants)
    else:
        raise FirmwareLibraryError(f"Unknown model preset: {preset}")

    model_root = library_root / folder
    definition = model_root / "model.json"
    if definition.exists():
        raise FirmwareLibraryError(f"Model already exists: {definition}")
    model_root.mkdir(parents=True, exist_ok=True)
    definition.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return definition


def scan_firmware_library(library_root: Path) -> dict[str, Any]:
    """Discover configured models and firmware packages below a library root."""

    if not library_root.exists():
        raise FirmwareLibraryError(f"Firmware library does not exist: {library_root}")
    if not library_root.is_dir():
        raise FirmwareLibraryError(f"Firmware library is not a directory: {library_root}")

    models = [_scan_model(path) for path in sorted(library_root.iterdir(), key=lambda item: item.name.casefold()) if path.is_dir()]
    status_counts: dict[str, int] = {}
    package_count = 0
    for model in models:
        status_counts[model["status"]] = status_counts.get(model["status"], 0) + 1
        package_count += len(model["packages"])
    return {
        "schema": CATALOG_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "library_root": str(library_root),
        "model_count": len(models),
        "package_count": package_count,
        "status_counts": status_counts,
        "models": models,
    }


def write_firmware_catalog(catalog: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def firmware_catalog_text(catalog: dict[str, Any]) -> str:
    lines = [
        "Huawei Revive firmware library",
        f"Location: {catalog['library_root']}",
        f"Models: {catalog['model_count']}  Packages: {catalog['package_count']}",
    ]
    if not catalog["models"]:
        lines.append("No model folders found.")
        return "\n".join(lines)
    for model in catalog["models"]:
        variants = ", ".join(model["variants"]) or "not specified"
        lines.append("")
        lines.append(f"{model['name']} [{model['status']}]")
        lines.append(f"  Folder: {model['folder']}")
        lines.append(f"  Variants: {variants}")
        if not model["configured"]:
            lines.append("  Add model.json to configure package validation.")
        for package in model["packages"]:
            lines.append(f"  - {package['name']} [{package['status']}]")
            lines.append(f"    Path: {package['path']}")
            if package["missing"]:
                lines.append(f"    Missing: {', '.join(package['missing'])}")
    return "\n".join(lines)


def _scan_model(model_root: Path) -> dict[str, Any]:
    definition_path = model_root / "model.json"
    configured = definition_path.exists()
    if configured:
        definition = _load_model_definition(definition_path)
    else:
        definition = {
            "id": _slug(model_root.name),
            "name": model_root.name,
            "manufacturer": "Unknown",
            "variants": [],
            "profiles": [],
        }

    packages: list[dict[str, Any]] = []
    recognized_roots: set[str] = set()
    for profile in definition["profiles"]:
        for package_root in _find_package_roots(model_root, profile["marker"]):
            packages.append(_scan_profile_package(package_root, profile))
            recognized_roots.add(str(package_root).casefold())

    for item in sorted(model_root.iterdir(), key=lambda candidate: candidate.name.casefold()):
        if item.name == "model.json" or str(item).casefold() in recognized_roots:
            continue
        packages.append(
            {
                "name": item.name,
                "path": str(item),
                "profile": None,
                "status": "UNVERIFIED",
                "size": item.stat().st_size if item.is_file() else None,
                "artifacts": [],
                "missing": [],
            }
        )

    statuses = {item["status"] for item in packages}
    if "READY" in statuses:
        status = "READY"
    elif "NEEDS_EXTRACTION" in statuses:
        status = "NEEDS_EXTRACTION"
    elif "INCOMPLETE" in statuses:
        status = "INCOMPLETE"
    elif packages:
        status = "UNVERIFIED"
    else:
        status = "EMPTY"
    return {
        "id": definition["id"],
        "name": definition["name"],
        "manufacturer": definition["manufacturer"],
        "variants": definition["variants"],
        "folder": model_root.name,
        "path": str(model_root),
        "configured": configured,
        "status": status,
        "packages": packages,
    }


def _load_model_definition(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FirmwareLibraryError(f"Cannot read model definition {path}: {exc}") from exc
    if data.get("schema") != MODEL_SCHEMA:
        raise FirmwareLibraryError(f"Unsupported model definition schema in {path}")
    for key in ("id", "name", "manufacturer", "variants", "profiles"):
        if key not in data:
            raise FirmwareLibraryError(f"Missing {key!r} in {path}")
    for profile in data["profiles"]:
        for key in ("id", "name", "marker", "package_patterns", "verification_patterns"):
            if key not in profile:
                raise FirmwareLibraryError(f"Missing profile {key!r} in {path}")
    return data


def _find_package_roots(model_root: Path, marker: str) -> list[Path]:
    marker_path = Path(marker)
    roots: dict[str, Path] = {}
    for candidate in model_root.rglob(marker_path.name):
        if not candidate.is_file():
            continue
        relative_parts = candidate.relative_to(model_root).parts
        marker_parts = marker_path.parts
        if len(relative_parts) < len(marker_parts):
            continue
        if tuple(part.casefold() for part in relative_parts[-len(marker_parts) :]) != tuple(
            part.casefold() for part in marker_parts
        ):
            continue
        package_root = candidate
        for _ in marker_parts:
            package_root = package_root.parent
        roots[str(package_root).casefold()] = package_root
    return sorted(roots.values(), key=lambda path: str(path).casefold())


def _scan_profile_package(package_root: Path, profile: dict[str, Any]) -> dict[str, Any]:
    package_matches, package_missing = _match_patterns(package_root, profile["package_patterns"])
    verification_matches, verification_missing = _match_patterns(package_root, profile["verification_patterns"])
    if package_missing:
        status = "INCOMPLETE"
    elif verification_missing:
        status = "NEEDS_EXTRACTION"
    else:
        status = "READY"
    artifacts = sorted({str(path) for path in package_matches + verification_matches}, key=str.casefold)
    size = sum(Path(path).stat().st_size for path in artifacts)
    return {
        "name": package_root.name,
        "path": str(package_root),
        "profile": profile["id"],
        "profile_name": profile["name"],
        "status": status,
        "size": size,
        "artifacts": artifacts,
        "missing": package_missing + verification_missing,
    }


def _match_patterns(root: Path, patterns: Iterable[str]) -> tuple[list[Path], list[str]]:
    matches: list[Path] = []
    missing: list[str] = []
    for pattern in patterns:
        found = sorted((item for item in root.glob(pattern) if item.is_file()), key=lambda path: str(path).casefold())
        if found:
            matches.extend(found)
        else:
            missing.append(pattern)
    return matches, missing


def _slug(value: str) -> str:
    slug = "-".join("".join(character.lower() if character.isalnum() else " " for character in value).split())
    return slug or "model"
