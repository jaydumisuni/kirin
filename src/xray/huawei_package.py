from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path
from typing import Any, BinaryIO
from zipfile import BadZipFile, ZipFile

from .oeminfo import (
    VOG_L29_C185_BASE_VERSION,
    VOG_L29_C185_CUST_VERSION,
    VOG_L29_C185_PRELOAD_VERSION,
)
from .update_app import UpdateAppError, parse_update_app


HUAWEI_PACKAGE_PROOF_SCHEMA = "xray.huawei.package-proof.v1"

EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES = {
    "base": (
        "SHA256RSA", "CRC", "BASE_VERLIST", "BASE_VER", "PACKAGE_TYPE", "HISIUFS_GPT",
        "XLOADER", "FASTBOOT", "DTS", "DTO", "VECTOR", "FW_LPM3", "HHEE", "VBMETA",
        "TEEOS", "TRUSTFIRMWARE", "SENSORHUB", "FW_HIFI", "KERNEL", "MODEMNVM_UPDATE",
        "MODEMNVM_CUST", "MODEM_DRIVER", "RECOVERY_RAMDISK", "RECOVERY_VENDOR",
        "RECOVERY_VBMETA", "PREAS", "PREAVS", "ERECOVERY_KERNEL", "ERECOVERY_RAMDISK",
        "ERECOVERY_VENDOR", "ERECOVERY_VBMETA", "ENG_VENDOR", "ENG_SYSTEM", "HDCP",
        "CACHE", "RAMDISK", "SUPER", "SUPER", "VBMETA_SYSTEM", "VBMETA_VENDOR",
        "VBMETA_ODM", "VBMETA_HW_PRODUCT", "VBMETA_CUST", "ISP_FIRMWARE", "MODEM_FW",
        "HISEE_IMG", "PATCH", "USERDATA", "UFSFW",
    ),
    "cust": ("SHA256RSA", "CRC", "CUST_VERLIST", "CUST_VER", "PACKAGE_TYPE", "PTABLE_CUST", "VERSION"),
    "preload": (
        "SHA256RSA", "CRC", "PRELOAD_VERLIST", "PRELOAD_VER", "PACKAGE_TYPE",
        "PTABLE_PRELOAD", "PRELOAD",
    ),
}

_PACKAGE_LAYOUT = {
    "base": {
        "archive": "update_sd_base.zip",
        "directory": "update_sd_base",
        "metadata": ("SOFTWARE_VER_LIST.mbn",),
    },
    "cust": {
        "archive": "update_sd_cust_VOG-L29_hw_meafnaf.zip",
        "directory": "update_sd_cust_VOG-L29_hw_meafnaf",
        "metadata": ("SOFTWARE_VER_LIST.mbn", "PTABLE_CUST.mbn"),
    },
    "preload": {
        "archive": "update_sd_preload_VOG-L29_hw_meafnaf_R5.zip",
        "directory": "update_sd_preload_VOG-L29_hw_meafnaf_R5",
        "metadata": ("SOFTWARE_VER_LIST.mbn", "PTABLE_PRELOAD.mbn"),
    },
}


class HuaweiPackageError(ValueError):
    """Raised when a Huawei target package fails offline verification."""


def _dload_root(package_root: Path) -> Path:
    nested = package_root / "Software" / "dload"
    return nested if nested.is_dir() else package_root


def _hash_stream(stream: BinaryIO) -> tuple[str, int, int]:
    digest = hashlib.sha256()
    crc32 = 0
    size = 0
    for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
        digest.update(chunk)
        crc32 = zlib.crc32(chunk, crc32)
        size += len(chunk)
    return digest.hexdigest(), crc32 & 0xFFFFFFFF, size


def _hash_file(path: Path) -> tuple[str, int, int]:
    with path.open("rb") as stream:
        return _hash_stream(stream)


def _require_version_evidence(dload_root: Path, package_root: Path) -> dict[str, Any]:
    files = {
        "base_version": package_root / "revive-extracted" / "metadata" / "BASE_VER.mbn",
        "cust_version": package_root / "revive-extracted" / "metadata" / "CUST_VER.mbn",
        "preload_version": package_root / "revive-extracted" / "metadata" / "PRELOAD_VER.mbn",
        "base_version_list": dload_root / "update_sd_base" / "SOFTWARE_VER_LIST.mbn",
        "cust_version_list": dload_root / "update_sd_cust_VOG-L29_hw_meafnaf" / "SOFTWARE_VER_LIST.mbn",
        "preload_version_list": dload_root / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "SOFTWARE_VER_LIST.mbn",
    }
    missing = [str(path) for path in files.values() if not path.is_file()]
    if missing:
        raise HuaweiPackageError(f"Missing target version evidence: {', '.join(missing)}")
    exact = {
        "base_version": VOG_L29_C185_BASE_VERSION,
        "cust_version": VOG_L29_C185_CUST_VERSION,
        "preload_version": VOG_L29_C185_PRELOAD_VERSION,
    }
    for label, expected in exact.items():
        try:
            value = files[label].read_bytes().decode("ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise HuaweiPackageError(f"Cannot read {label}: {exc}") from exc
        if value != expected:
            raise HuaweiPackageError(f"Unexpected {label}: {value!r}; expected {expected!r}")

    list_expectations = {
        "base_version_list": VOG_L29_C185_BASE_VERSION,
        "cust_version_list": VOG_L29_C185_CUST_VERSION,
        "preload_version_list": VOG_L29_C185_PRELOAD_VERSION,
    }
    result: dict[str, Any] = {}
    for label, expected in list_expectations.items():
        path = files[label]
        try:
            lines = path.read_text(encoding="ascii").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise HuaweiPackageError(f"Cannot read {label}: {exc}") from exc
        if expected not in lines:
            raise HuaweiPackageError(f"{path} does not contain exact target value {expected!r}")
        result[label] = {"path": str(path.resolve()), "target_line": expected}
    for label, expected in exact.items():
        path = files[label]
        result[label] = {"path": str(path.resolve()), "value": expected}
    return result


def verify_vog_l29_c185_package(package_root: Path) -> dict[str, Any]:
    """Fully verify matched VOG-L29 C185 archives and extracted UPDATE.APP files."""

    dload_root = _dload_root(package_root)
    version_evidence = _require_version_evidence(dload_root, package_root)
    packages: list[dict[str, Any]] = []
    try:
        for role, layout in _PACKAGE_LAYOUT.items():
            archive_path = dload_root / layout["archive"]
            extracted_root = dload_root / layout["directory"]
            update_app_path = extracted_root / "UPDATE.APP"
            if not archive_path.is_file() or not update_app_path.is_file():
                raise HuaweiPackageError(
                    f"Missing {role} archive or extracted UPDATE.APP: {archive_path}, {update_app_path}"
                )

            with ZipFile(archive_path) as archive:
                corrupt_member = archive.testzip()
                if corrupt_member is not None:
                    raise HuaweiPackageError(f"Archive CRC failed for {archive_path}: {corrupt_member}")
                try:
                    packaged_app = archive.getinfo("UPDATE.APP")
                except KeyError as exc:
                    raise HuaweiPackageError(f"Archive has no UPDATE.APP: {archive_path}") from exc
                for metadata_name in layout["metadata"]:
                    extracted_metadata = extracted_root / metadata_name
                    if not extracted_metadata.is_file():
                        raise HuaweiPackageError(f"Missing extracted metadata: {extracted_metadata}")
                    if archive.read(metadata_name) != extracted_metadata.read_bytes():
                        raise HuaweiPackageError(
                            f"Extracted metadata does not match {metadata_name} in {archive_path}"
                        )

            app_sha256, app_crc32, app_size = _hash_file(update_app_path)
            if app_size != packaged_app.file_size or app_crc32 != packaged_app.CRC:
                raise HuaweiPackageError(
                    f"Extracted UPDATE.APP does not match the {role} archive size/CRC: {update_app_path}"
                )
            entries = parse_update_app(update_app_path)
            names = tuple(entry.name for entry in entries)
            expected_names = EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES[role]
            if names != expected_names:
                raise HuaweiPackageError(f"Unexpected {role} UPDATE.APP entries: {names!r}")
            archive_sha256, _, archive_size = _hash_file(archive_path)
            packages.append(
                {
                    "role": role,
                    "archive": {
                        "path": str(archive_path.resolve()),
                        "size": archive_size,
                        "sha256": archive_sha256,
                        "zip_crc_test": "PASS",
                    },
                    "update_app": {
                        "path": str(update_app_path.resolve()),
                        "size": app_size,
                        "sha256": app_sha256,
                        "crc32": f"{app_crc32:08x}",
                        "matches_archive": True,
                    },
                    "entry_count": len(entries),
                    "entries": [entry.to_dict() for entry in entries],
                }
            )
    except (OSError, BadZipFile, UpdateAppError, zlib.error) as exc:
        raise HuaweiPackageError(f"Cannot verify Huawei target package: {exc}") from exc

    return {
        "schema": HUAWEI_PACKAGE_PROOF_SCHEMA,
        "status": "VERIFIED",
        "profile": "huawei-p30-pro-vog-l29-c185",
        "package_root": str(package_root.resolve()),
        "dload_root": str(dload_root.resolve()),
        "version_evidence": version_evidence,
        "packages": packages,
        "package_count": len(packages),
        "total_update_app_entries": sum(item["entry_count"] for item in packages),
        "install_order": ["base", "cust", "preload"],
        "write_authorized": False,
    }


def write_huawei_package_proof(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f"{output.name}.tmp")
    if temporary.exists():
        raise HuaweiPackageError(f"Refusing to overwrite temporary package proof: {temporary}")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
