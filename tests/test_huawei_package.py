from __future__ import annotations

import struct
from pathlib import Path
from zipfile import ZIP_STORED, ZipFile

import pytest

from xray.huawei_package import (
    EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES,
    HuaweiPackageError,
    verify_vog_l29_c185_package,
)
from xray.oeminfo import (
    VOG_L29_C185_BASE_VERSION,
    VOG_L29_C185_CUST_VERSION,
    VOG_L29_C185_PRELOAD_VERSION,
)
from xray.update_app import MAGIC, PREFIX_SIZE, _huawei_crc16


def _write_update_app(path: Path, names: tuple[str, ...]) -> None:
    package = bytearray(PREFIX_SIZE)
    for sequence, name in enumerate(names, start=1):
        data = f"payload-{sequence}-{name}".encode("ascii")
        checksums = b"".join(
            _huawei_crc16(data[offset : offset + 4]) for offset in range(0, len(data), 4)
        )
        header_size = 98 + len(checksums)
        header = bytearray(header_size)
        header[:4] = MAGIC
        struct.pack_into("<I", header, 4, header_size)
        header[12:20] = b"VOGTEST\x00"
        struct.pack_into("<I", header, 20, sequence)
        struct.pack_into("<I", header, 24, len(data))
        encoded_name = name.encode("ascii")
        header[60 : 60 + len(encoded_name)] = encoded_name
        struct.pack_into("<I", header, 94, 4)
        header[98:] = checksums
        package.extend(header)
        package.extend(data)
        package.extend(b"\x00" * ((4 - len(package) % 4) % 4))
    path.write_bytes(package)


def _target_package(tmp_path: Path) -> Path:
    package_root = tmp_path / "VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP"
    metadata = package_root / "revive-extracted" / "metadata"
    metadata.mkdir(parents=True)
    (metadata / "BASE_VER.mbn").write_text(VOG_L29_C185_BASE_VERSION, encoding="ascii")
    (metadata / "CUST_VER.mbn").write_text(VOG_L29_C185_CUST_VERSION, encoding="ascii")
    (metadata / "PRELOAD_VER.mbn").write_text(VOG_L29_C185_PRELOAD_VERSION, encoding="ascii")

    layouts = {
        "base": ("update_sd_base.zip", "update_sd_base", {"SOFTWARE_VER_LIST.mbn": VOG_L29_C185_BASE_VERSION}),
        "cust": (
            "update_sd_cust_VOG-L29_hw_meafnaf.zip",
            "update_sd_cust_VOG-L29_hw_meafnaf",
            {"SOFTWARE_VER_LIST.mbn": VOG_L29_C185_CUST_VERSION, "PTABLE_CUST.mbn": "ptable-cust"},
        ),
        "preload": (
            "update_sd_preload_VOG-L29_hw_meafnaf_R5.zip",
            "update_sd_preload_VOG-L29_hw_meafnaf_R5",
            {"SOFTWARE_VER_LIST.mbn": VOG_L29_C185_PRELOAD_VERSION, "PTABLE_PRELOAD.mbn": "ptable-preload"},
        ),
    }
    for role, (archive_name, directory, files) in layouts.items():
        extracted = package_root / directory
        extracted.mkdir(parents=True)
        update_app = extracted / "UPDATE.APP"
        _write_update_app(update_app, EXPECTED_VOG_L29_C185_UPDATE_APP_ENTRIES[role])
        for name, value in files.items():
            (extracted / name).write_text(value, encoding="ascii")
        with ZipFile(package_root / archive_name, "w", ZIP_STORED) as archive:
            archive.write(update_app, "UPDATE.APP")
            for name in files:
                archive.write(extracted / name, name)
    return package_root


def test_full_target_package_proof_matches_archives_entries_and_versions(tmp_path: Path):
    package_root = _target_package(tmp_path)

    report = verify_vog_l29_c185_package(package_root)

    assert report["status"] == "VERIFIED"
    assert report["package_count"] == 3
    assert report["total_update_app_entries"] == 63
    assert report["install_order"] == ["base", "cust", "preload"]
    assert all(item["archive"]["zip_crc_test"] == "PASS" for item in report["packages"])
    assert all(item["update_app"]["matches_archive"] for item in report["packages"])


def test_target_package_proof_rejects_extracted_update_app_not_in_archive(tmp_path: Path):
    package_root = _target_package(tmp_path)
    update_app = package_root / "update_sd_cust_VOG-L29_hw_meafnaf" / "UPDATE.APP"
    update_app.write_bytes(update_app.read_bytes() + b"changed")

    with pytest.raises(HuaweiPackageError, match="does not match the cust archive"):
        verify_vog_l29_c185_package(package_root)
