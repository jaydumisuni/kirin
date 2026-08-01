from __future__ import annotations

import struct
from pathlib import Path

import pytest

from xray.update_app import (
    MAGIC,
    PREFIX_SIZE,
    UpdateAppError,
    _huawei_crc16,
    extract_update_app_entry,
    parse_update_app,
    update_app_report,
)


def _write_update_app(path: Path, entries: list[tuple[str, bytes]]) -> None:
    package = bytearray(PREFIX_SIZE)
    for sequence, (name, data) in enumerate(entries, start=1):
        block_size = 4
        checksums = b"".join(_huawei_crc16(data[offset : offset + block_size]) for offset in range(0, len(data), block_size))
        header_size = 98 + len(checksums)
        header = bytearray(header_size)
        header[:4] = MAGIC
        struct.pack_into("<I", header, 4, header_size)
        header[12:20] = b"VOGTEST\x00"
        struct.pack_into("<I", header, 20, sequence)
        struct.pack_into("<I", header, 24, len(data))
        header[28:44] = b"2026.08.01\x00\x00\x00\x00\x00\x00"
        header[44:60] = b"12.00.00\x00\x00\x00\x00\x00\x00\x00\x00"
        encoded_name = name.encode("utf-8")
        header[60 : 60 + len(encoded_name)] = encoded_name
        struct.pack_into("<I", header, 94, block_size)
        header[98:] = checksums
        package.extend(header)
        package.extend(data)
        package.extend(b"\x00" * ((4 - len(package) % 4) % 4))
    path.write_bytes(package)


def test_update_app_lists_named_payloads(tmp_path: Path):
    path = tmp_path / "UPDATE.APP"
    _write_update_app(path, [("VERSION", b"version-data"), ("SYSTEM", b"system-data")])

    entries = parse_update_app(path)
    report = update_app_report(path, ["VERSION"])

    assert [entry.name for entry in entries] == ["VERSION", "SYSTEM"]
    assert report["entry_count"] == 2
    assert report["selected_count"] == 1
    assert report["entries"][0]["name"] == "VERSION"


def test_update_app_extracts_one_payload_and_verifies_checksum(tmp_path: Path):
    path = tmp_path / "UPDATE.APP"
    output = tmp_path / "extracted" / "VERSION.img"
    _write_update_app(path, [("VERSION", b"verified-version")])

    result = extract_update_app_entry(path, "VERSION", output)

    assert output.read_bytes() == b"verified-version"
    assert result["checksum_verifiable"] is True
    assert result["checksum_valid"] is True


def test_update_app_refuses_ambiguous_or_existing_outputs(tmp_path: Path):
    path = tmp_path / "UPDATE.APP"
    output = tmp_path / "VERSION.img"
    _write_update_app(path, [("VERSION", b"one"), ("VERSION", b"two")])

    with pytest.raises(UpdateAppError, match="found 2"):
        extract_update_app_entry(path, "VERSION", output)

    output.write_bytes(b"existing")
    with pytest.raises(UpdateAppError, match="Refusing to overwrite"):
        extract_update_app_entry(path, "VERSION", output, sequence=1)


def test_update_app_rejects_invalid_prefix(tmp_path: Path):
    path = tmp_path / "UPDATE.APP"
    path.write_bytes(b"not-an-update-app" * 20)

    with pytest.raises(UpdateAppError, match="Invalid UPDATE.APP prefix"):
        parse_update_app(path)
