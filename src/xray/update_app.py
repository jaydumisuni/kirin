from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable


UPDATE_APP_SCHEMA = "xray-huawei-update-app-v1"
MAGIC = b"\x55\xAA\x5A\xA5"
PREFIX_SIZE = 92
FIXED_HEADER_SIZE = 98
PROBE_SIZE = 102
COPY_CHUNK_SIZE = 8 * 1024 * 1024


class UpdateAppError(ValueError):
    """Raised when a Huawei UPDATE.APP cannot be parsed or extracted safely."""


@dataclass(frozen=True)
class UpdateAppEntry:
    index: int
    offset: int
    header_size: int
    data_offset: int
    file_size: int
    sequence: int
    hardware_id: str
    file_date: str
    file_time: str
    name: str
    block_size: int
    checksum_offset: int
    checksum_size: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "offset": self.offset,
            "header_size": self.header_size,
            "data_offset": self.data_offset,
            "file_size": self.file_size,
            "sequence": self.sequence,
            "hardware_id": self.hardware_id,
            "file_date": self.file_date,
            "file_time": self.file_time,
            "name": self.name,
            "block_size": self.block_size,
            "checksum_offset": self.checksum_offset,
            "checksum_size": self.checksum_size,
        }


def parse_update_app(path: Path) -> list[UpdateAppEntry]:
    """List UPDATE.APP entries without loading image payloads into memory."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise UpdateAppError(f"Cannot stat UPDATE.APP {path}: {exc}") from exc
    if size < PREFIX_SIZE + PROBE_SIZE:
        raise UpdateAppError(f"UPDATE.APP is too small: {path}")

    entries: list[UpdateAppEntry] = []
    with path.open("rb") as stream:
        if stream.read(PREFIX_SIZE) != bytes(PREFIX_SIZE):
            raise UpdateAppError(f"Invalid UPDATE.APP prefix: {path}")
        offset = PREFIX_SIZE
        while offset + PROBE_SIZE < size:
            stream.seek(offset)
            probe = stream.read(PROBE_SIZE)
            if len(probe) < PROBE_SIZE:
                break
            if probe[:4] != MAGIC:
                offset += 1
                continue
            entry = _parse_entry(probe, len(entries) + 1, offset, size)
            entries.append(entry)
            offset = entry.data_offset + entry.file_size

    if not entries:
        raise UpdateAppError(f"No UPDATE.APP entries found: {path}")
    return entries


def update_app_report(path: Path, names: Iterable[str] = ()) -> dict[str, Any]:
    filters = {name.strip().upper() for name in names if name.strip()}
    entries = parse_update_app(path)
    selected = [entry for entry in entries if not filters or entry.name.upper() in filters]
    return {
        "schema": UPDATE_APP_SCHEMA,
        "path": str(path),
        "size": path.stat().st_size,
        "entry_count": len(entries),
        "selected_count": len(selected),
        "entries": [entry.to_dict() for entry in selected],
    }


def update_app_report_text(report: dict[str, Any]) -> str:
    lines = [
        "Huawei UPDATE.APP",
        f"Path: {report['path']}",
        f"Entries: {report['entry_count']}  Selected: {report['selected_count']}",
    ]
    for entry in report["entries"]:
        lines.append(
            f"{entry['index']:>3}  {entry['name']:<32} {entry['file_size']:>12} bytes  sequence={entry['sequence']}"
        )
    return "\n".join(lines)


def extract_update_app_entry(
    path: Path,
    name: str,
    output: Path,
    *,
    sequence: int | None = None,
) -> dict[str, Any]:
    """Extract one named payload and verify its packaged block checksums."""

    matches = [
        entry
        for entry in parse_update_app(path)
        if entry.name.casefold() == name.casefold() and (sequence is None or entry.sequence == sequence)
    ]
    if len(matches) != 1:
        raise UpdateAppError(
            f"Expected exactly one {name!r} entry in {path}; found {len(matches)}"
        )
    entry = matches[0]
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise UpdateAppError(f"Refusing to overwrite extracted payload: {output}")

    with path.open("rb") as source:
        expected_checksums = _read_checksums(source, entry)
        source.seek(entry.data_offset)
        digest = hashlib.sha256()
        actual_checksums = bytearray()
        remaining = entry.file_size
        with output.open("xb") as destination:
            while remaining:
                block_length = min(entry.block_size or COPY_CHUNK_SIZE, remaining)
                block = _read_exact(source, block_length)
                destination.write(block)
                digest.update(block)
                if entry.block_size:
                    actual_checksums.extend(_huawei_crc16(block))
                remaining -= len(block)

    checksum_verifiable = bool(entry.block_size and entry.checksum_size)
    checksum_valid = actual_checksums == expected_checksums if checksum_verifiable else None
    if checksum_valid is False:
        output.unlink(missing_ok=True)
        raise UpdateAppError(f"Checksum verification failed for {entry.name} from {path}")
    return {
        "schema": "xray-huawei-update-app-extract-v1",
        "source": str(path),
        "output": str(output),
        "entry": entry.to_dict(),
        "sha256": digest.hexdigest().upper(),
        "checksum_verifiable": checksum_verifiable,
        "checksum_valid": checksum_valid,
    }


def write_update_app_report(report: dict[str, Any], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _parse_entry(probe: bytes, index: int, offset: int, total_size: int) -> UpdateAppEntry:
    header_size = struct.unpack_from("<I", probe, 4)[0]
    file_size = struct.unpack_from("<I", probe, 24)[0]
    if header_size < FIXED_HEADER_SIZE or header_size > 64 * 1024 * 1024:
        raise UpdateAppError(f"Invalid entry header size {header_size} at offset {offset}")
    data_offset = offset + header_size
    if data_offset + file_size > total_size:
        raise UpdateAppError(f"Entry at offset {offset} extends past UPDATE.APP end")
    return UpdateAppEntry(
        index=index,
        offset=offset,
        header_size=header_size,
        data_offset=data_offset,
        file_size=file_size,
        sequence=struct.unpack_from("<I", probe, 20)[0],
        hardware_id=_text(probe[12:20]),
        file_date=_text(probe[28:44]),
        file_time=_text(probe[44:60]),
        name=_text(probe[60:92]),
        block_size=struct.unpack_from("<I", probe, 94)[0],
        checksum_offset=offset + FIXED_HEADER_SIZE,
        checksum_size=header_size - FIXED_HEADER_SIZE,
    )


def _read_checksums(source: BinaryIO, entry: UpdateAppEntry) -> bytes:
    source.seek(entry.checksum_offset)
    return _read_exact(source, entry.checksum_size)


def _read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise UpdateAppError(f"Unexpected end of UPDATE.APP while reading {size} bytes")
    return data


def _text(value: bytes) -> str:
    return value.rstrip(b"\x00").decode("utf-8", errors="replace")


def _huawei_crc16(data: bytes) -> bytes:
    value = 0xFFFF
    for byte in data:
        value = _CRC_TABLE[(byte ^ value) & 0xFF] ^ (value >> 8)
    return struct.pack("<H", value ^ 0xFFFF)


def _crc_table() -> tuple[int, ...]:
    table: list[int] = []
    for index in range(256):
        value = 0
        temporary = index
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if (value ^ temporary) & 1 else value >> 1
            temporary >>= 1
        table.append(value)
    return tuple(table)


_CRC_TABLE = _crc_table()
