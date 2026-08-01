from __future__ import annotations

import gzip
import hashlib
import json
import struct
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable


BOOT_MAGIC = b"ANDROID!"
CPIO_MAGICS = {b"070701", b"070702"}
CPIO_TRAILER = b"TRAILER!!!"
CPIO_HEADER_SIZE = 110


class AndroidRecoveryError(ValueError):
    """Raised when a recovery image cannot be validated or built safely."""


@dataclass(frozen=True)
class CpioEntry:
    magic: bytes
    ino: int
    mode: int
    uid: int
    gid: int
    nlink: int
    mtime: int
    devmajor: int
    devminor: int
    rdevmajor: int
    rdevminor: int
    name: bytes
    data: bytes
    check: int = 0


@dataclass(frozen=True)
class NewcArchive:
    entries: tuple[CpioEntry, ...]
    tail: bytes = b""


@dataclass(frozen=True)
class AndroidBootImage:
    image: bytes
    page_size: int
    kernel_size: int
    ramdisk_size: int
    second_size: int
    dt_size: int
    ramdisk_offset: int
    ramdisk: bytes


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def parse_newc(data: bytes) -> NewcArchive:
    """Parse a newc/CRC cpio archive without discarding Unix metadata."""

    entries: list[CpioEntry] = []
    offset = 0
    while True:
        if offset + CPIO_HEADER_SIZE > len(data):
            raise AndroidRecoveryError("Truncated newc cpio header")
        magic = data[offset : offset + 6]
        if magic not in CPIO_MAGICS:
            raise AndroidRecoveryError(f"Invalid newc cpio magic at offset {offset}")
        try:
            values = [
                int(data[offset + 6 + index * 8 : offset + 14 + index * 8], 16)
                for index in range(13)
            ]
        except ValueError as exc:
            raise AndroidRecoveryError(f"Invalid newc cpio header at offset {offset}") from exc

        (
            ino,
            mode,
            uid,
            gid,
            nlink,
            mtime,
            file_size,
            devmajor,
            devminor,
            rdevmajor,
            rdevminor,
            name_size,
            check,
        ) = values
        if name_size < 1:
            raise AndroidRecoveryError(f"Invalid newc name length at offset {offset}")

        name_start = offset + CPIO_HEADER_SIZE
        name_end = name_start + name_size
        if name_end > len(data) or data[name_end - 1] != 0:
            raise AndroidRecoveryError(f"Invalid newc name at offset {offset}")
        name = data[name_start : name_end - 1]
        payload_start = _align(name_end, 4)
        payload_end = payload_start + file_size
        if payload_end > len(data):
            raise AndroidRecoveryError(f"Truncated newc payload for {name!r}")
        payload = data[payload_start:payload_end]
        offset = _align(payload_end, 4)

        if magic == b"070702" and (sum(payload) & 0xFFFFFFFF) != check:
            raise AndroidRecoveryError(f"Invalid newc checksum for {name!r}")

        entry = CpioEntry(
            magic=magic,
            ino=ino,
            mode=mode,
            uid=uid,
            gid=gid,
            nlink=nlink,
            mtime=mtime,
            devmajor=devmajor,
            devminor=devminor,
            rdevmajor=rdevmajor,
            rdevminor=rdevminor,
            name=name,
            data=payload,
            check=check,
        )
        entries.append(entry)
        if name == CPIO_TRAILER:
            return NewcArchive(entries=tuple(entries), tail=data[offset:])


def serialize_newc(archive: NewcArchive) -> bytes:
    """Serialize a parsed archive while retaining record order and metadata."""

    output = bytearray()
    for entry in archive.entries:
        name = entry.name + b"\x00"
        check = sum(entry.data) & 0xFFFFFFFF if entry.magic == b"070702" else entry.check
        values = (
            entry.ino,
            entry.mode,
            entry.uid,
            entry.gid,
            entry.nlink,
            entry.mtime,
            len(entry.data),
            entry.devmajor,
            entry.devminor,
            entry.rdevmajor,
            entry.rdevminor,
            len(name),
            check,
        )
        output.extend(entry.magic)
        output.extend("".join(f"{value:08x}" for value in values).encode("ascii"))
        output.extend(name)
        output.extend(b"\x00" * ((_align(len(output), 4)) - len(output)))
        output.extend(entry.data)
        output.extend(b"\x00" * ((_align(len(output), 4)) - len(output)))
    output.extend(archive.tail)
    return bytes(output)


def parse_android_boot_image(path: Path) -> AndroidBootImage:
    """Read the classic Android boot image layout used by Huawei ramdisk partitions."""

    image = path.read_bytes()
    if len(image) < 608 or image[:8] != BOOT_MAGIC:
        raise AndroidRecoveryError(f"Not a classic Android boot image: {path}")
    kernel_size = struct.unpack_from("<I", image, 8)[0]
    ramdisk_size = struct.unpack_from("<I", image, 16)[0]
    second_size = struct.unpack_from("<I", image, 24)[0]
    page_size = struct.unpack_from("<I", image, 36)[0]
    dt_size = struct.unpack_from("<I", image, 40)[0]
    if page_size < 512 or page_size & (page_size - 1):
        raise AndroidRecoveryError(f"Invalid Android boot page size: {page_size}")
    ramdisk_offset = page_size + _align(kernel_size, page_size)
    ramdisk_end = ramdisk_offset + ramdisk_size
    if ramdisk_size == 0 or ramdisk_end > len(image):
        raise AndroidRecoveryError("Android boot ramdisk extends beyond the image")
    return AndroidBootImage(
        image=image,
        page_size=page_size,
        kernel_size=kernel_size,
        ramdisk_size=ramdisk_size,
        second_size=second_size,
        dt_size=dt_size,
        ramdisk_offset=ramdisk_offset,
        ramdisk=image[ramdisk_offset:ramdisk_end],
    )


def _replace_property(data: bytes, key: str, value: str) -> bytes:
    text = data.decode("utf-8")
    lines = text.splitlines(keepends=True)
    prefix = f"{key}="
    replaced = False
    for index, line in enumerate(lines):
        line_ending = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
        if line.rstrip("\r\n").startswith(prefix):
            lines[index] = f"{prefix}{value}{line_ending}"
            replaced = True
    if not replaced:
        if lines and not lines[-1].endswith(("\n", "\r\n")):
            lines[-1] += "\n"
        lines.append(f"{prefix}{value}\n")
    return "".join(lines).encode("utf-8")


def _replace_entries(archive: NewcArchive, replacements: dict[bytes, bytes]) -> NewcArchive:
    found: set[bytes] = set()
    entries: list[CpioEntry] = []
    for entry in archive.entries:
        if entry.name in replacements:
            entries.append(replace(entry, data=replacements[entry.name]))
            found.add(entry.name)
        else:
            entries.append(entry)
    missing = set(replacements) - found
    if missing:
        names = ", ".join(sorted(name.decode("utf-8", errors="replace") for name in missing))
        raise AndroidRecoveryError(f"Required ramdisk entries are missing: {names}")
    return replace(archive, entries=tuple(entries))


def _entry_map(entries: Iterable[CpioEntry]) -> dict[bytes, CpioEntry]:
    return {entry.name: entry for entry in entries}


def build_debug_recovery(
    source: Path,
    engineering_adbd: Path,
    output: Path,
    *,
    manifest: Path | None = None,
) -> dict[str, object]:
    """Build a temporary root-ADB recovery without changing target firmware content."""

    if output.exists():
        raise AndroidRecoveryError(f"Refusing to overwrite existing output: {output}")
    if manifest is not None and manifest.exists():
        raise AndroidRecoveryError(f"Refusing to overwrite existing manifest: {manifest}")

    boot = parse_android_boot_image(source)
    if boot.kernel_size or boot.second_size or boot.dt_size:
        raise AndroidRecoveryError("Expected a standalone recovery ramdisk image with no embedded kernel or DT")
    try:
        cpio_data = gzip.decompress(boot.ramdisk)
    except (EOFError, OSError) as exc:
        raise AndroidRecoveryError("Recovery ramdisk is not valid gzip data") from exc
    archive = parse_newc(cpio_data)
    entries = _entry_map(archive.entries)
    required = (b"prop.default", b"init.rc", b"sbin/adbd")
    missing = [name.decode("ascii") for name in required if name not in entries]
    if missing:
        raise AndroidRecoveryError(f"Required recovery entries are missing: {', '.join(missing)}")

    properties = entries[b"prop.default"].data
    for key, value in (
        ("ro.secure", "0"),
        ("ro.adb.secure", "0"),
        ("ro.debuggable", "1"),
        ("persist.sys.usb.config", "adb"),
    ):
        properties = _replace_property(properties, key, value)

    init_rc = entries[b"init.rc"].data
    marker = b"# Xray temporary recovery ADB\n"
    if marker not in init_rc:
        if init_rc and not init_rc.endswith(b"\n"):
            init_rc += b"\n"
        init_rc += (
            b"\n# Xray temporary recovery ADB\n"
            b"on early-boot && property:ro.debuggable=1\n"
            b"    setprop persist.sys.usb.config adb\n"
            b"    setprop sys.usb.config adb\n"
            b"    start adbd\n"
        )

    adbd = engineering_adbd.read_bytes()
    if not adbd.startswith(b"\x7fELF"):
        raise AndroidRecoveryError(f"Engineering ADB binary is not ELF: {engineering_adbd}")

    patched = _replace_entries(
        archive,
        {
            b"prop.default": properties,
            b"init.rc": init_rc,
            b"sbin/adbd": adbd,
        },
    )
    patched_cpio = serialize_newc(patched)
    reparsed = _entry_map(parse_newc(patched_cpio).entries)
    if reparsed[b"sbin/adbd"].data != adbd or b"ro.secure=0" not in reparsed[b"prop.default"].data:
        raise AndroidRecoveryError("Recovery ramdisk verification failed after serialization")

    compressed = gzip.compress(patched_cpio, compresslevel=6, mtime=0)
    capacity = len(boot.image) - boot.ramdisk_offset
    if len(compressed) > capacity:
        raise AndroidRecoveryError(
            f"Patched ramdisk is {len(compressed)} bytes but the partition image has only {capacity} bytes"
        )

    result_image = bytearray(boot.image[: boot.ramdisk_offset])
    result_image.extend(compressed)
    result_image.extend(b"\x00" * (len(boot.image) - len(result_image)))
    struct.pack_into("<I", result_image, 16, len(compressed))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(result_image)

    result: dict[str, object] = {
        "schema": "xray.huawei.debug-recovery.v1",
        "source": str(source.resolve()),
        "source_sha256": hashlib.sha256(boot.image).hexdigest(),
        "engineering_adbd": str(engineering_adbd.resolve()),
        "engineering_adbd_sha256": hashlib.sha256(adbd).hexdigest(),
        "output": str(output.resolve()),
        "output_sha256": hashlib.sha256(result_image).hexdigest(),
        "partition_size": len(result_image),
        "original_ramdisk_size": boot.ramdisk_size,
        "patched_ramdisk_size": len(compressed),
        "changes": [
            "ro.secure=0",
            "ro.adb.secure=0",
            "ro.debuggable=1",
            "persist.sys.usb.config=adb",
            "early-boot adbd start",
            "sbin/adbd replaced with supplied engineering ELF",
        ],
        "boot_id_policy": "preserved from source",
        "write_authorized": False,
    }
    if manifest is not None:
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result
