from __future__ import annotations

import gzip
import struct
from pathlib import Path

import pytest

from xray.android_recovery import (
    AndroidRecoveryError,
    CpioEntry,
    NewcArchive,
    build_debug_recovery,
    parse_android_boot_image,
    parse_newc,
    serialize_newc,
)


def _entry(name: bytes, data: bytes, mode: int = 0o100644, ino: int = 1) -> CpioEntry:
    return CpioEntry(
        magic=b"070701",
        ino=ino,
        mode=mode,
        uid=0,
        gid=0,
        nlink=1,
        mtime=123,
        devmajor=0,
        devminor=0,
        rdevmajor=0,
        rdevminor=0,
        name=name,
        data=data,
    )


def _write_recovery(path: Path) -> bytes:
    archive = NewcArchive(
        entries=(
            _entry(b"prop.default", b"ro.secure=1\nro.adb.secure=1\nro.debuggable=0\npersist.sys.usb.config=none\n"),
            _entry(b"init.rc", b"on boot\n    class_start default\n", ino=2),
            _entry(b"sbin/adbd", b"\x7fELForiginal", mode=0o100750, ino=3),
            _entry(b"bin", b"system/bin", mode=0o120777, ino=4),
            _entry(b"TRAILER!!!", b"", ino=5),
        ),
        tail=b"\x00" * 16,
    )
    cpio = serialize_newc(archive)
    ramdisk = gzip.compress(cpio, compresslevel=6, mtime=0)
    image = bytearray(16384)
    image[:8] = b"ANDROID!"
    struct.pack_into("<I", image, 12, 0x10008000)
    struct.pack_into("<I", image, 16, len(ramdisk))
    struct.pack_into("<I", image, 20, 0x11000000)
    struct.pack_into("<I", image, 28, 0x10F00000)
    struct.pack_into("<I", image, 32, 0x10000100)
    struct.pack_into("<I", image, 36, 2048)
    image[2048 : 2048 + len(ramdisk)] = ramdisk
    path.write_bytes(image)
    return bytes(image)


def test_newc_round_trip_preserves_records_and_tail():
    archive = NewcArchive(
        entries=(
            _entry(b"file", b"payload"),
            _entry(b"link", b"file", mode=0o120777, ino=2),
            _entry(b"TRAILER!!!", b"", ino=3),
        ),
        tail=b"\x00" * 12,
    )

    encoded = serialize_newc(archive)
    decoded = parse_newc(encoded)

    assert decoded == archive
    assert serialize_newc(decoded) == encoded


def test_build_debug_recovery_preserves_size_and_patches_only_ramdisk_controls(tmp_path: Path):
    source = tmp_path / "RECOVERY_RAMDISK.img"
    original = _write_recovery(source)
    engineering_adbd = tmp_path / "adbd"
    engineering_adbd.write_bytes(b"\x7fELFengineering-static-adbd")
    output = tmp_path / "RECOVERY_RAMDISK.debug.img"
    manifest = tmp_path / "RECOVERY_RAMDISK.debug.json"

    result = build_debug_recovery(source, engineering_adbd, output, manifest=manifest)
    built = parse_android_boot_image(output)
    entries = {entry.name: entry for entry in parse_newc(gzip.decompress(built.ramdisk)).entries}

    assert len(output.read_bytes()) == len(original)
    assert entries[b"sbin/adbd"].data == engineering_adbd.read_bytes()
    assert entries[b"sbin/adbd"].mode == 0o100750
    assert entries[b"bin"].data == b"system/bin"
    assert b"ro.secure=0" in entries[b"prop.default"].data
    assert b"ro.adb.secure=0" in entries[b"prop.default"].data
    assert b"ro.debuggable=1" in entries[b"prop.default"].data
    assert b"persist.sys.usb.config=adb" in entries[b"prop.default"].data
    assert b"# Xray temporary recovery ADB" in entries[b"init.rc"].data
    assert result["partition_size"] == len(original)
    assert result["write_authorized"] is False
    assert manifest.is_file()


def test_build_debug_recovery_refuses_to_overwrite(tmp_path: Path):
    source = tmp_path / "RECOVERY_RAMDISK.img"
    _write_recovery(source)
    engineering_adbd = tmp_path / "adbd"
    engineering_adbd.write_bytes(b"\x7fELFengineering-static-adbd")
    output = tmp_path / "existing.img"
    output.write_bytes(b"existing")

    with pytest.raises(AndroidRecoveryError, match="Refusing to overwrite"):
        build_debug_recovery(source, engineering_adbd, output)
