from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

import pytest

from xray.huawei_usb import (
    START_FRAME,
    HuaweiUsbError,
    HuaweiUsbLoader,
    UsbLoaderImage,
    frame_with_crc,
    hisi_crc16,
    load_huawei_bootloader,
    parse_image_spec,
    wait_for_huawei_usb_port,
)


class FakeSerial:
    def __init__(self, acknowledgements: bytes, *, short_write_at: int | None = None):
        self.acknowledgements = bytearray(acknowledgements)
        self.writes: list[bytes] = []
        self.short_write_at = short_write_at
        self.closed = False
        self.dtr = False
        self.rts = False

    def write(self, data: bytes) -> int:
        self.writes.append(data)
        if self.short_write_at == len(self.writes) - 1:
            return len(data) - 1
        return len(data)

    def read(self, size: int = 1) -> bytes:
        result = bytes(self.acknowledgements[:size])
        del self.acknowledgements[:size]
        return result

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


@dataclass
class FakePort:
    device: str
    description: str
    hwid: str
    vid: int | None
    pid: int | None


def test_hisi_crc_matches_reference_vector():
    assert hisi_crc16(b"123456789") == 0x31C3
    assert frame_with_crc(b"123456789") == b"123456789\x31\xc3"


def test_loader_frames_header_data_and_tail(tmp_path: Path):
    path = tmp_path / "loader.img"
    path.write_bytes(bytes(range(256)) * 5)
    serial = FakeSerial(b"\xaa" * 4)

    result = HuaweiUsbLoader(serial).send_image(UsbLoaderImage(path, 0x1A400000))

    header = b"\xfe\x00\xff\x01" + struct.pack(">II", 1280, 0x1A400000)
    assert serial.writes[0] == frame_with_crc(header)
    assert serial.writes[1][:3] == b"\xda\x01\xfe"
    assert len(serial.writes[1]) == 3 + 0x400 + 2
    assert serial.writes[2][:3] == b"\xda\x02\xfd"
    assert serial.writes[3] == frame_with_crc(b"\xed\x03\xfc")
    assert result["frames"] == 2


def test_loader_stops_on_bad_acknowledgement(tmp_path: Path):
    path = tmp_path / "loader.img"
    path.write_bytes(b"loader")

    with pytest.raises(HuaweiUsbError, match="expected AA, received 55"):
        HuaweiUsbLoader(FakeSerial(b"\x55")).send_image(UsbLoaderImage(path, 0x22000))


def test_load_huawei_bootloader_configures_and_closes_port(tmp_path: Path):
    path = tmp_path / "loader.img"
    path.write_bytes(b"loader")
    serial = FakeSerial(b"\xaa" * 3)
    options = {}

    def factory(**kwargs):
        options.update(kwargs)
        return serial

    load_huawei_bootloader("COM117", [UsbLoaderImage(path, 0x22000)], serial_factory=factory)

    assert options["port"] == "COM117"
    assert options["baudrate"] == 115200
    assert serial.writes[0] == START_FRAME
    assert serial.dtr is True
    assert serial.rts is True
    assert serial.closed is True


def test_loader_stops_on_short_start_handshake(tmp_path: Path):
    path = tmp_path / "loader.img"
    path.write_bytes(b"loader")

    with pytest.raises(HuaweiUsbError, match="Short write during loader start handshake"):
        HuaweiUsbLoader(FakeSerial(b"", short_write_at=0)).send_images(
            [UsbLoaderImage(path, 0x22000)]
        )


def test_parse_image_spec_requires_explicit_address(tmp_path: Path):
    path = tmp_path / "sec_fastboot.img"

    assert parse_image_spec(f"0x1A400000={path}") == UsbLoaderImage(path, 0x1A400000)
    with pytest.raises(HuaweiUsbError, match="expected ADDRESS=PATH"):
        parse_image_spec(str(path))


def test_wait_for_huawei_usb_port_catches_exact_loader_interface():
    snapshots = iter(
        [
            [FakePort("COM3", "Bluetooth", "BTHENUM", None, None)],
            [FakePort("COM117", "HUAWEI USB COM 1.0", "USB VID:PID=12D1:3609", 0x12D1, 0x3609)],
        ]
    )
    ticks = iter([0.0, 0.1, 0.2])

    port = wait_for_huawei_usb_port(
        1,
        ports_factory=lambda: next(snapshots),
        monotonic=lambda: next(ticks),
        sleep=lambda _: None,
    )

    assert port == "COM117"


def test_wait_for_huawei_usb_port_times_out_without_huawei_interface():
    ticks = iter([0.0, 0.5, 1.0])
    visible = [FakePort("COM3", "Bluetooth", "BTHENUM", None, None)]

    with pytest.raises(HuaweiUsbError, match="visible ports: COM3"):
        wait_for_huawei_usb_port(
            1,
            ports_factory=lambda: visible,
            monotonic=lambda: next(ticks),
            sleep=lambda _: None,
        )
