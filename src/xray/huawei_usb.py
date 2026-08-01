from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol, Sequence


ACK = b"\xaa"
BAUD_RATE = 115200
MAX_CHUNK_SIZE = 0x400


def _build_crc_table() -> tuple[int, ...]:
    table = []
    for value in range(256):
        crc = value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
        table.append(crc)
    return tuple(table)


_CRC_TABLE = _build_crc_table()


class HuaweiUsbError(RuntimeError):
    """Raised when a Huawei USB-loader transfer cannot be completed safely."""


class SerialPort(Protocol):
    def write(self, data: bytes) -> int: ...

    def read(self, size: int = 1) -> bytes: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class PortInfo(Protocol):
    device: str
    description: str
    hwid: str
    vid: int | None
    pid: int | None


@dataclass(frozen=True)
class UsbLoaderImage:
    path: Path
    address: int


ProgressCallback = Callable[[UsbLoaderImage, int, int], None]
SerialFactory = Callable[..., SerialPort]
PortsFactory = Callable[[], Sequence[PortInfo]]


def hisi_crc16(data: bytes) -> int:
    """Return the HiSilicon USB-loader CRC-16 value for one frame."""

    crc = 0
    for octet in data + b"\x00\x00":
        crc = (((crc << 8) | octet) ^ _CRC_TABLE[(crc >> 8) & 0xFF]) & 0xFFFF
    return crc


def frame_with_crc(payload: bytes) -> bytes:
    return payload + struct.pack(">H", hisi_crc16(payload))


def parse_image_spec(value: str) -> UsbLoaderImage:
    """Parse ADDRESS=PATH without guessing a device-specific load address."""

    address_text, separator, path_text = value.partition("=")
    if not separator or not address_text or not path_text:
        raise HuaweiUsbError(f"Invalid image specification {value!r}; expected ADDRESS=PATH")
    try:
        address = int(address_text, 0)
    except ValueError as exc:
        raise HuaweiUsbError(f"Invalid image address {address_text!r}") from exc
    if not 0 <= address <= 0xFFFFFFFF:
        raise HuaweiUsbError(f"Image address is outside the 32-bit range: {address_text}")
    return UsbLoaderImage(path=Path(path_text), address=address)


def wait_for_huawei_usb_port(
    timeout: float,
    *,
    poll_interval: float = 0.1,
    ports_factory: PortsFactory | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> str:
    """Wait for Huawei's short-lived USB COM loader interface."""

    if timeout <= 0:
        raise HuaweiUsbError("Huawei USB wait timeout must be greater than zero")
    if ports_factory is None:
        try:
            from serial.tools import list_ports
        except ImportError as exc:
            raise HuaweiUsbError('Huawei USB loading requires pyserial; install ".[huawei-usb]"') from exc
        ports_factory = list_ports.comports

    deadline = monotonic() + timeout
    last_ports: list[str] = []
    while True:
        ports = list(ports_factory())
        last_ports = [str(port.device) for port in ports]
        exact = [
            port
            for port in ports
            if "HUAWEI USB COM" in f"{port.description} {port.hwid}".upper()
        ]
        candidates = exact or [
            port
            for port in ports
            if port.vid == 0x12D1 and "COM" in str(port.device).upper()
        ]
        if len(candidates) == 1:
            return str(candidates[0].device)
        if len(candidates) > 1:
            names = ", ".join(str(port.device) for port in candidates)
            raise HuaweiUsbError(f"Multiple Huawei USB COM ports detected: {names}")
        if monotonic() >= deadline:
            visible = ", ".join(last_ports) if last_ports else "none"
            raise HuaweiUsbError(f"Huawei USB COM mode did not appear within {timeout:g}s; visible ports: {visible}")
        sleep(poll_interval)


class HuaweiUsbLoader:
    """Transfer signed loaders to Huawei's HiSilicon USB boot interface."""

    def __init__(self, serial_port: SerialPort, *, progress: ProgressCallback | None = None):
        self._serial = serial_port
        self._progress = progress

    def _send_frame(self, payload: bytes, *, description: str) -> None:
        frame = frame_with_crc(payload)
        written = self._serial.write(frame)
        if written != len(frame):
            raise HuaweiUsbError(f"Short write during {description}: wrote {written} of {len(frame)} bytes")
        self._serial.flush()
        acknowledgement = self._serial.read(1)
        if acknowledgement != ACK:
            received = acknowledgement.hex().upper() if acknowledgement else "no response"
            raise HuaweiUsbError(f"Loader rejected {description}: expected AA, received {received}")

    def send_image(self, image: UsbLoaderImage) -> dict[str, int | str]:
        try:
            size = image.path.stat().st_size
        except OSError as exc:
            raise HuaweiUsbError(f"Cannot read loader image {image.path}: {exc}") from exc
        if size <= 0 or size > 0xFFFFFFFF:
            raise HuaweiUsbError(f"Invalid loader image size for {image.path}: {size}")

        header = b"\xfe\x00\xff\x01" + struct.pack(">II", size, image.address)
        self._send_frame(header, description=f"{image.path.name} header")

        transferred = 0
        sequence = 1
        try:
            with image.path.open("rb") as source:
                while chunk := source.read(MAX_CHUNK_SIZE):
                    sequence_byte = sequence & 0xFF
                    payload = bytes((0xDA, sequence_byte, sequence_byte ^ 0xFF)) + chunk
                    self._send_frame(payload, description=f"{image.path.name} data frame {sequence}")
                    transferred += len(chunk)
                    if self._progress:
                        self._progress(image, transferred, size)
                    sequence += 1
        except OSError as exc:
            raise HuaweiUsbError(f"Cannot stream loader image {image.path}: {exc}") from exc

        tail_sequence = sequence & 0xFF
        self._send_frame(
            bytes((0xED, tail_sequence, tail_sequence ^ 0xFF)),
            description=f"{image.path.name} tail",
        )
        return {"path": str(image.path), "address": image.address, "size": size, "frames": sequence - 1}

    def send_images(self, images: Sequence[UsbLoaderImage]) -> list[dict[str, int | str]]:
        if not images:
            raise HuaweiUsbError("At least one loader image is required")
        return [self.send_image(image) for image in images]


def load_huawei_bootloader(
    port: str,
    images: Sequence[UsbLoaderImage],
    *,
    progress: ProgressCallback | None = None,
    serial_factory: SerialFactory | None = None,
) -> list[dict[str, int | str]]:
    """Open one Huawei USB interface and transfer all images in order."""

    if serial_factory is None:
        try:
            import serial
        except ImportError as exc:
            raise HuaweiUsbError('Huawei USB loading requires pyserial; install ".[huawei-usb]"') from exc
        serial_factory = serial.Serial

    try:
        serial_port = serial_factory(
            port=port,
            baudrate=BAUD_RATE,
            timeout=10,
            write_timeout=30,
            dsrdtr=False,
            rtscts=False,
        )
    except Exception as exc:
        raise HuaweiUsbError(f"Cannot open Huawei USB loader port {port}: {exc}") from exc

    try:
        if hasattr(serial_port, "dtr"):
            serial_port.dtr = True
        if hasattr(serial_port, "rts"):
            serial_port.rts = True
        return HuaweiUsbLoader(serial_port, progress=progress).send_images(images)
    finally:
        serial_port.close()
