from __future__ import annotations

import json
import platform
import re
import threading
from dataclasses import replace
from pathlib import Path
from collections.abc import Callable, Sequence
from typing import Protocol

from .live_models import CommandResult, DeviceDescriptor, DeviceEvent, EventKind

_PROTOCOL_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class SnapshotSource(Protocol):
    """Provider of current USB/PnP endpoint snapshots."""

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Return current connected endpoints."""


class CommandRunner(Protocol):
    """Shell-free command runner used by host snapshot sources."""

    def run(self, argv: Sequence[str], *, timeout: int = 15) -> CommandResult:
        """Run one fixed command."""


def _infer_mode(text: str, vid: str | None, pid: str | None) -> str | None:
    upper = text.upper()
    if vid == "05AC" and pid == "1227":
        return "DFU"
    if vid == "05AC" and pid == "1281":
        return "RECOVERY"
    markers = [
        ("FASTBOOT", "FASTBOOT"),
        ("BOOTLOADER INTERFACE", "FASTBOOT"),
        ("DFU", "DFU"),
        ("RECOVERY", "RECOVERY"),
        ("DOWNLOAD MODE", "DOWNLOAD"),
        ("BROM", "BROM"),
        ("PRELOADER", "PRELOADER"),
        ("ADB", "ADB"),
        ("MTP", "MTP"),
    ]
    return next((mode for marker, mode in markers if marker in upper), None)


class StaticSnapshotSource:
    """Deterministic snapshot source used for simulation and tests."""

    def __init__(self, snapshots: Sequence[Sequence[DeviceDescriptor]]) -> None:
        self._snapshots = [tuple(item) for item in snapshots]
        self._index = 0

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Snapshot."""
        if not self._snapshots:
            return ()
        index = min(self._index, len(self._snapshots) - 1)
        result = self._snapshots[index]
        self._index += 1
        return result


class PollingDeviceWatcher:
    """Cross-platform snapshot-diff USB/PnP event watcher."""

    def __init__(self, source: SnapshotSource, *, emit_present: bool = False) -> None:
        self.source = source
        self.emit_present = emit_present
        self._previous: dict[str, DeviceDescriptor] = {}

    def poll_once(self) -> tuple[DeviceEvent, ...]:
        """Poll once and return normalized connect/disconnect/change events."""

        current_descriptors = tuple(self.source.snapshot())
        deduplicated: dict[str, DeviceDescriptor] = {}
        for descriptor in current_descriptors:
            if descriptor.slot_key in deduplicated:
                # Snapshot providers can transiently report duplicate interfaces for one USB slot.
                # Retain the first deterministic descriptor and keep the watcher alive.
                continue
            deduplicated[descriptor.slot_key] = descriptor
        apple_recovery_count = sum(
            1
            for item in deduplicated.values()
            if item.vid == "05AC" and item.pid in {"1227", "1281"}
        )
        current: dict[str, DeviceDescriptor] = {}
        for slot, descriptor in deduplicated.items():
            if descriptor.vid == "05AC" and descriptor.pid in {"1227", "1281"}:
                metadata = dict(descriptor.metadata)
                metadata.setdefault("apple_recovery_device_count", apple_recovery_count)
                descriptor = replace(descriptor, metadata=metadata)
            current[slot] = descriptor

        events: list[DeviceEvent] = []
        for slot, descriptor in current.items():
            previous = self._previous.get(slot)
            if previous is None:
                events.append(DeviceEvent(EventKind.CONNECTED, descriptor))
                continue
            if previous.fingerprint == descriptor.fingerprint:
                if self.emit_present:
                    events.append(DeviceEvent(EventKind.PRESENT, descriptor, previous=previous))
                continue
            mode_changed = (
                previous.mode != descriptor.mode
                or previous.vid != descriptor.vid
                or previous.pid != descriptor.pid
            )
            events.append(
                DeviceEvent(
                    EventKind.MODE_TRANSITION if mode_changed else EventKind.CHANGED,
                    descriptor,
                    previous=previous,
                )
            )

        for slot, previous in self._previous.items():
            if slot not in current:
                events.append(DeviceEvent(EventKind.DISCONNECTED, previous, previous=previous))

        self._previous = current
        return tuple(sorted(events, key=lambda item: (item.descriptor.slot_key, item.kind.value)))

    def run(
        self,
        callback: Callable[[DeviceEvent], None],
        *,
        interval: float = 1.0,
        stop_event: threading.Event | None = None,
    ) -> None:
        """Run until stop_event is set, delivering events synchronously."""

        if interval <= 0:
            raise ValueError("interval must be positive")
        stopper = stop_event or threading.Event()
        while not stopper.is_set():
            for event in self.poll_once():
                callback(event)
            stopper.wait(interval)


class WindowsPnpSnapshotSource:
    """Windows USB/PnP snapshot source using built-in PowerShell only."""

    _SCRIPT = r"""
$items = Get-CimInstance Win32_PnPEntity | Where-Object {
  $_.PNPDeviceID -match '^USB\\' -or $_.PNPClass -in @('Ports','WPD','USB')
} | ForEach-Object {
  [PSCustomObject]@{
    InstanceId   = $_.PNPDeviceID
    FriendlyName = $_.Name
    Manufacturer = $_.Manufacturer
    Class        = $_.PNPClass
    Location     = $_.LocationInformation
    ContainerId  = $_.ContainerID
    Status       = $_.Status
  }
}
$items | ConvertTo-Json -Depth 4 -Compress
""".strip()

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @staticmethod
    def parse(payload: str) -> tuple[DeviceDescriptor, ...]:
        """Parse PowerShell JSON into normalized descriptors."""

        if not payload.strip():
            return ()
        raw = json.loads(payload)
        items = raw if isinstance(raw, list) else [raw]
        output: list[DeviceDescriptor] = []
        for item in items:
            instance = str(item.get("InstanceId") or "").strip()
            if not instance:
                continue
            match = re.search(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", instance)
            vid = match.group(1) if match else None
            pid = match.group(2) if match else None
            friendly = str(item.get("FriendlyName") or "")
            if "ROOT HUB" in friendly.upper() or "GENERIC USB HUB" in friendly.upper():
                continue
            location = str(item.get("Location") or "").strip() or None
            container_id = str(item.get("ContainerId") or "").strip() or None
            tail = instance.rsplit("\\", 1)[-1].strip() if "\\" in instance else ""
            serial = tail if tail and "&" not in tail and _PROTOCOL_SERIAL.fullmatch(tail) else None
            mode = _infer_mode(friendly, vid.upper() if vid else None, pid.upper() if pid else None)
            protocol_metadata = {}
            if serial and mode == "ADB":
                protocol_metadata["adb_serial"] = serial
            if serial and mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"}:
                protocol_metadata["fastboot_serial"] = serial
            output.append(
                DeviceDescriptor(
                    source="windows-pnp",
                    os_path=instance,
                    topology_path=location or container_id or instance,
                    vid=vid,
                    pid=pid,
                    serial=serial,
                    mode=mode,
                    manufacturer=str(item.get("Manufacturer") or "") or None,
                    product=friendly or None,
                    interface_class=str(item.get("Class") or "") or None,
                    metadata={
                        "container_id": container_id,
                        "status": item.get("Status"),
                        **protocol_metadata,
                    },
                )
            )
        return tuple(output)

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Snapshot."""
        result = self.runner.run(
            ("powershell", "-NoProfile", "-NonInteractive", "-Command", self._SCRIPT),
            timeout=20,
        )
        if not result.available or result.timed_out or result.returncode != 0:
            return ()
        return self.parse(result.stdout)


class LinuxSysfsSnapshotSource:
    """Linux USB snapshot source using stable sysfs port topology with lsusb fallback."""

    def __init__(self, runner: CommandRunner, *, root: str | Path = "/sys/bus/usb/devices") -> None:
        self.runner = runner
        self.root = Path(root)

    @staticmethod
    def _read(path: Path) -> str | None:
        try:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return None
        return value or None

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Snapshot."""
        if not self.root.is_dir():
            return LinuxUsbSnapshotSource(self.runner).snapshot()
        output: list[DeviceDescriptor] = []
        for device in sorted(self.root.iterdir(), key=lambda item: item.name):
            if device.name.startswith("usb"):
                continue
            vid = self._read(device / "idVendor")
            pid = self._read(device / "idProduct")
            if not vid or not pid:
                continue
            serial = self._read(device / "serial")
            product = self._read(device / "product")
            manufacturer = self._read(device / "manufacturer")
            interface_class = self._read(device / "bDeviceClass")
            mode = _infer_mode(" ".join(filter(None, (product, manufacturer))), vid.upper(), pid.upper())
            metadata: dict[str, str] = {"sysfs_name": device.name}
            if serial and mode == "ADB":
                metadata["adb_serial"] = serial
            if serial and mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"}:
                metadata["fastboot_serial"] = serial
            output.append(
                DeviceDescriptor(
                    source="linux-sysfs",
                    os_path=str(device),
                    topology_path=device.name,
                    vid=vid,
                    pid=pid,
                    serial=serial,
                    mode=mode,
                    manufacturer=manufacturer,
                    product=product,
                    interface_class=interface_class,
                    metadata=metadata,
                )
            )
        return tuple(output)


class LinuxUsbSnapshotSource:
    """Linux USB fallback snapshot source using lsusb."""

    _LINE = re.compile(
        r"^Bus\s+(?P<bus>\d+)\s+Device\s+(?P<device>\d+):\s+ID\s+"
        r"(?P<vid>[0-9A-Fa-f]{4}):(?P<pid>[0-9A-Fa-f]{4})\s*(?P<name>.*)$"
    )

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @classmethod
    def parse(cls, payload: str) -> tuple[DeviceDescriptor, ...]:
        """Parse."""
        output: list[DeviceDescriptor] = []
        for line in payload.splitlines():
            match = cls._LINE.match(line.strip())
            if not match:
                continue
            vid = match.group("vid")
            pid = match.group("pid")
            name = match.group("name").strip()
            bus = match.group("bus")
            device = match.group("device")
            output.append(
                DeviceDescriptor(
                    source="linux-lsusb",
                    os_path=f"usb://bus/{bus}/device/{device}",
                    topology_path=f"bus-{bus}-device-{device}",
                    vid=vid,
                    pid=pid,
                    mode=_infer_mode(name, vid.upper(), pid.upper()),
                    product=name or None,
                    metadata={"topology_quality": "weak-bus-device"},
                )
            )
        return tuple(output)

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Snapshot."""
        result = self.runner.run(("lsusb",), timeout=10)
        if not result.available or result.timed_out or result.returncode != 0:
            return ()
        return self.parse(result.stdout)


class MacUsbSnapshotSource:
    """macOS USB snapshot source using system_profiler JSON."""

    def __init__(self, runner: CommandRunner) -> None:
        self.runner = runner

    @staticmethod
    def parse(payload: str) -> tuple[DeviceDescriptor, ...]:
        """Parse."""
        if not payload.strip():
            return ()
        root = json.loads(payload)
        output: list[DeviceDescriptor] = []

        def walk(node: object, ancestry: tuple[str, ...] = ()) -> None:
            """Walk."""
            if isinstance(node, list):
                for child in node:
                    walk(child, ancestry)
                return
            if not isinstance(node, dict):
                return
            name = str(node.get("_name") or "USB Device")
            location = str(node.get("location_id") or "").strip()
            vendor = str(node.get("vendor_id") or "")
            product = str(node.get("product_id") or "")
            vid_match = re.search(r"0x([0-9A-Fa-f]{4})", vendor)
            pid_match = re.search(r"0x([0-9A-Fa-f]{4})", product)
            if vid_match or pid_match:
                vid = vid_match.group(1) if vid_match else None
                pid = pid_match.group(1) if pid_match else None
                path = "/".join((*ancestry, name))
                serial = str(node.get("serial_num") or "") or None
                mode = _infer_mode(name, vid.upper() if vid else None, pid.upper() if pid else None)
                metadata = {"location_id": location or None}
                if serial and mode == "ADB":
                    metadata["adb_serial"] = serial
                if serial and mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"}:
                    metadata["fastboot_serial"] = serial
                output.append(
                    DeviceDescriptor(
                        source="macos-system-profiler",
                        os_path=location or path,
                        topology_path=location or path,
                        vid=vid,
                        pid=pid,
                        serial=serial,
                        mode=mode,
                        manufacturer=str(node.get("manufacturer") or "") or None,
                        product=name,
                        metadata=metadata,
                    )
                )
            walk(node.get("_items", []), (*ancestry, name))

        walk(root.get("SPUSBDataType", root))
        return tuple(output)

    def snapshot(self) -> Sequence[DeviceDescriptor]:
        """Snapshot."""
        result = self.runner.run(("system_profiler", "SPUSBDataType", "-json"), timeout=30)
        if not result.available or result.timed_out or result.returncode != 0:
            return ()
        return self.parse(result.stdout)


def platform_snapshot_source(runner: CommandRunner) -> SnapshotSource:
    """Select the built-in host snapshot source for the current platform."""

    system = platform.system().casefold()
    if system == "windows":
        return WindowsPnpSnapshotSource(runner)
    if system == "darwin":
        return MacUsbSnapshotSource(runner)
    return LinuxSysfsSnapshotSource(runner)
