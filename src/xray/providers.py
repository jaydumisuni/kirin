from __future__ import annotations

import abc
import json
import re
import shutil
import subprocess
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from .live_models import (
    Capability,
    CommandResult,
    DeviceDescriptor,
    ProviderManifest,
    ProviderProbeResult,
    RawEvidenceEnvelope,
    canonical_sha256,
    utc_now,
)

_FORBIDDEN_CAPABILITY_TOKENS = ("write", "flash", "erase", "unlock", "relock", "format", "repair")
_SAFE_SERIAL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_ECID = re.compile(r"^(?:0x)?[0-9A-Fa-f]{1,16}$")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class SubprocessRunner:
    """Fixed-argv, shell-free command runner for read-only providers."""

    def run(self, argv: Sequence[str], *, timeout: int = 15) -> CommandResult:
        if not argv:
            raise ValueError("command argv cannot be empty")
        executable = shutil.which(argv[0])
        started = _timestamp()
        start_ns = time.monotonic_ns()
        if executable is None:
            completed = _timestamp()
            return CommandResult(
                tuple(argv),
                None,
                "",
                "executable not found",
                started,
                completed,
                max(0, (time.monotonic_ns() - start_ns) // 1_000_000),
                executable=None,
                available=False,
            )
        resolved = (executable, *tuple(argv[1:]))
        try:
            process = subprocess.run(
                resolved,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
                shell=False,
            )
            return CommandResult(
                resolved,
                process.returncode,
                process.stdout,
                process.stderr,
                started,
                _timestamp(),
                max(0, (time.monotonic_ns() - start_ns) // 1_000_000),
                executable=executable,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return CommandResult(
                resolved,
                None,
                stdout,
                stderr or f"timeout after {timeout}s",
                started,
                _timestamp(),
                max(0, (time.monotonic_ns() - start_ns) // 1_000_000),
                executable=executable,
                timed_out=True,
            )


class SimulatedRunner:
    """Queue-backed deterministic runner used by simulations and tests."""

    def __init__(
        self,
        responses: Mapping[tuple[str, ...], CommandResult | Sequence[CommandResult] | Callable[[Sequence[str]], CommandResult]],
    ) -> None:
        self._responses: dict[tuple[str, ...], deque[CommandResult] | Callable[[Sequence[str]], CommandResult]] = {}
        for key, value in responses.items():
            if callable(value):
                self._responses[tuple(key)] = value
            elif isinstance(value, CommandResult):
                self._responses[tuple(key)] = deque([value])
            else:
                self._responses[tuple(key)] = deque(value)
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout: int = 15) -> CommandResult:
        key = tuple(argv)
        self.calls.append(key)
        response = self._responses.get(key)
        if response is None:
            now = utc_now()
            return CommandResult(key, None, "", "simulated command not configured", now, now, 0, available=False)
        if callable(response):
            return response(argv)
        if not response:
            raise AssertionError(f"simulated response queue exhausted for {key!r}")
        result = response.popleft()
        return replace(result, argv=key)


def simulated_result(
    argv: Sequence[str],
    *,
    stdout: str = "",
    stderr: str = "",
    returncode: int | None = 0,
    available: bool = True,
    duration_ms: int = 1,
) -> CommandResult:
    """Construct one deterministic simulated command result."""

    now = utc_now()
    return CommandResult(
        tuple(argv),
        returncode,
        stdout,
        stderr,
        now,
        now,
        duration_ms,
        executable=argv[0] if available and argv else None,
        available=available,
    )


def _envelope(
    *,
    session_id: str,
    descriptor: DeviceDescriptor,
    manifest: ProviderManifest,
    capability: Capability,
    result: CommandResult,
    observations: Mapping[str, Any],
    sensitive_fields: Sequence[str] = (),
) -> RawEvidenceEnvelope:
    topology = {
        "host_path": descriptor.topology_path,
        "os_path": descriptor.os_path,
        "slot_key": descriptor.slot_key,
        "descriptor": descriptor.to_dict(),
    }
    command = {
        "argv": list(result.argv),
        "returncode": result.returncode,
        "started_at": result.started_at,
        "completed_at": result.completed_at,
        "duration_ms": result.duration_ms,
        "executable": result.executable,
        "timed_out": result.timed_out,
        "available": result.available,
    }
    captured_at = utc_now()
    envelope_id = f"xray-envelope-{uuid.uuid4().hex}"
    provisional = RawEvidenceEnvelope(
        envelope_id=envelope_id,
        schema="xray-raw-evidence-v1",
        session_id=session_id,
        captured_at=captured_at,
        provider=manifest.name,
        provider_version=manifest.version,
        capability=capability.value,
        source="command" if result.argv else "event",
        topology=topology,
        command=command,
        observations=dict(observations),
        sensitive_fields=tuple(sorted(set(sensitive_fields))),
        stdout_sha256=canonical_sha256(result.stdout),
        stderr_sha256=canonical_sha256(result.stderr),
        descriptor_sha256=canonical_sha256(descriptor.to_dict()),
        payload_sha256="",
        raw_stdout=result.stdout,
        raw_stderr=result.stderr,
    )
    return replace(provisional, payload_sha256=canonical_sha256(provisional.unsigned_dict()))


def _validate_serial(value: str | None, kind: str) -> str:
    if not value or not _SAFE_SERIAL.fullmatch(value):
        raise ValueError(f"unsafe or missing {kind} serial")
    return value


def _validate_ecid(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    normalized = value.strip()
    if not _SAFE_ECID.fullmatch(normalized):
        raise ValueError("unsafe Apple ECID")
    return normalized


class DeviceProvider(abc.ABC):
    """Versioned read-only provider interface."""

    manifest: ProviderManifest

    @abc.abstractmethod
    def supports(self, descriptor: DeviceDescriptor) -> bool:
        """Return whether this provider can safely inspect the descriptor."""

    @abc.abstractmethod
    def probe(self, session_id: str, descriptor: DeviceDescriptor, runner: Any) -> ProviderProbeResult:
        """Run read-only probes and return evidence envelopes."""


class ProviderRegistry:
    """Capability registry that rejects duplicate or write-capable providers."""

    def __init__(self, providers: Sequence[DeviceProvider] = ()) -> None:
        self._providers: dict[str, DeviceProvider] = {}
        for provider in providers:
            self.register(provider)

    @staticmethod
    def _validate_manifest(manifest: ProviderManifest) -> None:
        if not manifest.name or not manifest.version:
            raise ValueError("provider name and version are required")
        if not manifest.read_only:
            raise ValueError(f"provider {manifest.name} is not read-only")
        for capability in manifest.capabilities:
            if not isinstance(capability, Capability):
                raise ValueError(f"provider {manifest.name} has an invalid capability value")
            lowered = capability.value.casefold()
            if any(token in lowered for token in _FORBIDDEN_CAPABILITY_TOKENS):
                raise ValueError(f"forbidden provider capability: {capability.value}")

    def register(self, provider: DeviceProvider) -> None:
        self._validate_manifest(provider.manifest)
        name = provider.manifest.name
        if name in self._providers:
            raise ValueError(f"provider already registered: {name}")
        self._providers[name] = provider

    def manifests(self) -> tuple[ProviderManifest, ...]:
        return tuple(self._providers[name].manifest for name in sorted(self._providers))

    def providers_for(self, descriptor: DeviceDescriptor) -> tuple[DeviceProvider, ...]:
        return tuple(
            provider
            for _, provider in sorted(self._providers.items())
            if provider.supports(descriptor)
        )

    def capabilities(self) -> dict[str, tuple[str, ...]]:
        index: dict[str, list[str]] = defaultdict(list)
        for manifest in self.manifests():
            for capability in manifest.capabilities:
                index[capability.value].append(manifest.name)
        return {key: tuple(value) for key, value in sorted(index.items())}


class UsbDescriptorProvider(DeviceProvider):
    """Always-available provider for raw event/descriptor custody."""

    manifest = ProviderManifest(
        name="usb-descriptor",
        version="1.0.0",
        transports=("usb", "pnp"),
        capabilities=(Capability.DISCOVER, Capability.READ_USB_IDENTITY, Capability.READ_TOPOLOGY, Capability.READ_MODE),
    )

    def supports(self, descriptor: DeviceDescriptor) -> bool:
        return True

    def probe(self, session_id: str, descriptor: DeviceDescriptor, runner: Any) -> ProviderProbeResult:
        now = utc_now()
        result = CommandResult((), 0, json.dumps(descriptor.to_dict(), sort_keys=True), "", now, now, 0, available=True)
        observations = {
            "usb.vid": descriptor.vid,
            "usb.pid": descriptor.pid,
            "usb.topology": descriptor.topology_path,
            "transport.mode": descriptor.mode,
            "transport.os_path": descriptor.os_path,
            "product.name": descriptor.product,
            "product.manufacturer": descriptor.manufacturer,
        }
        envelope = _envelope(
            session_id=session_id,
            descriptor=descriptor,
            manifest=self.manifest,
            capability=Capability.READ_USB_IDENTITY,
            result=result,
            observations={key: value for key, value in observations.items() if value is not None},
            sensitive_fields=("serial", "metadata.ecid", "metadata.udid"),
        )
        return ProviderProbeResult(self.manifest.name, True, (envelope,), envelope.observations)


class AdbProvider(DeviceProvider):
    """Read-only ADB identity and property provider."""

    manifest = ProviderManifest(
        name="adb",
        version="1.0.0",
        transports=("adb", "android-normal"),
        capabilities=(Capability.READ_IDENTITY, Capability.READ_PROPERTIES, Capability.READ_VERSION, Capability.READ_BOOT_STATE),
        commands=("adb",),
    )

    _PROPERTY_MAP = {
        "ro.product.manufacturer": "product.manufacturer",
        "ro.product.brand": "product.brand",
        "ro.product.model": "product.model",
        "ro.product.device": "product.device",
        "ro.product.board": "product.board",
        "ro.hardware": "hardware.platform",
        "ro.board.platform": "hardware.bsp_platform",
        "ro.build.id": "os.build_id",
        "ro.build.version.release": "os.release",
        "ro.build.version.sdk": "os.sdk",
        "ro.build.version.security_patch": "os.security_patch",
        "ro.boot.slot_suffix": "partition.slot_suffix",
        "ro.boot.verifiedbootstate": "security.verified_boot",
    }

    def supports(self, descriptor: DeviceDescriptor) -> bool:
        return descriptor.mode == "ADB" or bool(descriptor.metadata.get("adb_serial"))

    @classmethod
    def parse_properties(cls, payload: str) -> dict[str, str]:
        observations: dict[str, str] = {}
        for line in payload.splitlines():
            match = re.match(r"^\[([^]]+)\]:\s*\[(.*)\]$", line.strip())
            if not match:
                continue
            mapped = cls._PROPERTY_MAP.get(match.group(1))
            if mapped and match.group(2):
                observations[mapped] = match.group(2)
        return observations

    def probe(self, session_id: str, descriptor: DeviceDescriptor, runner: Any) -> ProviderProbeResult:
        serial = _validate_serial(str(descriptor.metadata.get("adb_serial") or descriptor.serial or ""), "ADB")
        state_result = runner.run(("adb", "-s", serial, "get-state"), timeout=10)
        property_result = runner.run(("adb", "-s", serial, "shell", "getprop"), timeout=15)
        state_observations = {"transport.mode": "ADB", "adb.state": state_result.stdout.strip()}
        property_observations = self.parse_properties(property_result.stdout)
        state_envelope = _envelope(
            session_id=session_id,
            descriptor=descriptor,
            manifest=self.manifest,
            capability=Capability.READ_BOOT_STATE,
            result=state_result,
            observations=state_observations,
            sensitive_fields=("command.argv[2]",),
        )
        property_envelope = _envelope(
            session_id=session_id,
            descriptor=descriptor,
            manifest=self.manifest,
            capability=Capability.READ_PROPERTIES,
            result=property_result,
            observations=property_observations,
            sensitive_fields=("command.argv[2]",),
        )
        warnings: list[str] = []
        if not state_result.available or state_result.timed_out or state_result.returncode != 0:
            warnings.append("ADB state probe unavailable or failed")
        if not property_result.available or property_result.timed_out or property_result.returncode != 0:
            warnings.append("ADB property probe unavailable or failed")
        combined = {**state_observations, **property_observations}
        return ProviderProbeResult(self.manifest.name, True, (state_envelope, property_envelope), combined, warnings=tuple(warnings))


class FastbootProvider(DeviceProvider):
    """Read-only Fastboot/Fastbootd/Huawei rescue provider."""

    manifest = ProviderManifest(
        name="fastboot",
        version="1.0.0",
        transports=("fastboot", "fastbootd", "huawei-rescue"),
        capabilities=(Capability.READ_IDENTITY, Capability.READ_BOOT_STATE, Capability.READ_SECURITY_STATE, Capability.READ_VERSION),
        commands=("fastboot",),
    )

    _KEY_MAP = {
        "product": "fastboot.product",
        "current-slot": "partition.active_slot",
        "slot-count": "partition.slot_count",
        "unlocked": "security.bootloader_unlocked",
        "secure": "security.secure",
        "version-baseband": "firmware.baseband",
        "version-bootloader": "firmware.bootloader",
        "rescue_phoneinfo": "firmware.main_version",
        "vendorcountry": "oeminfo.vendor_country",
        "serialno": "identity.fastboot_serial",
    }

    def supports(self, descriptor: DeviceDescriptor) -> bool:
        return descriptor.mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"} or bool(descriptor.metadata.get("fastboot_serial"))

    @classmethod
    def parse_getvar_all(cls, stdout: str, stderr: str) -> dict[str, str]:
        observations: dict[str, str] = {}
        for line in f"{stdout}\n{stderr}".splitlines():
            cleaned = re.sub(r"^\(bootloader\)\s*", "", line.strip())
            if ":" not in cleaned:
                continue
            key, value = cleaned.split(":", 1)
            mapped = cls._KEY_MAP.get(key.strip())
            if mapped and value.strip():
                normalized = value.strip()
                if mapped == "oeminfo.vendor_country" and "cannot get" in normalized.casefold():
                    normalized = "UNREADABLE"
                observations[mapped] = normalized
        return observations

    def probe(self, session_id: str, descriptor: DeviceDescriptor, runner: Any) -> ProviderProbeResult:
        serial = _validate_serial(str(descriptor.metadata.get("fastboot_serial") or descriptor.serial or ""), "Fastboot")
        result = runner.run(("fastboot", "-s", serial, "getvar", "all"), timeout=20)
        observations = self.parse_getvar_all(result.stdout, result.stderr)
        observations.setdefault("transport.mode", descriptor.mode or "FASTBOOT")
        envelope = _envelope(
            session_id=session_id,
            descriptor=descriptor,
            manifest=self.manifest,
            capability=Capability.READ_IDENTITY,
            result=result,
            observations=observations,
            sensitive_fields=("command.argv[2]", "identity.fastboot_serial"),
        )
        warnings: list[str] = []
        if not result.available or result.timed_out or result.returncode != 0:
            warnings.append("Fastboot getvar probe unavailable or failed")
        if observations.get("firmware.main_version", "").upper() == "NO MAIN VERSION":
            warnings.append("Huawei main-version readback is missing; identity-dependent work remains blocked.")
        return ProviderProbeResult(self.manifest.name, True, (envelope,), observations, tuple(warnings))


class _AppleRecoveryBase(DeviceProvider):
    expected_mode: str
    expected_pid: str

    def supports(self, descriptor: DeviceDescriptor) -> bool:
        return (
            descriptor.vid == "05AC"
            and (descriptor.pid == self.expected_pid or descriptor.mode == self.expected_mode)
        )

    @staticmethod
    def parse_irecovery(payload: str) -> dict[str, str]:
        mapping = {
            "MODE": "transport.mode",
            "CPID": "apple.cpid",
            "BDID": "apple.bdid",
            "ECID": "apple.ecid",
            "PRODUCT": "apple.product_type",
            "MODEL": "apple.model",
            "NAME": "apple.name",
            "SRNM": "apple.serial",
            "NONC": "apple.nonce",
        }
        observations: dict[str, str] = {}
        for line in payload.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            mapped = mapping.get(key.strip().upper())
            if mapped and value.strip():
                observations[mapped] = value.strip()
        return observations

    def probe(self, session_id: str, descriptor: DeviceDescriptor, runner: Any) -> ProviderProbeResult:
        ecid = _validate_ecid(str(descriptor.metadata.get("ecid") or ""))
        argv = ("irecovery", "-i", ecid, "-q") if ecid else ("irecovery", "-q")
        result = runner.run(argv, timeout=15)
        observations = self.parse_irecovery(f"{result.stdout}\n{result.stderr}")
        observations.setdefault("transport.mode", self.expected_mode)
        observations.setdefault("usb.vid", descriptor.vid or "05AC")
        observations.setdefault("usb.pid", descriptor.pid or self.expected_pid)
        envelope = _envelope(
            session_id=session_id,
            descriptor=descriptor,
            manifest=self.manifest,
            capability=Capability.READ_IDENTITY,
            result=result,
            observations=observations,
            sensitive_fields=("apple.ecid", "apple.serial", "apple.nonce"),
        )
        warnings: list[str] = []
        if not result.available or result.timed_out or result.returncode != 0:
            warnings.append(f"{self.expected_mode} irecovery probe unavailable or failed")
        if not ecid:
            warnings.append("irecovery query was not ECID-pinned; multiple Apple recovery devices would be ambiguous")
        reported_mode = observations.get("transport.mode", "").upper()
        if reported_mode and reported_mode != self.expected_mode:
            warnings.append(f"USB mode {self.expected_mode} disagrees with irecovery mode {reported_mode}")
        return ProviderProbeResult(self.manifest.name, True, (envelope,), observations, tuple(warnings))


class AppleRecoveryProvider(_AppleRecoveryBase):
    """Apple recovery-mode provider using irecovery readback."""

    expected_mode = "RECOVERY"
    expected_pid = "1281"
    manifest = ProviderManifest(
        name="apple-recovery",
        version="1.0.0",
        transports=("apple-recovery",),
        capabilities=(Capability.READ_IDENTITY, Capability.READ_MODE, Capability.READ_BOOT_STATE),
        commands=("irecovery",),
    )


class AppleDfuProvider(_AppleRecoveryBase):
    """Apple DFU provider using USB PID plus irecovery readback when available."""

    expected_mode = "DFU"
    expected_pid = "1227"
    manifest = ProviderManifest(
        name="apple-dfu",
        version="1.0.0",
        transports=("apple-dfu",),
        capabilities=(Capability.READ_IDENTITY, Capability.READ_MODE, Capability.READ_BOOT_STATE),
        commands=("irecovery",),
    )


def default_registry() -> ProviderRegistry:
    """Return the first-run live provider registry."""

    return ProviderRegistry(
        (
            UsbDescriptorProvider(),
            AdbProvider(),
            FastbootProvider(),
            AppleRecoveryProvider(),
            AppleDfuProvider(),
        )
    )
