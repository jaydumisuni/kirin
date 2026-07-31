from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence

_HEX4 = re.compile(r"^[0-9A-F]{4}$")
_ECID_PREFIXED_HEX = re.compile(r"^0[Xx][0-9A-Fa-f]{1,16}$")
_ECID_DECIMAL = re.compile(r"^[0-9]{1,20}$")
_ECID_BARE_HEX = re.compile(r"^[0-9A-Fa-f]{1,16}$")


def utc_now() -> str:
    """Return a stable UTC timestamp in RFC3339 form."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_hex(value: str | None) -> str | None:
    """Normalize USB vendor/product IDs to four uppercase hexadecimal digits."""

    if value is None:
        return None
    cleaned = value.strip().upper().removeprefix("0X")
    if not cleaned:
        return None
    if len(cleaned) < 4:
        cleaned = cleaned.zfill(4)
    if not _HEX4.fullmatch(cleaned):
        raise ValueError(f"invalid USB hexadecimal identifier: {value!r}")
    return cleaned


def normalize_topology(value: str | None) -> str | None:
    """Normalize a host USB/PnP topology path without destroying port identity."""

    if value is None:
        return None
    collapsed = " ".join(value.strip().split())
    return collapsed.casefold() or None


def normalize_ecid(value: str | None) -> str | None:
    """Normalize decimal or hexadecimal Apple ECIDs to canonical 64-bit hex."""

    if value is None or not value.strip():
        return None
    raw = value.strip()
    if _ECID_PREFIXED_HEX.fullmatch(raw):
        number = int(raw, 16)
    elif _ECID_DECIMAL.fullmatch(raw):
        number = int(raw, 10)
    elif _ECID_BARE_HEX.fullmatch(raw):
        number = int(raw, 16)
    else:
        raise ValueError(f"invalid Apple ECID: {value!r}")
    if not 0 < number <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Apple ECID is outside the unsigned 64-bit range: {value!r}")
    return f"0x{number:016X}"


def canonical_sha256(payload: Mapping[str, Any] | Sequence[Any] | str | bytes) -> str:
    """Hash canonical JSON, text, or bytes deterministically."""

    if isinstance(payload, bytes):
        data = payload
    elif isinstance(payload, str):
        data = payload.encode("utf-8", errors="replace")
    else:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class EventKind(str, Enum):
    """USB/PnP lifecycle events emitted by the watcher."""

    CONNECTED = "CONNECTED"
    DISCONNECTED = "DISCONNECTED"
    CHANGED = "CHANGED"
    MODE_TRANSITION = "MODE_TRANSITION"
    PRESENT = "PRESENT"


class Capability(str, Enum):
    """Read-only provider capabilities accepted by Xray Live."""

    DISCOVER = "discover"
    READ_USB_IDENTITY = "read_usb_identity"
    READ_TOPOLOGY = "read_topology"
    READ_IDENTITY = "read_identity"
    READ_BOOT_STATE = "read_boot_state"
    READ_SECURITY_STATE = "read_security_state"
    READ_VERSION = "read_version"
    READ_MODE = "read_mode"
    READ_PROPERTIES = "read_properties"


@dataclass(frozen=True)
class DeviceDescriptor:
    """One host-side observation of a connected physical endpoint."""

    source: str
    os_path: str
    topology_path: str | None = None
    vid: str | None = None
    pid: str | None = None
    serial: str | None = None
    mode: str | None = None
    manufacturer: str | None = None
    product: str | None = None
    interface_class: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "vid", normalize_hex(self.vid))
        object.__setattr__(self, "pid", normalize_hex(self.pid))
        object.__setattr__(self, "topology_path", normalize_topology(self.topology_path))
        object.__setattr__(self, "mode", self.mode.strip().upper() if self.mode else None)
        object.__setattr__(self, "serial", self.serial.strip() if self.serial else None)
        metadata = dict(self.metadata)
        if metadata.get("ecid"):
            metadata["ecid"] = normalize_ecid(str(metadata["ecid"]))
        object.__setattr__(self, "metadata", metadata)
        if not self.source.strip():
            raise ValueError("descriptor source is required")
        if not self.os_path.strip():
            raise ValueError("descriptor os_path is required")

    @property
    def slot_key(self) -> str:
        """Return the best host-side key for watcher snapshot comparison."""

        if self.topology_path:
            return f"topology:{self.topology_path}"
        return f"os-path:{self.os_path.casefold()}"

    @property
    def fingerprint(self) -> str:
        """Hash the endpoint's current mode-specific descriptor."""

        return canonical_sha256(self.to_dict())

    def identity_anchors(self) -> tuple[str, ...]:
        """Return stable correlation anchors ordered from strongest to weakest."""

        anchors: list[str] = []
        for key in ("ecid", "udid", "container_id", "hardware_id", "adb_serial", "fastboot_serial"):
            value = self.metadata.get(key)
            if value and str(value).strip():
                digest = canonical_sha256(str(value).strip().casefold())
                anchors.append(f"{key}-sha256:{digest}")
        if self.serial and self.serial.casefold() not in {"unknown", "none", "????????", "0123456789abcdef"}:
            anchors.append(f"serial-sha256:{canonical_sha256(self.serial.casefold())}")
        if self.topology_path:
            anchors.append(f"topology:{self.topology_path}")
        return tuple(dict.fromkeys(anchors))

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe descriptor mapping."""

        return {
            "source": self.source,
            "os_path": self.os_path,
            "topology_path": self.topology_path,
            "vid": self.vid,
            "pid": self.pid,
            "serial": self.serial,
            "mode": self.mode,
            "manufacturer": self.manufacturer,
            "product": self.product,
            "interface_class": self.interface_class,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DeviceEvent:
    """A normalized device lifecycle event."""

    kind: EventKind
    descriptor: DeviceDescriptor
    observed_at: str = field(default_factory=utc_now)
    previous: DeviceDescriptor | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe event mapping."""

        return {
            "kind": self.kind.value,
            "observed_at": self.observed_at,
            "descriptor": self.descriptor.to_dict(),
            "previous": self.previous.to_dict() if self.previous else None,
        }


@dataclass(frozen=True)
class CommandResult:
    """Raw result from one fixed, shell-free read-only command."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    started_at: str
    completed_at: str
    duration_ms: int
    executable: str | None = None
    timed_out: bool = False
    available: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe command result mapping."""

        return asdict(self)


@dataclass(frozen=True)
class ProviderManifest:
    """Immutable provider contract advertised to the capability registry."""

    name: str
    version: str
    transports: tuple[str, ...]
    capabilities: tuple[Capability, ...]
    commands: tuple[str, ...] = ()
    read_only: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe provider manifest."""

        return {
            "name": self.name,
            "version": self.version,
            "transports": list(self.transports),
            "capabilities": [item.value for item in self.capabilities],
            "commands": list(self.commands),
            "read_only": self.read_only,
        }


@dataclass(frozen=True)
class RawEvidenceEnvelope:
    """Custody-preserving raw evidence captured by one provider capability."""

    envelope_id: str
    schema: str
    session_id: str
    captured_at: str
    provider: str
    provider_version: str
    capability: str
    source: str
    topology: Mapping[str, Any]
    command: Mapping[str, Any]
    observations: Mapping[str, Any]
    sensitive_fields: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str
    descriptor_sha256: str
    payload_sha256: str
    raw_stdout: str
    raw_stderr: str

    def unsigned_dict(self) -> dict[str, Any]:
        """Return the envelope payload excluding its self-hash."""

        result = asdict(self)
        result.pop("payload_sha256", None)
        return result

    def verify(self) -> bool:
        """Verify every raw hash and the canonical envelope hash."""

        if canonical_sha256(self.raw_stdout) != self.stdout_sha256:
            return False
        if canonical_sha256(self.raw_stderr) != self.stderr_sha256:
            return False
        descriptor = self.topology.get("descriptor", {})
        if canonical_sha256(descriptor) != self.descriptor_sha256:
            return False
        return canonical_sha256(self.unsigned_dict()) == self.payload_sha256

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe complete evidence envelope."""

        return asdict(self)


@dataclass(frozen=True)
class ProviderProbeResult:
    """Normalized output from one provider probe."""

    provider: str
    supported: bool
    envelopes: tuple[RawEvidenceEnvelope, ...] = ()
    observations: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe provider result."""

        return {
            "provider": self.provider,
            "supported": self.supported,
            "envelopes": [item.to_dict() for item in self.envelopes],
            "observations": dict(self.observations),
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


@dataclass(frozen=True)
class LivePrivateResult:
    """One deterministic SRG private check in the live review corps."""

    private_id: str
    wave: int
    assignment: str
    passed: bool
    severity: str
    findings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe private result."""

        return asdict(self)


@dataclass(frozen=True)
class LiveReviewReport:
    """Two-wave SRG review and Governor verdict for one live event."""

    method: str
    privates: tuple[LivePrivateResult, ...]
    officers: Mapping[str, Any]
    governor: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe live review report."""

        return {
            "method": self.method,
            "privates": [item.to_dict() for item in self.privates],
            "officers": dict(self.officers),
            "governor": dict(self.governor),
        }


@dataclass(frozen=True)
class LiveInspectionReport:
    """Complete live provider, session, evidence, and SRG result."""

    schema: str
    created_at: str
    event: DeviceEvent
    session: Mapping[str, Any]
    providers: tuple[ProviderProbeResult, ...]
    review: LiveReviewReport

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe live inspection report."""

        return {
            "schema": self.schema,
            "created_at": self.created_at,
            "event": self.event.to_dict(),
            "session": dict(self.session),
            "providers": [item.to_dict() for item in self.providers],
            "review": self.review.to_dict(),
        }
