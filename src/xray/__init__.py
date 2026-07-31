"""Xray model-independent device evidence and live provider core."""

from .engine import inspect_text, parse_external_claim
from .envelopes import EnvelopeJournal
from .knowledge import load_knowledge
from .live_models import (
    Capability,
    CommandResult,
    DeviceDescriptor,
    DeviceEvent,
    EventKind,
    LiveInspectionReport,
    LiveReviewReport,
    ProviderManifest,
    ProviderProbeResult,
    RawEvidenceEnvelope,
)
from .live_runtime import XrayLiveRuntime, doctor_live
from .models import Claim, Evidence, KnowledgeError, OfficerReport, PrivateResult, Status, VERSION, XrayReport
from .providers import (
    AdbProvider,
    AppleDfuProvider,
    AppleRecoveryProvider,
    FastbootProvider,
    ProviderRegistry,
    SimulatedRunner,
    SubprocessRunner,
    UsbDescriptorProvider,
    default_registry,
)
from .runtime import SELFTEST_APPLE, SELFTEST_HUAWEI, SELFTEST_UNISOC, doctor, report_text, run_selftest, scan_host
from .sessions import SessionRecord, SessionRegistry
from .simulation import run_simulation
from .watcher import PollingDeviceWatcher, platform_snapshot_source

__all__ = [
    "AdbProvider",
    "AppleDfuProvider",
    "AppleRecoveryProvider",
    "Capability",
    "Claim",
    "CommandResult",
    "DeviceDescriptor",
    "DeviceEvent",
    "EnvelopeJournal",
    "EventKind",
    "Evidence",
    "FastbootProvider",
    "KnowledgeError",
    "LiveInspectionReport",
    "LiveReviewReport",
    "OfficerReport",
    "PollingDeviceWatcher",
    "PrivateResult",
    "ProviderManifest",
    "ProviderProbeResult",
    "ProviderRegistry",
    "RawEvidenceEnvelope",
    "SELFTEST_APPLE",
    "SELFTEST_HUAWEI",
    "SELFTEST_UNISOC",
    "SessionRecord",
    "SessionRegistry",
    "SimulatedRunner",
    "Status",
    "SubprocessRunner",
    "UsbDescriptorProvider",
    "VERSION",
    "XrayLiveRuntime",
    "XrayReport",
    "default_registry",
    "doctor",
    "doctor_live",
    "inspect_text",
    "load_knowledge",
    "parse_external_claim",
    "platform_snapshot_source",
    "report_text",
    "run_selftest",
    "run_simulation",
    "scan_host",
]
