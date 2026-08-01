from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Sequence

from .providers import FORBIDDEN_CAPABILITY_TOKENS
from .live_models import (
    DeviceEvent,
    EventKind,
    LivePrivateResult,
    LiveReviewReport,
    ProviderManifest,
    ProviderProbeResult,
)

Check = Callable[[dict[str, Any]], LivePrivateResult]
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SAFE_COMMAND = re.compile(r"^[A-Za-z0-9._+-]+$")


def _private(
    private_id: str,
    wave: int,
    assignment: str,
    passed: bool,
    findings: Sequence[str] = (),
    *,
    severity: str | None = None,
) -> LivePrivateResult:
    chosen = severity or ("info" if passed else "critical")
    return LivePrivateResult(
        private_id,
        wave,
        assignment,
        passed,
        chosen,
        tuple(findings),
    )


def _event_integrity(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    passed = bool(event.observed_at and event.descriptor.os_path)
    return _private(
        "private-001",
        1,
        "Validate event timestamp and endpoint",
        passed,
        () if passed else ("missing timestamp or os_path",),
    )


def _topology_capture(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    passed = bool(descriptor.topology_path)
    return _private(
        "private-002",
        1,
        "Capture physical USB/PnP topology",
        passed,
        () if passed else ("topology unavailable; correlation is weaker",),
        severity="warning" if not passed else None,
    )


def _session_format(ctx: dict[str, Any]) -> LivePrivateResult:
    session_id = str(ctx["session"]["session_id"])
    passed = session_id.startswith("xray-device-") and len(session_id) == len(
        "xray-device-"
    ) + 20
    return _private(
        "private-003",
        1,
        "Validate stable physical-device session ID",
        passed,
        () if passed else (f"invalid session ID: {session_id}",),
    )


def _session_anchor(ctx: dict[str, Any]) -> LivePrivateResult:
    anchors = ctx["session"].get("anchors", [])
    passed = bool(anchors)
    return _private(
        "private-004",
        1,
        "Verify session correlation anchors",
        passed,
        () if passed else ("session has no stable anchors",),
        severity="warning" if not passed else None,
    )


def _provider_manifest(ctx: dict[str, Any]) -> LivePrivateResult:
    manifests: Sequence[ProviderManifest] = ctx["manifests"]
    bad = [item.name for item in manifests if not item.read_only or not item.capabilities]
    return _private(
        "private-005",
        1,
        "Validate provider manifests",
        not bad,
        tuple(f"invalid manifest: {name}" for name in bad),
    )


def _provider_support(ctx: dict[str, Any]) -> LivePrivateResult:
    results: Sequence[ProviderProbeResult] = ctx["providers"]
    unsupported = [item.provider for item in results if not item.supported]
    empty = [
        item.provider
        for item in results
        if item.supported and not item.envelopes and not item.errors
    ]
    findings = [f"unsupported provider executed: {name}" for name in unsupported]
    findings.extend(f"provider returned no evidence: {name}" for name in empty)
    return _private(
        "private-006",
        1,
        "Confirm selected providers support the endpoint",
        not findings,
        tuple(findings),
        severity="warning" if findings else None,
    )


def _envelope_hashes(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [
        item.envelope_id for item in ctx["envelopes"] if not item.verify()
    ]
    return _private(
        "private-007",
        1,
        "Verify raw evidence envelope hashes",
        not bad,
        tuple(f"hash failure: {item}" for item in bad),
    )


def _timestamps(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [
        item.envelope_id
        for item in ctx["envelopes"]
        if item.command.get("completed_at", "")
        < item.command.get("started_at", "")
    ]
    return _private(
        "private-008",
        1,
        "Check provider timestamp ordering",
        not bad,
        tuple(f"timestamp regression: {item}" for item in bad),
    )


def _capability_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    manifests = {item.name: item for item in ctx["manifests"]}
    bad: list[str] = []
    for envelope in ctx["envelopes"]:
        manifest = manifests.get(envelope.provider)
        declared = {item.value for item in manifest.capabilities} if manifest else set()
        if envelope.capability not in declared:
            bad.append(f"{envelope.provider}:{envelope.capability}")
    return _private(
        "private-009",
        1,
        "Cross-check envelope capabilities against manifests",
        not bad,
        tuple(f"undeclared capability: {item}" for item in bad),
    )


def _write_boundary(ctx: dict[str, Any]) -> LivePrivateResult:
    forbidden = []
    for manifest in ctx["manifests"]:
        for capability in manifest.capabilities:
            if any(
                token in capability.value.casefold()
                for token in FORBIDDEN_CAPABILITY_TOKENS
            ):
                forbidden.append(f"{manifest.name}:{capability.value}")
    return _private(
        "private-010",
        1,
        "Enforce read-only authority boundary",
        not forbidden,
        tuple(forbidden),
    )


def _event_kind_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    requires_previous = event.kind in {
        EventKind.DISCONNECTED,
        EventKind.MODE_TRANSITION,
    }
    passed = not requires_previous or event.previous is not None
    return _private(
        "private-021",
        1,
        "Validate lifecycle event transition contract",
        passed,
        () if passed else (f"{event.kind.value} requires a previous descriptor",),
    )


def _usb_pair_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    passed = (descriptor.vid is None) == (descriptor.pid is None)
    return _private(
        "private-022",
        1,
        "Validate USB VID/PID pair completeness",
        passed,
        () if passed else (f"incomplete USB pair: {descriptor.vid}:{descriptor.pid}",),
        severity="warning" if not passed else None,
    )


def _mode_normalization(ctx: dict[str, Any]) -> LivePrivateResult:
    mode = ctx["event"].descriptor.mode
    passed = mode is None or mode == mode.strip().upper()
    return _private(
        "private-023",
        1,
        "Validate normalized transport mode",
        passed,
        () if passed else (f"mode is not normalized: {mode!r}",),
    )


def _provider_uniqueness(ctx: dict[str, Any]) -> LivePrivateResult:
    names = [item.provider for item in ctx["providers"]]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    return _private(
        "private-024",
        1,
        "Reject duplicate provider results",
        not duplicates,
        tuple(f"duplicate provider result: {name}" for name in duplicates),
    )


def _manifest_uniqueness(ctx: dict[str, Any]) -> LivePrivateResult:
    names = [item.name for item in ctx["manifests"]]
    duplicates = sorted({name for name in names if names.count(name) > 1})
    return _private(
        "private-025",
        1,
        "Reject duplicate provider manifests",
        not duplicates,
        tuple(f"duplicate manifest: {name}" for name in duplicates),
    )


def _manifest_version_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [
        item.name
        for item in ctx["manifests"]
        if not _SEMVER.fullmatch(item.version)
    ]
    return _private(
        "private-026",
        1,
        "Validate provider semantic versions",
        not bad,
        tuple(f"invalid provider version: {name}" for name in bad),
    )


def _manifest_command_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    bad: list[str] = []
    for manifest in ctx["manifests"]:
        if len(set(manifest.commands)) != len(manifest.commands):
            bad.append(f"{manifest.name}:duplicate-command")
        for command in manifest.commands:
            if not _SAFE_COMMAND.fullmatch(command):
                bad.append(f"{manifest.name}:{command}")
    return _private(
        "private-027",
        1,
        "Validate provider command declarations",
        not bad,
        tuple(f"invalid command declaration: {item}" for item in bad),
    )


def _envelope_schema_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [
        item.envelope_id
        for item in ctx["envelopes"]
        if item.schema != "xray-raw-evidence-v1"
        or not item.envelope_id.startswith("xray-envelope-")
        or not item.provider
        or not item.provider_version
        or not item.capability
    ]
    return _private(
        "private-028",
        1,
        "Validate evidence envelope schema identity",
        not bad,
        tuple(f"invalid envelope schema identity: {item}" for item in bad),
    )


def _envelope_manifest_identity(ctx: dict[str, Any]) -> LivePrivateResult:
    manifests = {item.name: item for item in ctx["manifests"]}
    bad: list[str] = []
    for envelope in ctx["envelopes"]:
        manifest = manifests.get(envelope.provider)
        if manifest is None or manifest.version != envelope.provider_version:
            bad.append(envelope.envelope_id)
    return _private(
        "private-029",
        1,
        "Bind evidence envelopes to exact provider manifests",
        not bad,
        tuple(f"provider manifest mismatch: {item}" for item in bad),
    )


def _evidence_source_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    bad: list[str] = []
    for envelope in ctx["envelopes"]:
        argv = tuple(envelope.command.get("argv", ()))
        valid = (envelope.source == "event" and not argv) or (
            envelope.source == "command" and bool(argv)
        )
        if not valid:
            bad.append(envelope.envelope_id)
    return _private(
        "private-030",
        1,
        "Validate evidence source and command-vector coherence",
        not bad,
        tuple(f"source/argv mismatch: {item}" for item in bad),
    )


def _session_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    expected = ctx["session"]["session_id"]
    bad = [
        item.envelope_id
        for item in ctx["envelopes"]
        if item.session_id != expected
    ]
    return _private(
        "private-011",
        2,
        "Verify all providers used one physical-device session",
        not bad,
        tuple(f"foreign session envelope: {item}" for item in bad),
    )


def _mode_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor_mode = ctx["event"].descriptor.mode
    observed = {
        str(value).upper()
        for result in ctx["providers"]
        for key, value in result.observations.items()
        if key == "transport.mode" and value
    }
    conflict = bool(
        descriptor_mode
        and observed
        and descriptor_mode.upper() not in observed
    )
    findings = (
        (f"descriptor={descriptor_mode}, providers={sorted(observed)}",)
        if conflict
        else ()
    )
    return _private(
        "private-012",
        2,
        "Challenge mode consistency across providers",
        not conflict,
        findings,
        severity="warning" if conflict else None,
    )


def _adb_constraints(ctx: dict[str, Any]) -> LivePrivateResult:
    event = ctx["event"]
    adb = [item for item in ctx["providers"] if item.provider == "adb"]
    bad = bool(
        adb
        and not (
            event.descriptor.mode == "ADB"
            or event.descriptor.metadata.get("adb_serial")
        )
    )
    return _private(
        "private-013",
        2,
        "Validate ADB transport selection",
        not bad,
        ("ADB provider ran without ADB evidence",) if bad else (),
    )


def _fastboot_constraints(ctx: dict[str, Any]) -> LivePrivateResult:
    event = ctx["event"]
    fastboot = [
        item for item in ctx["providers"] if item.provider == "fastboot"
    ]
    allowed = event.descriptor.mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"} or (
        event.descriptor.metadata.get("fastboot_serial")
    )
    bad = bool(fastboot and not allowed)
    return _private(
        "private-014",
        2,
        "Validate Fastboot transport selection",
        not bad,
        ("Fastboot provider ran without Fastboot evidence",) if bad else (),
    )


def _apple_pid_mode(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    expected = (
        {"1227": "DFU", "1281": "RECOVERY"}.get(descriptor.pid or "")
        if descriptor.vid == "05AC"
        else None
    )
    reported = {
        str(value).upper()
        for result in ctx["providers"]
        for key, value in result.observations.items()
        if key == "transport.mode"
        and value
        and result.provider.startswith("apple-")
    }
    bad = bool(expected and reported and expected not in reported)
    return _private(
        "private-015",
        2,
        "Cross-check Apple USB PID against Recovery/DFU mode",
        not bad,
        (f"PID expects {expected}, provider reports {sorted(reported)}",)
        if bad
        else (),
    )


def _raw_custody(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [
        item.envelope_id
        for item in ctx["envelopes"]
        if not item.stdout_sha256
        or not item.stderr_sha256
        or not item.descriptor_sha256
    ]
    return _private(
        "private-016",
        2,
        "Verify raw command and descriptor custody",
        not bad,
        tuple(f"missing custody hash: {item}" for item in bad),
    )


def _topology_stability(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    if event.kind != EventKind.MODE_TRANSITION or not event.previous:
        return _private(
            "private-017",
            2,
            "Verify topology stability across mode transitions",
            True,
        )
    current = event.descriptor.topology_path
    previous = event.previous.topology_path
    passed = bool(current and previous and current == previous)
    return _private(
        "private-017",
        2,
        "Verify topology stability across mode transitions",
        passed,
        () if passed else (f"topology changed: {previous} -> {current}",),
        severity="warning" if not passed else None,
    )


def _sensitive_declaration(ctx: dict[str, Any]) -> LivePrivateResult:
    bad: list[str] = []
    for item in ctx["envelopes"]:
        observations = item.observations
        has_sensitive = any(
            key in observations
            for key in (
                "apple.ecid",
                "apple.serial",
                "apple.nonce",
                "identity.fastboot_serial",
            )
        )
        if has_sensitive and not item.sensitive_fields:
            bad.append(item.envelope_id)
    return _private(
        "private-018",
        2,
        "Verify sensitive identifier declarations",
        not bad,
        tuple(f"undeclared sensitive fields: {item}" for item in bad),
    )


def _duplicate_envelopes(ctx: dict[str, Any]) -> LivePrivateResult:
    ids = [item.envelope_id for item in ctx["envelopes"]]
    duplicate = sorted({item for item in ids if ids.count(item) > 1})
    return _private(
        "private-019",
        2,
        "Reject duplicate evidence envelopes",
        not duplicate,
        tuple(f"duplicate envelope: {item}" for item in duplicate),
    )


def _identity_gate(ctx: dict[str, Any]) -> LivePrivateResult:
    observations = {
        key: value
        for result in ctx["providers"]
        for key, value in result.observations.items()
    }
    missing_main = (
        str(observations.get("firmware.main_version", "")).upper()
        == "NO MAIN VERSION"
    )
    unreadable_vendor = (
        str(observations.get("oeminfo.vendor_country", "")).upper()
        == "UNREADABLE"
    )
    passed = not (missing_main or unreadable_vendor)
    findings: list[str] = []
    if missing_main:
        findings.append("device reports NO MAIN VERSION")
    if unreadable_vendor:
        findings.append("OEMINFO vendor/country is unreadable")
    return _private(
        "private-020",
        2,
        "Apply identity and recovery readback gate",
        passed,
        findings,
        severity="critical" if not passed else None,
    )


def _session_lifecycle_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    connected = bool(ctx["session"].get("connected"))
    expected = event.kind != EventKind.DISCONNECTED
    passed = connected == expected
    return _private(
        "private-031",
        2,
        "Validate session connection lifecycle state",
        passed,
        () if passed else (f"session connected={connected}, expected={expected}",),
    )


def _session_event_counter(ctx: dict[str, Any]) -> LivePrivateResult:
    events = ctx["session"].get("events")
    passed = isinstance(events, int) and events >= 1 and bool(
        ctx["session"].get("updated_at")
    )
    return _private(
        "private-032",
        2,
        "Validate session event accounting",
        passed,
        () if passed else (f"invalid event counter or update time: {events!r}",),
    )


def _session_mode_history(ctx: dict[str, Any]) -> LivePrivateResult:
    mode = ctx["event"].descriptor.mode
    modes = ctx["session"].get("modes", [])
    passed = mode is None or mode in modes
    return _private(
        "private-033",
        2,
        "Confirm current mode is retained in session history",
        passed,
        () if passed else (f"current mode {mode!r} missing from {modes!r}",),
    )


def _session_topology_history(ctx: dict[str, Any]) -> LivePrivateResult:
    topology = ctx["event"].descriptor.topology_path
    paths = ctx["session"].get("topology_paths", [])
    passed = topology is None or topology in paths
    return _private(
        "private-034",
        2,
        "Confirm current topology is retained in session history",
        passed,
        () if passed else (f"topology {topology!r} missing from session",),
        severity="warning" if not passed else None,
    )


def _envelope_topology_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    bad = [
        item.envelope_id
        for item in ctx["envelopes"]
        if item.topology.get("slot_key") != descriptor.slot_key
        or item.topology.get("host_path") != descriptor.topology_path
    ]
    return _private(
        "private-035",
        2,
        "Cross-check envelope topology against the live event",
        not bad,
        tuple(f"envelope topology mismatch: {item}" for item in bad),
    )


def _provider_observation_custody(ctx: dict[str, Any]) -> LivePrivateResult:
    bad: list[str] = []
    for result in ctx["providers"]:
        if not result.envelopes:
            if not result.errors and result.supported:
                bad.append(f"{result.provider}:no-envelope")
            continue
        merged: dict[str, Any] = {}
        for envelope in result.envelopes:
            merged.update(envelope.observations)
        if dict(result.observations) != merged:
            bad.append(result.provider)
    return _private(
        "private-036",
        2,
        "Bind normalized provider observations to envelope evidence",
        not bad,
        tuple(f"observation custody mismatch: {item}" for item in bad),
    )


def _apple_selector_gate(ctx: dict[str, Any]) -> LivePrivateResult:
    findings: list[str] = []
    for result in ctx["providers"]:
        if not result.provider.startswith("apple-"):
            continue
        ecid = result.observations.get("apple.ecid")
        pinned = (
            str(result.observations.get("apple.selector_pinned", "")).casefold()
            == "true"
        )
        count = str(result.observations.get("apple.recovery_device_count", ""))
        if ecid and not pinned and count != "1":
            findings.append(f"{result.provider}:unpinned ECID with count={count or 'unknown'}")
    return _private(
        "private-037",
        2,
        "Gate unpinned Apple identity observations",
        not findings,
        tuple(findings),
        severity="warning" if findings else None,
    )


def _apple_identity_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    ecids = {
        str(result.observations["apple.ecid"])
        for result in ctx["providers"]
        if result.observations.get("apple.ecid")
    }
    passed = len(ecids) <= 1
    return _private(
        "private-038",
        2,
        "Challenge Apple ECID consistency across providers",
        passed,
        () if passed else (f"conflicting Apple ECIDs: {sorted(ecids)}",),
    )


def _protocol_selector_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    expected = {
        "adb": descriptor.metadata.get("adb_serial") or descriptor.serial,
        "fastboot": descriptor.metadata.get("fastboot_serial") or descriptor.serial,
    }
    bad: list[str] = []
    for result in ctx["providers"]:
        selected = expected.get(result.provider)
        if selected is None:
            continue
        for envelope in result.envelopes:
            argv = tuple(envelope.command.get("argv", ()))
            if "-s" in argv:
                index = argv.index("-s")
                actual = argv[index + 1] if index + 1 < len(argv) else None
                if actual != selected:
                    bad.append(f"{result.provider}:{actual!r}!={selected!r}")
    return _private(
        "private-039",
        2,
        "Verify protocol commands are pinned to the observed endpoint",
        not bad,
        tuple(f"selector mismatch: {item}" for item in bad),
    )


def _disconnect_provider_boundary(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    providers = {item.provider for item in ctx["providers"]}
    passed = event.kind != EventKind.DISCONNECTED or providers <= {"usb-descriptor"}
    return _private(
        "private-040",
        2,
        "Prevent protocol probes after device disconnection",
        passed,
        () if passed else (f"disconnect invoked protocol providers: {sorted(providers)}",),
    )


WAVE_ONE: tuple[Check, ...] = (
    _event_integrity,
    _topology_capture,
    _session_format,
    _session_anchor,
    _provider_manifest,
    _provider_support,
    _envelope_hashes,
    _timestamps,
    _capability_contract,
    _write_boundary,
    _event_kind_contract,
    _usb_pair_contract,
    _mode_normalization,
    _provider_uniqueness,
    _manifest_uniqueness,
    _manifest_version_contract,
    _manifest_command_contract,
    _envelope_schema_contract,
    _envelope_manifest_identity,
    _evidence_source_contract,
)

WAVE_TWO: tuple[Check, ...] = (
    _session_consistency,
    _mode_consistency,
    _adb_constraints,
    _fastboot_constraints,
    _apple_pid_mode,
    _raw_custody,
    _topology_stability,
    _sensitive_declaration,
    _duplicate_envelopes,
    _identity_gate,
    _session_lifecycle_contract,
    _session_event_counter,
    _session_mode_history,
    _session_topology_history,
    _envelope_topology_consistency,
    _provider_observation_custody,
    _apple_selector_gate,
    _apple_identity_consistency,
    _protocol_selector_consistency,
    _disconnect_provider_boundary,
)


def _run_wave(
    functions: Sequence[Check],
    ctx: dict[str, Any],
    wave_number: int,
) -> list[LivePrivateResult]:
    results: list[LivePrivateResult] = []
    with ThreadPoolExecutor(
        max_workers=20,
        thread_name_prefix="xray-live-private",
    ) as pool:
        futures = {pool.submit(function, ctx): function.__name__ for function in functions}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001 - isolate one private from the corps
                results.append(
                    _private(
                        f"failed:{name}",
                        wave_number,
                        name,
                        False,
                        (str(exc),),
                    )
                )
    return sorted(results, key=lambda item: (item.wave, item.private_id))


def review_live_event(
    *,
    event: DeviceEvent,
    session: dict[str, Any],
    manifests: Sequence[ProviderManifest],
    providers: Sequence[ProviderProbeResult],
) -> LiveReviewReport:
    """Run the dedicated model-free SRG 20-for-2 live review corps."""

    envelopes = tuple(
        envelope for result in providers for envelope in result.envelopes
    )
    context = {
        "event": event,
        "session": session,
        "manifests": tuple(manifests),
        "providers": tuple(providers),
        "envelopes": envelopes,
    }
    privates = tuple(
        _run_wave(WAVE_ONE, context, 1) + _run_wave(WAVE_TWO, context, 2)
    )
    critical = [
        item for item in privates if not item.passed and item.severity == "critical"
    ]
    warnings = [
        item for item in privates if not item.passed and item.severity == "warning"
    ]
    provider_errors = [error for result in providers for error in result.errors]
    provider_warnings = [warning for result in providers for warning in result.warnings]
    if critical or provider_errors:
        result = "BLOCKED"
        reason = "A mandatory live evidence, provider, or identity gate failed."
    elif warnings or provider_warnings:
        result = "CONFLICTED"
        reason = (
            "Live evidence is usable but provider, correlation, or mode evidence "
            "requires confirmation."
        )
    else:
        result = "LIVE_READ_ONLY_READY"
        reason = (
            "Live evidence collection and two-wave deterministic review completed."
        )
    officers = {
        "Scout": {
            "summary": (
                f"Observed {event.descriptor.vid or '????'}:"
                f"{event.descriptor.pid or '????'} in "
                f"{event.descriptor.mode or 'UNKNOWN'} mode."
            ),
        },
        "Mechanic": {
            "summary": (
                f"Executed {len(providers)} provider(s); "
                f"provider errors={len(provider_errors)}, "
                f"warnings={len(provider_warnings)}."
            ),
            "errors": provider_errors,
            "warnings": provider_warnings,
        },
        "Quartermaster": {
            "summary": f"Registered {len(envelopes)} verified evidence envelope(s).",
            "envelope_ids": [item.envelope_id for item in envelopes],
        },
        "Engineer": {
            "summary": (
                f"Session {session['session_id']} uses "
                f"{len(session.get('anchors', []))} correlation anchor(s)."
            ),
        },
        "Medic": {
            "summary": (
                "Read-only boundary remains active; no flash, erase, unlock, "
                "relock, format, or identity write capability exists."
            ),
        },
        "Analyst": {
            "summary": (
                f"SRG checks passed="
                f"{sum(1 for item in privates if item.passed)}/{len(privates)}."
            ),
        },
        "Challenger": {
            "summary": (
                f"Raised {len(warnings) + len(provider_warnings)} warning(s) "
                f"and {len(critical)} critical challenge(s)."
            ),
            "findings": [
                finding
                for item in privates
                if not item.passed
                for finding in item.findings
            ]
            + provider_warnings,
        },
        "Judge": {
            "summary": (
                "Applied capability, custody, topology, mode, and identity policies "
                "without a model."
            ),
        },
    }
    governor = {
        "result": result,
        "reason": reason,
        "write_authorized": False,
        "model_required": False,
        "model_used": False,
        "passed_privates": sum(1 for item in privates if item.passed),
        "failed_privates": sum(1 for item in privates if not item.passed),
    }
    return LiveReviewReport("SRG 20-for-2 live corps", privates, officers, governor)
