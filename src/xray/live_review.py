from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Sequence

from .live_models import (
    DeviceEvent,
    EventKind,
    LivePrivateResult,
    LiveReviewReport,
    ProviderManifest,
    ProviderProbeResult,
)

Check = Callable[[dict[str, Any]], LivePrivateResult]


def _private(private_id: str, wave: int, assignment: str, passed: bool, findings: Sequence[str] = (), *, severity: str | None = None) -> LivePrivateResult:
    chosen = severity or ("info" if passed else "critical")
    return LivePrivateResult(private_id, wave, assignment, passed, chosen, tuple(findings))


def _event_integrity(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    passed = bool(event.observed_at and event.descriptor.os_path)
    return _private("private-001", 1, "Validate event timestamp and endpoint", passed, () if passed else ("missing timestamp or os_path",))


def _topology_capture(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    passed = bool(descriptor.topology_path)
    return _private("private-002", 1, "Capture physical USB/PnP topology", passed, () if passed else ("topology unavailable; correlation is weaker",), severity="warning" if not passed else None)


def _session_format(ctx: dict[str, Any]) -> LivePrivateResult:
    session_id = str(ctx["session"]["session_id"])
    passed = session_id.startswith("xray-device-") and len(session_id) == len("xray-device-") + 20
    return _private("private-003", 1, "Validate stable physical-device session ID", passed, () if passed else (f"invalid session ID: {session_id}",))


def _session_anchor(ctx: dict[str, Any]) -> LivePrivateResult:
    anchors = ctx["session"].get("anchors", [])
    passed = bool(anchors)
    return _private("private-004", 1, "Verify session correlation anchors", passed, () if passed else ("session has no stable anchors",), severity="warning" if not passed else None)


def _provider_manifest(ctx: dict[str, Any]) -> LivePrivateResult:
    manifests: Sequence[ProviderManifest] = ctx["manifests"]
    bad = [item.name for item in manifests if not item.read_only or not item.capabilities]
    return _private("private-005", 1, "Validate provider manifests", not bad, tuple(f"invalid manifest: {name}" for name in bad))


def _provider_support(ctx: dict[str, Any]) -> LivePrivateResult:
    results: Sequence[ProviderProbeResult] = ctx["providers"]
    unsupported = [item.provider for item in results if not item.supported]
    empty = [item.provider for item in results if item.supported and not item.envelopes and not item.errors]
    findings = [f"unsupported provider executed: {name}" for name in unsupported]
    findings.extend(f"provider returned no evidence: {name}" for name in empty)
    return _private("private-006", 1, "Confirm selected providers support the endpoint", not findings, tuple(findings))


def _envelope_hashes(ctx: dict[str, Any]) -> LivePrivateResult:
    envelopes = ctx["envelopes"]
    bad = [item.envelope_id for item in envelopes if not item.verify()]
    return _private("private-007", 1, "Verify raw evidence envelope hashes", not bad, tuple(f"hash failure: {item}" for item in bad))


def _timestamps(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [item.envelope_id for item in ctx["envelopes"] if item.command.get("completed_at", "") < item.command.get("started_at", "")]
    return _private("private-008", 1, "Check provider timestamp ordering", not bad, tuple(f"timestamp regression: {item}" for item in bad))


def _capability_contract(ctx: dict[str, Any]) -> LivePrivateResult:
    manifests = {item.name: item for item in ctx["manifests"]}
    bad: list[str] = []
    for envelope in ctx["envelopes"]:
        manifest = manifests.get(envelope.provider)
        declared = {item.value for item in manifest.capabilities} if manifest else set()
        if envelope.capability not in declared:
            bad.append(f"{envelope.provider}:{envelope.capability}")
    return _private("private-009", 1, "Cross-check envelope capabilities against manifests", not bad, tuple(f"undeclared capability: {item}" for item in bad))


def _write_boundary(ctx: dict[str, Any]) -> LivePrivateResult:
    forbidden = []
    for manifest in ctx["manifests"]:
        for capability in manifest.capabilities:
            if any(token in capability.value for token in ("write", "flash", "erase", "unlock", "format", "repair")):
                forbidden.append(f"{manifest.name}:{capability.value}")
    return _private("private-010", 1, "Enforce read-only authority boundary", not forbidden, tuple(forbidden))


def _session_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    expected = ctx["session"]["session_id"]
    bad = [item.envelope_id for item in ctx["envelopes"] if item.session_id != expected]
    return _private("private-011", 2, "Verify all providers used one physical-device session", not bad, tuple(f"foreign session envelope: {item}" for item in bad))


def _mode_consistency(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor_mode = ctx["event"].descriptor.mode
    observed = {
        str(value).upper()
        for result in ctx["providers"]
        for key, value in result.observations.items()
        if key == "transport.mode" and value
    }
    conflict = bool(descriptor_mode and observed and descriptor_mode.upper() not in observed)
    findings = (f"descriptor={descriptor_mode}, providers={sorted(observed)}",) if conflict else ()
    return _private("private-012", 2, "Challenge mode consistency across providers", not conflict, findings, severity="warning" if conflict else None)


def _adb_constraints(ctx: dict[str, Any]) -> LivePrivateResult:
    event = ctx["event"]
    adb = [item for item in ctx["providers"] if item.provider == "adb"]
    bad = bool(adb and not (event.descriptor.mode == "ADB" or event.descriptor.metadata.get("adb_serial")))
    return _private("private-013", 2, "Validate ADB transport selection", not bad, ("ADB provider ran without ADB evidence",) if bad else ())


def _fastboot_constraints(ctx: dict[str, Any]) -> LivePrivateResult:
    event = ctx["event"]
    fastboot = [item for item in ctx["providers"] if item.provider == "fastboot"]
    allowed = event.descriptor.mode in {"FASTBOOT", "FASTBOOTD", "RESCUE"} or event.descriptor.metadata.get("fastboot_serial")
    bad = bool(fastboot and not allowed)
    return _private("private-014", 2, "Validate Fastboot transport selection", not bad, ("Fastboot provider ran without Fastboot evidence",) if bad else ())


def _apple_pid_mode(ctx: dict[str, Any]) -> LivePrivateResult:
    descriptor = ctx["event"].descriptor
    expected = {"1227": "DFU", "1281": "RECOVERY"}.get(descriptor.pid or "") if descriptor.vid == "05AC" else None
    reported = {
        str(value).upper()
        for result in ctx["providers"]
        for key, value in result.observations.items()
        if key == "transport.mode" and result.provider.startswith("apple-")
    }
    bad = bool(expected and reported and expected not in reported)
    return _private("private-015", 2, "Cross-check Apple USB PID against Recovery/DFU mode", not bad, (f"PID expects {expected}, provider reports {sorted(reported)}",) if bad else ())


def _raw_custody(ctx: dict[str, Any]) -> LivePrivateResult:
    bad = [item.envelope_id for item in ctx["envelopes"] if not item.stdout_sha256 or not item.stderr_sha256 or not item.descriptor_sha256]
    return _private("private-016", 2, "Verify raw command and descriptor custody", not bad, tuple(f"missing custody hash: {item}" for item in bad))


def _topology_stability(ctx: dict[str, Any]) -> LivePrivateResult:
    event: DeviceEvent = ctx["event"]
    if event.kind != EventKind.MODE_TRANSITION or not event.previous:
        return _private("private-017", 2, "Verify topology stability across mode transitions", True)
    current = event.descriptor.topology_path
    previous = event.previous.topology_path
    passed = bool(current and previous and current == previous)
    return _private("private-017", 2, "Verify topology stability across mode transitions", passed, () if passed else (f"topology changed: {previous} -> {current}",), severity="warning" if not passed else None)


def _sensitive_declaration(ctx: dict[str, Any]) -> LivePrivateResult:
    bad: list[str] = []
    for item in ctx["envelopes"]:
        observations = item.observations
        has_sensitive = any(key in observations for key in ("apple.ecid", "apple.serial", "apple.nonce", "identity.fastboot_serial"))
        if has_sensitive and not item.sensitive_fields:
            bad.append(item.envelope_id)
    return _private("private-018", 2, "Verify sensitive identifier declarations", not bad, tuple(f"undeclared sensitive fields: {item}" for item in bad))


def _duplicate_envelopes(ctx: dict[str, Any]) -> LivePrivateResult:
    ids = [item.envelope_id for item in ctx["envelopes"]]
    duplicate = sorted({item for item in ids if ids.count(item) > 1})
    return _private("private-019", 2, "Reject duplicate evidence envelopes", not duplicate, tuple(f"duplicate envelope: {item}" for item in duplicate))


def _identity_gate(ctx: dict[str, Any]) -> LivePrivateResult:
    observations = {
        key: value
        for result in ctx["providers"]
        for key, value in result.observations.items()
    }
    missing_main = str(observations.get("firmware.main_version", "")).upper() == "NO MAIN VERSION"
    unreadable_vendor = str(observations.get("oeminfo.vendor_country", "")).upper() == "UNREADABLE"
    passed = not (missing_main or unreadable_vendor)
    findings: list[str] = []
    if missing_main:
        findings.append("device reports NO MAIN VERSION")
    if unreadable_vendor:
        findings.append("OEMINFO vendor/country is unreadable")
    return _private("private-020", 2, "Apply identity and recovery readback gate", passed, findings, severity="critical" if not passed else None)


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
)


def _run_wave(functions: Sequence[Check], ctx: dict[str, Any]) -> list[LivePrivateResult]:
    results: list[LivePrivateResult] = []
    with ThreadPoolExecutor(max_workers=10, thread_name_prefix="xray-live-private") as pool:
        futures = {pool.submit(function, ctx): function.__name__ for function in functions}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # isolate one private from the rest of the corps
                wave = 1 if function_index(name, WAVE_ONE) is not None else 2
                results.append(_private(f"failed:{name}", wave, name, False, (str(exc),)))
    return sorted(results, key=lambda item: (item.wave, item.private_id))


def function_index(name: str, functions: Sequence[Check]) -> int | None:
    """Return the position of a named private check, if present."""

    for index, function in enumerate(functions):
        if function.__name__ == name:
            return index
    return None


def review_live_event(
    *,
    event: DeviceEvent,
    session: dict[str, Any],
    manifests: Sequence[ProviderManifest],
    providers: Sequence[ProviderProbeResult],
) -> LiveReviewReport:
    """Run the dedicated model-free SRG 10-for-2 live review corps."""

    envelopes = tuple(envelope for result in providers for envelope in result.envelopes)
    context = {
        "event": event,
        "session": session,
        "manifests": tuple(manifests),
        "providers": tuple(providers),
        "envelopes": envelopes,
    }
    privates = tuple(_run_wave(WAVE_ONE, context) + _run_wave(WAVE_TWO, context))
    critical = [item for item in privates if not item.passed and item.severity == "critical"]
    warnings = [item for item in privates if not item.passed and item.severity == "warning"]
    provider_errors = [error for result in providers for error in result.errors]
    provider_warnings = [warning for result in providers for warning in result.warnings]
    if critical or provider_errors:
        result = "BLOCKED"
        reason = "A mandatory live evidence, provider, or identity gate failed."
    elif warnings or provider_warnings:
        result = "CONFLICTED"
        reason = "Live evidence is usable but provider, correlation, or mode evidence requires confirmation."
    else:
        result = "LIVE_READ_ONLY_READY"
        reason = "Live evidence collection and two-wave deterministic review completed."
    officers = {
        "Scout": {
            "summary": f"Observed {event.descriptor.vid or '????'}:{event.descriptor.pid or '????'} in {event.descriptor.mode or 'UNKNOWN'} mode.",
        },
        "Mechanic": {
            "summary": f"Executed {len(providers)} provider(s); provider errors={len(provider_errors)}, warnings={len(provider_warnings)}.",
            "errors": provider_errors,
            "warnings": provider_warnings,
        },
        "Quartermaster": {
            "summary": f"Registered {len(envelopes)} verified evidence envelope(s).",
            "envelope_ids": [item.envelope_id for item in envelopes],
        },
        "Engineer": {
            "summary": f"Session {session['session_id']} uses {len(session.get('anchors', []))} correlation anchor(s).",
        },
        "Medic": {
            "summary": "Read-only boundary remains active; no flash, erase, unlock, relock, format, or identity write capability exists.",
        },
        "Analyst": {
            "summary": f"SRG checks passed={sum(1 for item in privates if item.passed)}/20.",
        },
        "Challenger": {
            "summary": f"Raised {len(warnings) + len(provider_warnings)} warning(s) and {len(critical)} critical challenge(s).",
            "findings": [finding for item in privates if not item.passed for finding in item.findings] + provider_warnings,
        },
        "Judge": {
            "summary": "Applied capability, custody, topology, mode, and identity policies without a model.",
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
    return LiveReviewReport("SRG 10-for-2 live corps", privates, officers, governor)
