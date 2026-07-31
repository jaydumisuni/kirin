from __future__ import annotations

from typing import Any, Callable
from .common import _ev
from .models import Evidence, PrivateResult


def _private_variant_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    observed_model = context.get("observed_model")
    external_model = context.get("external_model")
    if observed_model and external_model:
        status = "MATCH" if observed_model.casefold() == external_model.casefold() else "MISMATCH"
        evidence.append(_ev("review.variant_match", status, "private.variant-guard", observed=False, confidence=1.0))
        if status == "MISMATCH":
            warnings.append(f"External claim applies to {external_model}, while the device reports {observed_model}.")
    return PrivateResult("private-011", 2, "Challenge model/SKU transitivity", tuple(evidence), tuple(warnings))


def _private_loader_truth_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    loader = context.get("loader_profile")
    if loader:
        evidence.append(_ev("review.loader_is_compatibility_only", "true", "private.loader-truth-guard", observed=False))
        warnings.append(f"{loader} proves loader compatibility, not exact physical silicon identity.")
    return PrivateResult("private-012", 2, "Prevent loader profile from becoming silicon truth", tuple(evidence), tuple(warnings))


def _private_main_version_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    warnings: list[str] = []
    evidence: list[Evidence] = []
    if str(context.get("main_version", "")).upper() == "NO MAIN VERSION":
        evidence.append(_ev("review.identity_gate", "BLOCKED", "private.main-version-guard", observed=False))
        warnings.append("Identity-dependent operations are blocked until main-version readback is restored.")
    return PrivateResult("private-013", 2, "Enforce main-version identity gate", tuple(evidence), tuple(warnings))


def _private_apple_mode_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    vid = str(context.get("usb_vid", "")).upper()
    pid = str(context.get("usb_pid", "")).upper()
    knowledge = context["knowledge"]
    if vid == "05AC":
        mapped = knowledge.get("apple_usb_modes", {}).get(pid)
        if mapped:
            evidence.append(_ev("apple.usb_mode", mapped, "private.apple-mode-guard", source_class="device_read", excerpt=f"VID={vid} PID={pid}"))
        else:
            warnings.append(f"Apple USB device detected with unmapped PID {pid or 'UNKNOWN'}.")
    return PrivateResult("private-014", 2, "Resolve Apple USB mode without assuming product model", tuple(evidence), tuple(warnings))


def _private_model_source_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    model = context.get("observed_model")
    if model:
        evidence.append(_ev("review.model_source", "device_partition_or_protocol", "private.model-source-guard", observed=False))
    return PrivateResult("private-015", 2, "Label model provenance", tuple(evidence))


def _private_soc_proof_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    proof_keys = [
        "hardware.silicon_id",
        "hardware.bootrom_id",
        "hardware.cpu_signature",
        "hardware.gpu_signature",
    ]
    present = [key for key in proof_keys if context.get("all_values", {}).get(key)]
    evidence.append(_ev("review.exact_soc_proof_count", len(present), "private.soc-proof-guard", observed=False))
    if not present:
        warnings.append("Exact SoC cannot be certified: no silicon ID, BootROM ID, CPU signature, or GPU signature is present.")
    return PrivateResult("private-016", 2, "Enforce exact-SoC proof policy", tuple(evidence), tuple(warnings))


def _private_write_safety_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence = (_ev("policy.write_authorized", "false", "private.write-safety-guard", observed=False),)
    return PrivateResult(
        "private-017",
        2,
        "Enforce read-only first-run boundary",
        evidence,
        ("Xray first-run cannot authorize flashing, erase, unlock, relock, format, identity repair, or partition writes.",),
    )


def _private_correlation_guard(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    identifiers = [context.get("usb_vid"), context.get("usb_pid"), context.get("observed_model"), context.get("artifact_sha")]
    count = sum(1 for value in identifiers if value)
    evidence.append(_ev("review.correlation_identifiers", count, "private.correlation-guard", observed=False))
    warnings: list[str] = []
    if count < 2:
        warnings.append("Cross-mode physical-device correlation is weak; retain USB topology and timing in live providers.")
    return PrivateResult("private-018", 2, "Assess physical-device correlation strength", tuple(evidence), tuple(warnings))


def _private_parser_consistency(text: str, context: dict[str, Any]) -> PrivateResult:
    warnings: list[str] = []
    evidence: list[Evidence] = []
    modes = set(context.get("all_values", {}).get("transport.mode", [])) | set(context.get("all_values", {}).get("apple.usb_mode", []))
    candidates = set(context.get("all_values", {}).get("transport.mode_candidate", []))
    hard = {item.upper() for item in modes if item}
    soft = {item.upper() for item in candidates if item}
    conflict = bool(hard and soft and not (hard & soft))
    evidence.append(_ev("review.parser_conflict", str(conflict).lower(), "private.parser-consistency", observed=False))
    if conflict:
        warnings.append(f"Mode parsers disagree: direct={sorted(hard)}, candidates={sorted(soft)}")
    return PrivateResult("private-019", 2, "Cross-check independent parser outputs", tuple(evidence), tuple(warnings))


def _private_report_integrity(text: str, context: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    required = ["artifact.sha256", "artifact.bytes", "artifact.name"]
    missing = [key for key in required if not context.get("all_values", {}).get(key)]
    evidence.append(_ev("review.report_integrity", "PASS" if not missing else "FAIL", "private.report-integrity", observed=False))
    warnings = tuple([f"Missing custody field: {key}" for key in missing])
    return PrivateResult("private-020", 2, "Verify evidence-envelope integrity", tuple(evidence), warnings)


WAVE_TWO: tuple[Callable[[str, dict[str, Any]], PrivateResult], ...] = (
    _private_variant_guard,
    _private_loader_truth_guard,
    _private_main_version_guard,
    _private_apple_mode_guard,
    _private_model_source_guard,
    _private_soc_proof_guard,
    _private_write_safety_guard,
    _private_correlation_guard,
    _private_parser_consistency,
    _private_report_integrity,
)
