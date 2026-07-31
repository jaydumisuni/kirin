from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

VERSION = "0.1.0"
SCHEMA = "xray-report-v1"


class Status(str, Enum):
    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    CONFLICTED = "CONFLICTED"
    CERTIFIED = "CERTIFIED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Evidence:
    key: str
    value: str
    source: str
    source_class: str
    observed: bool = True
    confidence: float = 1.0
    excerpt: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PrivateResult:
    private_id: str
    wave: int
    assignment: str
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class Claim:
    name: str
    value: str | None
    status: Status
    score: int
    supporting_evidence: tuple[str, ...] = ()
    contradictions: tuple[str, ...] = ()
    missing_proof: tuple[str, ...] = ()
    note: str = ""


@dataclass(frozen=True)
class OfficerReport:
    officer: str
    summary: str
    severity: str = "info"
    evidence_keys: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()


@dataclass
class XrayReport:
    session_id: str
    created_at: str
    schema: str
    xray_version: str
    artifact: dict[str, Any]
    workforce: dict[str, Any]
    evidence: list[Evidence]
    claims: list[Claim]
    officers: list[OfficerReport]
    governor_verdict: dict[str, Any]
    provider_expectations: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for claim in result["claims"]:
            claim["status"] = claim["status"].value if isinstance(claim["status"], Status) else claim["status"]
        return result


class KnowledgeError(RuntimeError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _project_root() -> Path:
    explicit = os.environ.get("XRAY_PROJECT_ROOT")
    if explicit:
        return Path(explicit).resolve()
    here = Path(__file__).resolve()
    for candidate in [here.parents[2], here.parents[1], Path.cwd()]:
        if (candidate / "knowledge" / "base.json").is_file():
            return candidate
    return here.parents[2]


def load_knowledge(path: str | Path | None = None) -> dict[str, Any]:
    target = Path(path) if path else _project_root() / "knowledge" / "base.json"
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KnowledgeError(f"Cannot load knowledge pack {target}: {exc}") from exc
    if payload.get("schema") != "xray-knowledge-v1":
        raise KnowledgeError(f"Unsupported knowledge schema in {target}")
    required = {"source_weights", "usb_signatures", "proof_policies", "expected_apple_providers"}
    missing = sorted(required - payload.keys())
    if missing:
        raise KnowledgeError(f"Knowledge pack missing keys: {', '.join(missing)}")
    return payload


def _ev(
    key: str,
    value: Any,
    source: str,
    source_class: str = "device_read",
    *,
    confidence: float = 1.0,
    excerpt: str = "",
    observed: bool = True,
    metadata: Mapping[str, Any] | None = None,
) -> Evidence:
    return Evidence(
        key=key,
        value=str(value).strip(),
        source=source,
        source_class=source_class,
        observed=observed,
        confidence=max(0.0, min(1.0, confidence)),
        excerpt=excerpt.strip(),
        metadata=dict(metadata or {}),
    )


def _first_value(evidence: Sequence[Evidence], key: str) -> str | None:
    for item in evidence:
        if item.key == key and item.value:
            return item.value
    return None


def _values(evidence: Sequence[Evidence], key: str) -> list[str]:
    seen: list[str] = []
    for item in evidence:
        if item.key == key and item.value not in seen:
            seen.append(item.value)
    return seen


def _has_value(evidence: Sequence[Evidence], key: str, value: str | None = None) -> bool:
    for item in evidence:
        if item.key != key:
            continue
        if value is None or item.value.casefold() == value.casefold():
            return True
    return False


def _line_match(pattern: str, text: str, flags: int = re.IGNORECASE | re.MULTILINE) -> re.Match[str] | None:
    return re.search(pattern, text, flags)


def _extract_kv(text: str, label: str) -> tuple[str, str] | None:
    match = _line_match(rf"^\s*{re.escape(label)}\s*:\s*(.*?)\s*$", text)
    if not match:
        return None
    return match.group(1), match.group(0)


def _private_usb_fingerprint(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    for match in re.finditer(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", text):
        evidence.append(_ev("usb.vid", match.group(1).upper(), "private.usb-fingerprint", excerpt=match.group(0)))
        evidence.append(_ev("usb.pid", match.group(2).upper(), "private.usb-fingerprint", excerpt=match.group(0)))
    for label, key in [("Port", "transport.port"), ("Driver", "transport.driver")]:
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.usb-fingerprint", excerpt=found[1]))
    match = _line_match(r"Device found at\s+([^\r\n]+)", text)
    if match:
        evidence.append(_ev("transport.endpoint", match.group(1), "private.usb-fingerprint", excerpt=match.group(0)))
    return PrivateResult("private-001", 1, "Enumerate USB identity", tuple(evidence))


def _private_mode_detector(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    for label in ("Port type", "MODE", "Mode"):
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev("transport.mode", found[0].upper(), "private.mode-detector", excerpt=found[1]))
    markers = [
        (r"\bBROM\b", "BROM"),
        (r"\bFASTBOOT\b", "FASTBOOT"),
        (r"\bDFU\b", "DFU"),
        (r"\bRECOVERY\b", "RECOVERY"),
        (r"\bDOWNLOAD MODE\b", "DOWNLOAD"),
        (r"\bPRELOADER\b", "PRELOADER"),
        (r"\bEDL\b", "EDL"),
    ]
    for pattern, value in markers:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev("transport.mode_candidate", value, "private.mode-detector", confidence=0.75, excerpt=match.group(0)))
    return PrivateResult("private-002", 1, "Detect active device mode", tuple(evidence))


def _private_android_identity(text: str, _: dict[str, Any]) -> PrivateResult:
    mapping = {
        "Product Brand": "product.brand",
        "Product Manufacturer": "product.manufacturer",
        "Product Model": "product.model",
        "Product Name": "product.name",
        "Product Device": "product.device",
        "Product Board": "product.board",
        "Board Platform": "hardware.bsp_platform",
        "Build ID": "os.build_id",
        "Build Date": "os.build_date",
        "Display ID": "os.display_id",
        "Security Patch": "os.security_patch",
        "Version SDK": "os.sdk",
        "Version Release": "os.release",
        "Version Codename": "os.codename",
        "Firmware Version": "firmware.version",
        "Userdata FS Type": "storage.userdata_fs",
    }
    evidence: list[Evidence] = []
    for label, key in mapping.items():
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.android-identity", excerpt=found[1]))
    return PrivateResult("private-003", 1, "Read Android product and build identity", tuple(evidence))


def _private_apple_identity(text: str, _: dict[str, Any]) -> PrivateResult:
    mapping = {
        "CPID": "apple.cpid",
        "BDID": "apple.bdid",
        "ECID": "apple.ecid",
        "PRODUCT": "apple.product_type",
        "MODEL": "apple.model",
        "NAME": "apple.name",
        "SRNM": "apple.serial",
        "NONC": "apple.nonce",
    }
    evidence: list[Evidence] = []
    for label, key in mapping.items():
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.apple-identity", excerpt=found[1]))
    if _line_match(r"Apple Mobile Device", text):
        evidence.append(_ev("product.family_hint", "Apple", "private.apple-identity", confidence=0.9, excerpt="Apple Mobile Device"))
    return PrivateResult("private-004", 1, "Read Apple recovery and product identity", tuple(evidence))


def _private_huawei_rescue(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    match = _line_match(r"rescue_phoneinfo\s*:\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        evidence.append(_ev("firmware.main_version", value, "private.huawei-rescue", excerpt=match.group(0)))
        if value.upper() == "NO MAIN VERSION":
            warnings.append("Huawei main-version identity is absent or unreadable.")
    match = _line_match(r"vendorcountry\s*:\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        if "cannot get vendorcountry" in value.casefold() or "unreadable" in value.casefold():
            value = "UNREADABLE"
            warnings.append("Huawei OEMINFO vendor/country is unreadable.")
        evidence.append(_ev("oeminfo.vendor_country", value, "private.huawei-rescue", excerpt=match.group(0)))
    elif _line_match(r"cannot get vendorcountry in oeminfo", text):
        evidence.append(_ev("oeminfo.vendor_country", "UNREADABLE", "private.huawei-rescue", excerpt="cannot get vendorcountry in oeminfo"))
        warnings.append("Huawei OEMINFO vendor/country is unreadable.")
    match = _line_match(r"(?:oem get-bootinfo|bootinfo)\s*:\s*([^\r\n]+)", text)
    if match:
        evidence.append(_ev("security.bootloader", match.group(1), "private.huawei-rescue", excerpt=match.group(0)))
    match = _line_match(r"FASTBOOT_PRODUCT\s*:\s*([^\r\n]+)", text)
    if match:
        evidence.append(_ev("hardware.fastboot_product", match.group(1), "private.huawei-rescue", excerpt=match.group(0)))
    return PrivateResult("private-005", 1, "Read Huawei rescue/OEMINFO state", tuple(evidence), tuple(warnings))


def _private_unisoc_bootrom(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    for label, key, source_class in [
        ("Selected processor", "transport.loader_profile", "loader_compatibility"),
        ("Flash Type", "storage.type", "device_read"),
    ]:
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.unisoc-bootrom", source_class, excerpt=found[1]))
    for stage in ["Connecting to device", "Connect preloader 1", "Connect preloader 2", "Connect loader 1", "Connect loader 2", "Read partitions info"]:
        match = _line_match(rf"^{re.escape(stage)}\.{{0,3}}\s*(OK[^\r\n]*)", text)
        if match:
            evidence.append(_ev("transport.handshake", f"{stage}: {match.group(1)}", "private.unisoc-bootrom", excerpt=match.group(0)))
    return PrivateResult("private-006", 1, "Read UNISOC BootROM and loader compatibility", tuple(evidence))


def _private_storage(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    patterns = [
        (r"Flash Type\s*:\s*([^\r\n]+)", "storage.type"),
        (r"Userdata FS Type\s*:\s*([^\r\n]+)", "storage.userdata_fs"),
        (r"Checking A/B state\.\.\.\s*OK\s*\[([^\]]+)\]", "partition.active_slot"),
        (r"Read product info\.\.\.\s*\[([^\]]+)\]", "partition.product_fs"),
    ]
    for pattern, key in patterns:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev(key, match.group(1), "private.storage", excerpt=match.group(0)))
    return PrivateResult("private-007", 1, "Inspect storage and partition state", tuple(evidence))


def _private_security(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    warnings: list[str] = []
    match = _line_match(r"Read IMEI\.\.\.\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        evidence.append(_ev("identity.imei_read", value, "private.security", excerpt=match.group(0)))
        if "error" in value.casefold():
            warnings.append("IMEI read failed; identity-related conclusions remain incomplete.")
    if _line_match(r"bootloader.*unlocked|bootinfo\s*:\s*unlocked", text):
        evidence.append(_ev("security.bootloader", "unlocked", "private.security", excerpt="bootloader unlocked"))
    if _line_match(r"security patch", text):
        found = _extract_kv(text, "Security Patch")
        if found:
            evidence.append(_ev("os.security_patch", found[0], "private.security", excerpt=found[1]))
    return PrivateResult("private-008", 1, "Inspect security and protected identity readback", tuple(evidence), tuple(warnings))


def _private_versions(text: str, _: dict[str, Any]) -> PrivateResult:
    evidence: list[Evidence] = []
    patterns = [
        (r"\bAndroid\s+([0-9]+(?:\.[0-9]+)*)\b", "os.release"),
        (r"\bEMUI\s*([0-9]+(?:\.[0-9]+)*)", "os.emui"),
        (r"\b(?:iOS|ProductVersion)\s*[:=]?\s*([0-9]+(?:\.[0-9]+)+)", "os.apple_version"),
        (r"\b(?:Build Version|Build)\s*:\s*([^\r\n]+)", "firmware.build"),
    ]
    for pattern, key in patterns:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev(key, match.group(1), "private.versions", excerpt=match.group(0)))
    return PrivateResult("private-009", 1, "Read version and firmware identifiers", tuple(evidence))


def _private_artifact(text: str, context: dict[str, Any]) -> PrivateResult:
    encoded = text.encode("utf-8", errors="replace")
    evidence = (
        _ev("artifact.sha256", hashlib.sha256(encoded).hexdigest(), "private.artifact-custody", source_class="artifact_custody"),
        _ev("artifact.bytes", len(encoded), "private.artifact-custody"),
        _ev("artifact.name", context.get("artifact_name", "stdin"), "private.artifact-custody"),
    )
    return PrivateResult("private-010", 1, "Hash and register source artifact", evidence)


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


WAVE_ONE: tuple[Callable[[str, dict[str, Any]], PrivateResult], ...] = (
    _private_usb_fingerprint,
    _private_mode_detector,
    _private_android_identity,
    _private_apple_identity,
    _private_huawei_rescue,
    _private_unisoc_bootrom,
    _private_storage,
    _private_security,
    _private_versions,
    _private_artifact,
)

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


def _run_wave(
    functions: Sequence[Callable[[str, dict[str, Any]], PrivateResult]],
    text: str,
    context: dict[str, Any],
) -> list[PrivateResult]:
    results: list[PrivateResult] = []
    with ThreadPoolExecutor(max_workers=10, thread_name_prefix="xray-private") as pool:
        futures = {pool.submit(func, text, context): func.__name__ for func in functions}
        for future in as_completed(futures):
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # defensive isolation between privates
                results.append(PrivateResult(f"failed:{name}", context.get("wave", 0), name, errors=(str(exc),)))
    return sorted(results, key=lambda item: item.private_id)


def _all_values(evidence: Sequence[Evidence]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for item in evidence:
        result.setdefault(item.key, [])
        if item.value not in result[item.key]:
            result[item.key].append(item.value)
    return result


def _parse_external_claim(raw: str) -> dict[str, str]:
    # key=value|source_class|applies_to_model
    if "=" not in raw:
        raise ValueError("External claims use key=value|source_class|model")
    key, tail = raw.split("=", 1)
    parts = tail.split("|")
    return {
        "key": key.strip(),
        "value": parts[0].strip(),
        "source_class": (parts[1].strip() if len(parts) > 1 and parts[1].strip() else "unsourced"),
        "applies_to_model": (parts[2].strip() if len(parts) > 2 else ""),
    }


def _external_evidence(claims: Sequence[Mapping[str, str]]) -> list[Evidence]:
    output: list[Evidence] = []
    for index, claim in enumerate(claims, start=1):
        key = claim.get("key", "").strip()
        value = claim.get("value", "").strip()
        if not key or not value:
            continue
        output.append(
            _ev(
                key,
                value,
                f"external-claim-{index}",
                claim.get("source_class", "unsourced"),
                observed=False,
                confidence=0.5,
                metadata={"applies_to_model": claim.get("applies_to_model", "")},
            )
        )
    return output


def _context_from_evidence(evidence: Sequence[Evidence], knowledge: dict[str, Any], artifact_name: str) -> dict[str, Any]:
    values = _all_values(evidence)
    external_models = [
        item.metadata.get("applies_to_model", "")
        for item in evidence
        if not item.observed and item.metadata.get("applies_to_model")
    ]
    return {
        "wave": 2,
        "artifact_name": artifact_name,
        "knowledge": knowledge,
        "all_values": values,
        "observed_model": _first_value(evidence, "product.model") or _first_value(evidence, "apple.product_type"),
        "external_model": external_models[0] if external_models else None,
        "loader_profile": _first_value(evidence, "transport.loader_profile"),
        "main_version": _first_value(evidence, "firmware.main_version"),
        "usb_vid": _first_value(evidence, "usb.vid"),
        "usb_pid": _first_value(evidence, "usb.pid"),
        "artifact_sha": _first_value(evidence, "artifact.sha256"),
    }


def _source_score(items: Iterable[Evidence], knowledge: dict[str, Any]) -> int:
    weights = knowledge["source_weights"]
    # Independent sources count once. Multiple parsers of one artifact do not manufacture confidence.
    strongest_by_source: dict[str, int] = {}
    for item in items:
        weight = int(weights.get(item.source_class, 0))
        strongest_by_source[item.source] = max(strongest_by_source.get(item.source, 0), weight)
    return min(100, sum(strongest_by_source.values()))


def _build_claims(evidence: Sequence[Evidence], knowledge: dict[str, Any]) -> list[Claim]:
    claims: list[Claim] = []
    values = _all_values(evidence)

    vid = _first_value(evidence, "usb.vid")
    family_support: list[Evidence] = []
    family_value: str | None = None
    if vid:
        for signature in knowledge["usb_signatures"]:
            if signature["vid"].upper() == vid.upper():
                family_value = signature["family"]
                family_support.extend([item for item in evidence if item.key == "usb.vid"])
                break
    brand = _first_value(evidence, "product.brand") or _first_value(evidence, "product.manufacturer")
    if not family_value and brand:
        family_value = brand
        family_support.extend([item for item in evidence if item.key in {"product.brand", "product.manufacturer"}])
    if family_value:
        score = max(80 if vid else 60, _source_score(family_support, knowledge))
        claims.append(
            Claim(
                "device.family",
                family_value,
                Status.CERTIFIED if vid else Status.CORROBORATED,
                score,
                tuple(sorted({item.key for item in family_support})),
                note="Family is resolved independently from exact product model or SoC.",
            )
        )
    else:
        claims.append(Claim("device.family", None, Status.UNKNOWN, 0, missing_proof=("usb.vid", "protocol identity")))

    mode = _first_value(evidence, "transport.mode") or _first_value(evidence, "apple.usb_mode")
    mode_candidates = _values(evidence, "transport.mode_candidate")
    if mode:
        contradictions = tuple(candidate for candidate in mode_candidates if candidate.upper() != mode.upper())
        status = Status.CONFLICTED if contradictions else Status.CERTIFIED
        claims.append(
            Claim(
                "transport.mode",
                mode.upper(),
                status,
                95 if not contradictions else 45,
                tuple(sorted({item.key for item in evidence if item.key in {"transport.mode", "apple.usb_mode", "usb.pid"}})),
                contradictions,
            )
        )
    elif mode_candidates:
        unique = sorted(set(mode_candidates))
        status = Status.INFERRED if len(unique) == 1 else Status.CONFLICTED
        claims.append(Claim("transport.mode", unique[0] if len(unique) == 1 else None, status, 45, ("transport.mode_candidate",), tuple(unique[1:])))
    else:
        claims.append(Claim("transport.mode", None, Status.UNKNOWN, 0, missing_proof=("mode handshake",)))

    model_values = []
    for key in ("product.model", "product.device", "product.board", "apple.product_type"):
        model_values.extend(values.get(key, []))
    model_values = list(dict.fromkeys(model_values))
    if model_values:
        primary = _first_value(evidence, "product.model") or _first_value(evidence, "apple.product_type") or model_values[0]
        aliases = [item for item in model_values if item != primary]
        status = Status.CORROBORATED if len(model_values) >= 2 else Status.OBSERVED
        claims.append(
            Claim(
                "device.reported_model",
                primary,
                status,
                70 if status == Status.CORROBORATED else 60,
                tuple(key for key in ("product.model", "product.device", "product.board", "apple.product_type") if values.get(key)),
                note=(f"Related identifiers: {', '.join(aliases)}" if aliases else "Reported by one device-side source."),
            )
        )
    else:
        claims.append(Claim("device.reported_model", None, Status.UNKNOWN, 0, missing_proof=("product/model readback",)))

    loader = _first_value(evidence, "transport.loader_profile")
    if loader:
        claims.append(
            Claim(
                "hardware.loader_compatibility",
                loader,
                Status.OBSERVED,
                5,
                ("transport.loader_profile", "transport.handshake"),
                note="A working loader profile is compatibility evidence only.",
            )
        )

    bsp = _first_value(evidence, "hardware.bsp_platform")
    if bsp:
        claims.append(Claim("hardware.bsp_platform", bsp, Status.OBSERVED, 60, ("hardware.bsp_platform",)))

    marketed_soc_evidence = [item for item in evidence if item.key in {"hardware.marketed_soc", "hardware.exact_soc"}]
    direct_soc_keys = [
        "hardware.silicon_id",
        "hardware.bootrom_id",
        "hardware.cpu_signature",
        "hardware.gpu_signature",
    ]
    direct_soc = [item for item in evidence if item.key in direct_soc_keys]
    soc_value = marketed_soc_evidence[0].value if marketed_soc_evidence else None
    missing_soc = tuple(key for key in direct_soc_keys if not values.get(key))
    contradictions: list[str] = []
    observed_model = _first_value(evidence, "product.model") or _first_value(evidence, "apple.product_type")
    for item in marketed_soc_evidence:
        applies = item.metadata.get("applies_to_model")
        if applies and observed_model and applies.casefold() != observed_model.casefold():
            contradictions.append(f"Claim applies to {applies}; device reports {observed_model}")
    if direct_soc:
        exact_value = _first_value(evidence, "hardware.exact_soc") or soc_value or _first_value(evidence, "hardware.silicon_id")
        score = _source_score(direct_soc + marketed_soc_evidence, knowledge)
        claims.append(
            Claim(
                "hardware.exact_soc",
                exact_value,
                Status.CONFLICTED if contradictions else Status.CERTIFIED,
                score,
                tuple(sorted({item.key for item in direct_soc + marketed_soc_evidence})),
                tuple(contradictions),
            )
        )
    elif soc_value:
        score = _source_score(marketed_soc_evidence, knowledge)
        if loader:
            score = min(69, score + 5)
        status = Status.CONFLICTED if contradictions else Status.INFERRED
        claims.append(
            Claim(
                "hardware.exact_soc",
                soc_value,
                status,
                score,
                tuple(sorted({item.key for item in marketed_soc_evidence} | ({"transport.loader_profile"} if loader else set()))),
                tuple(contradictions),
                missing_soc,
                "External or compatibility evidence cannot certify physical silicon.",
            )
        )
    elif loader or bsp:
        claims.append(
            Claim(
                "hardware.exact_soc",
                None,
                Status.UNKNOWN,
                5 if loader else 0,
                tuple(key for key in ("transport.loader_profile", "hardware.bsp_platform") if values.get(key)),
                missing_proof=missing_soc,
                note="Xray deliberately separates loader/BSP identity from exact silicon.",
            )
        )

    main_version = _first_value(evidence, "firmware.main_version")
    vendor_country = _first_value(evidence, "oeminfo.vendor_country")
    if main_version:
        if main_version.upper() == "NO MAIN VERSION":
            claims.append(
                Claim(
                    "firmware.main_version",
                    None,
                    Status.BLOCKED,
                    100,
                    ("firmware.main_version",),
                    ("Device explicitly reports NO MAIN VERSION",),
                    ("readable OEMINFO/main-version identity",),
                )
            )
        else:
            claims.append(Claim("firmware.main_version", main_version, Status.OBSERVED, 80, ("firmware.main_version",)))
    if vendor_country:
        status = Status.BLOCKED if vendor_country.upper() == "UNREADABLE" else Status.OBSERVED
        claims.append(Claim("oeminfo.vendor_country", None if status == Status.BLOCKED else vendor_country, status, 80, ("oeminfo.vendor_country",)))

    cpid = _first_value(evidence, "apple.cpid")
    if cpid:
        claims.append(
            Claim(
                "apple.cpid",
                cpid,
                Status.OBSERVED,
                90,
                ("apple.cpid",),
                note="CPID is preserved separately from marketed model naming.",
            )
        )

    return claims


def _build_officers(
    evidence: Sequence[Evidence],
    claims: Sequence[Claim],
    private_results: Sequence[PrivateResult],
) -> list[OfficerReport]:
    warnings = [warning for result in private_results for warning in result.warnings]
    errors = [error for result in private_results for error in result.errors]
    values = _all_values(evidence)
    claim_by_name = {claim.name: claim for claim in claims}

    scout_summary = f"Family={claim_by_name['device.family'].value or 'unknown'}, mode={claim_by_name['transport.mode'].value or 'unknown'}, model={claim_by_name['device.reported_model'].value or 'unknown'}."
    reports = [
        OfficerReport("Scout", scout_summary, evidence_keys=("usb.vid", "usb.pid", "transport.mode", "product.model", "apple.product_type")),
        OfficerReport(
            "Mechanic",
            f"Detected {len(values.get('transport.handshake', []))} successful handshake stage(s); transport endpoint={_first_value(evidence, 'transport.endpoint') or 'not reported'}.",
            severity="warning" if not values.get("transport.handshake") and claim_by_name["transport.mode"].status == Status.UNKNOWN else "info",
            evidence_keys=("transport.handshake", "transport.driver", "transport.port"),
        ),
        OfficerReport(
            "Quartermaster",
            f"Artifact {_first_value(evidence, 'artifact.name') or 'unknown'} registered with SHA-256 {_first_value(evidence, 'artifact.sha256') or 'missing'}.",
            severity="critical" if not values.get("artifact.sha256") else "info",
            evidence_keys=("artifact.sha256", "artifact.bytes", "artifact.name"),
        ),
        OfficerReport(
            "Engineer",
            f"BSP={_first_value(evidence, 'hardware.bsp_platform') or 'unknown'}, storage={_first_value(evidence, 'storage.type') or 'unknown'}, active slot={_first_value(evidence, 'partition.active_slot') or 'unknown'}.",
            evidence_keys=("hardware.bsp_platform", "storage.type", "partition.active_slot", "partition.product_fs"),
        ),
        OfficerReport(
            "Medic",
            "Read-only preservation gate active. " + ("Critical identity/readback issue detected." if any(claim.status == Status.BLOCKED for claim in claims) else "No write action is authorized by this runtime."),
            severity="critical" if any(claim.status == Status.BLOCKED for claim in claims) else "warning",
            evidence_keys=("identity.imei_read", "firmware.main_version", "policy.write_authorized"),
            blockers=tuple(claim.name for claim in claims if claim.status == Status.BLOCKED),
        ),
        OfficerReport(
            "Analyst",
            f"Built {len(claims)} typed claim(s); exact-SoC status={claim_by_name.get('hardware.exact_soc', Claim('', None, Status.UNKNOWN, 0)).status.value}.",
            evidence_keys=tuple(sorted({item.key for item in evidence})),
        ),
        OfficerReport(
            "Challenger",
            f"Raised {len(warnings)} limitation/challenge notice(s).",
            severity="warning" if warnings else "info",
            blockers=tuple(warnings),
            next_actions=tuple(
                claim_missing
                for claim in claims
                for claim_missing in claim.missing_proof
                if claim_missing
            )[:12],
        ),
        OfficerReport(
            "Judge",
            "Applied deterministic proof policies; models were not used and cannot set certification or write authority.",
            severity="critical" if errors else "info",
            blockers=tuple(errors),
        ),
    ]
    return reports


def _governor_verdict(claims: Sequence[Claim], private_results: Sequence[PrivateResult]) -> dict[str, Any]:
    statuses = {claim.status for claim in claims}
    errors = [error for result in private_results for error in result.errors]
    if errors:
        result = "BLOCKED"
        reason = "One or more governed workers failed."
    elif Status.BLOCKED in statuses:
        result = "BLOCKED"
        reason = "A mandatory identity or safety gate failed."
    elif Status.CONFLICTED in statuses:
        result = "CONFLICTED"
        reason = "Credible evidence disagrees; further discriminating reads are required."
    else:
        result = "READ_ONLY_READY"
        reason = "Evidence collection and deterministic review completed. No write action is authorized."
    return {
        "result": result,
        "reason": reason,
        "write_authorized": False,
        "model_required": False,
        "model_used": False,
        "certified_claims": [claim.name for claim in claims if claim.status == Status.CERTIFIED],
        "blocked_claims": [claim.name for claim in claims if claim.status == Status.BLOCKED],
        "conflicted_claims": [claim.name for claim in claims if claim.status == Status.CONFLICTED],
    }


def inspect_text(
    text: str,
    *,
    artifact_name: str = "stdin",
    external_claims: Sequence[Mapping[str, str]] | None = None,
    knowledge_path: str | Path | None = None,
) -> XrayReport:
    knowledge = load_knowledge(knowledge_path)
    wave1_context = {"wave": 1, "artifact_name": artifact_name, "knowledge": knowledge}
    wave1 = _run_wave(WAVE_ONE, text, wave1_context)
    evidence = [item for result in wave1 for item in result.evidence]
    evidence.extend(_external_evidence(external_claims or ()))

    wave2_context = _context_from_evidence(evidence, knowledge, artifact_name)
    wave2 = _run_wave(WAVE_TWO, text, wave2_context)
    evidence.extend(item for result in wave2 for item in result.evidence)

    private_results = wave1 + wave2
    claims = _build_claims(evidence, knowledge)
    officers = _build_officers(evidence, claims, private_results)
    governor = _governor_verdict(claims, private_results)
    officers.append(
        OfficerReport(
            "Governor",
            f"Verdict={governor['result']}. {governor['reason']}",
            severity="critical" if governor["result"] == "BLOCKED" else ("warning" if governor["result"] == "CONFLICTED" else "info"),
            blockers=tuple(governor["blocked_claims"] + governor["conflicted_claims"]),
        )
    )

    return XrayReport(
        session_id=f"xray-{uuid.uuid4().hex[:16]}",
        created_at=_utc_now(),
        schema=SCHEMA,
        xray_version=VERSION,
        artifact={
            "name": artifact_name,
            "bytes": len(text.encode("utf-8", errors="replace")),
            "sha256": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest(),
        },
        workforce={
            "method": "SRG 10-for-2",
            "waves": 2,
            "privates_per_wave": 10,
            "total_privates": 20,
            "completed": sum(1 for item in private_results if not item.errors),
            "failed": sum(1 for item in private_results if item.errors),
            "assignments": [asdict(item) for item in private_results],
        },
        evidence=evidence,
        claims=claims,
        officers=officers,
        governor_verdict=governor,
        provider_expectations={
            "apple": knowledge["expected_apple_providers"],
            "current_runtime": "cross-platform read-only CLI",
            "future_edges": ["Android host APK", "Android probe APK", "Windows", "macOS", "Linux", "web/native bridge"],
        },
    )


def _report_text(report: XrayReport) -> str:
    lines = [
        f"Xray {report.xray_version} — {report.governor_verdict['result']}",
        f"Session: {report.session_id}",
        f"Artifact: {report.artifact['name']} ({report.artifact['bytes']} bytes)",
        f"SHA-256: {report.artifact['sha256']}",
        f"Workforce: {report.workforce['total_privates']} privates in {report.workforce['waves']} waves",
        "",
        "Claims",
        "------",
    ]
    for claim in report.claims:
        value = claim.value if claim.value is not None else "unknown"
        lines.append(f"{claim.name}: {value} [{claim.status.value}, score={claim.score}]")
        if claim.contradictions:
            lines.append(f"  contradictions: {'; '.join(claim.contradictions)}")
        if claim.missing_proof:
            lines.append(f"  missing proof: {', '.join(claim.missing_proof)}")
        if claim.note:
            lines.append(f"  note: {claim.note}")
    lines.extend(["", "Officer reports", "---------------"])
    for officer in report.officers:
        lines.append(f"{officer.officer}: {officer.summary}")
        for blocker in officer.blockers:
            lines.append(f"  blocker: {blocker}")
    lines.extend(
        [
            "",
            "Authority boundary",
            "------------------",
            "Write authorized: NO",
            "Model required: NO",
            "Model used: NO",
        ]
    )
    return "\n".join(lines)


def _safe_command(name: str, argv: Sequence[str], timeout: int = 12) -> dict[str, Any]:
    executable = shutil.which(argv[0])
    if not executable:
        return {"name": name, "available": False, "argv": list(argv), "returncode": None, "stdout": "", "stderr": "not found"}
    try:
        completed = subprocess.run(
            list(argv),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            errors="replace",
        )
        return {
            "name": name,
            "available": True,
            "argv": list(argv),
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "name": name,
            "available": True,
            "argv": list(argv),
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": f"timeout after {timeout}s",
        }


def doctor() -> dict[str, Any]:
    knowledge = load_knowledge()
    commands = ["adb", "fastboot", "idevice_id", "ideviceinfo", "irecovery", "lsusb", "system_profiler", "powershell"]
    return {
        "xray_version": VERSION,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "knowledge_schema": knowledge["schema"],
        "knowledge_version": knowledge["version"],
        "commands": {command: shutil.which(command) for command in commands},
        "write_authorized": False,
        "model_required": False,
    }


def scan_host() -> XrayReport:
    system = platform.system().lower()
    probes: list[tuple[str, list[str]]] = [
        ("adb-list", ["adb", "devices", "-l"]),
        ("fastboot-list", ["fastboot", "devices"]),
        ("apple-usbmux-list", ["idevice_id", "-l"]),
        ("apple-recovery-query", ["irecovery", "-q"]),
    ]
    if system == "linux":
        probes.append(("linux-usb", ["lsusb"]))
    elif system == "darwin":
        probes.append(("macos-usb", ["system_profiler", "SPUSBDataType"]))
    elif system == "windows":
        probes.append(
            (
                "windows-pnp",
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-PnpDevice -PresentOnly | Where-Object {$_.Class -in 'USB','Ports','WPD'} | Format-List",
                ],
            )
        )
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=10, thread_name_prefix="xray-provider") as pool:
        futures = [pool.submit(_safe_command, name, argv) for name, argv in probes]
        for future in as_completed(futures):
            results.append(future.result())
    joined = []
    for result in sorted(results, key=lambda item: item["name"]):
        joined.append(f"### {result['name']}\nreturncode: {result['returncode']}\n{result['stdout']}\n{result['stderr']}")
    return inspect_text("\n".join(joined), artifact_name="live-host-scan.txt")


SELFTEST_UNISOC = """Connect phone in BROM mode. Use volume key buttons or testpoint.
Waiting for device... OK
Device found at COM19
Port: USB\\VID_1782&PID_4D00\\5&242A2F40&0&5
Driver: [UNISOC Communications Inc.,sprdvcom,SPRD U2S Diag,sprdvcom.sys,4.19.38.134]
Port type: BROM
Connecting to device... OK
Selected processor: Tiger_T616_64
Connect preloader 1... OK
Connect preloader 2... OK
Connect loader 1... OK
Connect loader 2... OK
Flash Type: EMMC
Read partitions info... OK
Checking A/B state... OK [A]
Read product info... [EROFS] ... OK
Product Brand        : Infinix
Product Manufacturer : INFINIX
Product Model        : Infinix X6725
Product Name         : X6725-OP
Product Device       : Infinix-X6725
Product Board        : Infinix-X6725
Board Platform       : ums9230
Build ID             : TP1A.220624.014
Build Date           : Thu Oct 23 11:24:58 CST 2025
Display ID           : X6725-(BASE001PF001AZ)251023V2806DevT
Security Patch       : 2025-10-01
Version SDK          : 35
Version Release      : 15
Version Codename     : REL
Firmware Version     : 28626
Userdata FS Type     : F2FS
Read IMEI... error(1)
"""

SELFTEST_HUAWEI = """Xray Android Device Readout
FASTBOOT_PRESENT: 1 device(s) answered fastboot.
FASTBOOT_PRODUCT: kirin980
rescue_phoneinfo: NO MAIN VERSION
vendorcountry: cannot get vendorcountry in oeminfo
oem get-bootinfo: unlocked
"""

SELFTEST_APPLE = """Apple Mobile Device (DFU Mode)
Port: USB\\VID_05AC&PID_1227\\CPID8015
MODE: DFU
CPID: 0x8015
BDID: 0x0C
ECID: 0x0011223344556677
PRODUCT: iPhone10,6
"""


def _claim(report: XrayReport, name: str) -> Claim:
    for item in report.claims:
        if item.name == name:
            return item
    raise AssertionError(f"Missing claim: {name}")


def run_selftest() -> dict[str, Any]:
    tests: list[dict[str, Any]] = []

    unisoc = inspect_text(
        SELFTEST_UNISOC,
        artifact_name="selftest-unisoc.txt",
        external_claims=[
            {
                "key": "hardware.marketed_soc",
                "value": "UNISOC T7250",
                "source_class": "specialist_online",
                "applies_to_model": "Infinix X6725B",
            }
        ],
    )
    tests.append(
        {
            "name": "unisoc-loader-not-silicon",
            "passed": (
                _claim(unisoc, "device.family").value == "UNISOC"
                and _claim(unisoc, "transport.mode").value == "BROM"
                and _claim(unisoc, "hardware.loader_compatibility").value == "Tiger_T616_64"
                and _claim(unisoc, "hardware.exact_soc").status in {Status.CONFLICTED, Status.INFERRED}
                and _claim(unisoc, "hardware.exact_soc").status != Status.CERTIFIED
            ),
            "verdict": unisoc.governor_verdict["result"],
        }
    )

    huawei = inspect_text(SELFTEST_HUAWEI, artifact_name="selftest-huawei.txt")
    tests.append(
        {
            "name": "huawei-main-version-gate",
            "passed": (
                _claim(huawei, "firmware.main_version").status == Status.BLOCKED
                and huawei.governor_verdict["result"] == "BLOCKED"
            ),
            "verdict": huawei.governor_verdict["result"],
        }
    )

    apple = inspect_text(SELFTEST_APPLE, artifact_name="selftest-apple.txt")
    tests.append(
        {
            "name": "apple-dfu-readiness",
            "passed": (
                _claim(apple, "device.family").value == "Apple"
                and _claim(apple, "transport.mode").value == "DFU"
                and _claim(apple, "apple.cpid").value == "0x8015"
                and "dfu" in apple.provider_expectations["apple"]
            ),
            "verdict": apple.governor_verdict["result"],
        }
    )

    return {
        "xray_version": VERSION,
        "passed": all(item["passed"] for item in tests),
        "tests": tests,
        "write_authorized": False,
        "model_required": False,
    }


def _write_output(payload: str, output: str | None) -> None:
    if output:
        Path(output).write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
    else:
        print(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray",
        description="Model-independent, read-only device evidence and verification core.",
    )
    parser.add_argument("--version", action="version", version=f"xray {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect a captured device/tool log")
    inspect_cmd.add_argument("path", help="Input log path, or - for stdin")
    inspect_cmd.add_argument(
        "--claim",
        action="append",
        default=[],
        metavar="KEY=VALUE|SOURCE_CLASS|MODEL",
        help="Add a structured external claim without treating it as device truth",
    )
    inspect_cmd.add_argument("--format", choices=("text", "json"), default="text")
    inspect_cmd.add_argument("--output", help="Write report to this path")

    doctor_cmd = sub.add_parser("doctor", help="Verify Xray core and optional provider tools")
    doctor_cmd.add_argument("--format", choices=("text", "json"), default="text")

    scan_cmd = sub.add_parser("scan", help="Run available read-only host providers")
    scan_cmd.add_argument("--format", choices=("text", "json"), default="text")
    scan_cmd.add_argument("--output", help="Write report to this path")

    selftest_cmd = sub.add_parser("selftest", help="Run deterministic Android, Huawei and Apple proof cases")
    selftest_cmd.add_argument("--format", choices=("text", "json"), default="text")

    knowledge_cmd = sub.add_parser("knowledge-verify", help="Validate the signed-pack-ready knowledge schema")
    knowledge_cmd.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect":
            if args.path == "-":
                text = sys.stdin.read()
                artifact_name = "stdin"
            else:
                path = Path(args.path)
                text = path.read_text(encoding="utf-8", errors="replace")
                artifact_name = path.name
            external_claims = [_parse_external_claim(raw) for raw in args.claim]
            report = inspect_text(text, artifact_name=artifact_name, external_claims=external_claims)
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else _report_text(report)
            _write_output(payload, args.output)
            return 0 if report.governor_verdict["result"] != "BLOCKED" else 2

        if args.command == "doctor":
            payload = doctor()
            if args.format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"Xray {payload['xray_version']} doctor")
                print(f"Python: {payload['python']}")
                print(f"Platform: {payload['platform']}")
                print(f"Knowledge: {payload['knowledge_schema']} {payload['knowledge_version']}")
                for name, location in payload["commands"].items():
                    print(f"{name}: {location or 'not found'}")
                print("Write authorized: NO")
                print("Model required: NO")
            return 0

        if args.command == "scan":
            report = scan_host()
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else _report_text(report)
            _write_output(payload, args.output)
            return 0 if report.governor_verdict["result"] != "BLOCKED" else 2

        if args.command == "selftest":
            result = run_selftest()
            if args.format == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"Xray {result['xray_version']} selftest")
                for item in result["tests"]:
                    print(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']} ({item['verdict']})")
                print("Write authorized: NO")
                print("Model required: NO")
            return 0 if result["passed"] else 1

        if args.command == "knowledge-verify":
            knowledge = load_knowledge()
            result = {
                "valid": True,
                "schema": knowledge["schema"],
                "version": knowledge["version"],
                "rules": len(knowledge.get("rules", [])),
                "usb_signatures": len(knowledge.get("usb_signatures", [])),
                "write_authorized": knowledge["proof_policies"]["write_authorization"]["enabled"],
            }
            if args.format == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"PASS: {result['schema']} {result['version']}")
                print(f"Rules: {result['rules']}")
                print(f"USB signatures: {result['usb_signatures']}")
                print("Write authorized: NO")
            return 0
    except (OSError, ValueError, KnowledgeError) as exc:
        print(f"xray: {exc}", file=sys.stderr)
        return 2
    return 2
