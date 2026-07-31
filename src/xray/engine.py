from __future__ import annotations

import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .common import _ev, _first_value, _values
from .discovery import WAVE_ONE
from .knowledge import _utc_now, load_knowledge
from .models import Claim, Evidence, OfficerReport, PrivateResult, SCHEMA, Status, VERSION, XrayReport
from .review import WAVE_TWO


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
