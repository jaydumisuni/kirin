from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

VERSION = "0.2.0"
SCHEMA = "xray-report-v1"


class Status(str, Enum):
    """Evidence-state classifications emitted by Xray."""

    OBSERVED = "OBSERVED"
    CORROBORATED = "CORROBORATED"
    INFERRED = "INFERRED"
    CONFLICTED = "CONFLICTED"
    CERTIFIED = "CERTIFIED"
    UNKNOWN = "UNKNOWN"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class Evidence:
    """One provenance-preserving observation or external assertion."""

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
    """Result returned by one governed SRG private worker."""

    private_id: str
    wave: int
    assignment: str
    evidence: tuple[Evidence, ...] = ()
    warnings: tuple[str, ...] = ()
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class Claim:
    """Typed interpretation built from one or more evidence items."""

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
    """Permanent-officer review output."""

    officer: str
    summary: str
    severity: str = "info"
    evidence_keys: tuple[str, ...] = ()
    blockers: tuple[str, ...] = ()
    next_actions: tuple[str, ...] = ()


@dataclass
class XrayReport:
    """Complete evidence, review, and Governor verdict envelope."""

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
        """Return a JSON-serializable report mapping."""

        result = asdict(self)
        for claim in result["claims"]:
            claim["status"] = claim["status"].value if isinstance(claim["status"], Status) else claim["status"]
        return result


class KnowledgeError(RuntimeError):
    """Raised when the local Xray knowledge pack is malformed or unavailable."""
