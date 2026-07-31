from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Any

from .models import KnowledgeError


def _utc_now() -> str:
    """Return a stable UTC timestamp without microseconds."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _project_root() -> Path:
    """Locate a source-tree knowledge pack while preserving explicit overrides."""

    explicit = os.environ.get("XRAY_PROJECT_ROOT")
    if explicit:
        return Path(explicit).resolve()
    here = Path(__file__).resolve()
    for candidate in [here.parents[2], here.parents[1], Path.cwd()]:
        if (candidate / "knowledge" / "base.json").is_file():
            return candidate
    return here.parents[2]


def _default_knowledge_target() -> Path | Any:
    """Return the source-tree pack or the installed package-data fallback."""

    source_target = _project_root() / "knowledge" / "base.json"
    if source_target.is_file():
        return source_target
    return resources.files("xray").joinpath("data/base.json")


def load_knowledge(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate the Xray knowledge pack."""

    target = Path(path) if path else _default_knowledge_target()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KnowledgeError(f"Cannot load knowledge pack {target}: {exc}") from exc
    if not isinstance(payload, dict):
        raise KnowledgeError(f"Knowledge pack {target} must contain a JSON object")
    if payload.get("schema") != "xray-knowledge-v1":
        raise KnowledgeError(f"Unsupported knowledge schema in {target}")
    required = {
        "version",
        "source_weights",
        "usb_signatures",
        "proof_policies",
        "expected_apple_providers",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise KnowledgeError(f"Knowledge pack missing keys: {', '.join(missing)}")
    try:
        write_enabled = payload["proof_policies"]["write_authorization"]["enabled"]
    except (KeyError, TypeError) as exc:
        raise KnowledgeError("Knowledge pack is missing proof_policies.write_authorization.enabled") from exc
    if not isinstance(write_enabled, bool):
        raise KnowledgeError("proof_policies.write_authorization.enabled must be boolean")
    return payload
