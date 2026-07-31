from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import KnowledgeError


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
