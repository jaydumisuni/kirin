from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Iterable

from .live_models import RawEvidenceEnvelope


class EnvelopeJournal:
    """Append-only JSONL evidence journal with replay verification."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def append(self, envelope: RawEvidenceEnvelope) -> None:
        """Verify and append one envelope atomically at line granularity."""

        if not envelope.verify():
            raise ValueError(f"invalid evidence envelope: {envelope.envelope_id}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(envelope.to_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")
            handle.flush()

    def append_many(self, envelopes: Iterable[RawEvidenceEnvelope]) -> None:
        """Append verified envelopes in caller order."""

        for envelope in envelopes:
            self.append(envelope)

    @staticmethod
    def _from_dict(payload: dict) -> RawEvidenceEnvelope:
        payload = dict(payload)
        payload["sensitive_fields"] = tuple(payload.get("sensitive_fields", ()))
        return RawEvidenceEnvelope(**payload)

    def replay(self) -> tuple[RawEvidenceEnvelope, ...]:
        """Read and verify the entire journal."""

        if not self.path.exists():
            return ()
        output: list[RawEvidenceEnvelope] = []
        seen: set[str] = set()
        with self._lock, self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                payload = json.loads(line)
                envelope = self._from_dict(payload)
                if envelope.envelope_id in seen:
                    raise ValueError(f"duplicate envelope ID at line {line_number}: {envelope.envelope_id}")
                if not envelope.verify():
                    raise ValueError(f"envelope verification failed at line {line_number}")
                seen.add(envelope.envelope_id)
                output.append(envelope)
        return tuple(output)

    def verify(self) -> dict[str, object]:
        """Return a deterministic journal verification summary."""

        envelopes = self.replay()
        return {
            "schema": "xray-evidence-journal-v1",
            "valid": True,
            "envelopes": len(envelopes),
            "sessions": sorted({item.session_id for item in envelopes}),
            "providers": sorted({item.provider for item in envelopes}),
        }
