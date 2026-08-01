from __future__ import annotations

import json
import platform
from contextlib import contextmanager
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .live_models import DeviceDescriptor, DeviceEvent, EventKind, canonical_sha256, utc_now

_SESSION_NAMESPACE = uuid.UUID("d86caf2f-2dc2-44f6-95d4-92c9e4078c5c")


def _parse_timestamp(value: str) -> datetime:
    """Parse an Xray RFC3339 timestamp as an aware UTC datetime."""

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class SessionRecord:
    """Persistent correlation state for one physical device across modes."""

    session_id: str
    created_at: str
    updated_at: str
    stability: str
    anchors: set[str] = field(default_factory=set)
    topology_paths: set[str] = field(default_factory=set)
    modes: list[str] = field(default_factory=list)
    events: int = 0
    envelope_ids: list[str] = field(default_factory=list)
    last_descriptor: dict[str, Any] = field(default_factory=dict)
    connected: bool = True
    last_event_kind: str = EventKind.CONNECTED.value
    disconnected_at: str | None = None

    def add_descriptor(self, descriptor: DeviceDescriptor, observed_at: str) -> None:
        """Merge a new endpoint observation into the session."""

        self.updated_at = observed_at
        self.events += 1
        self.anchors.update(descriptor.identity_anchors())
        if descriptor.topology_path:
            self.topology_paths.add(descriptor.topology_path)
        if descriptor.mode and (not self.modes or self.modes[-1] != descriptor.mode):
            self.modes.append(descriptor.mode)
        descriptor_payload = descriptor.to_dict()
        raw_os_path = descriptor_payload.get("os_path")
        if raw_os_path:
            descriptor_payload["os_path_sha256"] = canonical_sha256(str(raw_os_path).casefold())
            descriptor_payload["os_path"] = None
        raw_serial = descriptor_payload.get("serial")
        if raw_serial:
            descriptor_payload["serial_sha256"] = canonical_sha256(str(raw_serial).casefold())
            descriptor_payload["serial"] = None
        metadata = dict(descriptor_payload.get("metadata") or {})
        for key in ("ecid", "udid", "container_id", "hardware_id", "adb_serial", "fastboot_serial"):
            value = metadata.pop(key, None)
            if value:
                metadata[f"{key}_sha256"] = canonical_sha256(str(value).casefold())
        descriptor_payload["metadata"] = metadata
        self.last_descriptor = descriptor_payload
        strong = [anchor for anchor in descriptor.identity_anchors() if not anchor.startswith("topology:")]
        if self.stability == "weak" and strong:
            self.stability = "stable"

    def mark_event(self, kind: EventKind, observed_at: str) -> None:
        """Update connection lifecycle state for one watcher event."""

        self.last_event_kind = kind.value
        self.updated_at = observed_at
        if kind == EventKind.DISCONNECTED:
            self.connected = False
            self.disconnected_at = observed_at
        else:
            self.connected = True
            self.disconnected_at = None

    def add_envelope(self, envelope_id: str) -> None:
        """Associate an evidence envelope with the session once."""

        if envelope_id not in self.envelope_ids:
            self.envelope_ids.append(envelope_id)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe session snapshot."""

        payload = asdict(self)
        payload["anchors"] = sorted(self.anchors)
        payload["topology_paths"] = sorted(self.topology_paths)
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SessionRecord":
        """Restore a session record from persisted JSON."""

        return cls(
            session_id=str(payload["session_id"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            stability=str(payload.get("stability", "weak")),
            anchors=set(payload.get("anchors", [])),
            topology_paths=set(payload.get("topology_paths", [])),
            modes=list(payload.get("modes", [])),
            events=int(payload.get("events", 0)),
            envelope_ids=list(payload.get("envelope_ids", [])),
            last_descriptor=dict(payload.get("last_descriptor", {})),
            connected=bool(payload.get("connected", True)),
            last_event_kind=str(payload.get("last_event_kind", EventKind.CONNECTED.value)),
            disconnected_at=(str(payload["disconnected_at"]) if payload.get("disconnected_at") else None),
        )


class SessionRegistry:
    """Thread-safe physical-device session correlator with optional persistence."""

    def __init__(
        self,
        *,
        host_scope: str | None = None,
        persistence_path: str | Path | None = None,
        topology_reuse_window_seconds: float = 8.0,
    ) -> None:
        if topology_reuse_window_seconds < 0:
            raise ValueError("topology_reuse_window_seconds cannot be negative")
        self.host_scope = (host_scope or platform.node() or "unknown-host").strip().casefold()
        self.persistence_path = Path(persistence_path) if persistence_path else None
        self.topology_reuse_window_seconds = float(topology_reuse_window_seconds)
        self._sessions: dict[str, SessionRecord] = {}
        self._anchor_to_session: dict[str, str] = {}
        self._lock = threading.RLock()
        self._dirty = False
        self._batch_depth = 0
        if self.persistence_path and self.persistence_path.exists():
            self.load()

    def _scoped_anchors(self, descriptor: DeviceDescriptor) -> tuple[str, ...]:
        return tuple(f"host:{self.host_scope}:{anchor}" for anchor in descriptor.identity_anchors())

    def _scoped_strong_anchors(self, descriptor: DeviceDescriptor) -> tuple[str, ...]:
        return tuple(
            anchor
            for anchor in self._scoped_anchors(descriptor)
            if ":topology:" not in anchor
        )

    def _scoped_topology_anchor(self, descriptor: DeviceDescriptor) -> str | None:
        if not descriptor.topology_path:
            return None
        return f"host:{self.host_scope}:topology:{descriptor.topology_path}"

    def _fallback_anchor(self, descriptor: DeviceDescriptor) -> str:
        basis = "|".join(
            [
                self.host_scope,
                descriptor.source.casefold(),
                descriptor.os_path.casefold(),
                descriptor.vid or "",
                descriptor.pid or "",
                descriptor.product or "",
            ]
        )
        return f"weak:{basis}"

    def _new_session_id(self, anchor: str) -> str:
        """Allocate a stable ID without reusing an earlier physical session."""

        generation = 1
        while True:
            basis = anchor if generation == 1 else f"{anchor}|generation:{generation}"
            candidate = f"xray-device-{uuid.uuid5(_SESSION_NAMESPACE, basis).hex[:20]}"
            if candidate not in self._sessions:
                return candidate
            generation += 1

    @staticmethod
    def _record_strong_anchors(record: SessionRecord) -> set[str]:
        return {anchor for anchor in record.anchors if not anchor.startswith("topology:")}

    def _has_hard_identity_conflict(
        self,
        record: SessionRecord,
        descriptor: DeviceDescriptor,
    ) -> bool:
        incoming = {
            anchor.removeprefix(f"host:{self.host_scope}:")
            for anchor in self._scoped_strong_anchors(descriptor)
        }
        existing = self._record_strong_anchors(record)
        return bool(incoming and existing and incoming.isdisjoint(existing))

    def _within_topology_reuse_window(self, record: SessionRecord, observed_at: str) -> bool:
        if not record.disconnected_at:
            return False
        elapsed = (_parse_timestamp(observed_at) - _parse_timestamp(record.disconnected_at)).total_seconds()
        return 0 <= elapsed <= self.topology_reuse_window_seconds

    def _merge_sessions(self, session_ids: set[str]) -> str:
        ordered = sorted(
            (self._sessions[item] for item in session_ids),
            key=lambda item: (item.created_at, item.session_id),
        )
        keeper = ordered[0]
        for duplicate in ordered[1:]:
            keeper.anchors.update(duplicate.anchors)
            keeper.topology_paths.update(duplicate.topology_paths)
            keeper.modes.extend(mode for mode in duplicate.modes if mode not in keeper.modes)
            keeper.events += duplicate.events
            keeper.envelope_ids.extend(
                item for item in duplicate.envelope_ids if item not in keeper.envelope_ids
            )
            if duplicate.updated_at > keeper.updated_at:
                keeper.updated_at = duplicate.updated_at
                keeper.last_descriptor = dict(duplicate.last_descriptor)
                keeper.last_event_kind = duplicate.last_event_kind
                keeper.connected = duplicate.connected
                keeper.disconnected_at = duplicate.disconnected_at
            for anchor, mapped in list(self._anchor_to_session.items()):
                if mapped == duplicate.session_id:
                    self._anchor_to_session[anchor] = keeper.session_id
            self._sessions.pop(duplicate.session_id, None)
        return keeper.session_id

    def _create(self, descriptor: DeviceDescriptor, timestamp: str) -> SessionRecord:
        anchors = self._scoped_anchors(descriptor)
        primary = anchors[0] if anchors else self._fallback_anchor(descriptor)
        session_id = self._new_session_id(primary)
        record = SessionRecord(
            session_id=session_id,
            created_at=timestamp,
            updated_at=timestamp,
            stability="stable" if self._scoped_strong_anchors(descriptor) else "weak",
        )
        self._sessions[session_id] = record
        return record

    def _strong_matches(self, descriptor: DeviceDescriptor) -> set[str]:
        return {
            self._anchor_to_session[anchor]
            for anchor in self._scoped_strong_anchors(descriptor)
            if anchor in self._anchor_to_session
        }

    def _topology_match(self, descriptor: DeviceDescriptor) -> str | None:
        anchor = self._scoped_topology_anchor(descriptor)
        return self._anchor_to_session.get(anchor) if anchor else None

    def _apply_descriptor(
        self,
        record: SessionRecord,
        descriptor: DeviceDescriptor,
        timestamp: str,
    ) -> SessionRecord:
        record.add_descriptor(descriptor, timestamp)
        for anchor in self._scoped_anchors(descriptor):
            self._anchor_to_session[anchor] = record.session_id
        for anchor in record.anchors:
            self._anchor_to_session[f"host:{self.host_scope}:{anchor}"] = record.session_id
        return record

    def resolve(self, descriptor: DeviceDescriptor, *, observed_at: str | None = None) -> SessionRecord:
        """Resolve or create a session using strong identity before topology."""

        timestamp = observed_at or utc_now()
        with self._lock:
            matched = self._strong_matches(descriptor)
            if len(matched) > 1:
                session_id = self._merge_sessions(matched)
                record = self._sessions[session_id]
            elif matched:
                record = self._sessions[next(iter(matched))]
            else:
                record = None

            topology_id = self._topology_match(descriptor)
            topology_record = self._sessions.get(topology_id) if topology_id else None
            if record is not None and topology_record is not None and topology_record.session_id != record.session_id:
                if not self._has_hard_identity_conflict(topology_record, descriptor):
                    record = self._sessions[self._merge_sessions({record.session_id, topology_record.session_id})]
            elif record is None:
                can_reuse_topology = bool(
                    topology_record
                    and not self._has_hard_identity_conflict(topology_record, descriptor)
                    and (
                        topology_record.connected
                        or self._within_topology_reuse_window(topology_record, timestamp)
                    )
                )
                record = topology_record if can_reuse_topology else self._create(descriptor, timestamp)
            self._apply_descriptor(record, descriptor, timestamp)
            self._save_if_configured()
            return SessionRecord.from_dict(record.to_dict())

    def resolve_event(self, event: DeviceEvent) -> SessionRecord:
        """Resolve a lifecycle event without confusing port reuse for identity."""

        timestamp = event.observed_at
        descriptor = event.descriptor
        with self._lock:
            matched = self._strong_matches(descriptor)
            record: SessionRecord | None = None
            if len(matched) > 1:
                record = self._sessions[self._merge_sessions(matched)]
            elif matched:
                record = self._sessions[next(iter(matched))]

            topology_id = self._topology_match(descriptor)
            topology_record = self._sessions.get(topology_id) if topology_id else None
            if record is not None and topology_record is not None and topology_record.session_id != record.session_id:
                if not self._has_hard_identity_conflict(topology_record, descriptor):
                    record = self._sessions[self._merge_sessions({record.session_id, topology_record.session_id})]

            if event.kind == EventKind.MODE_TRANSITION and event.previous:
                previous_candidates = set(self._strong_matches(event.previous))
                previous_topology_id = self._topology_match(event.previous)
                if previous_topology_id:
                    previous_candidates.add(previous_topology_id)
                previous_candidates.intersection_update(self._sessions)
                if previous_candidates:
                    previous_id = (
                        self._merge_sessions(previous_candidates)
                        if len(previous_candidates) > 1
                        else next(iter(previous_candidates))
                    )
                    if record is not None and record.session_id != previous_id:
                        record = self._sessions[self._merge_sessions({record.session_id, previous_id})]
                    else:
                        record = self._sessions[previous_id]
            elif record is None and topology_record is not None:
                if event.kind in {EventKind.CHANGED, EventKind.PRESENT, EventKind.DISCONNECTED}:
                    record = topology_record
                elif (
                    event.kind == EventKind.CONNECTED
                    and not self._has_hard_identity_conflict(topology_record, descriptor)
                    and self._within_topology_reuse_window(topology_record, timestamp)
                ):
                    record = topology_record

            if record is None:
                record = self._create(descriptor, timestamp)

            self._apply_descriptor(record, descriptor, timestamp)
            if event.kind == EventKind.MODE_TRANSITION and event.previous and event.previous.mode:
                if not record.modes or record.modes[0] != event.previous.mode:
                    record.modes.insert(0, event.previous.mode)
            record.mark_event(event.kind, timestamp)
            self._save_if_configured()
            return SessionRecord.from_dict(record.to_dict())

    def link_observation(self, session_id: str, key: str, value: str) -> SessionRecord:
        """Link a provider-observed stable identifier and merge duplicate sessions."""

        allowed = {"ecid", "udid", "container_id", "hardware_id", "adb_serial", "fastboot_serial"}
        if key not in allowed:
            raise ValueError(f"unsupported session observation anchor: {key}")
        normalized = value.strip().casefold()
        if not normalized:
            raise ValueError("session observation anchor cannot be empty")
        unscoped = f"{key}-sha256:{canonical_sha256(normalized)}"
        scoped = f"host:{self.host_scope}:{unscoped}"
        with self._lock:
            if session_id not in self._sessions:
                raise KeyError(session_id)
            existing = self._anchor_to_session.get(scoped)
            if existing and existing != session_id:
                session_id = self._merge_sessions({session_id, existing})
            record = self._sessions[session_id]
            record.anchors.add(unscoped)
            self._anchor_to_session[scoped] = session_id
            record.updated_at = utc_now()
            if record.stability == "weak":
                record.stability = "stable"
            self._save_if_configured()
            return SessionRecord.from_dict(record.to_dict())

    def attach_envelope(self, session_id: str, envelope_id: str) -> None:
        """Attach one evidence envelope to an existing session."""

        with self._lock:
            record = self._sessions[session_id]
            record.add_envelope(envelope_id)
            self._save_if_configured()

    def get(self, session_id: str) -> SessionRecord:
        """Return a defensive session snapshot."""

        with self._lock:
            return SessionRecord.from_dict(self._sessions[session_id].to_dict())

    def all(self) -> list[SessionRecord]:
        """Return all sessions ordered by creation time."""

        with self._lock:
            return [
                SessionRecord.from_dict(item.to_dict())
                for item in sorted(self._sessions.values(), key=lambda record: record.created_at)
            ]

    @contextmanager
    def batch(self):
        """Defer persistence so one event boundary performs at most one registry write."""

        with self._lock:
            self._batch_depth += 1
        try:
            yield self
        finally:
            with self._lock:
                self._batch_depth -= 1
                if self._batch_depth < 0:
                    self._batch_depth = 0
                    raise RuntimeError("session persistence batch underflow")
                if self._batch_depth == 0:
                    self.flush()

    def save(self) -> None:
        """Persist session state atomically and clear the dirty flag."""

        if not self.persistence_path:
            raise ValueError("persistence_path is not configured")
        with self._lock:
            self.persistence_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "schema": "xray-session-registry-v1",
                "host_scope": self.host_scope,
                "topology_reuse_window_seconds": self.topology_reuse_window_seconds,
                "sessions": [item.to_dict() for item in self._sessions.values()],
                "anchors": self._anchor_to_session,
            }
            temporary = self.persistence_path.with_suffix(self.persistence_path.suffix + ".tmp")
            temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            temporary.replace(self.persistence_path)
            self._dirty = False

    def flush(self) -> None:
        """Persist pending changes once when persistence is configured."""

        with self._lock:
            if self.persistence_path and self._dirty:
                self.save()

    def _save_if_configured(self) -> None:
        if not self.persistence_path:
            return
        self._dirty = True
        if self._batch_depth == 0:
            self.flush()

    def load(self) -> None:
        """Load and validate persisted session state."""

        if not self.persistence_path:
            raise ValueError("persistence_path is not configured")
        payload = json.loads(self.persistence_path.read_text(encoding="utf-8"))
        if payload.get("schema") != "xray-session-registry-v1":
            raise ValueError("unsupported session registry schema")
        if str(payload.get("host_scope", "")).casefold() != self.host_scope:
            raise ValueError("session registry belongs to a different host scope")
        stored_window = float(payload.get("topology_reuse_window_seconds", self.topology_reuse_window_seconds))
        if stored_window < 0:
            raise ValueError("persisted topology reuse window cannot be negative")
        self.topology_reuse_window_seconds = stored_window
        with self._lock:
            self._sessions = {
                item["session_id"]: SessionRecord.from_dict(item)
                for item in payload.get("sessions", [])
            }
            self._anchor_to_session = {
                str(key): str(value) for key, value in payload.get("anchors", {}).items()
            }
            dangling = set(self._anchor_to_session.values()) - set(self._sessions)
            if dangling:
                raise ValueError(f"session registry contains dangling anchors: {sorted(dangling)}")
            self._dirty = False
