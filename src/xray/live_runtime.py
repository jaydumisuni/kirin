from __future__ import annotations

import json
import shutil
import threading
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Sequence

from .envelopes import EnvelopeJournal
from .live_models import DeviceEvent, EventKind, LiveInspectionReport, ProviderProbeResult, canonical_sha256, utc_now
from .models import VERSION
from .live_review import review_live_event
from .providers import DeviceProvider, ProviderRegistry, SubprocessRunner, default_registry
from .sessions import SessionRegistry
from .watcher import PollingDeviceWatcher, platform_snapshot_source


class XrayLiveRuntime:
    """Orchestrate watcher events, session correlation, providers, custody, and SRG review."""

    def __init__(
        self,
        *,
        registry: ProviderRegistry | None = None,
        sessions: SessionRegistry | None = None,
        runner: Any | None = None,
        journal: EnvelopeJournal | None = None,
    ) -> None:
        self.registry = registry or default_registry()
        self.sessions = sessions or SessionRegistry()
        self.runner = runner or SubprocessRunner()
        self.journal = journal

    def _probe(self, provider: DeviceProvider, session_id: str, event: DeviceEvent) -> ProviderProbeResult:
        try:
            return provider.probe(session_id, event.descriptor, self.runner)
        except Exception as exc:
            return ProviderProbeResult(
                provider=provider.manifest.name,
                supported=True,
                errors=(f"provider exception: {exc}",),
            )

    @staticmethod
    def _rebind_result_session(result: ProviderProbeResult, session_id: str) -> ProviderProbeResult:
        """Rebind newly captured envelopes after provider-observed session merging."""

        envelopes = []
        for envelope in result.envelopes:
            rebound = replace(envelope, session_id=session_id, payload_sha256="")
            rebound = replace(rebound, payload_sha256=canonical_sha256(rebound.unsigned_dict()))
            envelopes.append(rebound)
        return replace(result, envelopes=tuple(envelopes))

    def handle_event(self, event: DeviceEvent) -> LiveInspectionReport:
        """Process one event through providers and the two-wave live review corps."""

        with self.sessions.batch():
            session = self.sessions.resolve_event(event)
            providers = self.registry.providers_for(event.descriptor)
            if event.kind == EventKind.DISCONNECTED:
                providers = tuple(provider for provider in providers if provider.manifest.name == "usb-descriptor")
            results: list[ProviderProbeResult] = []
            with ThreadPoolExecutor(max_workers=min(10, max(1, len(providers))), thread_name_prefix="xray-provider") as pool:
                futures = {
                    pool.submit(self._probe, provider, session.session_id, event): provider.manifest.name
                    for provider in providers
                }
                for future in as_completed(futures):
                    results.append(future.result())
            results.sort(key=lambda item: item.provider)

            verified_results: list[ProviderProbeResult] = []
            for result in results:
                valid_envelopes = []
                errors = list(result.errors)
                observations: dict[str, Any] = {}
                for envelope in result.envelopes:
                    if not envelope.verify():
                        errors.append(f"invalid evidence envelope: {envelope.envelope_id}")
                        continue
                    valid_envelopes.append(envelope)
                    observations.update(envelope.observations)
                verified_results.append(
                    replace(
                        result,
                        envelopes=tuple(valid_envelopes),
                        observations=observations if result.envelopes else result.observations,
                        errors=tuple(errors),
                    )
                )
            results = verified_results

            canonical_session = session
            anchor_map = {
                "apple.ecid": "ecid",
                "identity.fastboot_serial": "fastboot_serial",
                "identity.adb_serial": "adb_serial",
                "apple.udid": "udid",
            }
            for result in results:
                for observation_key, anchor_key in anchor_map.items():
                    value = result.observations.get(observation_key)
                    if not value:
                        continue
                    if observation_key == "apple.ecid":
                        pinned = str(result.observations.get("apple.selector_pinned", "")).casefold() == "true"
                        single_device = str(result.observations.get("apple.recovery_device_count", "")) == "1"
                        if not (pinned or single_device):
                            continue
                    canonical_session = self.sessions.link_observation(
                        canonical_session.session_id,
                        anchor_key,
                        str(value),
                    )
            if canonical_session.session_id != session.session_id:
                results = [
                    self._rebind_result_session(result, canonical_session.session_id)
                    for result in results
                ]

            for result in results:
                for envelope in result.envelopes:
                    self.sessions.attach_envelope(canonical_session.session_id, envelope.envelope_id)
                    if self.journal:
                        self.journal.append(envelope)

            session_snapshot = self.sessions.get(canonical_session.session_id).to_dict()

        review = review_live_event(
            event=event,
            session=session_snapshot,
            manifests=self.registry.manifests(),
            providers=tuple(results),
        )
        return LiveInspectionReport(
            schema="xray-live-report-v1",
            created_at=utc_now(),
            event=event,
            session=session_snapshot,
            providers=tuple(results),
            review=review,
        )

    def snapshot_once(self) -> list[LiveInspectionReport]:
        """Capture and process the current host snapshot once."""

        watcher = PollingDeviceWatcher(platform_snapshot_source(self.runner))
        return [self.handle_event(event) for event in watcher.poll_once()]

    def watch(
        self,
        *,
        interval: float = 1.0,
        duration: float | None = None,
        output: str | Path | None = None,
    ) -> list[LiveInspectionReport]:
        """Watch the current host and optionally persist JSONL reports."""

        watcher = PollingDeviceWatcher(platform_snapshot_source(self.runner))
        reports: list[LiveInspectionReport] = []
        stop = threading.Event()
        timer: threading.Timer | None = None
        if duration is not None:
            if duration <= 0:
                raise ValueError("duration must be positive")
            timer = threading.Timer(duration, stop.set)
            timer.daemon = True
            timer.start()

        path = Path(output) if output else None
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)

        def callback(event: DeviceEvent) -> None:
            """Process and persist one watcher event."""

            report = self.handle_event(event)
            reports.append(report)
            if path:
                with path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(json.dumps(report.to_dict(), sort_keys=True) + "\n")

        try:
            watcher.run(callback, interval=interval, stop_event=stop)
        finally:
            if timer:
                timer.cancel()
        return reports


def doctor_live(registry: ProviderRegistry | None = None, runner: Any | None = None) -> dict[str, Any]:
    """Report provider, command, and authority readiness without touching a device."""

    active_registry = registry or default_registry()
    command_runner = runner or SubprocessRunner()
    commands: dict[str, dict[str, Any]] = {}
    unique = sorted({command for manifest in active_registry.manifests() for command in manifest.commands})
    # Do not execute providers during doctor; resolve availability through PATH lookup only.
    for command in unique:
        path = shutil.which(command)
        commands[command] = {"available": path is not None, "path": path}
    return {
        "schema": "xray-live-doctor-v1",
        "xray_version": VERSION,
        "providers": [manifest.to_dict() for manifest in active_registry.manifests()],
        "capabilities": active_registry.capabilities(),
        "commands": commands,
        "write_authorized": False,
        "model_required": False,
        "runner": type(command_runner).__name__,
    }
