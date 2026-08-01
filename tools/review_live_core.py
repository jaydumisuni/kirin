from __future__ import annotations

import ast
import importlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from xray.live_models import DeviceEvent, EventKind, normalize_ecid  # noqa: E402
from xray.live_review import WAVE_ONE as RUNTIME_WAVE_ONE  # noqa: E402
from xray.live_review import WAVE_TWO as RUNTIME_WAVE_TWO  # noqa: E402
from xray.live_runtime import XrayLiveRuntime  # noqa: E402
from xray.models import VERSION  # noqa: E402
from xray.providers import FORBIDDEN_CAPABILITY_TOKENS, SimulatedRunner, default_registry  # noqa: E402
from xray.sessions import SessionRegistry  # noqa: E402
from xray.simulation import apple_events, p30_events, run_simulation  # noqa: E402
from xray.watcher import PollingDeviceWatcher, StaticSnapshotSource  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    """One independent local reviewer result."""

    name: str
    passed: bool
    detail: str


Check = Callable[[], CheckResult]
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SAFE_COMMAND = re.compile(r"^[A-Za-z0-9._+-]+$")


def _result(name: str, passed: bool, detail: object) -> CheckResult:
    return CheckResult(name, passed, str(detail))


def _sources() -> list[pathlib.Path]:
    return sorted((SRC / "xray").glob("*.py"))


@lru_cache(maxsize=1)
def _simulation() -> dict:
    return run_simulation("all")


def check_compile() -> CheckResult:
    try:
        for path in _sources():
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
    except SyntaxError as exc:
        return _result("compile", False, exc)
    return _result("compile", True, len(_sources()))


def check_imports() -> CheckResult:
    modules = (
        "xray.live_models",
        "xray.sessions",
        "xray.watcher",
        "xray.providers",
        "xray.envelopes",
        "xray.live_review",
        "xray.live_runtime",
        "xray.simulation",
        "xray.live_cli",
    )
    for module in modules:
        importlib.import_module(module)
    return _result("imports", True, len(modules))


def check_provider_set() -> CheckResult:
    names = {item.name for item in default_registry().manifests()}
    expected = {"usb-descriptor", "adb", "fastboot", "apple-recovery", "apple-dfu"}
    return _result("provider-set", names == expected, sorted(names))


def check_read_only_manifests() -> CheckResult:
    bad = [item.name for item in default_registry().manifests() if not item.read_only]
    return _result("read-only-manifests", not bad, bad)


def check_manifest_capabilities() -> CheckResult:
    bad = [item.name for item in default_registry().manifests() if not item.capabilities]
    return _result("manifest-capabilities", not bad, bad)


def check_manifest_commands() -> CheckResult:
    bad = [
        f"{item.name}:{command}"
        for item in default_registry().manifests()
        for command in item.commands
        if not _SAFE_COMMAND.fullmatch(command)
    ]
    return _result("manifest-commands", not bad, bad)


def check_manifest_versions() -> CheckResult:
    bad = [item.name for item in default_registry().manifests() if not _SEMVER.fullmatch(item.version)]
    return _result("manifest-versions", not bad, bad)


def check_no_shell_execution() -> CheckResult:
    bad: list[str] = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if (node.func.value.id, node.func.attr) in {("os", "system"), ("os", "popen")}:
                    bad.append(f"{path.name}:{node.lineno}")
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                bad.append(f"{path.name}:{node.lineno}:shell=True")
    return _result("no-shell-execution", not bad, bad)


def check_runtime_wave_sizes() -> CheckResult:
    sizes = (len(RUNTIME_WAVE_ONE), len(RUNTIME_WAVE_TWO))
    return _result("runtime-wave-sizes", sizes == (20, 20), sizes)


def check_runtime_private_ids() -> CheckResult:
    ids = [item["private_id"] for item in _simulation()["reports"][0]["review"]["privates"]]
    expected = {f"private-{index:03d}" for index in range(1, 41)}
    return _result("runtime-private-ids", len(ids) == 40 and set(ids) == expected, len(ids))


def check_runtime_method() -> CheckResult:
    methods = {item["review"]["method"] for item in _simulation()["reports"]}
    return _result("runtime-method", methods == {"SRG 20-for-2 live corps"}, methods)


def check_live_report_schema() -> CheckResult:
    values = {item["schema"] for item in _simulation()["reports"]}
    return _result("live-report-schema", values == {"xray-live-report-v1"}, values)


def check_simulation_schema() -> CheckResult:
    value = _simulation()["schema"]
    return _result("simulation-schema", value == "xray-live-simulation-v1", value)


def check_session_schema() -> CheckResult:
    required = {
        "session_id",
        "created_at",
        "updated_at",
        "anchors",
        "topology_paths",
        "modes",
        "events",
        "connected",
    }
    bad = [index for index, item in enumerate(_simulation()["sessions"]) if not required <= set(item)]
    return _result("session-schema", not bad, bad)


def check_evidence_schema() -> CheckResult:
    values = {
        envelope["schema"]
        for report in _simulation()["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    }
    return _result("evidence-schema", values == {"xray-raw-evidence-v1"}, values)


def check_runtime_version() -> CheckResult:
    return _result("runtime-version", VERSION == "0.2.0", VERSION)


def check_cli_entrypoint() -> CheckResult:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    return _result("cli-entrypoint", 'xray-live = "xray.live_cli:main"' in text, "xray-live")


def check_docs_20_for_2() -> CheckResult:
    paths = (
        ROOT / "README.md",
        ROOT / "docs" / "xray" / "live-provider-session-core.md",
    )
    text = "\n".join(path.read_text(encoding="utf-8") for path in paths)
    return _result("docs-20-for-2", "20-for-2" in text and "10-for-2" not in text, "docs")


def check_workflow_matrix() -> CheckResult:
    text = (ROOT / ".github" / "workflows" / "xray.yml").read_text(encoding="utf-8")
    required = (
        'python-version: ["3.11", "3.13"]',
        'install-mode: ["editable", "standard"]',
        "live-review:",
        "rust-proof:",
    )
    missing = [item for item in required if item not in text]
    return _result("workflow-matrix", not missing, missing)


def check_authority_terms() -> CheckResult:
    required = {"write", "flash", "erase", "unlock", "relock", "format", "repair"}
    actual = set(FORBIDDEN_CAPABILITY_TOKENS)
    return _result("authority-terms", required <= actual, sorted(required - actual))


def check_simulation_count() -> CheckResult:
    payload = _simulation()
    value = (len(payload["reports"]), len(payload["sessions"]))
    return _result("simulation-count", value == (4, 2), value)


def check_p30_verdicts() -> CheckResult:
    values = [
        item["review"]["governor"]["result"]
        for item in run_simulation("p30")["reports"]
    ]
    return _result("p30-verdicts", values == ["LIVE_READ_ONLY_READY", "BLOCKED"], values)


def check_apple_verdicts() -> CheckResult:
    values = [
        item["review"]["governor"]["result"]
        for item in run_simulation("apple")["reports"]
    ]
    return _result(
        "apple-verdicts",
        values == ["LIVE_READ_ONLY_READY", "LIVE_READ_ONLY_READY"],
        values,
    )


def check_forty_privates() -> CheckResult:
    values = [len(item["review"]["privates"]) for item in _simulation()["reports"]]
    return _result("forty-privates", values == [40, 40, 40, 40], values)


def check_envelope_hashes() -> CheckResult:
    envelopes = [
        envelope
        for report in _simulation()["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    ]
    passed = all(
        item.get("payload_sha256")
        and item.get("stdout_sha256")
        and item.get("stderr_sha256")
        and item.get("descriptor_sha256")
        for item in envelopes
    )
    return _result("envelope-hashes", passed, len(envelopes))


def check_journal_replay() -> CheckResult:
    journal = _simulation()["journal"]
    return _result(
        "journal-replay",
        journal.get("valid") is True and journal.get("envelopes") == 8,
        journal,
    )


def check_model_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["model_required"] is False and all(
        item["review"]["governor"]["model_required"] is False
        for item in payload["reports"]
    )
    return _result("model-boundary", passed, payload["model_required"])


def check_write_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["write_authorized"] is False and all(
        item["review"]["governor"]["write_authorized"] is False
        for item in payload["reports"]
    )
    return _result("write-boundary", passed, payload["write_authorized"])


def check_p30_session() -> CheckResult:
    registry = SessionRegistry(host_scope="review")
    ids = [registry.resolve_event(event).session_id for event in p30_events()]
    return _result("p30-session", len(set(ids)) == 1, ids)


def check_apple_session() -> CheckResult:
    registry = SessionRegistry(host_scope="review")
    ids = [registry.resolve_event(event).session_id for event in apple_events()]
    return _result("apple-session", len(set(ids)) == 1, ids)


def check_session_modes() -> CheckResult:
    modes = [item["modes"] for item in _simulation()["sessions"]]
    expected = {("FASTBOOT", "RESCUE"), ("RECOVERY", "DFU")}
    return _result("session-modes", {tuple(item) for item in modes} == expected, modes)


def check_watcher_transition() -> CheckResult:
    first, second = p30_events()
    watcher = PollingDeviceWatcher(
        StaticSnapshotSource(((first.descriptor,), (second.descriptor,)))
    )
    values = [item.kind for item in (*watcher.poll_once(), *watcher.poll_once())]
    return _result(
        "watcher-transition",
        values == [EventKind.CONNECTED, EventKind.MODE_TRANSITION],
        [item.value for item in values],
    )


def check_port_reuse_isolation() -> CheckResult:
    registry = SessionRegistry(host_scope="review", topology_reuse_window_seconds=8)
    first = p30_events()[0].descriptor
    one = registry.resolve_event(
        DeviceEvent(
            EventKind.CONNECTED,
            first,
            observed_at="2026-08-01T00:00:00Z",
        )
    )
    registry.resolve_event(
        DeviceEvent(
            EventKind.DISCONNECTED,
            first,
            observed_at="2026-08-01T00:00:01Z",
            previous=first,
        )
    )
    replacement = first.__class__(
        **{
            **first.to_dict(),
            "serial": "REPLACEMENT",
            "metadata": {"fastboot_serial": "REPLACEMENT"},
        }
    )
    two = registry.resolve_event(
        DeviceEvent(
            EventKind.CONNECTED,
            replacement,
            observed_at="2026-08-01T00:00:02Z",
        )
    )
    return _result(
        "port-reuse-isolation",
        one.session_id != two.session_id,
        (one.session_id, two.session_id),
    )


def check_disconnect_boundary() -> CheckResult:
    connected = p30_events()[0]
    runner = SimulatedRunner({})
    runtime = XrayLiveRuntime(
        sessions=SessionRegistry(host_scope="review"),
        runner=runner,
    )
    report = runtime.handle_event(
        DeviceEvent(
            EventKind.DISCONNECTED,
            connected.descriptor,
            previous=connected.descriptor,
        )
    )
    providers = [item.provider for item in report.providers]
    return _result(
        "disconnect-boundary",
        providers == ["usb-descriptor"] and runner.calls == [],
        providers,
    )


def check_ecid_normalization() -> CheckResult:
    canonical = "0x0011223344556677"
    decimal = str(int(canonical, 16))
    passed = normalize_ecid(decimal) == canonical and normalize_ecid(canonical) == canonical
    return _result("ecid-normalization", passed, decimal)


def check_observation_custody() -> CheckResult:
    bad: list[str] = []
    for report in _simulation()["reports"]:
        for provider in report["providers"]:
            if not provider["envelopes"]:
                continue
            merged: dict[str, object] = {}
            for envelope in provider["envelopes"]:
                merged.update(envelope["observations"])
            if provider["observations"] != merged:
                bad.append(provider["provider"])
    return _result("observation-custody", not bad, bad)


def check_unique_envelopes() -> CheckResult:
    ids = [
        envelope["envelope_id"]
        for report in _simulation()["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    ]
    return _result("unique-envelopes", len(ids) == len(set(ids)) == 8, len(ids))


def check_session_event_accounting() -> CheckResult:
    values = [item["events"] for item in _simulation()["sessions"]]
    return _result("session-event-accounting", values == [2, 2], values)


def check_session_connected_state() -> CheckResult:
    values = [item["connected"] for item in _simulation()["sessions"]]
    return _result("session-connected-state", values == [True, True], values)


def check_simulation_determinism() -> CheckResult:
    def summary(payload: dict) -> tuple:
        return (
            len(payload["reports"]),
            len(payload["sessions"]),
            payload["journal"]["envelopes"],
            tuple(
                item["review"]["governor"]["result"]
                for item in payload["reports"]
            ),
            tuple(
                len(item["review"]["privates"])
                for item in payload["reports"]
            ),
        )

    one = summary(run_simulation("all"))
    two = summary(run_simulation("all"))
    return _result("simulation-determinism", one == two, (one, two))


WAVE_ONE: tuple[Check, ...] = (
    check_compile,
    check_imports,
    check_provider_set,
    check_read_only_manifests,
    check_manifest_capabilities,
    check_manifest_commands,
    check_manifest_versions,
    check_no_shell_execution,
    check_runtime_wave_sizes,
    check_runtime_private_ids,
    check_runtime_method,
    check_live_report_schema,
    check_simulation_schema,
    check_session_schema,
    check_evidence_schema,
    check_runtime_version,
    check_cli_entrypoint,
    check_docs_20_for_2,
    check_workflow_matrix,
    check_authority_terms,
)

WAVE_TWO: tuple[Check, ...] = (
    check_simulation_count,
    check_p30_verdicts,
    check_apple_verdicts,
    check_forty_privates,
    check_envelope_hashes,
    check_journal_replay,
    check_model_boundary,
    check_write_boundary,
    check_p30_session,
    check_apple_session,
    check_session_modes,
    check_watcher_transition,
    check_port_reuse_isolation,
    check_disconnect_boundary,
    check_ecid_normalization,
    check_observation_custody,
    check_unique_envelopes,
    check_session_event_accounting,
    check_session_connected_state,
    check_simulation_determinism,
)


def _execute(check: Check) -> CheckResult:
    try:
        return check()
    except Exception as exc:
        return _result(check.__name__, False, f"{type(exc).__name__}: {exc}")


def main() -> int:
    """Run the independent local SRG 20-for-2 reviewer."""

    waves = []
    for number, checks in enumerate((WAVE_ONE, WAVE_TWO), start=1):
        results = [_execute(check) for check in checks]
        waves.append(
            {
                "wave": number,
                "results": [result.__dict__ for result in results],
            }
        )
    passed = all(
        item["passed"]
        for wave in waves
        for item in wave["results"]
    )
    payload = {
        "schema": "xray-live-local-review-v1",
        "method": "SRG 20-for-2 independent reviewer",
        "passed": passed,
        "waves": waves,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
