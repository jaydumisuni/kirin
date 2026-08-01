from __future__ import annotations

import ast
import importlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from tempfile import TemporaryDirectory
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from xray.envelopes import EnvelopeJournal  # noqa: E402
from xray.live_models import (  # noqa: E402
    Capability,
    DeviceDescriptor,
    DeviceEvent,
    EventKind,
    ProviderManifest,
    normalize_ecid,
)
from xray.live_review import WAVE_ONE as RUNTIME_WAVE_ONE  # noqa: E402
from xray.live_review import WAVE_TWO as RUNTIME_WAVE_TWO  # noqa: E402
from xray.live_runtime import XrayLiveRuntime  # noqa: E402
from xray.models import VERSION  # noqa: E402
from xray.providers import (  # noqa: E402
    AdbProvider,
    DeviceProvider,
    FORBIDDEN_CAPABILITY_TOKENS,
    ProviderRegistry,
    SimulatedRunner,
    UsbDescriptorProvider,
    default_registry,
    simulated_result,
)
from xray.sessions import SessionRegistry  # noqa: E402
from xray.simulation import apple_events, p30_events, run_simulation  # noqa: E402
from xray.watcher import PollingDeviceWatcher, StaticSnapshotSource  # noqa: E402


@dataclass(frozen=True)
class CheckResult:
    """One independent local reviewer check."""

    name: str
    passed: bool
    detail: str


Check = Callable[[], CheckResult]
_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
_SAFE_COMMAND = re.compile(r"^[A-Za-z0-9._+-]+$")


def _result(name: str, passed: bool, detail: str) -> CheckResult:
    return CheckResult(name, passed, detail)


def _python_sources() -> list[pathlib.Path]:
    return sorted((ROOT / "src" / "xray").glob("*.py"))


def check_compile() -> CheckResult:
    sources = _python_sources()
    try:
        for path in sources:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
    except SyntaxError as exc:
        return _result("compile", False, str(exc))
    return _result("compile", True, f"compiled {len(sources)} module(s)")


def check_imports() -> CheckResult:
    modules = [
        "xray.live_models",
        "xray.sessions",
        "xray.watcher",
        "xray.providers",
        "xray.envelopes",
        "xray.live_review",
        "xray.live_runtime",
        "xray.simulation",
        "xray.live_cli",
    ]
    for module in modules:
        importlib.import_module(module)
    return _result("imports", True, f"imported {len(modules)} module(s)")


def check_provider_count() -> CheckResult:
    names = [item.name for item in default_registry().manifests()]
    expected = {"usb-descriptor", "adb", "fastboot", "apple-recovery", "apple-dfu"}
    return _result("provider-count", set(names) == expected, ", ".join(names))


def check_read_only_manifests() -> CheckResult:
    bad = [item.name for item in default_registry().manifests() if not item.read_only]
    return _result("read-only-manifests", not bad, f"bad={bad}")


def check_forbidden_capabilities() -> CheckResult:
    forbidden = []
    for manifest in default_registry().manifests():
        for capability in manifest.capabilities:
            if any(token in capability.value for token in FORBIDDEN_CAPABILITY_TOKENS):
                forbidden.append(f"{manifest.name}:{capability.value}")
    return _result("forbidden-capabilities", not forbidden, f"forbidden={forbidden}")


def check_no_shell_execution() -> CheckResult:
    violations: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = ""
            if isinstance(node.func, ast.Attribute):
                name = node.func.attr
            elif isinstance(node.func, ast.Name):
                name = node.func.id
            if isinstance(node.func, ast.Attribute) and isinstance(
                node.func.value, ast.Name
            ):
                owner = node.func.value.id
                if (owner, name) in {("os", "system"), ("os", "popen")}:
                    violations.append(f"{path.name}:{node.lineno}:{owner}.{name}")
            for keyword in node.keywords:
                if (
                    keyword.arg == "shell"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is True
                ):
                    violations.append(f"{path.name}:{node.lineno}:shell=True")
    return _result("no-shell-execution", not violations, f"violations={violations}")


def check_public_docstrings() -> CheckResult:
    missing: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = [tree, *(node for node in tree.body if isinstance(node, ast.ClassDef))]
        for parent in parents:
            for node in parent.body:
                if not isinstance(
                    node,
                    (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
                ):
                    continue
                if node.name.startswith("_"):
                    continue
                if not ast.get_docstring(node):
                    missing.append(f"{path.name}:{node.lineno}:{node.name}")
    return _result("public-docstrings", not missing, f"missing={missing}")


def check_runtime_wave_sizes() -> CheckResult:
    sizes = (len(RUNTIME_WAVE_ONE), len(RUNTIME_WAVE_TWO))
    return _result("runtime-wave-sizes", sizes == (20, 20), f"sizes={sizes}")


def check_runtime_private_ids() -> CheckResult:
    ids: list[str] = []
    context = _simulation()["reports"][0]["review"]["privates"]
    ids.extend(item["private_id"] for item in context)
    expected = {f"private-{index:03d}" for index in range(1, 41)}
    return _result(
        "runtime-private-ids",
        len(ids) == len(set(ids)) == 40 and set(ids) == expected,
        f"count={len(ids)}, unique={len(set(ids))}",
    )


def check_runtime_method_name() -> CheckResult:
    methods = {
        report["review"]["method"] for report in _simulation()["reports"]
    }
    expected = {"SRG 20-for-2 live corps"}
    return _result("runtime-method", methods == expected, f"methods={sorted(methods)}")


def check_provider_manifest_versions() -> CheckResult:
    bad = [
        item.name
        for item in default_registry().manifests()
        if not _SEMVER.fullmatch(item.version)
    ]
    return _result("provider-semver", not bad, f"bad={bad}")


def check_provider_commands_safe() -> CheckResult:
    bad = [
        f"{manifest.name}:{command}"
        for manifest in default_registry().manifests()
        for command in manifest.commands
        if not _SAFE_COMMAND.fullmatch(command)
    ]
    return _result("provider-commands", not bad, f"bad={bad}")


def check_live_report_schema() -> CheckResult:
    schemas = {report["schema"] for report in _simulation()["reports"]}
    return _result(
        "live-report-schema",
        schemas == {"xray-live-report-v1"},
        f"schemas={sorted(schemas)}",
    )


def check_evidence_schema() -> CheckResult:
    schemas = {
        envelope["schema"]
        for report in _simulation()["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    }
    return _result(
        "evidence-schema",
        schemas == {"xray-raw-evidence-v1"},
        f"schemas={sorted(schemas)}",
    )


def check_session_schema() -> CheckResult:
    sessions = _simulation()["sessions"]
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
    bad = [index for index, item in enumerate(sessions)  if not required <= set(item)]
    return _result("session-schema", not bad, f"bad={bad}")


def check_runtime_version() -> CheckResult:
    payload = _simulation()
    return _result("runtime-version", VERSION == "0.2.0", f"version={VERSION}")


def check_cli_entrypoint() -> CheckResult:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    passed = 'xray-live = "xray.live_cli:main"' in text
    return _result("cli-entrypoint", passed, "xray-live entrypoint")


def check_docs_20_for_2() -> CheckResult:
    text = "\n".join(path.read_text(encoding="utf-8") for path in [ROOT / "README.md", ROOT / "docs" / "xray" / "live-provider-session-core.md"])
    passed = "20-for-2" in text and "10-for-2" not in text
    return _result("docs-20-for-2", passed, "20-for-2 present and 10-for-2 absent")


def check_workflow_matrix() -> CheckResult:
    text = (ROOT / ".github" / "workflows" / "xray.yml").read_text(encoding="utf-8")
    needles = ['python-version: ["3.11", "3.13"]', 'install-mode: ["editable", "standard"]', "live-review:", "rust-proof:"]
    missing = [needle for needle in needles if needle not in text]
    return _result("proof-workflow", not missing, f"missing={missing}")


def check_authority_terms() -> CheckResult:
    text = "\n".join(path.read_text(encoding="utf-8") for path in _python_sources())
    required = ("model_required", "write_authorized")
    missing = [item for item in required if item not in text]
    return _result("authority-terms", not missing, f"missing={missing}")


@lru_cache(maxsize=1)
def _simulation() -> dict:
    return run_simulation("all")


def check_simulation_count() -> CheckResult:
    payload = _simulation()
    passed = len(payload["reports"]) == 4 and len(payload["sessions"]) == 2
    return _result("simulation-count", passed, f"reports={len(payload["reports'])}, sessions={len(payload['sessions'])}")


def check_p30_verdicts() -> CheckResult:
    payload = run_simulation("p30")
    verdicts = [item["review"]["governor"]["result"] for item in payload["reports"]]
    return _result("p30-verdicts", verdicts == ["LIVE_READ_ONLY_READY", "BLOCKED"], f"verdicts={verdicts}")


def check_apple_verdicts() -> CheckResult:
    payload = run_simulation("apple")
    verdicts = [item["review"]["governor"]["result"] for item in payload["reports"]]
    return _result("apple-verdicts", verdicts == ["LIVE_READ_ONLY_READY", "LIVE_READ_ONLY_READY"], f"verdicts={verdicts}")


def check_forty_privates() -> CheckResult:
    payload = _simulation()
    counts = [len(item["review"]["privates"]) for item in payload["reports"]]
    return _result("forty-privates", counts == [40, 40, 40, 40], f"counts={counts}")


def check_envelope_hashes() -> CheckResult:
    envelopes = [
        envelope
        for report in _simulation()["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    ]
    passed = all(item.get("payload_sha256") and item.get("stdout_sha256") and item.get("descriptor_sha256") for item in envelopes)
    return _result("envelope-hashes", passed, f"envelopes={len(envelopes)}")


def check_journal_replay() -> CheckResult:
    journal = _simulation()["journal"]
    passed = journal.get("valid") is True and journal.get("envelopes") == 8
    return _result("journal-replay", passed, json.dumps(journal, sort_keys=True))


def check_model_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["model_required"] is False and all(report["review"]["governor"]["model_required"] is False for report in payload["reports"])
    return _result("model-boundary", passed, "model_required=false")


def check_write_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["write_authorized"] is False and all(report["review"]["governor"]["write_authorized"] is False for report in payload["reports"])
    return _result("write-boundary", passed, "write_authorized=false")


def check_unsafe_serial_rejected() -> CheckResult:
    event = p30_events()[0]
    bad = event.descriptor.__class__(
        **{
            **event.descriptor.to_dict(),
            "serial": "bad;rm",
            "metadata": {"adb_serial": "bad;rm"},
            "mode": "ADB",
        }
    )
    result = AdbProvider().probe("xray-device-12345678901234567890", bad, SimulatedRunner({}))
    passed = result.supported is False and bool("unsafe or missing AD
    serial" in result.warnings[0])
    return _result("unsafe-serial", passed, f"warnings={result.warnings}")


def check_provider_exception_isolation() -> CheckResult:
    class BrokenProvider(DeviceProvider):
        manifest = ProviderManifest("review-broken", "1.0.0", ("usb",), (Capability.READ_IDENTITY,))

        def supports(self, descriptor):
            return True

        def probe(self, session_id, descriptor, runner):
            raise RuntimeError("review-injection")

    runtime = XrayLiveRuntime(
        registry=ProviderRegistry((UsbDescriptorProvider(), BrokenProvider())),
        sessions=SessionRegistry(host_scope="review"),
        runner=SimulatedRunner({}),
    )
    report = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, p30_events()[0].descriptor))
    passed = report.review.governor["result"] == "BLOCKED" and any(item.provider == "review-broken" and item.errors for item in report.providers)
    return _result("provider-exception-isolation", passed, report.review.governor["result"])


def check_session_p30() -> CheckResult:
    registry = SessionRegistry(host_scope="review")
    ids = [registry.resolve_event(event).session_id for event in p30_events()]
    return _result("p30-session", len(set(ids)) == 1, f"ids={ids}")


def check_session_apple() -> CheckResult:
    registry = SessionRegistry(host_scope="review")
    ids = [registry.resolve_event(event).session_id for event in apple_events()]
    return _result("apple-session", len(set(ids)) == 1, f"ids={ids}")


def check_watcher_transition() -> CheckResult:
    first, second = p30_events()
    watcher = PollingDeviceWatcher(StaticSnapshotSource(((first.descriptor,), (second.descriptor,))))
    initial = watcher.poll_once()
    transition = watcher.poll_once()
    passed = initial[0].kind is EventKind.CONNECTED and transition[0].kind is EventKind.MODE_TRANSITION
    return _result(
        "watcher-transition",
        passed,
        f"kinds={[item.kind.value for item in (*initial, *transition)]}",
    )


def check_port_reuse_isolation() -> CheckResult:
    registry = SessionRegistry(host_scope="review", topology_reuse_window_seconds=8)
    first = p30_events()[0].descriptor
    first_session = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, first, observed_at="2026-08-01T00:00:00Z")
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
    second_session = registry.resolve_event(
        DeviceEvent(
            EventKind.CONNECTED,
            replacement,
            observed_at="2026-08-01T00:00:02Z",
        )
   )
    return _result(
        "port-reuse-isolation",
        first_session.session_id != second_session.session_id,
        f"first={first_session.session_id}, second={second_session.session_id}",
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
        f"providers={providers}, calls={runner.calls}",
    )


def check_unpinned_apple_ambiguity() -> CheckResult:
    first = DeviceDescriptor(
        source="review",
        os_path="apple-one",
        topology_path="port-one",
        vid="05AC",
        pid="1281",
        mode="RECOVERY",
        metadata={"apple_recovery_device_count": 2},
    )
    second = DeviceDescriptor(
        source="review",
        os_path="apple-two",
        topology_path="port-two",
        vid="05AC",
        pid="1227",
        mode="DFU",
        metadata={"apple_recovery_device_count": 2},
   )
    runner = SimulatedRunner(
        {
            ("irecovery", "-q"): [
                simulated_result(("irecovery", "-q"), stdout="MODE: Recovery\nECID: 0x1234\n"),
                simulated_result(("irecovery", "-q"), stdout="MODE: DFU\nECID: 0x1234\n"),
            ]
        }
    )
    runtime = XrayLiveRuntime(
        sessions=SessionRegistry(host_scope="review"),
        runner=runner,
    )
    one = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, first))
    two = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, second))
    passed = (
        one.session["session_id"] != two.session["session_id"]
        and one.review.governor["result"] == "CONFLICTED"
        and two.review.governor["result"] == "CONFLICTED"
    )
    return _result(
        "unpinned-apple-ambiguity",
        passed,
        f"sessions={[one.session['session_id'], two.session['session_id']]}",
    )


def check_ecid_normalization() -> CheckResult:
    canonical = "0x0011223344556677"
    decimal = str(int(canonical, 16))
    passed = normalize_ecid(decimal) == canonical and normalize_ecid(canonical) == canonical
    return _result("ecid-normalization", passed, f"decimal={decimal}")


def check_journal_corruption() -> CheckResult:
    with TemporaryDirectory(prefix="xray-review-") as temporary:
        path = pathlib.Path(temporary) / "bad.jsonl"
        path.write_text('{"schema":"wrong"}\n', encoding="utf-8")
        try:
            EnvelopeJournal(path).replay()
        except ValueError as exc:
            return _result("journal-corruption", "line 1" in str(exc), str(exc))
    return _result("journal-corruption", False, "malformed journal accepted")


def check_provider_observation_custody() -> CheckResult:
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
    return _result("observation-custody", not bad, f"bad={bad}")


def check_simulation_determinism() -> CheckResult:
    one = run_simulation("all")
    two = run_simulation("all")

    def summary(payload: dict) -> tuple:
        return (
            len(payload["reports"]),
            len(payload["sessions"]),
            payload["journal"]["envelopes"],
            tuple(
                report["review"]["governor"]["result"]
                for report in payload["reports"]
            ),
            tuple(len(report["review"]["privates"]) for report in payload["reports"]),
        )

    first = summary(one)
    second = summary(two)
    return _result("simulation-determinism", first == second, f"first={first}, second={second}")


WAVE_ONE: tuple[Check, ...] = (
    check_compile,
    check_imports,
    check_provider_count,
    check_read_only_manifests,
    check_forbidden_capabilities,
    check_no_shell_execution,
    check_public_docstrings,
    check_runtime_wave_sizes,
    check_runtime_private_ids,
    check_runtime_method_name,
    check_provider_manifest_versions,
    check_provider_commands_safe,
    check_live_report_schema,
    check_evidence_schema,
    check_session_schema,
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
    check_unsafe_serial_rejected,
    check_provider_exception_isolation,
    check_session_p30,
    check_session_apple,
    check_watcher_transition,
    check_port_reuse_isolation,
    check_disconnect_boundary,
    check_unpinned_apple_ambiguity,
    check_ecid_normalization,
    check_journal_corruption,
    check_provider_observation_custody,
    check_simulation_determinism,
)


def _execute_check(check: Check) -> CheckResult:
    """Convert an individual reviewer exception into an auditable failed result."""

    try:
        return check()
    except Exception as exc:
        return _result(check.__name__, False, f"{type(exc).__name__}: {exc}")


def main() -> int:
    """Run the independent local SRG 20-for-2 reviewer."""

    waves = []
    for wave_number, checks in enumerate((WAVE_ONE, WAVE_TWO), start=1):
        results = [_execute_check(check) for check in checks]
        waves.append(
            {"wave": wave_number, "results": [result.__dict__ for result in results]}
        )
    passed = all(item["passed"] for wave in waves for item in wave["results"])
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
