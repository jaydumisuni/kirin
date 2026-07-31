from __future__ import annotations

import ast
import importlib
import json
import pathlib
import sys
from dataclasses import dataclass
from typing import Callable

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from xray.live_models import DeviceEvent, EventKind  # noqa: E402
from xray.live_runtime import XrayLiveRuntime  # noqa: E402
from xray.providers import AdbProvider, SimulatedRunner, default_registry  # noqa: E402
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


def _result(name: str, passed: bool, detail: str) -> CheckResult:
    return CheckResult(name, passed, detail)


def _python_sources() -> list[pathlib.Path]:
    return sorted((ROOT / "src" / "xray").glob("*.py"))


def check_compile() -> CheckResult:
    try:
        for path in _python_sources():
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
    except SyntaxError as exc:
        return _result("compile", False, str(exc))
    return _result("compile", True, f"compiled {len(_python_sources())} module(s)")


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
            if any(token in capability.value for token in ("write", "flash", "erase", "unlock", "format", "repair")):
                forbidden.append(f"{manifest.name}:{capability.value}")
    return _result("forbidden-capabilities", not forbidden, f"forbidden={forbidden}")


def check_no_shell_execution() -> CheckResult:
    violations: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = ""
                if isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    name = node.func.id
                if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                    owner = node.func.value.id
                    if (owner, name) in {("os", "system"), ("os", "popen")}:
                        violations.append(f"{path.name}:{node.lineno}:{owner}.{name}")
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        violations.append(f"{path.name}:{node.lineno}:shell=True")
    return _result("no-shell-execution", not violations, f"violations={violations}")


def check_public_docstrings() -> CheckResult:
    missing: list[str] = []
    for path in _python_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and not node.name.startswith("_"):
                if not ast.get_docstring(node):
                    missing.append(f"{path.name}:{node.lineno}:{node.name}")
    return _result("public-docstrings", not missing, f"missing={missing}")


def check_session_p30() -> CheckResult:
    registry = SessionRegistry(host_scope="review")
    ids = [registry.resolve_event(event).session_id for event in p30_events()]
    first_descriptor = p30_events()[0].descriptor
    registry.resolve_event(
        DeviceEvent(EventKind.DISCONNECTED, first_descriptor, previous=first_descriptor)
    )
    replacement = first_descriptor.__class__(
        **{
            **first_descriptor.to_dict(),
            "serial": "DIFFERENT-PHYSICAL-DEVICE",
            "metadata": {"fastboot_serial": "DIFFERENT-PHYSICAL-DEVICE"},
        }
    )
    replacement_id = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, replacement)
    ).session_id
    passed = len(set(ids)) == 1 and replacement_id != ids[0]
    return _result(
        "p30-session-and-port-reuse",
        passed,
        f"transition_ids={ids}, replacement_id={replacement_id}",
    )


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
    return _result("watcher-transition", passed, f"events={[item.kind.value for item in (*initial, *transition)]}")


def _simulation() -> dict:
    return run_simulation("all")


def check_simulation_count() -> CheckResult:
    payload = _simulation()
    passed = len(payload["reports"]) == 4 and len(payload["sessions"]) == 2
    return _result("simulation-count", passed, f"reports={len(payload['reports'])}, sessions={len(payload['sessions'])}")


def check_p30_verdicts() -> CheckResult:
    payload = run_simulation("p30")
    verdicts = [item["review"]["governor"]["result"] for item in payload["reports"]]
    return _result("p30-verdicts", verdicts == ["LIVE_READ_ONLY_READY", "BLOCKED"], f"verdicts={verdicts}")


def check_apple_verdicts() -> CheckResult:
    payload = run_simulation("apple")
    verdicts = [item["review"]["governor"]["result"] for item in payload["reports"]]
    return _result("apple-verdicts", verdicts == ["LIVE_READ_ONLY_READY", "LIVE_READ_ONLY_READY"], f"verdicts={verdicts}")


def check_twenty_privates() -> CheckResult:
    payload = _simulation()
    counts = [len(item["review"]["privates"]) for item in payload["reports"]]
    return _result("twenty-privates", counts == [20, 20, 20, 20], f"counts={counts}")


def check_envelope_hashes() -> CheckResult:
    payload = _simulation()
    envelopes = [
        envelope
        for report in payload["reports"]
        for provider in report["providers"]
        for envelope in provider["envelopes"]
    ]
    passed = all(item.get("payload_sha256") and item.get("stdout_sha256") and item.get("descriptor_sha256") for item in envelopes)
    return _result("envelope-hashes", passed, f"envelopes={len(envelopes)}")


def check_journal_replay() -> CheckResult:
    payload = _simulation()
    journal = payload["journal"]
    return _result("journal-replay", journal.get("valid") is True and journal.get("envelopes") == 8, json.dumps(journal, sort_keys=True))


def check_model_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["model_required"] is False and all(item["review"]["governor"]["model_required"] is False for item in payload["reports"])
    return _result("model-boundary", passed, "model_required=false")


def check_write_boundary() -> CheckResult:
    payload = _simulation()
    passed = payload["write_authorized"] is False and all(item["review"]["governor"]["write_authorized"] is False for item in payload["reports"])
    return _result("write-boundary", passed, "write_authorized=false")


def check_unsafe_serial_rejected() -> CheckResult:
    event = p30_events()[0]
    bad = event.descriptor.__class__(**{**event.descriptor.to_dict(), "serial": "bad;rm", "metadata": {"adb_serial": "bad;rm"}, "mode": "ADB"})
    try:
        AdbProvider().probe("xray-device-12345678901234567890", bad, SimulatedRunner({}))
    except ValueError:
        return _result("unsafe-serial", True, "rejected")
    return _result("unsafe-serial", False, "unsafe serial accepted")


def check_provider_exception_isolation() -> CheckResult:
    class BrokenProvider:
        manifest = next(item for item in default_registry().manifests() if item.name == "usb-descriptor")

        def supports(self, descriptor):
            return True

        def probe(self, session_id, descriptor, runner):
            raise RuntimeError("review injection")

    from xray.providers import ProviderRegistry, UsbDescriptorProvider

    registry = ProviderRegistry((UsbDescriptorProvider(),))
    # Duplicate manifest name would be rejected, so use the runtime's own exception boundary with a unique manifest.
    from xray.live_models import Capability, ProviderManifest

    BrokenProvider.manifest = ProviderManifest("review-broken", "1", ("usb",), (Capability.READ_IDENTITY,))
    registry.register(BrokenProvider())
    runtime = XrayLiveRuntime(registry=registry, sessions=SessionRegistry(host_scope="review"), runner=SimulatedRunner({}))
    report = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, p30_events()[0].descriptor))
    passed = report.review.governor["result"] == "BLOCKED" and any(item.provider == "review-broken" and item.errors for item in report.providers)
    return _result("provider-exception-isolation", passed, report.review.governor["result"])


WAVE_ONE: tuple[Check, ...] = (
    check_compile,
    check_imports,
    check_provider_count,
    check_read_only_manifests,
    check_forbidden_capabilities,
    check_no_shell_execution,
    check_public_docstrings,
    check_session_p30,
    check_session_apple,
    check_watcher_transition,
)

WAVE_TWO: tuple[Check, ...] = (
    check_simulation_count,
    check_p30_verdicts,
    check_apple_verdicts,
    check_twenty_privates,
    check_envelope_hashes,
    check_journal_replay,
    check_model_boundary,
    check_write_boundary,
    check_unsafe_serial_rejected,
    check_provider_exception_isolation,
)


def main() -> int:
    """Run the independent local SRG 10-for-2 reviewer."""

    waves = []
    for wave_number, checks in enumerate((WAVE_ONE, WAVE_TWO), start=1):
        results = [check() for check in checks]
        waves.append({"wave": wave_number, "results": [result.__dict__ for result in results]})
    passed = all(item["passed"] for wave in waves for item in wave["results"])
    payload = {
        "schema": "xray-live-local-review-v1",
        "method": "SRG 10-for-2 independent reviewer",
        "passed": passed,
        "waves": waves,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
