from __future__ import annotations

import json
import os
import subprocess
import sys
from importlib import resources
from pathlib import Path

import pytest

from xray import (
    SELFTEST_APPLE,
    SELFTEST_HUAWEI,
    SELFTEST_UNISOC,
    KnowledgeError,
    Status,
    inspect_text,
    load_knowledge,
    run_selftest,
)
from xray import runtime


def claim(report, name):
    """Return a named claim from a test report."""

    return next(item for item in report.claims if item.name == name)


@pytest.fixture
def cli_env() -> dict[str, str]:
    """Return a CLI environment that imports the source checkout."""

    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    return env


def test_knowledge_pack_is_valid():
    knowledge = load_knowledge()
    assert knowledge["schema"] == "xray-knowledge-v1"
    assert knowledge["proof_policies"]["write_authorization"]["enabled"] is False
    assert "dfu" in knowledge["expected_apple_providers"]


def test_packaged_knowledge_exists():
    packaged = resources.files("xray").joinpath("data/base.json")
    assert packaged.is_file()
    assert json.loads(packaged.read_text(encoding="utf-8"))["schema"] == "xray-knowledge-v1"


def test_knowledge_rejects_non_object(tmp_path: Path):
    source = tmp_path / "bad.json"
    source.write_text("[]", encoding="utf-8")
    with pytest.raises(KnowledgeError, match="JSON object"):
        load_knowledge(source)


def test_knowledge_requires_version(tmp_path: Path):
    payload = load_knowledge().copy()
    payload.pop("version")
    source = tmp_path / "bad.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(KnowledgeError, match="version"):
        load_knowledge(source)


def test_unisoc_loader_is_not_certified_as_silicon():
    report = inspect_text(
        SELFTEST_UNISOC,
        artifact_name="unisoc.txt",
        external_claims=[
            {
                "key": "hardware.marketed_soc",
                "value": "UNISOC T7250",
                "source_class": "specialist_online",
                "applies_to_model": "Infinix X6725B",
            }
        ],
    )
    assert claim(report, "device.family").value == "UNISOC"
    assert claim(report, "device.family").status is Status.CERTIFIED
    assert claim(report, "transport.mode").value == "BROM"
    assert claim(report, "hardware.loader_compatibility").value == "Tiger_T616_64"
    assert claim(report, "hardware.exact_soc").status is Status.CONFLICTED
    assert claim(report, "hardware.exact_soc").status is not Status.CERTIFIED
    assert report.governor_verdict["write_authorized"] is False
    assert report.workforce["total_privates"] == 20
    assert report.workforce["waves"] == 2


def test_external_silicon_id_cannot_certify_soc():
    report = inspect_text(
        "Product Model: Example X1\n",
        external_claims=[
            {
                "key": "hardware.silicon_id",
                "value": "FAKE-SILICON",
                "source_class": "unsourced",
                "applies_to_model": "Example X1",
            }
        ],
    )
    soc = next((item for item in report.claims if item.name == "hardware.exact_soc"), None)
    assert soc is None or soc.status is not Status.CERTIFIED
    external = next(item for item in report.evidence if item.key == "hardware.silicon_id")
    assert external.observed is False


def test_huawei_no_main_version_blocks_identity():
    report = inspect_text(SELFTEST_HUAWEI, artifact_name="huawei.txt")
    assert claim(report, "firmware.main_version").status is Status.BLOCKED
    assert report.governor_verdict["result"] == "BLOCKED"
    assert report.governor_verdict["write_authorized"] is False


def test_apple_dfu_is_expected_without_android_dependency():
    report = inspect_text(SELFTEST_APPLE, artifact_name="apple.txt")
    assert claim(report, "device.family").value == "Apple"
    assert claim(report, "transport.mode").value == "DFU"
    assert claim(report, "apple.cpid").value == "0x8015"
    assert {"apple-usb", "usbmux", "mobiledevice", "irecovery", "dfu"}.issubset(
        report.provider_expectations["apple"]
    )


def test_unknown_input_still_returns_custodied_report():
    report = inspect_text("mystery bytes described as text", artifact_name="unknown.txt")
    assert claim(report, "device.family").status is Status.UNKNOWN
    assert claim(report, "transport.mode").status is Status.UNKNOWN
    assert report.artifact["sha256"]
    assert report.governor_verdict["result"] == "READ_ONLY_READY"


def test_selftest_passes():
    result = run_selftest()
    assert result["passed"] is True
    assert len(result["tests"]) == 3


def test_selftest_missing_claim_becomes_failure(monkeypatch):
    original = runtime.inspect_text

    def broken_inspect(text, **kwargs):
        report = original(text, **kwargs)
        report.claims = [item for item in report.claims if item.name != "apple.cpid"]
        return report

    monkeypatch.setattr(runtime, "inspect_text", broken_inspect)
    result = runtime.run_selftest()
    apple = next(item for item in result["tests"] if item["name"] == "apple-dfu-readiness")
    assert apple["passed"] is False
    assert result["passed"] is False


def test_safe_command_uses_resolved_executable(monkeypatch):
    captured = {}

    class Completed:
        returncode = 0
        stdout = "ok"
        stderr = ""

    monkeypatch.setattr(runtime.shutil, "which", lambda name: "/trusted/bin/tool")

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return Completed()

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    result = runtime._safe_command("probe", ["tool", "--read"])
    assert captured["argv"] == ["/trusted/bin/tool", "--read"]
    assert result["argv"] == ["/trusted/bin/tool", "--read"]


def test_json_report_is_serializable():
    report = inspect_text(SELFTEST_APPLE, artifact_name="apple.txt")
    encoded = json.dumps(report.to_dict())
    assert '"schema": "xray-report-v1"' in encoded


def test_cli_selftest(cli_env: dict[str, str]):
    result = subprocess.run(
        [sys.executable, "-m", "xray", "selftest", "--format", "json"],
        cwd=Path(__file__).resolve().parents[1],
        env=cli_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["passed"] is True


def test_cli_blocked_exit_code(tmp_path: Path, cli_env: dict[str, str]):
    source = tmp_path / "huawei.txt"
    source.write_text(SELFTEST_HUAWEI, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "xray", "inspect", str(source), "--format", "json"],
        cwd=Path(__file__).resolve().parents[1],
        env=cli_env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["governor_verdict"]["result"] == "BLOCKED"
