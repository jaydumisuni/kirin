from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from xray.core import (
    SELFTEST_APPLE,
    SELFTEST_HUAWEI,
    SELFTEST_UNISOC,
    Status,
    inspect_text,
    load_knowledge,
    run_selftest,
)


def claim(report, name):
    return next(item for item in report.claims if item.name == name)


def test_knowledge_pack_is_valid():
    knowledge = load_knowledge()
    assert knowledge["schema"] == "xray-knowledge-v1"
    assert knowledge["proof_policies"]["write_authorization"]["enabled"] is False
    assert "dfu" in knowledge["expected_apple_providers"]


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
    assert set(["apple-usb", "usbmux", "mobiledevice", "irecovery", "dfu"]).issubset(
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


def test_json_report_is_serializable():
    report = inspect_text(SELFTEST_APPLE, artifact_name="apple.txt")
    encoded = json.dumps(report.to_dict())
    assert '"schema": "xray-report-v1"' in encoded


def test_cli_selftest(tmp_path: Path):
    env = dict(**__import__("os").environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "xray", "selftest", "--format", "json"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["passed"] is True


def test_cli_blocked_exit_code(tmp_path: Path):
    source = tmp_path / "huawei.txt"
    source.write_text(SELFTEST_HUAWEI, encoding="utf-8")
    env = dict(**__import__("os").environ)
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "xray", "inspect", str(source), "--format", "json"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    payload = json.loads(result.stdout)
    assert payload["governor_verdict"]["result"] == "BLOCKED"
