from __future__ import annotations

import json
from pathlib import Path

from xray.live_cli import main


def test_cli_simulate_all_json(tmp_path: Path):
    output = tmp_path / "simulation.json"
    assert main(["simulate", "all", "--format", "json", "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload["reports"]) == 4
    assert payload["journal"]["valid"] is True


def test_cli_providers_and_doctor(capsys):
    assert main(["providers"]) == 0
    assert "apple-dfu" in capsys.readouterr().out
    assert main(["doctor", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["write_authorized"] is False


def test_cli_journal_verify(tmp_path: Path, capsys):
    journal = tmp_path / "evidence.jsonl"
    journal.write_text("", encoding="utf-8")
    assert main(["journal-verify", str(journal)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["envelopes"] == 0


def test_cli_watch_once_writes_reports(tmp_path: Path, monkeypatch):
    from xray.live_runtime import XrayLiveRuntime

    monkeypatch.setattr(XrayLiveRuntime, "snapshot_once", lambda self: [])
    output = tmp_path / "live-reports.jsonl"
    assert (
        main(
            [
                "watch",
                "--once",
                "--state",
                str(tmp_path / "sessions.json"),
                "--journal",
                str(tmp_path / "evidence.jsonl"),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert output.exists()
