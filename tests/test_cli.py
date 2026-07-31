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
