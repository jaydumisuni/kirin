"""Collect the frozen live regression corpus and enforce SRG 20-for-2 cardinality."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from xray.live_review import WAVE_ONE, WAVE_TWO
from xray.simulation import run_simulation

_REGRESSION_PATH = Path(__file__).with_name("live_core_regressions.py")
_SPEC = importlib.util.spec_from_file_location("tests.live_core_regressions", _REGRESSION_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load frozen live regressions from {_REGRESSION_PATH}")
_REGRESSIONS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_REGRESSIONS)

_SUPERSEDED = "test_full_simulation_has_two_physical_sessions_and_20_privates_each"
for _name, _value in vars(_REGRESSIONS).items():
    if _name.startswith("test_") and _name != _SUPERSEDED:
        globals()[_name] = _value


def test_full_simulation_has_two_physical_sessions_and_40_privates_each():
    """Require both twenty-private waves on every simulated live report."""

    payload = run_simulation("all")
    assert len(payload["sessions"]) == 2
    assert len(payload["reports"]) == 4
    assert all(
        len(report["review"]["privates"]) == 40
        for report in payload["reports"]
    )
    assert payload["write_authorized"] is False
    assert payload["model_required"] is False


def test_live_review_uses_complete_20_for_2_private_ids():
    """Prove two waves of twenty unique and complete private identifiers."""

    assert len(WAVE_ONE) == 20
    assert len(WAVE_TWO) == 20
    expected = {f"private-{index:03d}" for index in range(1, 41)}
    payload = run_simulation("all")
    for report in payload["reports"]:
        review = report["review"]
        privates = review["privates"]
        assert len(privates) == 40
        assert {item["private_id"] for item in privates} == expected
        assert review["method"] == "SRG 20-for-2 live corps"
