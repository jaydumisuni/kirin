from __future__ import annotations

from types import SimpleNamespace

from xray.live_models import ProviderProbeResult
from xray.live_review import _apple_pid_mode, _run_wave, _write_boundary
from xray.simulation import apple_events


def test_apple_pid_mode_ignores_empty_transport_observation() -> None:
    event = apple_events()[0]
    result = _apple_pid_mode(
        {
            "event": event,
            "providers": (
                ProviderProbeResult(
                    "apple-recovery",
                    True,
                    observations={"transport.mode": ""},
                ),
            ),
        }
    )

    assert result.passed


def test_write_boundary_casefolds_forbidden_capabilities() -> None:
    result = _write_boundary(
        {
            "manifests": (
                SimpleNamespace(
                    name="mixed-case",
                    capabilities=(SimpleNamespace(value="FlashDevice"),),
                ),
            )
        }
    )

    assert not result.passed


def test_run_wave_uses_explicit_wave_number_for_failures() -> None:
    def broken(_context: dict[str, object]):
        raise RuntimeError("expected reviewer failure")

    result = _run_wave((broken,), {}, 2)

    assert len(result) == 1
    assert result[0].wave == 2
    assert not result[0].passed
