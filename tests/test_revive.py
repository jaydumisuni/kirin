from __future__ import annotations

import json
from pathlib import Path

from xray.cli import main
from xray.revive import build_revive_plan, guarded_batch_script, vog_l29_c185_profile


def _write(path: Path, data: bytes = b"x") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _vog_package(root: Path) -> Path:
    package = root / "VOGUE-L29D 10.0.0.186(C185E8R5P1)_Firmware_EMUI10.0.0_05016EUP"
    dload = package / "Software" / "dload"
    _write(dload / "update_sd_base.zip", b"base")
    _write(dload / "update_sd_cust_VOG-L29_hw_meafnaf.zip", b"cust")
    _write(dload / "update_sd_preload_VOG-L29_hw_meafnaf_R5.zip", b"preload")
    _write(dload / "update_sd_base" / "SOFTWARE_VER_LIST.mbn", b"base-verlist")
    _write(dload / "update_sd_cust_VOG-L29_hw_meafnaf" / "SOFTWARE_VER_LIST.mbn", b"cust-verlist")
    _write(dload / "update_sd_cust_VOG-L29_hw_meafnaf" / "PTABLE_CUST.mbn", b"cust-ptable")
    _write(dload / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "SOFTWARE_VER_LIST.mbn", b"preload-verlist")
    _write(dload / "update_sd_preload_VOG-L29_hw_meafnaf_R5" / "PTABLE_PRELOAD.mbn", b"preload-ptable")
    return package


def test_vog_revive_plan_maps_matched_c185_artifacts(tmp_path: Path):
    package = _vog_package(tmp_path)
    plan = build_revive_plan(vog_l29_c185_profile(package))

    assert plan["schema"] == "xray-revive-plan-v1"
    assert plan["authority"]["write_authorized"] is False
    assert plan["target"]["model"] == "VOG-L29"
    assert plan["target"]["vendor"] == "hw"
    labels = {item["label"] for item in plan["artifacts"]}
    assert {"CUST_VERLIST", "CUST_PTABLE", "PRELOAD_VERLIST", "PRELOAD_PTABLE"} <= labels


def test_guarded_batch_script_is_audit_only(tmp_path: Path):
    package = _vog_package(tmp_path)
    plan = build_revive_plan(vog_l29_c185_profile(package))
    script = guarded_batch_script(plan)

    assert "AUDIT ONLY" in script
    assert "write_authorized=false" in script
    assert "Do not use VTR-L29C432.bin" in script
    assert "exit /b 2" in script


def test_cli_revive_plan_writes_outputs(tmp_path: Path, capsys):
    package = _vog_package(tmp_path)
    output = tmp_path / "out" / "plan.json"
    script = tmp_path / "out" / "revive.bat"

    assert (
        main(
            [
                "revive-plan",
                "vog-l29-c185",
                "--package-root",
                str(package),
                "--output",
                str(output),
                "--script-output",
                str(script),
            ]
        )
        == 0
    )
    assert "Write authorized: NO" in capsys.readouterr().out
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["profile"] == "vog-l29-c185-from-p10revive-pattern"
    assert "AUDIT ONLY" in script.read_text(encoding="utf-8")
