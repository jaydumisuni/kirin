from __future__ import annotations

import json
from pathlib import Path

from xray.cli import main
from xray.firmware import add_firmware_model, scan_firmware_library
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


def test_firmware_library_lists_ready_p30_package(tmp_path: Path):
    library = tmp_path / "firmware"
    add_firmware_model(library, "p 30 pro", preset="p30-pro")
    package = _vog_package(library / "p 30 pro")

    catalog = scan_firmware_library(library)

    assert catalog["model_count"] == 1
    assert catalog["package_count"] == 1
    model = catalog["models"][0]
    assert model["name"] == "P30 Pro"
    assert model["status"] == "READY"
    assert model["packages"][0]["path"] == str(package)
    assert model["packages"][0]["status"] == "READY"


def test_firmware_library_marks_unextracted_metadata(tmp_path: Path):
    library = tmp_path / "firmware"
    add_firmware_model(library, "p30", preset="p30-pro")
    package = _vog_package(library / "p30")
    for path in package.rglob("*.mbn"):
        path.unlink()

    catalog = scan_firmware_library(library)

    assert catalog["models"][0]["status"] == "NEEDS_EXTRACTION"
    assert catalog["models"][0]["packages"][0]["missing"]


def test_generic_new_model_lists_dropped_firmware_as_unverified(tmp_path: Path):
    library = tmp_path / "firmware"
    add_firmware_model(
        library,
        "mate 20 pro",
        name="Mate 20 Pro",
        manufacturer="Huawei",
        variants=["LYA-L29"],
    )
    _write(library / "mate 20 pro" / "downloaded-firmware.zip", b"archive")

    catalog = scan_firmware_library(library)

    model = catalog["models"][0]
    assert model["status"] == "UNVERIFIED"
    assert model["packages"][0]["name"] == "downloaded-firmware.zip"


def test_cli_firmware_list_refreshes_catalog(tmp_path: Path, capsys):
    library = tmp_path / "firmware"
    add_firmware_model(library, "p 30 pro", preset="p30-pro")
    _vog_package(library / "p 30 pro")
    output = library / "available-firmware.json"

    assert main(["firmware-list", "--library-root", str(library), "--catalog-output", str(output)]) == 0
    assert "P30 Pro [READY]" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["package_count"] == 1
