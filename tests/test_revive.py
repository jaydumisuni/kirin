from __future__ import annotations

import json
from pathlib import Path

from xray.cli import main
from xray.firmware import add_firmware_model, scan_firmware_library
from xray.huawei_board import build_p30_revive_workflow, inspect_huawei_board_package
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


def _board_package(root: Path) -> Path:
    package = root / "VOGUE-AL00A-BD_board-software"
    _write(package / "fastbootimage" / "ptable.img", b"ptable")
    _write(package / "fastbootimage" / "oeminfo.mbn", b"oeminfo")
    _write(package / "fastbootimage" / "version.img", b"version")
    xml = """<?xml version="1.0"?>
<configurations>
  <configuration ap_platform="kirin980" product_id="VOG" version="VOG-AL00-BD 1.0.0.82">
    <fastbootimage>
      <image name="PTABLE" identifier="ptable">fastbootimage/ptable.img</image>
      <image name="OEMINFO" identifier="oeminfo">fastbootimage/oeminfo.mbn</image>
      <image name="VERSION" identifier="version">fastbootimage/version.img</image>
    </fastbootimage>
    <partially_erase_configuration>
      <cmd type="fastboot" command="flash" identifier="ptable">fastbootimage/ptable.img</cmd>
      <cmd type="fastboot" command="erase" identifier="userdata"></cmd>
      <cmd type="fastboot" command="reboot"></cmd>
    </partially_erase_configuration>
  </configuration>
</configurations>
"""
    path = package / "VOG-AL00-BD_1.0.0.82_Download.xml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(xml, encoding="utf-8")
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


def test_huawei_board_xml_becomes_a_verified_recipe(tmp_path: Path):
    package = _board_package(tmp_path)

    recipe = inspect_huawei_board_package(package)

    assert recipe["status"] == "READY"
    assert recipe["platform"] == "kirin980"
    assert recipe["product"] == "VOG"
    assert recipe["inventory_count"] == 3
    assert recipe["operation_count"] == 3
    assert recipe["flash_count"] == 1
    assert recipe["erase_count"] == 1
    assert recipe["optional_inventory_missing"] == []
    assert recipe["write_authorized"] is False


def test_p30_catalog_recognizes_board_and_target_packages(tmp_path: Path):
    library = tmp_path / "firmware"
    add_firmware_model(library, "p 30 pro", preset="p30-pro")
    model_root = library / "p 30 pro"
    _vog_package(model_root)
    _board_package(model_root)

    catalog = scan_firmware_library(library)

    packages = {item["profile"]: item for item in catalog["models"][0]["packages"]}
    assert packages["vog-l29-three-part-dload"]["status"] == "READY"
    assert packages["vog-kirin980-board-xml"]["status"] == "READY"
    assert packages["vog-kirin980-board-xml"]["metadata"]["operations"] == 3


def test_p10_stage_pattern_is_carried_into_p30_workflow(tmp_path: Path):
    model_root = tmp_path / "p 30 pro"
    _vog_package(model_root)
    _board_package(model_root)

    workflow = build_p30_revive_workflow(model_root)

    assert workflow["schema"] == "xray-revive-workflow-v1"
    assert workflow["stages"][0]["status"] == "PREPARED"
    assert workflow["stages"][0]["operation_count"] == 3
    assert workflow["stages"][1]["status"] == "PREPARED"
    assert workflow["stages"][2]["status"] == "BLOCKED"
    assert workflow["authority"]["write_authorized"] is False


def test_cli_writes_carried_p30_workflow(tmp_path: Path, capsys):
    model_root = tmp_path / "p 30 pro"
    _vog_package(model_root)
    _board_package(model_root)
    output = tmp_path / "plans" / "p30-workflow.json"

    assert (
        main(
            [
                "revive-workflow",
                "p30-pro",
                "--model-root",
                str(model_root),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert "Board restore: PREPARED" in capsys.readouterr().out
    assert json.loads(output.read_text(encoding="utf-8"))["ready_for_execution"] is False
