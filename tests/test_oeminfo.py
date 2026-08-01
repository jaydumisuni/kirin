from __future__ import annotations

import json
from pathlib import Path

import pytest

from xray.cli import main
from xray.oeminfo import (
    OEMINFO_HEADER,
    OEMINFO_MAGIC,
    OEMINFO_PAGE_SIZE,
    OEMINFO_PARTITION_SIZE,
    OEMINFO_REGION_SIZE,
    OEMINFO_VERSION,
    OeminfoError,
    VOG_L29_C185_BASE_VERSION,
    VOG_L29_C185_CUST_VERSION,
    VOG_L29_C185_PRELOAD_VERSION,
    oeminfo_v8_layout,
    read_oeminfo_record,
    verify_vog_l29_c185_oeminfo,
    vog_l29_c185_record_specs,
)


def _board_template(path: Path) -> None:
    with path.open("wb") as stream:
        stream.truncate(OEMINFO_PARTITION_SIZE)
        for record_id in (4501, 4502, 4503):
            offset, _ = oeminfo_v8_layout(record_id)
            payload = f"factory-{record_id}".encode("ascii")
            stream.seek(offset)
            stream.write(
                OEMINFO_HEADER.pack(
                    OEMINFO_MAGIC,
                    OEMINFO_VERSION,
                    record_id,
                    1,
                    len(payload),
                    1,
                )
            )
            stream.seek(offset + OEMINFO_PAGE_SIZE)
            stream.write(payload)


def _metadata(tmp_path: Path) -> tuple[Path, Path, Path]:
    values = (
        ("BASE_VER.mbn", VOG_L29_C185_BASE_VERSION),
        ("CUST_VER.mbn", VOG_L29_C185_CUST_VERSION),
        ("PRELOAD_VER.mbn", VOG_L29_C185_PRELOAD_VERSION),
    )
    paths: list[Path] = []
    for name, value in values:
        path = tmp_path / name
        path.write_text(value, encoding="ascii")
        paths.append(path)
    return paths[0], paths[1], paths[2]


def test_v8_record_layout_matches_huawei_subpartitions():
    assert oeminfo_v8_layout(1) == (0, 4096)
    assert oeminfo_v8_layout(34) == (33 * 4096, 4096)
    assert oeminfo_v8_layout(1001) == (0x280000, 8192)
    assert oeminfo_v8_layout(1502) == (0x800000 + 4096, 4096)
    assert oeminfo_v8_layout(4501) == (0x1800000, 0x800000)
    assert oeminfo_v8_layout(4503) == (0x2800000, 0x800000)
    with pytest.raises(OeminfoError, match="no defined slot"):
        oeminfo_v8_layout(900)


def test_cli_builds_redundant_vog_l29_c185_image_and_preserves_board_records(
    tmp_path: Path,
    capsys,
):
    template = tmp_path / "oeminfo.mbn"
    _board_template(template)
    base, cust, preload = _metadata(tmp_path)
    output = tmp_path / "VOG-L29C185.bin"
    manifest = tmp_path / "VOG-L29C185.bin.manifest.json"

    assert (
        main(
            [
                "huawei-oeminfo-build",
                "--template",
                str(template),
                "--base-version",
                str(base),
                "--cust-version",
                str(cust),
                "--preload-version",
                str(preload),
                "--output",
                str(output),
                "--manifest",
                str(manifest),
            ]
        )
        == 0
    )
    assert "Verified identity records: 16 x 2 copies" in capsys.readouterr().out
    assert output.stat().st_size == OEMINFO_PARTITION_SIZE

    image = output.read_bytes()
    for spec in vog_l29_c185_record_specs():
        primary = read_oeminfo_record(image, spec.record_id)
        backup = read_oeminfo_record(image, spec.record_id, copy_index=1)
        assert primary is not None and primary.payload == spec.payload
        assert backup is not None and backup.payload == spec.payload
        assert backup.offset - primary.offset == OEMINFO_REGION_SIZE

    report = verify_vog_l29_c185_oeminfo(output, template)
    saved = json.loads(manifest.read_text(encoding="utf-8"))
    assert report["status"] == "VERIFIED"
    assert saved["output"]["sha256"] == report["image_sha256"]
    assert [item["slot_sha256"] for item in saved["preserved_board_records"]] == [
        item["slot_sha256"] for item in report["preserved_board_records"]
    ]


def test_generator_rejects_metadata_not_proven_by_target_package(tmp_path: Path, capsys):
    template = tmp_path / "oeminfo.mbn"
    base, cust, preload = _metadata(tmp_path)
    base.write_text("VOG-LGRP2-OVS 10.0.0.999", encoding="ascii")

    assert (
        main(
            [
                "huawei-oeminfo-build",
                "--template",
                str(template),
                "--base-version",
                str(base),
                "--cust-version",
                str(cust),
                "--preload-version",
                str(preload),
                "--output",
                str(tmp_path / "bad.bin"),
            ]
        )
        == 2
    )
    assert "Unexpected base version metadata" in capsys.readouterr().err
