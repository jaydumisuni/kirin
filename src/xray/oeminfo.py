from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


OEMINFO_SCHEMA = "xray.huawei.oeminfo.v8.v1"
OEMINFO_MAGIC = b"OEM_INFO"
OEMINFO_VERSION = 8
OEMINFO_PAGE_SIZE = 512
OEMINFO_REGION_SIZE = 48 * 1024 * 1024
OEMINFO_PARTITION_SIZE = 2 * OEMINFO_REGION_SIZE
OEMINFO_SUBPART_SIZE = 8 * 1024 * 1024
OEMINFO_HEADER = struct.Struct("<8sIIIII")

VOG_L29_C185_MODEL = "VOG-L29"
VOG_L29_C185_VENDOR_COUNTRY = "hw/meafnaf"
VOG_L29_C185_SYSTEM_VERSION = "VOG-L29 10.0.0.186(C185E8R5P1)"
VOG_L29_C185_BASE_VERSION = "VOG-LGRP2-OVS 10.0.0.1"
VOG_L29_C185_CUST_VERSION = "VOG-Global-CUST 10.0.0(C185)"
VOG_L29_C185_PRELOAD_VERSION = "VOG_GLOBAL_PRELOAD 10.0.0(C185)"


class OeminfoError(ValueError):
    """Raised when a Huawei OEMINFO image cannot be built or verified."""


@dataclass(frozen=True)
class OeminfoRecordSpec:
    name: str
    legacy_id: int
    record_id: int
    payload: bytes


@dataclass(frozen=True)
class OeminfoRecord:
    record_id: int
    offset: int
    slot_size: int
    total_blocks: int
    total_bytes: int
    age: int
    payload: bytes


def oeminfo_v8_layout(record_id: int) -> tuple[int, int]:
    """Return the offset within a 48 MiB v8 region and the record slot size."""

    if 4501 <= record_id <= 4503:
        return 3 * OEMINFO_SUBPART_SIZE + (record_id - 4501) * OEMINFO_SUBPART_SIZE, OEMINFO_SUBPART_SIZE

    quotient, remainder = divmod(record_id, 1500)
    if quotient not in range(3):
        raise OeminfoError(f"OEMINFO v8 record ID is outside the three normal subpartitions: {record_id}")
    subpart_offset = quotient * OEMINFO_SUBPART_SIZE
    if 1 <= remainder <= 640:
        return subpart_offset + (remainder - 1) * 4096, 4096
    if 1001 <= remainder <= 1200:
        return subpart_offset + 0x280000 + (remainder - 1001) * 8192, 8192
    raise OeminfoError(f"OEMINFO v8 record ID has no defined slot: {record_id}")


def vog_l29_c185_record_specs(
    *,
    base_version: str = VOG_L29_C185_BASE_VERSION,
    cust_version: str = VOG_L29_C185_CUST_VERSION,
    preload_version: str = VOG_L29_C185_PRELOAD_VERSION,
) -> tuple[OeminfoRecordSpec, ...]:
    """Return identity records translated from the legacy Huawei API to v8 IDs."""

    values = {
        "model": VOG_L29_C185_MODEL.encode("ascii"),
        "vendor_country": VOG_L29_C185_VENDOR_COUNTRY.encode("ascii"),
        "system_version": VOG_L29_C185_SYSTEM_VERSION.encode("ascii"),
        "base_version": base_version.encode("ascii"),
        "cust_version": cust_version.encode("ascii"),
        "preload_version": preload_version.encode("ascii"),
    }
    return (
        OeminfoRecordSpec("vendor_country", 18, 1502, values["vendor_country"]),
        OeminfoRecordSpec("build_number", 78, 1516, values["system_version"]),
        OeminfoRecordSpec("product_model", 91, 1518, values["model"]),
        OeminfoRecordSpec("device_model", 97, 1519, values["model"]),
        OeminfoRecordSpec("main_version", 101, 27, values["system_version"]),
        OeminfoRecordSpec("system_version_a", 111, 34, values["system_version"]),
        OeminfoRecordSpec("base_ver_type", 156, 76, values["base_version"]),
        OeminfoRecordSpec("cust_ver_type", 157, 77, values["cust_version"]),
        OeminfoRecordSpec("preload_ver_type", 158, 78, values["preload_version"]),
        OeminfoRecordSpec("system_version_b", 172, 68, values["system_version"]),
        OeminfoRecordSpec("custom_version_a", 180, 80, values["cust_version"]),
        OeminfoRecordSpec("custom_version_b", 181, 81, values["cust_version"]),
        OeminfoRecordSpec("preload_version_a", 182, 82, values["preload_version"]),
        OeminfoRecordSpec("preload_version_b", 183, 83, values["preload_version"]),
        OeminfoRecordSpec("base_version_a", 186, 86, values["base_version"]),
        OeminfoRecordSpec("base_version_b", 187, 87, values["base_version"]),
    )


def read_oeminfo_record(
    image: bytes | bytearray,
    record_id: int,
    *,
    copy_index: int = 0,
) -> OeminfoRecord | None:
    if copy_index not in (0, 1):
        raise OeminfoError(f"OEMINFO copy index must be 0 or 1: {copy_index}")
    if len(image) != OEMINFO_PARTITION_SIZE:
        raise OeminfoError(
            f"OEMINFO image must be exactly {OEMINFO_PARTITION_SIZE} bytes; found {len(image)}"
        )
    relative_offset, slot_size = oeminfo_v8_layout(record_id)
    offset = copy_index * OEMINFO_REGION_SIZE + relative_offset
    magic, version, stored_id, total_blocks, total_bytes, age = OEMINFO_HEADER.unpack_from(image, offset)
    if magic != OEMINFO_MAGIC:
        return None
    if version != OEMINFO_VERSION:
        raise OeminfoError(f"OEMINFO record {record_id} has version {version}, expected 8")
    if stored_id != record_id:
        raise OeminfoError(f"OEMINFO slot {record_id} contains record ID {stored_id}")
    expected_blocks = (total_bytes + OEMINFO_PAGE_SIZE - 1) // OEMINFO_PAGE_SIZE
    if total_blocks != expected_blocks:
        raise OeminfoError(
            f"OEMINFO record {record_id} has {total_blocks} blocks; expected {expected_blocks}"
        )
    if OEMINFO_PAGE_SIZE + total_blocks * OEMINFO_PAGE_SIZE > slot_size:
        raise OeminfoError(f"OEMINFO record {record_id} extends beyond its {slot_size}-byte slot")
    payload_offset = offset + OEMINFO_PAGE_SIZE
    payload = bytes(image[payload_offset : payload_offset + total_bytes])
    return OeminfoRecord(
        record_id=record_id,
        offset=offset,
        slot_size=slot_size,
        total_blocks=total_blocks,
        total_bytes=total_bytes,
        age=age,
        payload=payload,
    )


def _encode_record(record_id: int, payload: bytes, *, age: int = 1) -> bytes:
    _, slot_size = oeminfo_v8_layout(record_id)
    total_blocks = (len(payload) + OEMINFO_PAGE_SIZE - 1) // OEMINFO_PAGE_SIZE
    if OEMINFO_PAGE_SIZE + total_blocks * OEMINFO_PAGE_SIZE > slot_size:
        raise OeminfoError(
            f"OEMINFO payload for record {record_id} is too large for its {slot_size}-byte slot"
        )
    slot = bytearray(slot_size)
    OEMINFO_HEADER.pack_into(
        slot,
        0,
        OEMINFO_MAGIC,
        OEMINFO_VERSION,
        record_id,
        total_blocks,
        len(payload),
        age,
    )
    slot[OEMINFO_PAGE_SIZE : OEMINFO_PAGE_SIZE + len(payload)] = payload
    return bytes(slot)


def _read_exact_text(path: Path, expected: str, label: str) -> str:
    try:
        raw = path.read_bytes()
        value = raw.decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise OeminfoError(f"Cannot read {label} metadata {path}: {exc}") from exc
    if value != expected:
        raise OeminfoError(f"Unexpected {label} metadata in {path}: {value!r}; expected {expected!r}")
    return value


def _sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _special_record_manifest(image: bytes | bytearray) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for record_id in (4501, 4502, 4503):
        record = read_oeminfo_record(image, record_id)
        if record is None:
            raise OeminfoError(f"Board OEMINFO template is missing required reused record {record_id}")
        slot = image[record.offset : record.offset + record.slot_size]
        records.append(
            {
                "record_id": record_id,
                "offset": record.offset,
                "slot_size": record.slot_size,
                "total_blocks": record.total_blocks,
                "total_bytes": record.total_bytes,
                "age": record.age,
                "payload_sha256": _sha256_bytes(record.payload),
                "slot_sha256": _sha256_bytes(slot),
            }
        )
    return records


def _verify_profile_records(
    image: bytes | bytearray,
    specs: Iterable[OeminfoRecordSpec],
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for spec in specs:
        copies: list[dict[str, Any]] = []
        for copy_index in (0, 1):
            record = read_oeminfo_record(image, spec.record_id, copy_index=copy_index)
            if record is None:
                raise OeminfoError(
                    f"Generated OEMINFO is missing {spec.name} record {spec.record_id} in copy {copy_index}"
                )
            if record.payload != spec.payload:
                raise OeminfoError(
                    f"Generated OEMINFO record {spec.record_id} has the wrong {spec.name} payload"
                )
            copies.append(
                {
                    "copy": copy_index,
                    "offset": record.offset,
                    "age": record.age,
                    "total_blocks": record.total_blocks,
                    "total_bytes": record.total_bytes,
                }
            )
        records.append(
            {
                "name": spec.name,
                "legacy_id": spec.legacy_id,
                "record_id": spec.record_id,
                "payload_ascii": spec.payload.decode("ascii"),
                "payload_sha256": _sha256_bytes(spec.payload),
                "copies": copies,
            }
        )
    return records


def verify_vog_l29_c185_oeminfo(image_path: Path, template_path: Path) -> dict[str, Any]:
    """Verify target identity records and preservation of the board template records."""

    try:
        image = image_path.read_bytes()
        template = template_path.read_bytes()
    except OSError as exc:
        raise OeminfoError(f"Cannot read OEMINFO image: {exc}") from exc
    if len(image) != OEMINFO_PARTITION_SIZE or len(template) != OEMINFO_PARTITION_SIZE:
        raise OeminfoError(f"OEMINFO image and template must both be {OEMINFO_PARTITION_SIZE} bytes")

    template_special = _special_record_manifest(template)
    image_special = _special_record_manifest(image)
    for before, after in zip(template_special, image_special, strict=True):
        if before["slot_sha256"] != after["slot_sha256"]:
            raise OeminfoError(f"Board OEMINFO record {before['record_id']} was not preserved")

    records = _verify_profile_records(image, vog_l29_c185_record_specs())
    return {
        "schema": OEMINFO_SCHEMA,
        "status": "VERIFIED",
        "image": str(image_path.resolve()),
        "image_size": len(image),
        "image_sha256": _sha256_bytes(image),
        "template": str(template_path.resolve()),
        "template_sha256": _sha256_bytes(template),
        "preserved_board_records": image_special,
        "identity_records": records,
        "identity_record_count": len(records),
        "copy_count": 2,
        "write_authorized": False,
    }


def build_vog_l29_c185_oeminfo(
    template_path: Path,
    base_version_path: Path,
    cust_version_path: Path,
    preload_version_path: Path,
    output_path: Path,
    *,
    manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Create a P30 Pro VOG-L29 C185 v8 OEMINFO image from local package evidence."""

    if output_path.exists():
        raise OeminfoError(f"Refusing to overwrite existing OEMINFO output: {output_path}")
    if manifest_path is not None and manifest_path.exists():
        raise OeminfoError(f"Refusing to overwrite existing OEMINFO manifest: {manifest_path}")

    base_version = _read_exact_text(base_version_path, VOG_L29_C185_BASE_VERSION, "base version")
    cust_version = _read_exact_text(cust_version_path, VOG_L29_C185_CUST_VERSION, "CUST version")
    preload_version = _read_exact_text(
        preload_version_path,
        VOG_L29_C185_PRELOAD_VERSION,
        "PRELOAD version",
    )
    try:
        template = template_path.read_bytes()
    except OSError as exc:
        raise OeminfoError(f"Cannot read board OEMINFO template {template_path}: {exc}") from exc
    if len(template) != OEMINFO_PARTITION_SIZE:
        raise OeminfoError(
            f"Board OEMINFO template must be exactly {OEMINFO_PARTITION_SIZE} bytes; found {len(template)}"
        )
    preserved = _special_record_manifest(template)

    specs = vog_l29_c185_record_specs(
        base_version=base_version,
        cust_version=cust_version,
        preload_version=preload_version,
    )
    image = bytearray(template)
    for spec in specs:
        encoded = _encode_record(spec.record_id, spec.payload)
        relative_offset, slot_size = oeminfo_v8_layout(spec.record_id)
        for copy_index in (0, 1):
            offset = copy_index * OEMINFO_REGION_SIZE + relative_offset
            existing = image[offset : offset + slot_size]
            if any(existing):
                raise OeminfoError(
                    f"Board OEMINFO template slot {spec.record_id} copy {copy_index} is not blank"
                )
            image[offset : offset + slot_size] = encoded

    verified_records = _verify_profile_records(image, specs)
    after_special = _special_record_manifest(image)
    for before, after in zip(preserved, after_special, strict=True):
        if before["slot_sha256"] != after["slot_sha256"]:
            raise OeminfoError(f"Board OEMINFO record {before['record_id']} changed during generation")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as stream:
        stream.write(image)

    manifest: dict[str, Any] = {
        "schema": OEMINFO_SCHEMA,
        "profile": "huawei-p30-pro-vog-l29-c185",
        "status": "VERIFIED",
        "target": {
            "model": VOG_L29_C185_MODEL,
            "vendor_country": VOG_L29_C185_VENDOR_COUNTRY,
            "system_version": VOG_L29_C185_SYSTEM_VERSION,
            "base_version": base_version,
            "cust_version": cust_version,
            "preload_version": preload_version,
        },
        "template": {
            "path": str(template_path.resolve()),
            "size": len(template),
            "sha256": _sha256_bytes(template),
        },
        "metadata_sources": {
            "base_version": {"path": str(base_version_path.resolve()), "sha256": _sha256_file(base_version_path)},
            "cust_version": {"path": str(cust_version_path.resolve()), "sha256": _sha256_file(cust_version_path)},
            "preload_version": {
                "path": str(preload_version_path.resolve()),
                "sha256": _sha256_file(preload_version_path),
            },
        },
        "output": {
            "path": str(output_path.resolve()),
            "size": len(image),
            "sha256": _sha256_bytes(image),
        },
        "preserved_board_records": after_special,
        "identity_records": verified_records,
        "identity_record_count": len(verified_records),
        "copy_count": 2,
        "write_authorized": False,
    }
    if manifest_path is not None:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
