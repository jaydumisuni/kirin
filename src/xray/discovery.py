from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from .common import _ev, _extract_kv, _line_match
from .models import Evidence, PrivateResult


def _private_usb_fingerprint(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract USB VID/PID, endpoint, driver, and port evidence."""

    evidence: list[Evidence] = []
    for match in re.finditer(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", text):
        evidence.append(_ev("usb.vid", match.group(1).upper(), "private.usb-fingerprint", excerpt=match.group(0)))
        evidence.append(_ev("usb.pid", match.group(2).upper(), "private.usb-fingerprint", excerpt=match.group(0)))
    for label, key in [("Port", "transport.port"), ("Driver", "transport.driver")]:
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.usb-fingerprint", excerpt=found[1]))
    match = _line_match(r"Device found at\s+([^\r\n]+)", text)
    if match:
        evidence.append(_ev("transport.endpoint", match.group(1), "private.usb-fingerprint", excerpt=match.group(0)))
    return PrivateResult("private-001", 1, "Enumerate USB identity", tuple(evidence))


def _private_mode_detector(text: str, _: dict[str, Any]) -> PrivateResult:
    """Resolve direct and candidate device modes."""

    evidence: list[Evidence] = []
    for label in ("Port type", "MODE", "Mode"):
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev("transport.mode", found[0].upper(), "private.mode-detector", excerpt=found[1]))
    markers = [
        (r"\bBROM\b", "BROM"),
        (r"\bFASTBOOT\b", "FASTBOOT"),
        (r"\bDFU\b", "DFU"),
        (r"\bRECOVERY\b", "RECOVERY"),
        (r"\bDOWNLOAD MODE\b", "DOWNLOAD"),
        (r"\bPRELOADER\b", "PRELOADER"),
        (r"\bEDL\b", "EDL"),
    ]
    for pattern, value in markers:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev("transport.mode_candidate", value, "private.mode-detector", confidence=0.75, excerpt=match.group(0)))
    return PrivateResult("private-002", 1, "Detect active device mode", tuple(evidence))


def _private_android_identity(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract Android product, board, build, and filesystem identity."""

    mapping = {
        "Product Brand": "product.brand",
        "Product Manufacturer": "product.manufacturer",
        "Product Model": "product.model",
        "Product Name": "product.name",
        "Product Device": "product.device",
        "Product Board": "product.board",
        "Board Platform": "hardware.bsp_platform",
        "Build ID": "os.build_id",
        "Build Date": "os.build_date",
        "Display ID": "os.display_id",
        "Security Patch": "os.security_patch",
        "Version SDK": "os.sdk",
        "Version Release": "os.release",
        "Version Codename": "os.codename",
        "Firmware Version": "firmware.version",
        "Userdata FS Type": "storage.userdata_fs",
    }
    evidence: list[Evidence] = []
    for label, key in mapping.items():
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.android-identity", excerpt=found[1]))
    return PrivateResult("private-003", 1, "Read Android product and build identity", tuple(evidence))


def _private_apple_identity(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract Apple recovery identifiers without Android assumptions."""

    mapping = {
        "CPID": "apple.cpid",
        "BDID": "apple.bdid",
        "ECID": "apple.ecid",
        "PRODUCT": "apple.product_type",
        "MODEL": "apple.model",
        "NAME": "apple.name",
        "SRNM": "apple.serial",
        "NONC": "apple.nonce",
    }
    evidence: list[Evidence] = []
    for label, key in mapping.items():
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.apple-identity", excerpt=found[1]))
    if _line_match(r"Apple Mobile Device", text):
        evidence.append(_ev("product.family_hint", "Apple", "private.apple-identity", confidence=0.9, excerpt="Apple Mobile Device"))
    return PrivateResult("private-004", 1, "Read Apple recovery and product identity", tuple(evidence))


def _private_huawei_rescue(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract Huawei rescue, OEMINFO, and bootloader readback."""

    evidence: list[Evidence] = []
    warnings: list[str] = []
    match = _line_match(r"rescue_phoneinfo\s*:\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        evidence.append(_ev("firmware.main_version", value, "private.huawei-rescue", excerpt=match.group(0)))
        if value.upper() == "NO MAIN VERSION":
            warnings.append("Huawei main-version identity is absent or unreadable.")
    match = _line_match(r"vendorcountry\s*:\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        if "cannot get vendorcountry" in value.casefold() or "unreadable" in value.casefold():
            value = "UNREADABLE"
            warnings.append("Huawei OEMINFO vendor/country is unreadable.")
        evidence.append(_ev("oeminfo.vendor_country", value, "private.huawei-rescue", excerpt=match.group(0)))
    elif _line_match(r"cannot get vendorcountry in oeminfo", text):
        evidence.append(_ev("oeminfo.vendor_country", "UNREADABLE", "private.huawei-rescue", excerpt="cannot get vendorcountry in oeminfo"))
        warnings.append("Huawei OEMINFO vendor/country is unreadable.")
    match = _line_match(r"(?:oem get-bootinfo|bootinfo)\s*:\s*([^\r\n]+)", text)
    if match:
        evidence.append(_ev("security.bootloader", match.group(1), "private.huawei-rescue", excerpt=match.group(0)))
    match = _line_match(r"FASTBOOT_PRODUCT\s*:\s*([^\r\n]+)", text)
    if match:
        evidence.append(_ev("hardware.fastboot_product", match.group(1), "private.huawei-rescue", excerpt=match.group(0)))
    return PrivateResult("private-005", 1, "Read Huawei rescue/OEMINFO state", tuple(evidence), tuple(warnings))


def _private_unisoc_bootrom(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract UNISOC BootROM transport and loader compatibility evidence."""

    evidence: list[Evidence] = []
    for label, key, source_class in [
        ("Selected processor", "transport.loader_profile", "loader_compatibility"),
        ("Flash Type", "storage.type", "device_read"),
    ]:
        found = _extract_kv(text, label)
        if found:
            evidence.append(_ev(key, found[0], "private.unisoc-bootrom", source_class, excerpt=found[1]))
    for stage in ["Connecting to device", "Connect preloader 1", "Connect preloader 2", "Connect loader 1", "Connect loader 2", "Read partitions info"]:
        match = _line_match(rf"^{re.escape(stage)}\.{{0,3}}\s*(OK[^\r\n]*)", text)
        if match:
            evidence.append(_ev("transport.handshake", f"{stage}: {match.group(1)}", "private.unisoc-bootrom", excerpt=match.group(0)))
    return PrivateResult("private-006", 1, "Read UNISOC BootROM and loader compatibility", tuple(evidence))


def _private_storage(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract storage type, filesystem, slot, and partition evidence."""

    evidence: list[Evidence] = []
    patterns = [
        (r"Flash Type\s*:\s*([^\r\n]+)", "storage.type"),
        (r"Userdata FS Type\s*:\s*([^\r\n]+)", "storage.userdata_fs"),
        (r"Checking A/B state\.\.\.\s*OK\s*\[([^\]]+)\]", "partition.active_slot"),
        (r"Read product info\.\.\.\s*\[([^\]]+)\]", "partition.product_fs"),
    ]
    for pattern, key in patterns:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev(key, match.group(1), "private.storage", excerpt=match.group(0)))
    return PrivateResult("private-007", 1, "Inspect storage and partition state", tuple(evidence))


def _private_security(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract security, bootloader, patch, and protected-read status."""

    evidence: list[Evidence] = []
    warnings: list[str] = []
    match = _line_match(r"Read IMEI\.\.\.\s*([^\r\n]+)", text)
    if match:
        value = match.group(1).strip()
        evidence.append(_ev("identity.imei_read", value, "private.security", excerpt=match.group(0)))
        if "error" in value.casefold():
            warnings.append("IMEI read failed; identity-related conclusions remain incomplete.")
    if _line_match(r"bootloader.*unlocked|bootinfo\s*:\s*unlocked", text):
        evidence.append(_ev("security.bootloader", "unlocked", "private.security", excerpt="bootloader unlocked"))
    if _line_match(r"security patch", text):
        found = _extract_kv(text, "Security Patch")
        if found:
            evidence.append(_ev("os.security_patch", found[0], "private.security", excerpt=found[1]))
    return PrivateResult("private-008", 1, "Inspect security and protected identity readback", tuple(evidence), tuple(warnings))


def _private_versions(text: str, _: dict[str, Any]) -> PrivateResult:
    """Extract generic Android, EMUI, iOS, and firmware version strings."""

    evidence: list[Evidence] = []
    patterns = [
        (r"\bAndroid\s+([0-9]+(?:\.[0-9]+)*)\b", "os.release"),
        (r"\bEMUI\s*([0-9]+(?:\.[0-9]+)*)", "os.emui"),
        (r"\b(?:iOS|ProductVersion)\s*[:=]?\s*([0-9]+(?:\.[0-9]+)+)", "os.apple_version"),
        (r"\b(?:Build Version|Build)\s*:\s*([^\r\n]+)", "firmware.build"),
    ]
    for pattern, key in patterns:
        match = _line_match(pattern, text)
        if match:
            evidence.append(_ev(key, match.group(1), "private.versions", excerpt=match.group(0)))
    return PrivateResult("private-009", 1, "Read version and firmware identifiers", tuple(evidence))


def _private_artifact(text: str, context: dict[str, Any]) -> PrivateResult:
    """Hash and register the source artifact before interpretation."""

    encoded = text.encode("utf-8", errors="replace")
    evidence = (
        _ev("artifact.sha256", hashlib.sha256(encoded).hexdigest(), "private.artifact-custody", source_class="artifact_custody"),
        _ev("artifact.bytes", len(encoded), "private.artifact-custody"),
        _ev("artifact.name", context.get("artifact_name", "stdin"), "private.artifact-custody"),
    )
    return PrivateResult("private-010", 1, "Hash and register source artifact", evidence)


WAVE_ONE: tuple[Callable[[str, dict[str, Any]], PrivateResult], ...] = (
    _private_usb_fingerprint,
    _private_mode_detector,
    _private_android_identity,
    _private_apple_identity,
    _private_huawei_rescue,
    _private_unisoc_bootrom,
    _private_storage,
    _private_security,
    _private_versions,
    _private_artifact,
)
