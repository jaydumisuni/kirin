"""Compatibility exports for the original monolithic Xray module.

The implementation now lives in focused modules. This file intentionally contains
no duplicate runtime logic.
"""

from .cli import main
from .engine import inspect_text, parse_external_claim
from .knowledge import load_knowledge
from .models import Claim, Evidence, KnowledgeError, OfficerReport, PrivateResult, Status, VERSION, XrayReport
from .runtime import SELFTEST_APPLE, SELFTEST_HUAWEI, SELFTEST_UNISOC, doctor, report_text, run_selftest, scan_host

__all__ = [
    "Claim",
    "Evidence",
    "KnowledgeError",
    "OfficerReport",
    "PrivateResult",
    "SELFTEST_APPLE",
    "SELFTEST_HUAWEI",
    "SELFTEST_UNISOC",
    "Status",
    "VERSION",
    "XrayReport",
    "doctor",
    "inspect_text",
    "load_knowledge",
    "main",
    "parse_external_claim",
    "report_text",
    "run_selftest",
    "scan_host",
]
