from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .engine import _parse_external_claim, inspect_text
from .knowledge import load_knowledge
from .models import KnowledgeError, VERSION
from .runtime import _report_text, doctor, run_selftest, scan_host


def _write_output(payload: str, output: str | None) -> None:
    if output:
        Path(output).write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
    else:
        print(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray",
        description="Model-independent, read-only device evidence and verification core.",
    )
    parser.add_argument("--version", action="version", version=f"xray {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    inspect_cmd = sub.add_parser("inspect", help="Inspect a captured device/tool log")
    inspect_cmd.add_argument("path", help="Input log path, or - for stdin")
    inspect_cmd.add_argument(
        "--claim",
        action="append",
        default=[],
        metavar="KEY=VALUE|SOURCE_CLASS|MODEL",
        help="Add a structured external claim without treating it as device truth",
    )
    inspect_cmd.add_argument("--format", choices=("text", "json"), default="text")
    inspect_cmd.add_argument("--output", help="Write report to this path")

    doctor_cmd = sub.add_parser("doctor", help="Verify Xray core and optional provider tools")
    doctor_cmd.add_argument("--format", choices=("text", "json"), default="text")

    scan_cmd = sub.add_parser("scan", help="Run available read-only host providers")
    scan_cmd.add_argument("--format", choices=("text", "json"), default="text")
    scan_cmd.add_argument("--output", help="Write report to this path")

    selftest_cmd = sub.add_parser("selftest", help="Run deterministic Android, Huawei and Apple proof cases")
    selftest_cmd.add_argument("--format", choices=("text", "json"), default="text")

    knowledge_cmd = sub.add_parser("knowledge-verify", help="Validate the signed-pack-ready knowledge schema")
    knowledge_cmd.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "inspect":
            if args.path == "-":
                text = sys.stdin.read()
                artifact_name = "stdin"
            else:
                path = Path(args.path)
                text = path.read_text(encoding="utf-8", errors="replace")
                artifact_name = path.name
            external_claims = [_parse_external_claim(raw) for raw in args.claim]
            report = inspect_text(text, artifact_name=artifact_name, external_claims=external_claims)
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else _report_text(report)
            _write_output(payload, args.output)
            return 0 if report.governor_verdict["result"] != "BLOCKED" else 2

        if args.command == "doctor":
            payload = doctor()
            if args.format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"Xray {payload['xray_version']} doctor")
                print(f"Python: {payload['python']}")
                print(f"Platform: {payload['platform']}")
                print(f"Knowledge: {payload['knowledge_schema']} {payload['knowledge_version']}")
                for name, location in payload["commands"].items():
                    print(f"{name}: {location or 'not found'}")
                print("Write authorized: NO")
                print("Model required: NO")
            return 0

        if args.command == "scan":
            report = scan_host()
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else _report_text(report)
            _write_output(payload, args.output)
            return 0 if report.governor_verdict["result"] != "BLOCKED" else 2

        if args.command == "selftest":
            result = run_selftest()
            if args.format == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"Xray {result['xray_version']} selftest")
                for item in result["tests"]:
                    print(f"{'PASS' if item['passed'] else 'FAIL'}: {item['name']} ({item['verdict']})")
                print("Write authorized: NO")
                print("Model required: NO")
            return 0 if result["passed"] else 1

        if args.command == "knowledge-verify":
            knowledge = load_knowledge()
            result = {
                "valid": True,
                "schema": knowledge["schema"],
                "version": knowledge["version"],
                "rules": len(knowledge.get("rules", [])),
                "usb_signatures": len(knowledge.get("usb_signatures", [])),
                "write_authorized": knowledge["proof_policies"]["write_authorization"]["enabled"],
            }
            if args.format == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"PASS: {result['schema']} {result['version']}")
                print(f"Rules: {result['rules']}")
                print(f"USB signatures: {result['usb_signatures']}")
                print("Write authorized: NO")
            return 0
    except (OSError, ValueError, KnowledgeError) as exc:
        print(f"xray: {exc}", file=sys.stderr)
        return 2
    return 2
