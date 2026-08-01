from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .engine import inspect_text, parse_external_claim
from .firmware import (
    FirmwareLibraryError,
    add_firmware_model,
    firmware_catalog_text,
    scan_firmware_library,
    write_firmware_catalog,
)
from .knowledge import load_knowledge
from .huawei_board import HuaweiBoardError, build_p30_revive_workflow, write_p30_revive_workflow
from .models import KnowledgeError, VERSION
from .revive import RevivePlanError, build_revive_plan, vog_l29_c185_profile, write_revive_outputs
from .runtime import doctor, report_text, run_selftest, scan_host


def _write_output(payload: str, output: str | None) -> None:
    """Write output to a file or stdout."""

    if output:
        Path(output).write_text(payload + ("\n" if not payload.endswith("\n") else ""), encoding="utf-8")
    else:
        print(payload)


def _parser() -> argparse.ArgumentParser:
    """Build the Xray command-line parser."""

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

    revive_cmd = sub.add_parser("revive-plan", help="Build an audit-only reusable device revive plan")
    revive_cmd.add_argument("profile", choices=("vog-l29-c185",), help="Revive profile to plan")
    revive_cmd.add_argument("--package-root", required=True, help="Root of the matched firmware package")
    revive_cmd.add_argument("--template-root", help="Optional P10Revive-style template/tooling root")
    revive_cmd.add_argument("--format", choices=("text", "json"), default="text")
    revive_cmd.add_argument("--output", help="Write plan JSON to this path")
    revive_cmd.add_argument("--script-output", help="Write an audit-only batch scaffold to this path")

    firmware_list_cmd = sub.add_parser("firmware-list", help="Scan a model-based firmware library")
    firmware_list_cmd.add_argument("--library-root", required=True, help="Firmware library containing model folders")
    firmware_list_cmd.add_argument("--format", choices=("text", "json"), default="text")
    firmware_list_cmd.add_argument("--catalog-output", help="Write the refreshed catalog JSON to this path")

    firmware_add_cmd = sub.add_parser("firmware-add-model", help="Add a model folder to a firmware library")
    firmware_add_cmd.add_argument("--library-root", required=True, help="Firmware library root")
    firmware_add_cmd.add_argument("--folder", required=True, help="Folder name for the model")
    firmware_add_cmd.add_argument("--preset", choices=("generic", "p30-pro"), default="generic")
    firmware_add_cmd.add_argument("--name", help="Display name for a generic model")
    firmware_add_cmd.add_argument("--manufacturer", default="Unknown", help="Manufacturer for a generic model")
    firmware_add_cmd.add_argument("--variant", action="append", default=[], help="Supported model code; repeat as needed")

    workflow_cmd = sub.add_parser("revive-workflow", help="Build a carried model-specific revive workflow")
    workflow_cmd.add_argument("profile", choices=("p30-pro",), help="Workflow profile to prepare")
    workflow_cmd.add_argument("--model-root", required=True, help="Model folder containing board and target firmware")
    workflow_cmd.add_argument("--format", choices=("text", "json"), default="text")
    workflow_cmd.add_argument("--output", help="Write workflow JSON to this path")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Xray CLI and return a process status code."""

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
            external_claims = [parse_external_claim(raw) for raw in args.claim]
            report = inspect_text(text, artifact_name=artifact_name, external_claims=external_claims)
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else report_text(report)
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
                print(f"Write authorized: {'YES' if payload['write_authorized'] else 'NO'}")
                print("Model required: NO")
            return 0 if not payload["write_authorized"] else 2

        if args.command == "scan":
            report = scan_host()
            payload = json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.format == "json" else report_text(report)
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
            write_enabled = bool(knowledge["proof_policies"]["write_authorization"]["enabled"])
            result = {
                "valid": not write_enabled,
                "schema": knowledge["schema"],
                "version": knowledge["version"],
                "rules": len(knowledge.get("rules", [])),
                "usb_signatures": len(knowledge.get("usb_signatures", [])),
                "write_authorized": write_enabled,
            }
            if args.format == "json":
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                print(f"{'PASS' if result['valid'] else 'FAIL'}: {result['schema']} {result['version']}")
                print(f"Rules: {result['rules']}")
                print(f"USB signatures: {result['usb_signatures']}")
                print(f"Write authorized: {'YES' if result['write_authorized'] else 'NO'}")
            return 0 if result["valid"] else 2

        if args.command == "revive-plan":
            package_root = Path(args.package_root)
            template_root = Path(args.template_root) if args.template_root else None
            profile = vog_l29_c185_profile(package_root, template_root)
            plan = build_revive_plan(profile)
            write_revive_outputs(plan, Path(args.output) if args.output else None, Path(args.script_output) if args.script_output else None)
            if args.format == "json":
                print(json.dumps(plan, indent=2, sort_keys=True))
            else:
                target = plan["target"]
                print(f"Xray revive plan: {plan['profile']}")
                print(f"Target: {target['model']} {target['build']} {target['vendor']}/{target['country']}")
                print(f"Artifacts: {len(plan['artifacts'])}")
                print("Write authorized: NO")
                print("Script mode: audit-only")
            return 0

        if args.command == "firmware-list":
            catalog = scan_firmware_library(Path(args.library_root))
            if args.catalog_output:
                write_firmware_catalog(catalog, Path(args.catalog_output))
            payload = (
                json.dumps(catalog, indent=2, sort_keys=True)
                if args.format == "json"
                else firmware_catalog_text(catalog)
            )
            print(payload)
            return 0

        if args.command == "firmware-add-model":
            definition = add_firmware_model(
                Path(args.library_root),
                args.folder,
                name=args.name,
                manufacturer=args.manufacturer,
                variants=args.variant,
                preset=args.preset,
            )
            print(f"Added firmware model: {definition}")
            return 0

        if args.command == "revive-workflow":
            workflow = build_p30_revive_workflow(Path(args.model_root))
            if args.output:
                write_p30_revive_workflow(workflow, Path(args.output))
            if args.format == "json":
                print(json.dumps(workflow, indent=2, sort_keys=True))
            else:
                board_stage, target_stage, identity_stage = workflow["stages"][:3]
                print(f"Revive workflow: {workflow['profile']}")
                print(f"Board restore: {board_stage['status']} ({board_stage['operation_count']} operations)")
                print(f"Target package: {target_stage['status']}")
                print(f"Target identity: {identity_stage['status']}")
                print("Write authorized: NO")
            return 0
    except (OSError, ValueError, KnowledgeError, RevivePlanError, FirmwareLibraryError, HuaweiBoardError) as exc:
        print(f"xray: {exc}", file=sys.stderr)
        return 2
    return 2
