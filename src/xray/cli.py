from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .android_recovery import AndroidRecoveryError, build_debug_recovery
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
from .huawei_package import HuaweiPackageError, verify_vog_l29_c185_package, write_huawei_package_proof
from .huawei_usb import HuaweiUsbError, load_huawei_bootloader, parse_image_spec, wait_for_huawei_usb_port
from .models import KnowledgeError, VERSION
from .oeminfo import OeminfoError, build_vog_l29_c185_oeminfo
from .revive import RevivePlanError, build_revive_plan, vog_l29_c185_profile, write_revive_outputs
from .runtime import doctor, report_text, run_selftest, scan_host
from .update_app import (
    UpdateAppError,
    extract_update_app_entry,
    update_app_report,
    update_app_report_text,
    write_update_app_report,
)


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

    update_list_cmd = sub.add_parser("update-app-list", help="List Huawei UPDATE.APP payloads")
    update_list_cmd.add_argument("path", help="Path to UPDATE.APP")
    update_list_cmd.add_argument("--name", action="append", default=[], help="Select an exact payload name")
    update_list_cmd.add_argument("--format", choices=("text", "json"), default="text")
    update_list_cmd.add_argument("--output", help="Write report JSON to this path")

    update_extract_cmd = sub.add_parser("update-app-extract", help="Extract one verified UPDATE.APP payload")
    update_extract_cmd.add_argument("path", help="Path to UPDATE.APP")
    update_extract_cmd.add_argument("name", help="Exact payload name")
    update_extract_cmd.add_argument("--sequence", type=int, help="Select a sequence when names repeat")
    update_extract_cmd.add_argument("--output", required=True, help="New output file path")

    usb_boot_cmd = sub.add_parser("huawei-usb-boot", help="Load signed images through Huawei USB COM mode")
    usb_boot_cmd.add_argument("--port", default="auto", help="Huawei USB COM port, or auto to wait for it")
    usb_boot_cmd.add_argument(
        "--wait-seconds",
        type=float,
        default=180,
        help="Maximum time to wait when --port=auto",
    )
    usb_boot_cmd.add_argument(
        "--image",
        action="append",
        required=True,
        metavar="ADDRESS=PATH",
        help="Signed image and explicit RAM address; repeat in transfer order",
    )

    recovery_build_cmd = sub.add_parser(
        "huawei-recovery-build",
        help="Build a target-based temporary root-ADB recovery image",
    )
    recovery_build_cmd.add_argument("--source", required=True, help="Exact target RECOVERY_RAMDISK image")
    recovery_build_cmd.add_argument("--engineering-adbd", required=True, help="Self-contained engineering ADB ELF")
    recovery_build_cmd.add_argument("--output", required=True, help="New patched recovery image path")
    recovery_build_cmd.add_argument("--manifest", help="Write a build and checksum manifest")

    oeminfo_build_cmd = sub.add_parser(
        "huawei-oeminfo-build",
        help="Build a verified VOG-L29 C185 OEMINFO image",
    )
    oeminfo_build_cmd.add_argument("--template", required=True, help="96 MiB P30 board OEMINFO template")
    oeminfo_build_cmd.add_argument("--base-version", required=True, help="Exact target BASE_VER.mbn")
    oeminfo_build_cmd.add_argument("--cust-version", required=True, help="Exact target CUST_VER.mbn")
    oeminfo_build_cmd.add_argument("--preload-version", required=True, help="Exact target PRELOAD_VER.mbn")
    oeminfo_build_cmd.add_argument("--output", required=True, help="New VOG-L29C185.bin output path")
    oeminfo_build_cmd.add_argument("--manifest", help="Write a generation and verification manifest")

    package_verify_cmd = sub.add_parser(
        "huawei-package-verify",
        help="Fully verify the matched VOG-L29 C185 firmware package",
    )
    package_verify_cmd.add_argument("--package-root", required=True, help="Root of the three-part target package")
    package_verify_cmd.add_argument("--output", required=True, help="New package proof JSON path")
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

        if args.command == "update-app-list":
            report = update_app_report(Path(args.path), args.name)
            if args.output:
                write_update_app_report(report, Path(args.output))
            print(json.dumps(report, indent=2, sort_keys=True) if args.format == "json" else update_app_report_text(report))
            return 0

        if args.command == "update-app-extract":
            result = extract_update_app_entry(
                Path(args.path),
                args.name,
                Path(args.output),
                sequence=args.sequence,
            )
            print(f"Extracted: {result['entry']['name']} -> {result['output']}")
            print(f"SHA-256: {result['sha256']}")
            print(f"Checksum valid: {result['checksum_valid']}")
            return 0

        if args.command == "huawei-usb-boot":
            images = [parse_image_spec(value) for value in args.image]
            port = args.port
            if port.casefold() == "auto":
                print(f"Waiting up to {args.wait_seconds:g}s for Huawei USB COM mode...", flush=True)
                port = wait_for_huawei_usb_port(args.wait_seconds)
                print(f"Huawei USB COM mode detected: {port}", flush=True)
            last_percent: dict[Path, int] = {}

            def show_progress(image, transferred, size):
                percent = transferred * 100 // size
                if percent == 100 or percent >= last_percent.get(image.path, -10) + 10:
                    print(f"Loading {image.path.name}: {percent}%", flush=True)
                    last_percent[image.path] = percent

            results = load_huawei_bootloader(port, images, progress=show_progress)
            for result in results:
                print(
                    f"Loaded: {Path(str(result['path'])).name} "
                    f"({result['size']} bytes at 0x{int(result['address']):08X})"
                )
            return 0

        if args.command == "huawei-recovery-build":
            result = build_debug_recovery(
                Path(args.source),
                Path(args.engineering_adbd),
                Path(args.output),
                manifest=Path(args.manifest) if args.manifest else None,
            )
            print(f"Built temporary recovery: {result['output']}")
            print(f"SHA-256: {result['output_sha256']}")
            print(f"Partition size: {result['partition_size']} bytes")
            print("Write authorized: NO")
            return 0

        if args.command == "huawei-oeminfo-build":
            result = build_vog_l29_c185_oeminfo(
                Path(args.template),
                Path(args.base_version),
                Path(args.cust_version),
                Path(args.preload_version),
                Path(args.output),
                manifest_path=Path(args.manifest) if args.manifest else None,
            )
            print(f"Built P30 Pro identity image: {result['output']['path']}")
            print(f"SHA-256: {result['output']['sha256']}")
            print(f"Verified identity records: {result['identity_record_count']} x {result['copy_count']} copies")
            print("Write authorized: NO")
            return 0

        if args.command == "huawei-package-verify":
            result = verify_vog_l29_c185_package(Path(args.package_root))
            write_huawei_package_proof(result, Path(args.output))
            print(f"Verified target package: {result['profile']}")
            print(f"Archives: {result['package_count']}  UPDATE.APP entries: {result['total_update_app_entries']}")
            print(f"Proof: {Path(args.output).resolve()}")
            print("Write authorized: NO")
            return 0
    except (
        OSError,
        ValueError,
        KnowledgeError,
        RevivePlanError,
        FirmwareLibraryError,
        HuaweiBoardError,
        UpdateAppError,
        HuaweiUsbError,
        AndroidRecoveryError,
        OeminfoError,
        HuaweiPackageError,
    ) as exc:
        print(f"xray: {exc}", file=sys.stderr)
        return 2
    return 2
