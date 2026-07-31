from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .envelopes import EnvelopeJournal
from .live_runtime import XrayLiveRuntime, doctor_live
from .providers import SubprocessRunner, default_registry
from .sessions import SessionRegistry
from .simulation import run_simulation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xray-live",
        description="Model-independent USB/PnP watcher, session, provider, and evidence runtime.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Show provider and command readiness")
    doctor.add_argument("--format", choices=("json", "text"), default="text")

    providers = subparsers.add_parser("providers", help="List provider manifests and capabilities")
    providers.add_argument("--format", choices=("json", "text"), default="text")

    simulate = subparsers.add_parser("simulate", help="Run P30 Pro and Apple transition simulations")
    simulate.add_argument("scenario", choices=("p30", "apple", "all"), nargs="?", default="all")
    simulate.add_argument("--output", type=Path)
    simulate.add_argument("--format", choices=("json", "text"), default="text")

    watch = subparsers.add_parser("watch", help="Watch the current host for USB/PnP events")
    watch.add_argument("--interval", type=float, default=1.0)
    watch.add_argument("--duration", type=float, default=10.0)
    watch.add_argument("--once", action="store_true", help="Capture one current snapshot and exit")
    watch.add_argument("--state", type=Path, default=Path(".xray/sessions.json"))
    watch.add_argument("--journal", type=Path, default=Path(".xray/evidence.jsonl"))
    watch.add_argument("--output", type=Path, default=Path(".xray/live-reports.jsonl"))

    journal = subparsers.add_parser("journal-verify", help="Verify an evidence JSONL journal")
    journal.add_argument("path", type=Path)
    return parser


def _text_simulation(payload: dict) -> str:
    lines = [
        f"Xray Live simulation: {payload['scenario']}",
        f"Reports: {len(payload['reports'])}",
        f"Sessions: {len(payload['sessions'])}",
        f"Evidence envelopes: {payload['journal']['envelopes']}",
        "Write authorized: NO",
        "Model required: NO",
        "",
    ]
    for report in payload["reports"]:
        descriptor = report["event"]["descriptor"]
        governor = report["review"]["governor"]
        lines.append(
            f"{descriptor.get('product') or descriptor['os_path']} | "
            f"{descriptor.get('mode') or 'UNKNOWN'} | "
            f"{report['session']['session_id']} | {governor['result']}"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Xray Live command-line interface."""

    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            payload = doctor_live()
            if args.format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                print(f"Providers: {len(payload['providers'])}")
                for manifest in payload["providers"]:
                    print(f"- {manifest['name']} {manifest['version']}: {', '.join(manifest['capabilities'])}")
                for name, status in payload["commands"].items():
                    print(f"{name}: {status['path'] or 'not found'}")
                print("Write authorized: NO")
                print("Model required: NO")
            return 0

        if args.command == "providers":
            registry = default_registry()
            payload = {
                "providers": [item.to_dict() for item in registry.manifests()],
                "capabilities": registry.capabilities(),
            }
            if args.format == "json":
                print(json.dumps(payload, indent=2, sort_keys=True))
            else:
                for manifest in payload["providers"]:
                    print(f"{manifest['name']} {manifest['version']}")
                    print(f"  transports: {', '.join(manifest['transports'])}")
                    print(f"  capabilities: {', '.join(manifest['capabilities'])}")
                    print("  read-only: yes")
            return 0

        if args.command == "simulate":
            payload = run_simulation(args.scenario)
            rendered = json.dumps(payload, indent=2, sort_keys=True) if args.format == "json" else _text_simulation(payload)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered + "\n", encoding="utf-8")
            else:
                print(rendered)
            results = [report["review"]["governor"]["result"] for report in payload["reports"]]
            expected_blocked = 1 if args.scenario in {"p30", "all"} else 0
            structure_ok = (
                payload["journal"].get("valid") is True
                and all(len(report["review"]["privates"]) == 20 for report in payload["reports"])
                and results.count("BLOCKED") == expected_blocked
                and all(result in {"LIVE_READ_ONLY_READY", "CONFLICTED", "BLOCKED"} for result in results)
            )
            # The P30 rescue fixture intentionally proves that NO MAIN VERSION remains blocked.
            return 0 if structure_ok else 2

        if args.command == "watch":
            runtime = XrayLiveRuntime(
                sessions=SessionRegistry(persistence_path=args.state),
                runner=SubprocessRunner(),
                journal=EnvelopeJournal(args.journal),
            )
            if args.once:
                reports = runtime.snapshot_once()
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    "".join(json.dumps(report.to_dict(), sort_keys=True) + "\n" for report in reports),
                    encoding="utf-8",
                )
            else:
                reports = runtime.watch(interval=args.interval, duration=args.duration, output=args.output)
            print(f"Captured {len(reports)} live report(s).")
            return 0

        if args.command == "journal-verify":
            payload = EnvelopeJournal(args.path).verify()
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"xray-live: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
