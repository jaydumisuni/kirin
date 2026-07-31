from __future__ import annotations

import base64
import hashlib
import io
import tarfile
from pathlib import Path

EXPECTED_SHA256 = "27abe1ef5a3011bc636bc99207e0931c83681cc5b194029cfbfe8a68d49a0521"
BUNDLE = Path("tools/xray_live_reviewed_bundle.b64")
ALLOWED = {
    "README.md",
    "docs/xray/live-provider-session-core.md",
    "pyproject.toml",
    "src/xray/__init__.py",
    "src/xray/envelopes.py",
    "src/xray/live_cli.py",
    "src/xray/live_models.py",
    "src/xray/live_review.py",
    "src/xray/live_runtime.py",
    "src/xray/models.py",
    "src/xray/providers.py",
    "src/xray/sessions.py",
    "src/xray/simulation.py",
    "src/xray/watcher.py",
    "tests/test_cli.py",
    "tests/test_live_core.py",
    "tools/review_live_core.py",
}


def main() -> int:
    """Verify and extract the exact locally reviewed Xray source bundle."""

    encoded = BUNDLE.read_text(encoding="ascii").strip()
    archive = base64.b64decode(encoded, validate=True)
    actual = hashlib.sha256(archive).hexdigest()
    if actual != EXPECTED_SHA256:
        raise SystemExit(f"bundle SHA-256 mismatch: {actual}")
    root = Path.cwd().resolve()
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        names = {member.name for member in members if member.isfile()}
        if names != ALLOWED:
            raise SystemExit(
                f"bundle membership mismatch: missing={sorted(ALLOWED - names)} extra={sorted(names - ALLOWED)}"
            )
        for member in members:
            if not member.isfile():
                continue
            destination = (root / member.name).resolve()
            if root not in destination.parents:
                raise SystemExit(f"unsafe bundle member: {member.name}")
            source = bundle.extractfile(member)
            if source is None:
                raise SystemExit(f"cannot read bundle member: {member.name}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
