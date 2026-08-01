from __future__ import annotations

import base64
from pathlib import Path


def main() -> int:
    """Apply the staged SRG 20-for-2 source promotion and remove transfer parts."""

    parts = sorted(Path("tools").glob("promote20.part*"))
    if len(parts) != 5:
        raise SystemExit(f"expected 5 promotion parts, found {len(parts)}")
    encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
    source = base64.b64decode(encoded, validate=True)
    exec(compile(source, "<xray-srg-20-for-2-promotion>", "exec"), {"__name__": "__main__"})
    for part in parts:
        part.unlink()
    Path("tools/promote20.trigger").unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
