# Xray

Xray is the project notebook for Kirin recovery work. Each entry should separate
observed evidence from assumptions and unverified next steps.

The executable read-only collector is documented in
[`collector.md`](collector.md). Its raw JSON output preserves unsupported,
undefined, rejected, and concrete values as different states.

The sanitized local service-tool observations are documented in
[`unlocktool-static-kirin980-observations-2026-07-31.md`](unlocktool-static-kirin980-observations-2026-07-31.md).
They record test-point, patched-fastboot, and OEMINFO workflow evidence without
copying proprietary payloads or raw identifiers.

## Entry format

Use one Markdown file per recovery or conversion case.

Recommended sections:

- Scope: source model, target model, target region, and firmware build.
- Local evidence: firmware paths, extracted package names, and hashes for small
  metadata files.
- Observed workflow: OEMINFO values, flash sequence, successful writes, failed
  writes, and tool behavior.
- Interpretation: what the evidence suggests, with uncertainty called out.
- Recovery checklist: steps to repeat or avoid.
- Unverified items: anything not proven by logs, photos, or a final boot test.

## Evidence handling

Do not overwrite extracted firmware, screenshots, logs, or service-tool output.
Reference them by path and add a new dated note when the interpretation changes.
If a large binary is important, record its path, size, and SHA-256 hash instead
of committing it.
