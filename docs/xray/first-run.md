# Xray first usable runtime — 0.1.0

## Purpose

This first run proves the core architectural boundary before UI work:

```text
providers observe
privates gather
permanent officers review
Challenger attacks
Judge applies policy
Governor publishes the verdict
Hunter/model optionally adds reasoning power
repair engines remain separate
```

Xray works with no model and no internet. It is useful even when the brand,
model, operating system or current mode is unknown.

## SRG 10-for-2 execution

Each inspection runs twenty isolated private assignments in two waves of ten.
The first wave extracts evidence independently. The second wave challenges
variant transfer, loader-name assumptions, exact-SoC proof, Apple USB mode,
identity gates, parser consistency, physical-device correlation and report
integrity.

A failed private is recorded instead of crashing the investigation. Officer and
Governor output remains auditable.

## Proven first-run cases

### UNISOC / Infinix

The fixture records:

- USB `VID_1782&PID_4D00`
- BROM mode
- `Tiger_T616_64` selected loader
- `ums9230` BSP
- device-reported `Infinix X6725`
- external `X6725B -> T7250` claim

Expected result:

- UNISOC family: certified
- BROM mode: certified
- loader compatibility: observed
- exact T7250 silicon: not certified
- model-variant contradiction: reported

### Huawei fastboot rescue

The fixture records `rescue_phoneinfo: NO MAIN VERSION` and unreadable
vendor/country. The Governor must return `BLOCKED`; Xray cannot convert a write
request into proof that OEMINFO is readable.

### Apple DFU

The fixture records Apple VID `05AC`, DFU PID `1227`, CPID, BDID, ECID and
product type. Apple family and DFU mode are resolved without depending on ADB or
Android assumptions. Exact marketing-name resolution remains a separate claim.

## Live provider boundary

`xray scan` attempts only read-only discovery commands that already exist on the
host:

- `adb devices -l`
- `fastboot devices`
- `idevice_id -l`
- `irecovery -q`
- `lsusb`, macOS `system_profiler`, or Windows PnP enumeration

Missing tools are evidence about provider availability, not runtime failure.
Later Android Host APK, Probe APK, Windows, macOS, Linux and web/native bridge
surfaces will feed the same report schema.

## Verification commands

```bash
python -m compileall -q src tests
pytest
python -m xray selftest --format json
python -m xray knowledge-verify
python -m xray doctor
cargo fmt --manifest-path rust/Cargo.toml --check
cargo clippy --manifest-path rust/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path rust/Cargo.toml
```

Python verification was executed before repository submission. Rust is also
verified in GitHub Actions because the initial isolated build workspace did not
contain a Rust toolchain.

## Frozen safety rules

- Model required: no
- Internet required: no
- Write authorization: no
- Loader profile may certify exact silicon: no
- External model/SKU claims transfer automatically: no
- A missing mandatory identity read may be ignored: no
