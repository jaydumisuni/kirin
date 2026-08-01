# Xray 0.2 — Live Provider and Session Core

## Frozen boundary

```text
USB/PnP watcher observes endpoint lifecycle
Session Registry correlates one physical device across modes
Provider Registry selects declared read-only capabilities
Providers capture raw command/device evidence
Quartermaster journal preserves timestamps, topology and hashes
SRG 20-for-2 live corps challenges every report
Governor publishes LIVE_READ_ONLY_READY, CONFLICTED or BLOCKED
Hunter/model remains optional and cannot authorize writes
```

## Implemented providers

- USB/PnP descriptor provider
- ADB property and boot-state provider
- Fastboot/Fastbootd/Huawei rescue readback provider
- Apple Recovery provider
- Apple DFU provider

All provider commands are fixed argument arrays, resolved without a shell. Device
serials are validated before being inserted into command arguments.

## Physical session identity

The session registry prefers strong host-scoped identifiers such as ECID, UDID,
Container ID, hardware ID, ADB serial and Fastboot serial. USB topology provides
mode-transition continuity, but is not permanent identity: a disconnected port
is reusable only inside a short re-enumeration window, and conflicting strong
identifiers create a new physical session. The first accepted anchor creates a
stable UUIDv5 session ID. Later verified mode changes add aliases without changing
that ID. A descriptor that bridges an anonymous topology session to a strong
identifier can merge the records; ordinary port reuse cannot.

## Raw evidence envelope

Each provider result records:

- session and envelope IDs
- capture/start/completion timestamps
- provider version and declared capability
- host topology and complete normalized descriptor
- exact shell-free command vector and return status
- raw stdout/stderr
- SHA-256 for stdout, stderr, descriptor and canonical envelope
- normalized observations
- declared sensitive fields

The JSONL journal checks envelope self-consistency during append and replay and
detects accidental corruption or records that no longer match their embedded
hashes. These hashes are stored beside the data, so they are not an
attacker-resistant trust anchor. A later secured deployment must anchor a journal
head with an OS-keystore-backed HMAC/signature or an external signed ledger before
claiming adversarial tamper detection.

## SRG 20-for-2 review

Each live event is challenged by two governed waves of twenty deterministic
private checks. Wave one covers event, provider, manifest, schema, capability and
command-contract integrity. Wave two covers session continuity, topology,
provider evidence custody, protocol selectors, Apple ambiguity and the read-only
identity gate. The forty private IDs are fixed as `private-001` through
`private-040`; the permanent officers and Governor receive the complete result.

## Simulation proof

### Huawei P30 Pro

The simulation transitions one physical port from Fastboot to Huawei rescue while
VID/PID and protocol serial change. Xray retains one physical session. The first
readback is `LIVE_READ_ONLY_READY`; the rescue readback returns `NO MAIN VERSION`
and unreadable vendor/country, so the identity gate correctly returns `BLOCKED`.

### Apple

The simulation transitions one physical port from Recovery (`05AC:1281`) to DFU
(`05AC:1227`) with the same ECID. Xray retains one physical session and verifies
CPID, BDID, ECID, product type and mode through Apple provider envelopes.

## Local proof commands

```bash
python -m compileall -q src tests tools
pytest
python tools/review_live_core.py
python -m xray.live_cli doctor --format json
python -m xray.live_cli providers --format json
python -m xray.live_cli simulate all --format json
```

Real P30 Pro and Apple hardware remain the next physical verification step. No
claim in this milestone depends on having those devices connected during build.

## Apple multi-device selection

The Apple providers use `irecovery -i ECID -q` whenever the watcher or a prior
provider observation has an ECID. Current libirecovery documents `-i/--ecid` as
the specific-device selector and `-q/--query` as the read-only information query:
https://github.com/libimobiledevice/libirecovery/blob/master/tools/irecovery.c

When an ECID is not yet known, Xray may perform one unpinned query to recover it,
but the Governor marks that report `CONFLICTED` because multiple simultaneous
Recovery/DFU devices would otherwise be ambiguous. The observed ECID is hashed
into the Session Registry and can merge a newly enumerated endpoint back into
its older physical-device session.

## Sensitive-data retention and access control

Session correlation anchors are persisted as SHA-256 references. The persisted
`last_descriptor` also redacts the raw OS instance path, protocol serials, ECID,
UDID, Container ID and related stable identifiers into hashes. Live `DeviceEvent`
reports and raw evidence envelopes intentionally retain the complete descriptor,
command vector and provider output needed for forensic review. Their JSON/JSONL
files are sensitive evidence and must be protected with restrictive filesystem
permissions or encrypted storage; they are not suitable for public telemetry.
