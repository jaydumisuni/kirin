from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from xray.envelopes import EnvelopeJournal
from xray.live_models import Capability, DeviceDescriptor, DeviceEvent, EventKind, ProviderManifest
from xray.live_review import review_live_event
from xray.live_runtime import XrayLiveRuntime, doctor_live
from xray.providers import (
    AdbProvider,
    AppleDfuProvider,
    AppleRecoveryProvider,
    DeviceProvider,
    FastbootProvider,
    ProviderRegistry,
    SimulatedRunner,
    UsbDescriptorProvider,
    default_registry,
    simulated_result,
)
from xray.sessions import SessionRegistry
from xray.simulation import apple_events, p30_events, run_simulation, simulation_runner
from xray.watcher import (
    LinuxSysfsSnapshotSource,
    LinuxUsbSnapshotSource,
    MacUsbSnapshotSource,
    PollingDeviceWatcher,
    StaticSnapshotSource,
    WindowsPnpSnapshotSource,
)


def descriptor(**overrides):
    values = {
        "source": "test",
        "os_path": r"USB\VID_1234&PID_5678\SERIAL",
        "topology_path": " PCIROOT(0)  # USB(5) ",
        "vid": "1234",
        "pid": "5678",
        "serial": "SERIAL",
        "mode": "adb",
        "product": "Test Device",
        "metadata": {"adb_serial": "SERIAL"},
    }
    values.update(overrides)
    return DeviceDescriptor(**values)


def test_descriptor_normalizes_usb_and_topology():
    item = descriptor(vid="0x5ac", pid="1227", topology_path=" Port  7 ", mode="dfu")
    assert item.vid == "05AC"
    assert item.pid == "1227"
    assert item.topology_path == "port 7"
    assert item.mode == "DFU"
    assert item.identity_anchors()[-1] == "topology:port 7"
    assert item.identity_anchors()[0].startswith("adb_serial-sha256:")


def test_descriptor_rejects_invalid_usb_id():
    with pytest.raises(ValueError):
        descriptor(vid="ZZZZ")


def test_watcher_emits_connect_transition_present_disconnect():
    first = descriptor(mode="FASTBOOT", vid="18D1", pid="D00D")
    second = descriptor(mode="RESCUE", vid="12D1", pid="3609", serial="OTHER", metadata={"fastboot_serial": "OTHER"})
    source = StaticSnapshotSource(((first,), (second,), (second,), ()))
    watcher = PollingDeviceWatcher(source, emit_present=True)
    assert [event.kind for event in watcher.poll_once()] == [EventKind.CONNECTED]
    transition = watcher.poll_once()[0]
    assert transition.kind == EventKind.MODE_TRANSITION
    assert transition.previous == first
    assert [event.kind for event in watcher.poll_once()] == [EventKind.PRESENT]
    assert [event.kind for event in watcher.poll_once()] == [EventKind.DISCONNECTED]


def test_watcher_retains_first_duplicate_slot():
    item = descriptor()
    duplicate = replace(item, product="Duplicate")
    watcher = PollingDeviceWatcher(StaticSnapshotSource(((item, duplicate),)))
    events = watcher.poll_once()
    assert len(events) == 1
    assert events[0].descriptor.product == "Test Device"


def test_session_id_stable_across_vid_pid_serial_and_mode_changes(tmp_path: Path):
    registry = SessionRegistry(host_scope="athena", persistence_path=tmp_path / "sessions.json")
    events = p30_events()
    first = registry.resolve_event(events[0])
    second = registry.resolve_event(events[1])
    assert first.session_id == second.session_id
    restored = SessionRegistry(host_scope="athena", persistence_path=tmp_path / "sessions.json")
    assert restored.get(first.session_id).modes == ["FASTBOOT", "RESCUE"]


def test_session_correlates_by_ecid_when_topology_changes():
    registry = SessionRegistry(host_scope="host")
    first = descriptor(topology_path=None, vid="05AC", pid="1281", serial=None, mode="RECOVERY", metadata={"ecid": "0x123"})
    second = descriptor(os_path="usb-new", topology_path=None, vid="05AC", pid="1227", serial=None, mode="DFU", metadata={"ecid": "0x123"})
    assert registry.resolve(first).session_id == registry.resolve(second).session_id


def test_session_registry_rejects_other_host_state(tmp_path: Path):
    path = tmp_path / "sessions.json"
    SessionRegistry(host_scope="one", persistence_path=path).resolve(descriptor())
    with pytest.raises(ValueError):
        SessionRegistry(host_scope="two", persistence_path=path)


class BadWriteProvider(DeviceProvider):
    manifest = ProviderManifest("bad", "1", ("usb",), (Capability.READ_IDENTITY,), read_only=False)

    def supports(self, descriptor):
        return True

    def probe(self, session_id, descriptor, runner):
        raise AssertionError


def test_registry_rejects_write_provider_and_duplicates():
    with pytest.raises(ValueError):
        ProviderRegistry((BadWriteProvider(),))
    registry = ProviderRegistry((UsbDescriptorProvider(),))
    with pytest.raises(ValueError):
        registry.register(UsbDescriptorProvider())


def test_default_registry_has_required_providers_and_capabilities():
    registry = default_registry()
    names = {manifest.name for manifest in registry.manifests()}
    assert names == {"usb-descriptor", "adb", "fastboot", "apple-recovery", "apple-dfu"}
    assert "read_identity" in registry.capabilities()
    assert all(manifest.read_only for manifest in registry.manifests())


def test_adb_provider_parses_properties_and_captures_two_envelopes():
    item = descriptor()
    runner = SimulatedRunner(
        {
            ("adb", "-s", "SERIAL", "get-state"): simulated_result(("adb",), stdout="device\n"),
            ("adb", "-s", "SERIAL", "shell", "getprop"): simulated_result(
                ("adb",),
                stdout="""[ro.product.manufacturer]: [INFINIX]
[ro.product.model]: [Infinix X6725]
[ro.board.platform]: [ums9230]
[ro.build.version.release]: [15]
[ro.build.version.security_patch]: [2025-10-01]
""",
            ),
        }
    )
    result = AdbProvider().probe("xray-device-12345678901234567890", item, runner)
    assert result.observations["product.model"] == "Infinix X6725"
    assert result.observations["hardware.bsp_platform"] == "ums9230"
    assert len(result.envelopes) == 2
    assert all(envelope.verify() for envelope in result.envelopes)


def test_adb_provider_rejects_unsafe_serial():
    item = descriptor(serial="bad;rm", metadata={"adb_serial": "bad;rm"})
    result = AdbProvider().probe("xray-device-12345678901234567890", item, SimulatedRunner({}))
    assert result.supported is False
    assert "unsafe or missing ADB serial" in result.warnings[0]


def test_fastboot_parser_reads_stdout_and_stderr_huawei_fields():
    observations = FastbootProvider.parse_getvar_all(
        "",
        """(bootloader) product: kirin980
(bootloader) current-slot: a
(bootloader) unlocked: yes
(bootloader) rescue_phoneinfo: NO MAIN VERSION
(bootloader) vendorcountry: cannot get vendorcountry in oeminfo
""",
    )
    assert observations["fastboot.product"] == "kirin980"
    assert observations["firmware.main_version"] == "NO MAIN VERSION"
    assert observations["oeminfo.vendor_country"] == "UNREADABLE"


def test_fastboot_provider_creates_verified_envelope():
    item = descriptor(mode="FASTBOOT", vid="18D1", pid="D00D", metadata={"fastboot_serial": "FAST123"}, serial="FAST123")
    runner = SimulatedRunner(
        {
            ("fastboot", "-s", "FAST123", "getvar", "all"): simulated_result(
                ("fastboot",), stderr="(bootloader) product: kirin980\n"
            )
        }
    )
    result = FastbootProvider().probe("xray-device-12345678901234567890", item, runner)
    assert result.observations["fastboot.product"] == "kirin980"
    assert result.envelopes[0].verify()


def test_apple_recovery_and_dfu_support_are_mode_specific():
    recovery, dfu = (event.descriptor for event in apple_events())
    assert AppleRecoveryProvider().supports(recovery)
    assert not AppleRecoveryProvider().supports(dfu)
    assert AppleDfuProvider().supports(dfu)
    assert not AppleDfuProvider().supports(recovery)


def test_apple_irecovery_parser_preserves_hardware_identity():
    observations = AppleDfuProvider.parse_irecovery(
        "MODE: DFU\nCPID: 0x8015\nBDID: 0x0C\nECID: 0x123\nPRODUCT: iPhone10,6\n"
    )
    assert observations == {
        "transport.mode": "DFU",
        "apple.cpid": "0x8015",
        "apple.bdid": "0x0C",
        "apple.ecid": "0x0000000000000123",
        "apple.product_type": "iPhone10,6",
    }


def test_raw_envelope_detects_tampering():
    event = apple_events()[0]
    runner = SimulatedRunner({("irecovery", "-i", "0x0011223344556677", "-q"): simulated_result(("irecovery",), stdout="MODE: Recovery\n")})
    envelope = AppleRecoveryProvider().probe("xray-device-12345678901234567890", event.descriptor, runner).envelopes[0]
    assert envelope.verify()
    tampered = replace(envelope, raw_stdout=envelope.raw_stdout + "tampered")
    assert not tampered.verify()


def test_evidence_journal_round_trip_and_duplicate_detection(tmp_path: Path):
    event = apple_events()[0]
    runner = SimulatedRunner({("irecovery", "-i", "0x0011223344556677", "-q"): simulated_result(("irecovery",), stdout="MODE: Recovery\n")})
    envelope = AppleRecoveryProvider().probe("xray-device-12345678901234567890", event.descriptor, runner).envelopes[0]
    journal = EnvelopeJournal(tmp_path / "evidence.jsonl")
    journal.append(envelope)
    assert journal.verify()["envelopes"] == 1
    with journal.path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(envelope.to_dict()) + "\n")
    with pytest.raises(ValueError):
        journal.replay()


def test_windows_pnp_parser_handles_single_object():
    payload = json.dumps(
        {
            "InstanceId": r"USB\VID_05AC&PID_1227\DFU",
            "FriendlyName": "Apple Mobile Device (DFU Mode)",
            "Manufacturer": "Apple Inc.",
            "Class": "USB",
            "Location": "Port_#0007.Hub_#0001",
            "ContainerId": "abc",
            "Status": "OK",
        }
    )
    result = WindowsPnpSnapshotSource.parse(payload)
    assert result[0].vid == "05AC"
    assert result[0].mode == "DFU"
    assert result[0].topology_path == "port_#0007.hub_#0001"


def test_linux_lsusb_parser():
    result = LinuxUsbSnapshotSource.parse("Bus 001 Device 002: ID 05ac:1281 Apple, Inc. Recovery Mode\n")
    assert result[0].vid == "05AC"
    assert result[0].pid == "1281"
    assert result[0].mode == "RECOVERY"


def test_macos_system_profiler_parser():
    payload = json.dumps(
        {
            "SPUSBDataType": [
                {
                    "_name": "USB Bus",
                    "_items": [
                        {
                            "_name": "Apple Mobile Device (DFU Mode)",
                            "vendor_id": "0x05ac",
                            "product_id": "0x1227",
                            "location_id": "0x00100000 / 1",
                        }
                    ],
                }
            ]
        }
    )
    result = MacUsbSnapshotSource.parse(payload)
    assert result[0].mode == "DFU"
    assert result[0].vid == "05AC"


def test_p30_simulation_preserves_session_and_blocks_missing_main_version():
    payload = run_simulation("p30")
    assert len(payload["sessions"]) == 1
    session_ids = {report["session"]["session_id"] for report in payload["reports"]}
    assert len(session_ids) == 1
    assert payload["reports"][0]["review"]["governor"]["result"] == "LIVE_READ_ONLY_READY"
    assert payload["reports"][1]["review"]["governor"]["result"] == "BLOCKED"
    assert payload["journal"]["envelopes"] == 4


def test_apple_simulation_preserves_session_across_recovery_and_dfu():
    payload = run_simulation("apple")
    assert len(payload["sessions"]) == 1
    session = payload["sessions"][0]
    assert session["modes"] == ["RECOVERY", "DFU"]
    assert {report["review"]["governor"]["result"] for report in payload["reports"]} == {"LIVE_READ_ONLY_READY"}
    assert payload["journal"]["envelopes"] == 4


def test_full_simulation_has_two_physical_sessions_and_20_privates_each():
    payload = run_simulation("all")
    assert len(payload["sessions"]) == 2
    assert len(payload["reports"]) == 4
    assert all(len(report["review"]["privates"]) == 20 for report in payload["reports"])
    assert payload["write_authorized"] is False
    assert payload["model_required"] is False


def test_runtime_provider_exception_is_isolated(tmp_path: Path):
    class Broken(DeviceProvider):
        manifest = ProviderManifest("broken", "1", ("usb",), (Capability.READ_IDENTITY,))

        def supports(self, descriptor):
            return True

        def probe(self, session_id, descriptor, runner):
            raise RuntimeError("boom")

    registry = ProviderRegistry((UsbDescriptorProvider(), Broken()))
    runtime = XrayLiveRuntime(
        registry=registry,
        sessions=SessionRegistry(host_scope="test"),
        runner=SimulatedRunner({}),
        journal=EnvelopeJournal(tmp_path / "journal.jsonl"),
    )
    report = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, descriptor(mode="UNKNOWN", metadata={})))
    assert report.review.governor["result"] == "BLOCKED"
    assert any(result.provider == "broken" and result.errors for result in report.providers)


def test_review_rejects_foreign_session_envelope():
    event = apple_events()[0]
    runner = SimulatedRunner({("irecovery", "-i", "0x0011223344556677", "-q"): simulated_result(("irecovery",), stdout="MODE: Recovery\n")})
    provider = AppleRecoveryProvider()
    result = provider.probe("xray-device-aaaaaaaaaaaaaaaaaaaa", event.descriptor, runner)
    report = review_live_event(
        event=event,
        session={"session_id": "xray-device-bbbbbbbbbbbbbbbbbbbb", "anchors": ["x"]},
        manifests=(provider.manifest,),
        providers=(result,),
    )
    assert report.governor["result"] == "BLOCKED"


def test_doctor_is_model_free_and_read_only():
    payload = doctor_live()
    assert payload["write_authorized"] is False
    assert payload["model_required"] is False
    assert len(payload["providers"]) == 5


def test_watcher_default_suppresses_present_events():
    item = descriptor()
    watcher = PollingDeviceWatcher(StaticSnapshotSource(((item,), (item,))))
    assert watcher.poll_once()[0].kind is EventKind.CONNECTED
    assert watcher.poll_once() == ()


def test_linux_sysfs_uses_stable_port_path_and_protocol_serial(tmp_path: Path):
    device = tmp_path / "1-2.3"
    device.mkdir()
    (device / "idVendor").write_text("18d1\n")
    (device / "idProduct").write_text("d00d\n")
    (device / "serial").write_text("FAST123\n")
    (device / "product").write_text("Android Bootloader Interface\n")
    source = LinuxSysfsSnapshotSource(SimulatedRunner({}), root=tmp_path)
    result = source.snapshot()[0]
    assert result.topology_path == "1-2.3"
    assert result.mode == "FASTBOOT"
    assert result.metadata["fastboot_serial"] == "FAST123"


def test_unavailable_apple_tool_is_conflicted_not_falsely_certified():
    event = apple_events()[0]
    runtime = XrayLiveRuntime(
        sessions=SessionRegistry(host_scope="test"),
        runner=SimulatedRunner({}),
    )
    report = runtime.handle_event(event)
    assert report.review.governor["result"] == "CONFLICTED"
    assert report.review.governor["write_authorized"] is False


def test_disconnect_does_not_run_protocol_command():
    connected = p30_events()[0]
    disconnected = DeviceEvent(EventKind.DISCONNECTED, connected.descriptor, previous=connected.descriptor)
    runner = SimulatedRunner({})
    runtime = XrayLiveRuntime(sessions=SessionRegistry(host_scope="test"), runner=runner)
    report = runtime.handle_event(disconnected)
    assert [item.provider for item in report.providers] == ["usb-descriptor"]
    assert runner.calls == []


def test_session_anchors_hash_sensitive_identifiers():
    item = descriptor(topology_path=None, serial="SECRET", metadata={"ecid": "0xABC"})
    anchors = item.identity_anchors()
    assert all("SECRET" not in anchor and "0xabc" not in anchor for anchor in anchors)
    assert any(anchor.startswith("ecid-sha256:") for anchor in anchors)


def test_provider_observed_ecid_merges_sessions_after_topology_change():
    first = DeviceDescriptor(
        source="test",
        os_path="apple-one",
        topology_path="port-one",
        vid="05AC",
        pid="1281",
        mode="RECOVERY",
        product="Apple Mobile Device (Recovery Mode)",
        metadata={"apple_recovery_device_count": 1},
    )
    second = DeviceDescriptor(
        source="test",
        os_path="apple-two",
        topology_path="port-two",
        vid="05AC",
        pid="1227",
        mode="DFU",
        product="Apple Mobile Device (DFU Mode)",
        metadata={"apple_recovery_device_count": 1},
    )
    runner = SimulatedRunner(
        {
            ("irecovery", "-q"): [
                simulated_result(("irecovery", "-q"), stdout="MODE: Recovery\nECID: 0x1234\nCPID: 0x8015\n"),
                simulated_result(("irecovery", "-q"), stdout="MODE: DFU\nECID: 0x1234\nCPID: 0x8015\n"),
            ]
        }
    )
    runtime = XrayLiveRuntime(sessions=SessionRegistry(host_scope="test"), runner=runner)
    one = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, first))
    two = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, second))
    assert one.session["session_id"] == two.session["session_id"]
    assert len(runtime.sessions.all()) == 1
    assert all(
        envelope.session_id == one.session["session_id"]
        for provider in two.providers
        for envelope in provider.envelopes
    )


def test_session_registry_merges_two_prior_sessions_with_bridge_observation():
    registry = SessionRegistry(host_scope="test")
    one = registry.resolve(descriptor(topology_path="port-one", serial=None, metadata={}))
    two = registry.resolve(descriptor(os_path="two", topology_path=None, serial=None, metadata={"ecid": "0x1234"}))
    assert one.session_id != two.session_id
    bridged = registry.resolve(
        descriptor(os_path="bridge", topology_path="port-one", serial=None, metadata={"ecid": "0x1234"})
    )
    assert len(registry.all()) == 1
    assert bridged.session_id in {one.session_id, two.session_id}


def test_session_registry_is_thread_safe_for_same_device():
    from concurrent.futures import ThreadPoolExecutor

    registry = SessionRegistry(host_scope="test")
    item = descriptor()
    with ThreadPoolExecutor(max_workers=16) as pool:
        ids = list(pool.map(lambda _: registry.resolve(item).session_id, range(100)))
    assert len(set(ids)) == 1
    assert len(registry.all()) == 1


def test_apple_provider_rejects_unsafe_ecid():
    event = apple_events()[0]
    with pytest.raises(ValueError):
        replace(event.descriptor, metadata={"ecid": "0x123;rm"})


def test_session_port_reuse_does_not_merge_different_physical_devices():
    registry = SessionRegistry(host_scope="host", topology_reuse_window_seconds=8)
    first_descriptor = descriptor(serial="DEVICE-A", metadata={"adb_serial": "DEVICE-A"})
    second_descriptor = descriptor(serial="DEVICE-B", metadata={"adb_serial": "DEVICE-B"})
    first = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, first_descriptor, observed_at="2026-07-31T20:00:00Z")
    )
    registry.resolve_event(
        DeviceEvent(
            EventKind.DISCONNECTED,
            first_descriptor,
            observed_at="2026-07-31T20:00:01Z",
            previous=first_descriptor,
        )
    )
    second = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, second_descriptor, observed_at="2026-07-31T20:00:02Z")
    )
    assert first.session_id != second.session_id
    assert len(registry.all()) == 2


def test_session_explicit_mode_transition_can_change_protocol_serial():
    registry = SessionRegistry(host_scope="host")
    first_descriptor = descriptor(
        vid="18D1",
        pid="D00D",
        serial="FAST-A",
        mode="FASTBOOT",
        metadata={"fastboot_serial": "FAST-A"},
    )
    second_descriptor = descriptor(
        vid="12D1",
        pid="3609",
        serial="RESCUE-B",
        mode="RESCUE",
        metadata={"fastboot_serial": "RESCUE-B"},
    )
    first = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, first_descriptor, observed_at="2026-07-31T20:00:00Z")
    )
    second = registry.resolve_event(
        DeviceEvent(
            EventKind.MODE_TRANSITION,
            second_descriptor,
            observed_at="2026-07-31T20:00:01Z",
            previous=first_descriptor,
        )
    )
    assert first.session_id == second.session_id
    assert second.modes == ["FASTBOOT", "RESCUE"]


def test_session_topology_reuse_window_handles_unidentified_reenumeration():
    registry = SessionRegistry(host_scope="host", topology_reuse_window_seconds=8)
    anonymous = descriptor(serial=None, metadata={}, mode="RECOVERY")
    first = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, anonymous, observed_at="2026-07-31T20:00:00Z")
    )
    registry.resolve_event(
        DeviceEvent(
            EventKind.DISCONNECTED,
            anonymous,
            observed_at="2026-07-31T20:00:01Z",
            previous=anonymous,
        )
    )
    quick = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, anonymous, observed_at="2026-07-31T20:00:05Z")
    )
    assert quick.session_id == first.session_id
    registry.resolve_event(
        DeviceEvent(
            EventKind.DISCONNECTED,
            anonymous,
            observed_at="2026-07-31T20:00:06Z",
            previous=anonymous,
        )
    )
    late = registry.resolve_event(
        DeviceEvent(EventKind.CONNECTED, anonymous, observed_at="2026-07-31T20:00:20Z")
    )
    assert late.session_id != first.session_id


def test_live_doctor_reports_runtime_version():
    from xray.models import VERSION

    payload = doctor_live()
    assert payload["xray_version"] == VERSION


def test_decimal_and_hex_ecid_normalize_to_same_session():
    from xray.live_models import normalize_ecid

    canonical = "0x0011223344556677"
    decimal = str(int(canonical, 16))
    assert normalize_ecid(decimal) == canonical
    assert normalize_ecid(canonical) == canonical
    registry = SessionRegistry(host_scope="host")
    first = descriptor(
        os_path="apple-decimal",
        topology_path=None,
        serial=None,
        vid="05AC",
        pid="1281",
        mode="RECOVERY",
        metadata={"ecid": decimal},
    )
    second = descriptor(
        os_path="apple-hex",
        topology_path=None,
        serial=None,
        vid="05AC",
        pid="1227",
        mode="DFU",
        metadata={"ecid": canonical},
    )
    assert registry.resolve(first).session_id == registry.resolve(second).session_id


def test_windows_synthesized_instance_tail_is_not_a_protocol_serial():
    payload = json.dumps(
        {
            "InstanceId": r"USB\VID_18D1&PID_D00D\5&242A2F40&0&5",
            "FriendlyName": "Android Bootloader Interface",
            "Manufacturer": "Google",
            "Class": "USB",
            "Location": "Port_#0005.Hub_#0001",
            "ContainerId": "container",
            "Status": "OK",
        }
    )
    item = WindowsPnpSnapshotSource.parse(payload)[0]
    assert item.serial is None
    assert "fastboot_serial" not in item.metadata


def test_topology_only_session_remains_weak():
    registry = SessionRegistry(host_scope="host")
    item = descriptor(serial=None, metadata={}, mode="RECOVERY")
    session = registry.resolve(item)
    assert session.stability == "weak"


def test_malformed_journal_record_reports_line_number(tmp_path: Path):
    journal = EnvelopeJournal(tmp_path / "bad.jsonl")
    journal.path.write_text('{"schema": "wrong"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"line 1"):
        journal.replay()
    journal.path.write_text('{bad json}\n', encoding="utf-8")
    with pytest.raises(ValueError, match=r"line 1"):
        journal.replay()


def test_invalid_provider_envelope_is_isolated_and_blocks_review():
    class TamperingProvider(UsbDescriptorProvider):
        manifest = ProviderManifest(
            "tampering-provider",
            "1.0.0",
            ("usb",),
            (Capability.READ_USB_IDENTITY,),
        )

        def probe(self, session_id, descriptor, runner):
            result = super().probe(session_id, descriptor, runner)
            invalid = replace(result.envelopes[0], raw_stdout=result.envelopes[0].raw_stdout + "tampered")
            return replace(result, envelopes=(invalid,))

    runtime = XrayLiveRuntime(
        registry=ProviderRegistry((UsbDescriptorProvider(), TamperingProvider())),
        sessions=SessionRegistry(host_scope="test"),
        runner=SimulatedRunner({}),
    )
    report = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, descriptor(mode="UNKNOWN", metadata={})))
    tampered = next(item for item in report.providers if item.provider == "tampering-provider")
    assert tampered.envelopes == ()
    assert "invalid evidence envelope" in tampered.errors[0]
    assert report.review.governor["result"] == "BLOCKED"


def test_session_batch_persists_once_per_event_boundary(tmp_path: Path):
    registry = SessionRegistry(host_scope="host", persistence_path=tmp_path / "sessions.json")
    calls = 0
    original_save = registry.save

    def counted_save():
        nonlocal calls
        calls += 1
        original_save()

    registry.save = counted_save  # type: ignore[method-assign]
    with registry.batch():
        session = registry.resolve_event(DeviceEvent(EventKind.CONNECTED, descriptor()))
        registry.link_observation(session.session_id, "adb_serial", "SERIAL")
        registry.attach_envelope(session.session_id, "envelope-1")
    assert calls == 1


def test_session_persistence_redacts_last_descriptor_identifiers(tmp_path: Path):
    path = tmp_path / "sessions.json"
    registry = SessionRegistry(host_scope="host", persistence_path=path)
    registry.resolve_event(DeviceEvent(EventKind.CONNECTED, descriptor()))
    payload = json.loads(path.read_text(encoding="utf-8"))
    last = payload["sessions"][0]["last_descriptor"]
    assert last["serial"] is None
    assert last["os_path"] is None
    assert last["serial_sha256"]
    assert last["os_path_sha256"]
    assert "adb_serial" not in last["metadata"]
    assert last["metadata"]["adb_serial_sha256"]


def test_unpinned_apple_ecid_is_not_used_for_session_merge_when_ambiguous():
    first = DeviceDescriptor(
        source="test",
        os_path="apple-one",
        topology_path="port-one",
        vid="05AC",
        pid="1281",
        mode="RECOVERY",
        product="Apple Mobile Device (Recovery Mode)",
        metadata={"apple_recovery_device_count": 2},
    )
    second = DeviceDescriptor(
        source="test",
        os_path="apple-two",
        topology_path="port-two",
        vid="05AC",
        pid="1227",
        mode="DFU",
        product="Apple Mobile Device (DFU Mode)",
        metadata={"apple_recovery_device_count": 2},
    )
    runner = SimulatedRunner(
        {
            ("irecovery", "-q"): [
                simulated_result(("irecovery", "-q"), stdout="MODE: Recovery\nECID: 0x1234\n"),
                simulated_result(("irecovery", "-q"), stdout="MODE: DFU\nECID: 0x1234\n"),
            ]
        }
    )
    runtime = XrayLiveRuntime(sessions=SessionRegistry(host_scope="test"), runner=runner)
    one = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, first))
    two = runtime.handle_event(DeviceEvent(EventKind.CONNECTED, second))
    assert one.session["session_id"] != two.session["session_id"]
    assert len(runtime.sessions.all()) == 2
    assert one.review.governor["result"] == "CONFLICTED"
    assert two.review.governor["result"] == "CONFLICTED"


def test_watcher_annotates_apple_recovery_device_count():
    first, second = (event.descriptor for event in apple_events())
    other = replace(first, os_path="other", topology_path="other-port", metadata={})
    watcher = PollingDeviceWatcher(StaticSnapshotSource(((first, other, second),)))
    events = watcher.poll_once()
    apple_events_seen = [event for event in events if event.descriptor.vid == "05AC"]
    assert len(apple_events_seen) == 2
    assert {event.descriptor.metadata["apple_recovery_device_count"] for event in apple_events_seen} == {2}
