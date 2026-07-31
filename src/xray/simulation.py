from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from .envelopes import EnvelopeJournal
from .live_models import DeviceDescriptor, DeviceEvent, EventKind
from .live_runtime import XrayLiveRuntime
from .providers import SimulatedRunner, simulated_result
from .sessions import SessionRegistry


def p30_events() -> tuple[DeviceEvent, ...]:
    """Return a simulated P30 Pro Fastboot -> Huawei rescue transition."""

    topology = "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(5)"
    fastboot = DeviceDescriptor(
        source="simulation",
        os_path=r"USB\VID_18D1&PID_D00D\P30FAST123",
        topology_path=topology,
        vid="18D1",
        pid="D00D",
        serial="P30FAST123",
        mode="FASTBOOT",
        manufacturer="Huawei",
        product="Android Bootloader Interface",
        metadata={"fastboot_serial": "P30FAST123", "scenario": "p30-pro"},
    )
    rescue = DeviceDescriptor(
        source="simulation",
        os_path=r"USB\VID_12D1&PID_3609\P30RESCUE",
        topology_path=topology,
        vid="12D1",
        pid="3609",
        serial="P30RESCUE",
        mode="RESCUE",
        manufacturer="Huawei",
        product="Huawei USB COM 1.0",
        metadata={"fastboot_serial": "P30RESCUE", "scenario": "p30-pro"},
    )
    return (
        DeviceEvent(EventKind.CONNECTED, fastboot),
        DeviceEvent(EventKind.MODE_TRANSITION, rescue, previous=fastboot),
    )


def apple_events() -> tuple[DeviceEvent, ...]:
    """Return a simulated Apple Recovery -> DFU transition on one physical port."""

    topology = "PCIROOT(0)#PCI(1400)#USBROOT(0)#USB(7)"
    recovery = DeviceDescriptor(
        source="simulation",
        os_path=r"USB\VID_05AC&PID_1281\RECOVERY",
        topology_path=topology,
        vid="05AC",
        pid="1281",
        mode="RECOVERY",
        manufacturer="Apple Inc.",
        product="Apple Mobile Device (Recovery Mode)",
        metadata={"ecid": "0x0011223344556677", "scenario": "apple"},
    )
    dfu = DeviceDescriptor(
        source="simulation",
        os_path=r"USB\VID_05AC&PID_1227\DFU",
        topology_path=topology,
        vid="05AC",
        pid="1227",
        mode="DFU",
        manufacturer="Apple Inc.",
        product="Apple Mobile Device (DFU Mode)",
        metadata={"ecid": "0x0011223344556677", "scenario": "apple"},
    )
    return (
        DeviceEvent(EventKind.CONNECTED, recovery),
        DeviceEvent(EventKind.MODE_TRANSITION, dfu, previous=recovery),
    )


def simulation_runner() -> SimulatedRunner:
    """Return deterministic provider outputs for P30 Pro and Apple scenarios."""

    return SimulatedRunner(
        {
            ("fastboot", "-s", "P30FAST123", "getvar", "all"): simulated_result(
                ("fastboot", "-s", "P30FAST123", "getvar", "all"),
                stderr="""(bootloader) product: kirin980
(bootloader) current-slot: a
(bootloader) unlocked: yes
(bootloader) secure: yes
(bootloader) rescue_phoneinfo: VOG-L29 10.0.0.186(C185E8R5P1)
(bootloader) vendorcountry: hw/meafnaf
Finished. Total time: 0.012s
""",
            ),
            ("fastboot", "-s", "P30RESCUE", "getvar", "all"): simulated_result(
                ("fastboot", "-s", "P30RESCUE", "getvar", "all"),
                stderr="""(bootloader) product: kirin980
(bootloader) unlocked: yes
(bootloader) rescue_phoneinfo: NO MAIN VERSION
(bootloader) vendorcountry: cannot get vendorcountry in oeminfo
Finished. Total time: 0.010s
""",
            ),
            ("irecovery", "-i", "0x0011223344556677", "-q"): [
                simulated_result(
                    ("irecovery", "-i", "0x0011223344556677", "-q"),
                    stdout="""MODE: Recovery
CPID: 0x8015
BDID: 0x0C
ECID: 0x0011223344556677
PRODUCT: iPhone10,6
MODEL: d221ap
NAME: iPhone X
""",
                ),
                simulated_result(
                    ("irecovery", "-i", "0x0011223344556677", "-q"),
                    stdout="""MODE: DFU
CPID: 0x8015
BDID: 0x0C
ECID: 0x0011223344556677
PRODUCT: iPhone10,6
MODEL: d221ap
NAME: iPhone X
""",
                ),
            ],
        }
    )


def run_simulation(scenario: str = "all") -> dict[str, Any]:
    """Run simulated device transitions through the complete live runtime."""

    if scenario not in {"p30", "apple", "all"}:
        raise ValueError("scenario must be p30, apple, or all")
    with TemporaryDirectory(prefix="xray-live-sim-") as temporary:
        root = Path(temporary)
        runtime = XrayLiveRuntime(
            sessions=SessionRegistry(host_scope="simulation-host", persistence_path=root / "sessions.json"),
            runner=simulation_runner(),
            journal=EnvelopeJournal(root / "evidence.jsonl"),
        )
        reports = []
        chosen = []
        if scenario in {"p30", "all"}:
            chosen.extend(p30_events())
        if scenario in {"apple", "all"}:
            chosen.extend(apple_events())
        for event in chosen:
            reports.append(runtime.handle_event(event))
        journal = runtime.journal.verify() if runtime.journal else {}
        return {
            "schema": "xray-live-simulation-v1",
            "scenario": scenario,
            "reports": [item.to_dict() for item in reports],
            "sessions": [item.to_dict() for item in runtime.sessions.all()],
            "journal": journal,
            "write_authorized": False,
            "model_required": False,
        }
