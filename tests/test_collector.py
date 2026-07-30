from __future__ import annotations

import unittest

from xray.collector import (
    FASTBOOT_PARTITIONS,
    FASTBOOT_VARIABLES,
    assert_read_only,
    derive_findings,
    fastboot_read_commands,
    parse_adb_devices,
    parse_fastboot_devices,
    parse_fastboot_value,
)


class DeviceParserTests(unittest.TestCase):
    def test_adb_devices_include_modes_and_descriptors(self) -> None:
        output = (
            "* daemon started successfully *\n"
            "List of devices attached\n"
            "ABC123\tdevice product:vogue model:VOG-L29 transport_id:1\n"
            "XYZ999\trecovery\n"
        )
        self.assertEqual(
            [
                {
                    "serial": "ABC123",
                    "state": "device",
                    "product": "vogue",
                    "model": "VOG-L29",
                    "transport_id": "1",
                },
                {"serial": "XYZ999", "state": "recovery"},
            ],
            parse_adb_devices(output),
        )

    def test_fastboot_devices_ignore_waiting_noise(self) -> None:
        output = (
            "< waiting for any device >\n"
            "5T5PUB194L059785\tfastboot\n"
            "Finished. Total time: 0.001s\n"
        )
        self.assertEqual(
            [{"serial": "5T5PUB194L059785", "state": "fastboot"}],
            parse_fastboot_devices(output),
        )

    def test_fastboot_value_distinguishes_value_undefined_and_failure(self) -> None:
        self.assertEqual(
            "value",
            parse_fastboot_value(
                "(bootloader) product: kirin980\nOKAY", "product"
            )["status"],
        )
        self.assertEqual(
            "undefined",
            parse_fastboot_value("serialno: undefine\nFinished.", "serialno")[
                "status"
            ],
        )
        failed = parse_fastboot_value(
            "getvar:vendorcountry FAILED (remote: 'cannot get vendorcountry in oeminfo')",
            "vendorcountry",
        )
        self.assertEqual("error", failed["status"])
        self.assertIn("cannot get vendorcountry", failed["error"] or "")


class SafetyTests(unittest.TestCase):
    def test_complete_fastboot_matrix_is_read_only(self) -> None:
        commands = fastboot_read_commands()
        for command in commands:
            assert_read_only(command)
        flattened = {" ".join(command).casefold() for command in commands}
        self.assertFalse(any(command.startswith("flash ") for command in flattened))
        self.assertFalse(any(command.startswith("erase ") for command in flattened))
        self.assertFalse(any(command.startswith("reboot") for command in flattened))
        self.assertGreaterEqual(len(FASTBOOT_VARIABLES), 40)
        self.assertGreaterEqual(len(FASTBOOT_PARTITIONS), 15)

    def test_mutating_commands_are_rejected(self) -> None:
        for command in (
            ("flash", "oeminfo", "oeminfo.img"),
            ("erase", "userdata"),
            ("reboot",),
            ("boot", "recovery.img"),
            ("oem", "unlock"),
        ):
            with self.assertRaises(ValueError):
                assert_read_only(command)


class HuaweiFindingTests(unittest.TestCase):
    def test_current_phone_oeminfo_failures_are_promoted(self) -> None:
        evidence = {
            "windows_usb": {},
            "adb": {"devices": []},
            "fastboot": {
                "devices": [
                    {"serial": "5T5PUB194L059785", "state": "fastboot"}
                ],
                "probes": {
                    "5T5PUB194L059785": {
                        "variables": {
                            "product": {
                                "status": "value",
                                "value": "kirin980",
                                "error": None,
                            },
                            "rescue_phoneinfo": {
                                "status": "value",
                                "value": "NO MAIN VERSION",
                                "error": None,
                            },
                            "vendorcountry": {
                                "status": "error",
                                "value": None,
                                "error": (
                                    "FAILED (remote: 'cannot get vendorcountry "
                                    "in oeminfo')"
                                ),
                            },
                        }
                    }
                },
            },
        }
        codes = {item["code"] for item in derive_findings(evidence)}
        self.assertIn("OEMINFO_MAIN_VERSION_MISSING", codes)
        self.assertIn("OEMINFO_VENDORCOUNTRY_UNREADABLE", codes)


if __name__ == "__main__":
    unittest.main()
