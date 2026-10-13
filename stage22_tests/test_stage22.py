"""Stage22 SCP-compromise boundary invariants."""
import ast
import inspect
import json
import unittest

from research.stage20_structure import (
    serialize_counter,
    structural_counter,
)
from research.stage21_semantic import (
    semantic_projection,
    serialize_projection,
)
from research.stage22_capture import common_path_projection
from research.stage22_live_detect import detect
from research.stage22_scp_fault import (
    WARMUP_TICKS,
    build_private_schedule,
)


def _size(obj):
    return len(
        json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf8")
    )


def _row(tick, trusted_obj, consumer_obj):
    return {
        "seed": 99901,
        "tick": tick,
        "trusted_status": 200,
        "consumer_status": 200,
        "trusted_canonical_bytes": _size(trusted_obj),
        "consumer_canonical_bytes": _size(consumer_obj),
        "trusted_nssf_profiles": len(
            trusted_obj.get("nfInstances", [])
        ),
        "consumer_nssf_profiles": len(
            consumer_obj.get("nfInstances", [])
        ),
        "trusted_wire_bytes": 1,
        "consumer_wire_bytes": 1,
        "trusted_structure": serialize_counter(
            structural_counter(trusted_obj)
        ),
        "consumer_structure": serialize_counter(
            structural_counter(consumer_obj)
        ),
        "trusted_semantic": serialize_projection(
            semantic_projection(trusted_obj)
        ),
        "consumer_semantic": serialize_projection(
            semantic_projection(consumer_obj)
        ),
        "reference_scope": "direct_native_nrf_bypasses_scp",
    }


class Stage22BoundaryTests(unittest.TestCase):
    def test_schedule_is_fresh_and_after_warmup(self):
        a = build_private_schedule(8901)
        b = build_private_schedule(8902)
        self.assertNotEqual(
            [(x["kind"], x["pulse_local_ticks"]) for x in a],
            [(x["kind"], x["pulse_local_ticks"]) for x in b],
        )
        self.assertTrue(
            all(x["start_tick"] >= WARMUP_TICKS for x in a)
        )

    def test_common_path_projection_erases_pairwise_difference(self):
        clean = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfStatus": "REGISTERED",
                }
            ]
        }
        changed = {
            "nfInstances": [
                {
                    "nfInstanceId": "b",
                    "nfStatus": "REGISTERED",
                }
            ]
        }
        row = _row(30, clean, changed)
        projected = common_path_projection(row)
        for suffix in (
            "canonical_bytes",
            "structure",
            "semantic",
        ):
            self.assertEqual(
                projected[f"trusted_{suffix}"],
                projected[f"consumer_{suffix}"],
            )

    def test_frozen_detector_sees_external_reference_not_common_mode(self):
        clean = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
                {
                    "nfInstanceId": "b",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
            ]
        }
        changed = {
            "nfInstances": [
                {
                    "nfInstanceId": "f",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
                {
                    "nfInstanceId": "b",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
            ]
        }

        external = []
        for tick in range(36):
            consumer = (
                changed if tick in (30, 31, 32) else clean
            )
            external.append(_row(tick, clean, consumer))
        common = [
            common_path_projection(row) for row in external
        ]

        result = detect(external, common)
        external_alerts = [
            row["stage21_combined_alert"]
            for row in result["external_reference"]["ticks"]
        ]
        common_alerts = [
            row["stage21_combined_alert"]
            for row in result["common_path_control"]["ticks"]
        ]
        self.assertTrue(any(external_alerts[WARMUP_TICKS:]))
        self.assertFalse(any(common_alerts))

    def test_blind_detector_does_not_import_private_fault_schedule(self):
        import research.stage22_live_detect as module
        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage22_scp_fault" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)


if __name__ == "__main__":
    unittest.main()
