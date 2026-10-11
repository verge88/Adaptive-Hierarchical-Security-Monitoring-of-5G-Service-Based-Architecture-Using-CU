"""Stage-18 blind live validation invariants."""
import ast
import inspect
import unittest

from research.h2_wire import encode
from research.stage17_final import (
    FROZEN_DIRECTIONAL,
    FROZEN_PAGE_HINKLEY,
)
from research.stage18_detect import (
    DIRECTIONAL_DECAY,
    DIRECTIONAL_GATE_P,
    DIRECTIONAL_REFERENCE,
    DIRECTIONAL_THRESHOLD,
    PH_DELTA,
    PH_GATE_P,
    PH_MEAN_ALPHA,
    PH_THRESHOLD,
    WARMUP_TICKS,
    detect,
)
from research.stage18_gateway import (
    ATTACK_KINDS,
    EPISODE_TICKS,
    REPETITIONS_PER_KIND,
    TOTAL_TICKS,
    build_private_schedule,
    mutate_payload,
)


class Stage18ScheduleTests(unittest.TestCase):
    def test_schedule_is_balanced_and_after_warmup(self):
        schedule = build_private_schedule(8101)
        self.assertEqual(
            len(schedule),
            len(ATTACK_KINDS) * REPETITIONS_PER_KIND,
        )
        counts = {
            kind: sum(
                item["kind"] == kind for item in schedule
            )
            for kind in ATTACK_KINDS
        }
        self.assertEqual(
            counts,
            {
                kind: REPETITIONS_PER_KIND
                for kind in ATTACK_KINDS
            },
        )
        self.assertTrue(
            all(
                item["start_tick"] >= WARMUP_TICKS
                for item in schedule
            )
        )
        self.assertTrue(
            all(
                item["end_tick"] - item["start_tick"]
                == EPISODE_TICKS
                for item in schedule
            )
        )
        self.assertLessEqual(
            max(item["end_tick"] for item in schedule),
            TOTAL_TICKS,
        )

    def test_mutations_have_expected_byte_direction(self):
        payload = {
            "validityPeriod": 60,
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
                {
                    "nfInstanceId": "b",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "heartBeatTimer": 10,
                },
            ],
        }
        clean = len(encode(payload))

        positive, changed = mutate_payload(
            payload, "profile_duplicate", 0
        )
        self.assertTrue(changed)
        self.assertGreater(len(encode(positive)), clean)

        negative, changed = mutate_payload(
            payload, "profile_drop", 0
        )
        self.assertTrue(changed)
        self.assertLess(len(encode(negative)), clean)

        positive_sparse, changed = mutate_payload(
            payload, "padding_sparse", 1
        )
        self.assertTrue(changed)
        self.assertGreater(
            len(encode(positive_sparse)), clean
        )

        negative_sparse, changed = mutate_payload(
            payload, "metadata_strip_sparse", 1
        )
        self.assertTrue(changed)
        self.assertLess(
            len(encode(negative_sparse)), clean
        )


class Stage18BlindDetectorTests(unittest.TestCase):
    def test_frozen_parameters_equal_stage17(self):
        self.assertEqual(
            (
                DIRECTIONAL_DECAY,
                DIRECTIONAL_REFERENCE,
                DIRECTIONAL_THRESHOLD,
                DIRECTIONAL_GATE_P,
            ),
            (
                FROZEN_DIRECTIONAL.decay,
                FROZEN_DIRECTIONAL.reference,
                FROZEN_DIRECTIONAL.threshold,
                FROZEN_DIRECTIONAL.direction_gate_p,
            ),
        )
        self.assertEqual(PH_DELTA, FROZEN_PAGE_HINKLEY.delta)
        self.assertEqual(
            PH_THRESHOLD,
            FROZEN_PAGE_HINKLEY.threshold,
        )
        self.assertEqual(
            PH_GATE_P,
            FROZEN_PAGE_HINKLEY.integrity_gate_p,
        )
        self.assertEqual(
            PH_MEAN_ALPHA,
            FROZEN_PAGE_HINKLEY.mean_alpha,
        )

    def test_detector_module_does_not_import_fault_schedule(self):
        import research.stage18_detect as module

        source = inspect.getsource(module)
        tree = ast.parse(source)
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage18_gateway" not in name for name in imported)
        )
        self.assertNotIn("ATTACK_KINDS", module.__dict__)
        self.assertNotIn("build_private_schedule", module.__dict__)

    def test_detector_warmup_never_alarms(self):
        rows = []
        for tick in range(WARMUP_TICKS + 4):
            rows.append(
                {
                    "seed": 9999,
                    "tick": tick,
                    "trusted_status": 200,
                    "consumer_status": 200,
                    "trusted_canonical_bytes": 1000,
                    "consumer_canonical_bytes": (
                        1000 if tick < WARMUP_TICKS else 1100
                    ),
                }
            )
        result = detect(rows)
        self.assertTrue(
            all(
                not row["directional_alert"]
                and not row["page_hinkley_alert"]
                for row in result["ticks"][:WARMUP_TICKS]
            )
        )
        self.assertFalse(
            result["protocol"][
                "detector_received_private_labels"
            ]
        )


if __name__ == "__main__":
    unittest.main()
