"""Stage28 randomized robustness invariants."""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import unittest

from research.stage27_attestation import project
from research.stage27_authority import build_manifest
from research.stage28_capture import (
    DENSITY_RANGES,
    DURATION_RANGES,
    EPISODES,
    KINDS,
    WARMUP_TICKS,
    build_private_schedule,
)
from research.stage28_live_detect import detect
from research.stage28_report import wilson_interval


class Stage28Tests(unittest.TestCase):
    def test_private_schedule_is_balanced_and_within_preregistered_ranges(self):
        schedule = build_private_schedule()
        episodes = schedule["episodes"]
        self.assertEqual(len(episodes), EPISODES)

        self.assertEqual(
            sorted(row["kind"] for row in episodes),
            sorted(list(KINDS) * 4),
        )
        self.assertEqual(
            sorted(row["duration_bin"] for row in episodes),
            sorted(["short", "medium", "long"] * 4),
        )
        self.assertEqual(
            sorted(row["density_bin"] for row in episodes),
            sorted(["low", "medium", "high"] * 4),
        )

        for row in episodes:
            dlo, dhi = DURATION_RANGES[row["duration_bin"]]
            self.assertGreaterEqual(row["duration_ticks"], dlo)
            self.assertLessEqual(row["duration_ticks"], dhi)
            rlo, rhi = DENSITY_RANGES[row["density_bin"]]
            # realized density is discrete and can differ from the sampled
            # continuous target by at most one sample over duration.
            tolerance = 1 / row["duration_ticks"]
            self.assertGreaterEqual(
                row["realized_density"], max(0, rlo - tolerance)
            )
            self.assertLessEqual(
                row["realized_density"], min(1, rhi + tolerance)
            )
            self.assertTrue(row["mutation_ticks"])

        self.assertEqual(
            schedule["plan_sha256"].__len__(), 64
        )
        self.assertNotIn(schedule["plan_nonce"], schedule["plan_text"])

    def test_schedule_starts_after_clean_warmup(self):
        schedule = build_private_schedule()
        self.assertTrue(
            all(
                entry["tick"] >= WARMUP_TICKS
                for entry in schedule["entries"]
            )
        )

    def test_colluding_pair_has_no_disagreement_but_attested_view_does(self):
        raw = []
        total = WARMUP_TICKS + 16
        for tick in range(total):
            attacked = WARMUP_TICKS <= tick < WARMUP_TICKS + 8
            count = 3 if attacked else 2
            raw.append(
                {
                    "seed": 99501,
                    "tick": tick,
                    "witness_first": tick % 2 == 0,
                    "consumer_nssf_count": count,
                    "consumer_registered_count": count,
                    "compromised_witness_nssf_count": count,
                    "compromised_witness_registered_count": count,
                    "common_source_equal": True,
                }
            )

        manifest = build_manifest(Path("."))
        attested, compromised = project(raw, manifest)
        result = detect(attested, compromised)

        self.assertFalse(
            any(
                row["stage21_combined_alert"]
                for row in result["common_path_control"]["ticks"]
            )
        )
        self.assertTrue(
            any(
                row["stage21_combined_alert"]
                for row in result["external_reference"]["ticks"][
                    WARMUP_TICKS:
                ]
            )
        )

    def test_native_source_reads_local_private_plan_only(self):
        text = Path(
            "live/stage28-nnrf-handler.c"
        ).read_text(encoding="utf8")
        self.assertIn("/run/stage28/plan.tsv", text)
        self.assertIn("/run/stage28/enabled", text)
        self.assertIn("STAGE28_NATIVE_NRF_LAB_MUTATION", text)
        self.assertIn("phantom_registered", text)
        self.assertIn("phantom_suspended", text)
        self.assertIn("status_substitution", text)
        self.assertNotIn("STAGE28_ENABLE_PORT", text)

    def test_blind_detector_imports_no_schedule_generator(self):
        import research.stage28_live_detect as module

        tree = ast.parse(inspect.getsource(module))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertTrue(
            all("stage28_capture" not in name for name in imported)
        )
        self.assertNotIn("build_private_schedule", module.__dict__)

    def test_wilson_interval_not_degenerate_at_perfect_finite_recall(self):
        lo, hi = wilson_interval(96, 96)
        self.assertLess(lo, 1.0)
        self.assertEqual(hi, 1.0)


if __name__ == "__main__":
    unittest.main()
