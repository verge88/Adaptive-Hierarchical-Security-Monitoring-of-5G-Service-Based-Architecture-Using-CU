"""Regression tests for the Stage-15 synthetic detector comparison."""
import statistics
import unittest

from research.stage15_detector import (
    HIERARCHICAL_E_CUSUM,
    TUNED_STATIC,
    HierarchicalECUSUMDetector,
    StaticThresholdDetector,
    evaluate_detector,
)
from research.stage15_simulation import (
    CHALLENGES_PER_TICK,
    N_NF,
    STEP_SECONDS,
    WARMUP,
    WorldV2,
    fixed_schedule,
)


class Stage15InvariantTests(unittest.TestCase):
    def test_world_is_deterministic(self):
        a = WorldV2(2001)
        b = WorldV2(2001)
        self.assertEqual(a.attacks, b.attacks)
        self.assertEqual(a.bursts, b.bursts)
        self.assertEqual(a.maintenance, b.maintenance)
        self.assertEqual(a.samples, b.samples)

    def test_fixed_schedule_has_exact_budget_and_full_cycle(self):
        counts = [0] * N_NF
        ticks = N_NF // CHALLENGES_PER_TICK
        for tick in range(ticks):
            chosen = fixed_schedule(tick)
            self.assertEqual(
                len(set(chosen)), CHALLENGES_PER_TICK
            )
            for nf in chosen:
                counts[nf] += 1
        self.assertEqual(counts, [1] * N_NF)

    def test_evidence_calibration_uses_only_warmup_budget(self):
        world = WorldV2(2001)
        detector = HierarchicalECUSUMDetector(
            world, HIERARCHICAL_E_CUSUM
        )
        expected = (
            WARMUP // STEP_SECONDS
        ) * CHALLENGES_PER_TICK
        self.assertEqual(
            len(detector.discrepancy_calibration), expected
        )
        self.assertEqual(
            len(detector.joint_calibration), expected
        )

    def test_same_monitoring_probe_budget(self):
        world = WorldV2(2001)
        static = evaluate_detector(
            world,
            StaticThresholdDetector(world, TUNED_STATIC),
        )
        evidence = evaluate_detector(
            world,
            HierarchicalECUSUMDetector(
                world, HIERARCHICAL_E_CUSUM
            ),
        )
        self.assertEqual(static["probes"], evidence["probes"])


class Stage15HeldoutRegressionTests(unittest.TestCase):
    def test_evidence_detector_beats_tuned_static_on_small_heldout_block(self):
        static_rows = []
        evidence_rows = []
        for seed in range(2001, 2007):
            world = WorldV2(seed)
            static_rows.append(
                evaluate_detector(
                    world,
                    StaticThresholdDetector(
                        world, TUNED_STATIC
                    ),
                )
            )
            evidence_rows.append(
                evaluate_detector(
                    world,
                    HierarchicalECUSUMDetector(
                        world, HIERARCHICAL_E_CUSUM
                    ),
                )
            )

        static_recall = statistics.mean(
            row["event_recall"] for row in static_rows
        )
        evidence_recall = statistics.mean(
            row["event_recall"] for row in evidence_rows
        )
        static_delay = statistics.mean(
            row["mean_censored_delay_s"]
            for row in static_rows
        )
        evidence_delay = statistics.mean(
            row["mean_censored_delay_s"]
            for row in evidence_rows
        )
        static_false = statistics.mean(
            row["false_alarms_per_1000_clean_checks"]
            for row in static_rows
        )
        evidence_false = statistics.mean(
            row["false_alarms_per_1000_clean_checks"]
            for row in evidence_rows
        )

        self.assertGreater(evidence_recall, static_recall)
        self.assertLess(evidence_delay, static_delay)
        self.assertLessEqual(evidence_false, static_false)


if __name__ == "__main__":
    unittest.main()
