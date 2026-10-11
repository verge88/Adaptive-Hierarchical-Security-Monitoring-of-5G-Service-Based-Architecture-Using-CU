"""Stage-17 development invariants."""
import unittest

from research.stage16_eval import evaluate_detector
from research.stage16_simulation import WorldOOD
from research.stage17_detector import (
    AdaptiveEPageConfig,
    DriftAdaptiveEPageDetector,
)
from research.stage17_develop import (
    DEV_START_SEED,
    DEV_SEEDS,
    FINAL_START_SEED,
    FINAL_SEEDS,
    build_trace,
    develop,
    evaluate_hybrid_trace,
)


class Stage17DevelopmentTests(unittest.TestCase):
    def test_development_and_final_blocks_are_disjoint(self):
        dev = set(
            range(
                DEV_START_SEED,
                DEV_START_SEED + DEV_SEEDS,
            )
        )
        final = set(
            range(
                FINAL_START_SEED,
                FINAL_START_SEED + FINAL_SEEDS,
            )
        )
        old_eval = set(range(5001, 5201))
        self.assertFalse(dev & final)
        self.assertFalse(dev & old_eval)
        self.assertFalse(final & old_eval)

    def test_development_guard_rejects_old_evaluation_block(self):
        with self.assertRaises(ValueError):
            develop(5001, 4)

    def test_development_guard_rejects_final_block(self):
        with self.assertRaises(ValueError):
            develop(7001, 4)

    def test_fast_hybrid_replay_matches_full_detector(self):
        world = WorldOOD(6001)
        config = AdaptiveEPageConfig(
            mean_alpha=0.05,
            delta=0.06,
            threshold=2.0,
            integrity_gate_p=0.06,
            update_log_cap=0.70,
        )
        full = evaluate_detector(
            world,
            DriftAdaptiveEPageDetector(world, config),
        )
        fast = evaluate_hybrid_trace(
            world,
            build_trace(world),
            config,
        )

        self.assertAlmostEqual(
            full["primary_event_recall"],
            fast["event_recall"],
        )
        self.assertAlmostEqual(
            full["primary_horizon_penalized_delay_s"],
            fast["horizon_penalized_delay_s"],
        )
        self.assertAlmostEqual(
            full["false_alarms_per_1000_clean_checks"],
            fast["false_alarms_per_1000"],
        )

    def test_full_hybrid_uses_same_probe_budget(self):
        world = WorldOOD(6002)
        config = AdaptiveEPageConfig(
            mean_alpha=0.10,
            delta=0.12,
            threshold=3.0,
            integrity_gate_p=0.06,
            update_log_cap=1.20,
        )
        result = evaluate_detector(
            world,
            DriftAdaptiveEPageDetector(world, config),
        )
        self.assertEqual(result["probes"], 1200)


if __name__ == "__main__":
    unittest.main()
