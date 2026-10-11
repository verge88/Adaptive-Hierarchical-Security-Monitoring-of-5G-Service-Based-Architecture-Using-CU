"""Stage-19 frozen final-protocol invariants."""
import unittest

from research.stage19_final import (
    FINAL_SEEDS,
    FINAL_START_SEED,
    run_detector,
)
from research.stage19_frozen import (
    FROZEN_CONSECUTIVE,
    FROZEN_PAGE_HINKLEY,
    FROZEN_SINGLE,
    FROZEN_SPARSE,
    TriPathDirectionalEvidenceEnsemble,
)
from research.stage19_simulation import (
    WARMUP_TICKS,
    SparseIntegrityWorld,
)


class Stage19FrozenProtocolTests(unittest.TestCase):
    def test_final_block_is_exactly_predeclared(self):
        self.assertEqual(FINAL_START_SEED, 10001)
        self.assertEqual(FINAL_SEEDS, 200)

    def test_sparse_channel_is_exactly_development_selected(self):
        self.assertEqual(FROZEN_SPARSE.windows, (16, 32, 64))
        self.assertEqual(FROZEN_SPARSE.tail_gate_p, 0.07)
        self.assertEqual(FROZEN_SPARSE.magnitude_gate_z, 4.5)
        self.assertEqual(FROZEN_SPARSE.min_hits, 2)
        self.assertEqual(FROZEN_SPARSE.e_sum_threshold, 2.8)
        self.assertEqual(FROZEN_SPARSE.center_alpha, 0.03)
        self.assertEqual(FROZEN_SPARSE.scale_alpha, 0.02)
        self.assertEqual(FROZEN_SPARSE.update_clip_z, 3.0)

    def test_single_channel_is_exactly_development_selected(self):
        self.assertEqual(FROZEN_SINGLE.decay, 0.90)
        self.assertEqual(FROZEN_SINGLE.reference, 0.12)
        self.assertEqual(FROZEN_SINGLE.threshold, 7.0)
        self.assertEqual(FROZEN_SINGLE.direction_gate_p, 0.04)

    def test_consecutive_channel_is_exactly_development_selected(self):
        self.assertEqual(FROZEN_CONSECUTIVE.window, 4)
        self.assertEqual(FROZEN_CONSECUTIVE.hits, 3)
        self.assertEqual(
            FROZEN_CONSECUTIVE.magnitude_gate_z,
            2.6,
        )
        self.assertEqual(FROZEN_CONSECUTIVE.tail_gate_p, 0.15)
        self.assertEqual(FROZEN_CONSECUTIVE.center_alpha, 0.03)
        self.assertEqual(FROZEN_CONSECUTIVE.scale_alpha, 0.02)
        self.assertEqual(FROZEN_CONSECUTIVE.update_clip_z, 3.0)

    def test_page_hinkley_comparator_is_frozen(self):
        self.assertEqual(FROZEN_PAGE_HINKLEY.delta, 0.30)
        self.assertEqual(FROZEN_PAGE_HINKLEY.threshold, 5.0)
        self.assertEqual(FROZEN_PAGE_HINKLEY.gate_p, 0.08)
        self.assertEqual(FROZEN_PAGE_HINKLEY.mean_alpha, 0.20)

    def test_tri_path_executes_without_labels(self):
        world = SparseIntegrityWorld(10001)
        detector = TriPathDirectionalEvidenceEnsemble(
            world.values[:WARMUP_TICKS]
        )
        for value in world.values[WARMUP_TICKS:WARMUP_TICKS + 10]:
            alarm, state = detector.observe(value)
            self.assertIsInstance(alarm, bool)
            self.assertEqual(
                set(
                    (
                        "sparse_alarm",
                        "single_alarm",
                        "consecutive_alarm",
                    )
                ).issubset(state),
                True,
            )

    def test_final_evaluator_does_not_assert_superiority(self):
        world = SparseIntegrityWorld(10001)
        result = run_detector(
            world,
            "tri_path_directional",
        )
        self.assertGreaterEqual(result["event_recall"], 0.0)
        self.assertLessEqual(result["event_recall"], 1.0)
        self.assertGreaterEqual(
            result["false_alarms_per_1000_clean_ticks"],
            0.0,
        )


if __name__ == "__main__":
    unittest.main()
