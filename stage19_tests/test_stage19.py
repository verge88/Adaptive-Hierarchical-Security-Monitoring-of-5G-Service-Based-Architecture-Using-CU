"""Stage-19 development invariants."""
import unittest

from research.stage19_develop import (
    FALSE_ALARM_CEILING,
    TUNE_SEEDS,
    TUNE_START,
    VALID_SEEDS,
    VALID_START,
    SparseSignedWorld,
    stage17_outputs,
)
from research.stage19_detector import (
    MULTISCALE_GRID,
    MultiscaleDirectionalConfig,
    MultiscaleDirectionalState,
)


class Stage19ProtocolTests(unittest.TestCase):
    def test_development_blocks_are_disjoint_from_stage18_live(self):
        tuning = set(range(TUNE_START, TUNE_START + TUNE_SEEDS))
        validation = set(
            range(VALID_START, VALID_START + VALID_SEEDS)
        )
        live = set(range(8101, 8107))
        self.assertFalse(tuning & validation)
        self.assertFalse(tuning & live)
        self.assertFalse(validation & live)

    def test_fast_channel_is_stage17_frozen_for_every_grid_point(self):
        self.assertTrue(MULTISCALE_GRID)
        for config in MULTISCALE_GRID:
            self.assertEqual(config.fast_decay, 0.90)
            self.assertEqual(config.fast_reference, 0.12)
            self.assertEqual(config.fast_threshold, 5.0)

    def test_world_is_deterministic_and_balanced(self):
        a = SparseSignedWorld(11001)
        b = SparseSignedWorld(11001)
        self.assertEqual(a.values, b.values)
        self.assertEqual(a.episodes, b.episodes)

        families = {}
        for episode in a.episodes:
            families[episode.family] = (
                families.get(episode.family, 0) + 1
            )
        self.assertEqual(
            families,
            {
                "persistent_positive": 3,
                "persistent_negative": 3,
                "sparse_positive": 3,
                "sparse_negative": 3,
            },
        )

    def test_slow_memory_retains_separated_tail_evidence(self):
        calibration = [
            -0.01,
            -0.008,
            -0.006,
            -0.004,
            -0.002,
            0.0,
            0.002,
            0.004,
            0.006,
            0.008,
            0.01,
        ]
        config = MultiscaleDirectionalConfig(
            fast_decay=0.90,
            fast_reference=0.12,
            fast_threshold=99.0,
            slow_decay=0.995,
            slow_reference=0.0,
            slow_threshold=99.0,
            direction_gate_p=0.10,
            slow_update_gate_p=0.15,
        )
        state = MultiscaleDirectionalState(
            calibration, config
        )
        first = state.observe(0.08)
        retained = first["slow_positive"]
        self.assertGreater(retained, 0.0)
        state.observe(0.0)
        state.observe(0.0)
        later = state.observe(0.08)
        self.assertGreater(
            later["slow_positive"],
            retained,
        )

    def test_stage17_comparator_has_no_warmup_alerts(self):
        world = SparseSignedWorld(11002)
        alerts = stage17_outputs(world.values)
        self.assertTrue(not any(alerts[:30]))

    def test_false_alarm_ceiling_is_predeclared(self):
        self.assertEqual(FALSE_ALARM_CEILING, 0.50)


if __name__ == "__main__":
    unittest.main()
