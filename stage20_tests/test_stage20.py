"""Stage-20 environment-randomization and detector invariants."""
import unittest

from research.stage20_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    FINAL_SEEDS,
    FINAL_START_SEED,
    develop,
)
from research.stage20_detector import (
    CompetitiveLeakyConfig,
    CompetitiveLeakyDetector,
    CompetitiveSparseConfig,
    CompetitiveSparseDetector,
)
from research.stage20_simulation import (
    ALL_KINDS,
    ENVIRONMENT_MODES,
    REPETITIONS_PER_KIND,
    WARMUP_TICKS,
    EnvironmentRandomizedWorld,
)


class Stage20WorldTests(unittest.TestCase):
    def test_world_is_deterministic(self):
        a = EnvironmentRandomizedWorld(11001)
        b = EnvironmentRandomizedWorld(11001)
        self.assertEqual(a.environment, b.environment)
        self.assertEqual(a.episodes, b.episodes)
        self.assertEqual(a.values, b.values)

    def test_environment_modes_are_balanced_in_development(self):
        modes = [
            EnvironmentRandomizedWorld(seed).environment.mode
            for seed in range(
                DEV_START_SEED,
                DEV_START_SEED + DEV_SEEDS,
            )
        ]
        counts = {
            mode: modes.count(mode)
            for mode in ENVIRONMENT_MODES
        }
        self.assertEqual(
            counts,
            {
                mode: DEV_SEEDS // len(ENVIRONMENT_MODES)
                for mode in ENVIRONMENT_MODES
            },
        )

    def test_attack_families_are_balanced(self):
        world = EnvironmentRandomizedWorld(11002)
        self.assertEqual(
            {
                kind: sum(
                    episode.kind == kind
                    for episode in world.episodes
                )
                for kind in ALL_KINDS
            },
            {
                kind: REPETITIONS_PER_KIND
                for kind in ALL_KINDS
            },
        )

    def test_seed_blocks_are_disjoint(self):
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
        old19 = set(range(10001, 10201))
        live18 = set(range(8101, 8107))
        self.assertFalse(dev & final)
        self.assertFalse(dev & old19)
        self.assertFalse(dev & live18)
        self.assertFalse(final & old19)

    def test_development_guards_reject_old_and_final_blocks(self):
        with self.assertRaises(ValueError):
            develop(10001, 4)
        with self.assertRaises(ValueError):
            develop(8101, 4)
        with self.assertRaises(ValueError):
            develop(12001, 4)


class Stage20DetectorTests(unittest.TestCase):
    def test_competitive_sparse_opposite_evidence_reduces_score(self):
        calibration = [
            -0.02,
            -0.015,
            -0.01,
            -0.005,
            0.0,
            0.005,
            0.01,
            0.015,
            0.02,
        ] * 5
        config = CompetitiveSparseConfig(
            windows=(12,),
            tail_gate_p=0.10,
            magnitude_gate_z=1.0,
            min_hits=2,
            score_threshold=99.0,
            opposition_penalty=1.0,
            center_alpha=0.03,
            scale_alpha=0.02,
        )
        detector = CompetitiveSparseDetector(
            calibration, config
        )
        _, before = detector.observe(0.20)
        _, after_same = detector.observe(0.20)
        _, after_opposite = detector.observe(-0.20)
        self.assertGreaterEqual(
            after_same["positive_score"],
            before["positive_score"],
        )
        self.assertLess(
            after_opposite["positive_score"],
            after_same["positive_score"],
        )

    def test_detectors_execute_label_free(self):
        world = EnvironmentRandomizedWorld(11003)
        calibration = world.values[:WARMUP_TICKS]
        sparse = CompetitiveSparseDetector(
            calibration,
            CompetitiveSparseConfig(
                windows=(16, 32),
                tail_gate_p=0.07,
                magnitude_gate_z=4.5,
                min_hits=2,
                score_threshold=3.2,
                opposition_penalty=1.0,
                center_alpha=0.03,
                scale_alpha=0.02,
            ),
        )
        leaky = CompetitiveLeakyDetector(
            calibration,
            CompetitiveLeakyConfig(
                decay=0.90,
                reference=0.15,
                threshold=7.0,
                tail_gate_p=0.07,
                opposition_penalty=1.0,
                center_alpha=0.03,
                scale_alpha=0.02,
            ),
        )
        for value in world.values[
            WARMUP_TICKS:WARMUP_TICKS + 12
        ]:
            self.assertIsInstance(sparse.observe(value)[0], bool)
            self.assertIsInstance(leaky.observe(value)[0], bool)


if __name__ == "__main__":
    unittest.main()
