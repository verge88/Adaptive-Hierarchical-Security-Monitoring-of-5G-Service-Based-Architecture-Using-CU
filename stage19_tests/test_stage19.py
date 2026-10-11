"""Stage-19 development invariants."""
import unittest

from research.stage19_develop import (
    DEV_SEEDS,
    DEV_START_SEED,
    FINAL_SEEDS,
    FINAL_START_SEED,
    build_trace,
    develop,
    evaluate_multiscale,
    evaluate_page_hinkley,
    evaluate_single,
    evaluate_sparse_scan,
    evaluate_robust_sparse_scan,
    evaluate_adaptive_robust_sparse_scan,
    evaluate_dual_path,
    evaluate_sparse_plus_directional,
)
from research.stage19_detector import (
    MultiScaleDirectionalConfig,
    MultiScaleDirectionalDetector,
    ScalarPageHinkleyConfig,
    ScalarPageHinkleyDetector,
    SingleScaleDirectionalConfig,
    SingleScaleDirectionalDetector,
    SparseEScanConfig,
    SparseEScanDetector,
    RobustSparseEScanConfig,
    RobustSparseEScanDetector,
    AdaptiveRobustSparseEScanConfig,
    AdaptiveRobustSparseEScanDetector,
    DualPathDirectionalConfig,
    DualPathDirectionalDetector,
    SparsePlusDirectionalConfig,
    SparsePlusDirectionalDetector,
)
from research.stage19_simulation import (
    ALL_KINDS,
    REPETITIONS_PER_KIND,
    WARMUP_TICKS,
    SparseIntegrityWorld,
)


def replay_full(world, detector):
    alert_ticks = set()
    for tick, value in enumerate(world.values):
        if tick < WARMUP_TICKS:
            continue
        alarm, _ = detector.observe(value)
        if alarm:
            alert_ticks.add(tick)
    return alert_ticks


class Stage19WorldTests(unittest.TestCase):
    def test_world_is_deterministic(self):
        a = SparseIntegrityWorld(9001)
        b = SparseIntegrityWorld(9001)
        self.assertEqual(a.episodes, b.episodes)
        self.assertEqual(a.values, b.values)

    def test_episode_families_are_balanced(self):
        world = SparseIntegrityWorld(9002)
        counts = {
            kind: sum(ep.kind == kind for ep in world.episodes)
            for kind in ALL_KINDS
        }
        self.assertEqual(
            counts,
            {
                kind: REPETITIONS_PER_KIND
                for kind in ALL_KINDS
            },
        )
        self.assertTrue(
            all(ep.start_tick >= WARMUP_TICKS for ep in world.episodes)
        )

    def test_seed_blocks_are_disjoint(self):
        dev = set(range(DEV_START_SEED, DEV_START_SEED + DEV_SEEDS))
        final = set(range(FINAL_START_SEED, FINAL_START_SEED + FINAL_SEEDS))
        live18 = set(range(8101, 8107))
        self.assertFalse(dev & final)
        self.assertFalse(dev & live18)
        self.assertFalse(final & live18)

    def test_development_guards_reject_evaluation_blocks(self):
        with self.assertRaises(ValueError):
            develop(8101, 4)
        with self.assertRaises(ValueError):
            develop(10001, 4)


class Stage19ReplayTests(unittest.TestCase):
    def test_multiscale_fast_replay_matches_full_detector(self):
        world = SparseIntegrityWorld(9003)
        trace = build_trace(world)
        config = MultiScaleDirectionalConfig(
            decays=(0.75, 0.93, 0.99),
            reference=0.06,
            threshold=3.2,
            direction_gate_p=0.07,
        )
        fast = evaluate_multiscale(world, trace, config)
        full_detector = MultiScaleDirectionalDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full_detector)
        detected = []
        delays = []
        for ep in world.episodes:
            inside = sorted(
                tick for tick in alerts
                if ep.start_tick <= tick < ep.end_tick
            )
            detected.append(bool(inside))
            delays.append(
                inside[0] - ep.start_tick
                if inside
                else ep.end_tick - ep.start_tick
            )
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )
        self.assertAlmostEqual(
            fast["horizon_penalized_delay_ticks"],
            sum(delays) / len(delays),
        )

    def test_sparse_scan_fast_replay_matches_full_detector(self):
        world = SparseIntegrityWorld(9005)
        trace = build_trace(world)
        config = SparseEScanConfig(
            windows=(8, 16, 32),
            tail_gate_p=0.04,
            min_hits=2,
            e_sum_threshold=1.6,
        )
        fast = evaluate_sparse_scan(world, trace, config)
        full = SparseEScanDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full)
        detected = []
        for ep in world.episodes:
            detected.append(
                any(
                    ep.start_tick <= tick < ep.end_tick
                    for tick in alerts
                )
            )
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )

    def test_robust_sparse_scan_fast_replay_matches_full_detector(self):
        world = SparseIntegrityWorld(9006)
        trace = build_trace(world)
        config = RobustSparseEScanConfig(
            windows=(8, 16, 32),
            tail_gate_p=0.04,
            magnitude_gate_z=4.0,
            min_hits=2,
            e_sum_threshold=2.2,
        )
        fast = evaluate_robust_sparse_scan(
            world, trace, config
        )
        full = RobustSparseEScanDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full)
        detected = [
            any(
                ep.start_tick <= tick < ep.end_tick
                for tick in alerts
            )
            for ep in world.episodes
        ]
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )

    def test_adaptive_robust_scan_fast_replay_matches_full_detector(self):
        world = SparseIntegrityWorld(9007)
        trace = build_trace(world)
        config = AdaptiveRobustSparseEScanConfig(
            windows=(8, 16, 32),
            tail_gate_p=0.04,
            magnitude_gate_z=4.5,
            min_hits=2,
            e_sum_threshold=2.8,
            center_alpha=0.08,
            scale_alpha=0.04,
        )
        fast = evaluate_adaptive_robust_sparse_scan(
            world, trace, config
        )
        full = AdaptiveRobustSparseEScanDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full)
        detected = [
            any(
                ep.start_tick <= tick < ep.end_tick
                for tick in alerts
            )
            for ep in world.episodes
        ]
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )

    def test_dual_path_fast_replay_matches_full_detector(self):
        world = SparseIntegrityWorld(9008)
        trace = build_trace(world)
        config = DualPathDirectionalConfig(
            sparse_windows=(16, 32, 64),
            sparse_tail_gate_p=0.07,
            sparse_magnitude_gate_z=3.5,
            sparse_min_hits=2,
            sparse_e_sum_threshold=2.2,
            center_alpha=0.03,
            scale_alpha=0.02,
            sustained_window=6,
            sustained_hits=4,
            sustained_z=2.2,
            sustained_gate_p=0.25,
        )
        fast = evaluate_dual_path(world, trace, config)
        full = DualPathDirectionalDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full)
        detected = [
            any(
                ep.start_tick <= tick < ep.end_tick
                for tick in alerts
            )
            for ep in world.episodes
        ]
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )

    def test_sparse_plus_directional_fast_replay_matches_full(self):
        world = SparseIntegrityWorld(9009)
        trace = build_trace(world)
        config = SparsePlusDirectionalConfig(
            sparse_windows=(16, 32, 64),
            sparse_tail_gate_p=0.07,
            sparse_magnitude_gate_z=3.5,
            sparse_min_hits=2,
            sparse_e_sum_threshold=2.2,
            center_alpha=0.03,
            scale_alpha=0.02,
            single_decay=0.90,
            single_reference=0.12,
            single_threshold=7.0,
            single_gate_p=0.04,
        )
        fast = evaluate_sparse_plus_directional(
            world, trace, config
        )
        full = SparsePlusDirectionalDetector(
            trace["calibration"], config
        )
        alerts = replay_full(world, full)
        detected = [
            any(
                ep.start_tick <= tick < ep.end_tick
                for tick in alerts
            )
            for ep in world.episodes
        ]
        self.assertAlmostEqual(
            fast["event_recall"],
            sum(detected) / len(detected),
        )

    def test_single_and_page_fast_replay_execute(self):
        world = SparseIntegrityWorld(9004)
        trace = build_trace(world)
        single = SingleScaleDirectionalConfig(
            decay=0.96,
            reference=0.06,
            threshold=4.2,
            direction_gate_p=0.07,
        )
        page = ScalarPageHinkleyConfig(
            delta=0.50,
            threshold=7.0,
            gate_p=0.08,
            mean_alpha=0.10,
        )
        a = evaluate_single(world, trace, single)
        b = evaluate_page_hinkley(world, trace, page)
        self.assertGreaterEqual(a["event_recall"], 0.0)
        self.assertLessEqual(a["event_recall"], 1.0)
        self.assertGreaterEqual(b["event_recall"], 0.0)
        self.assertLessEqual(b["event_recall"], 1.0)

        SingleScaleDirectionalDetector(
            trace["calibration"], single
        ).observe(world.values[WARMUP_TICKS])
        ScalarPageHinkleyDetector(
            [abs(v) for v in trace["calibration"]], page
        ).observe(world.values[WARMUP_TICKS])


if __name__ == "__main__":
    unittest.main()
