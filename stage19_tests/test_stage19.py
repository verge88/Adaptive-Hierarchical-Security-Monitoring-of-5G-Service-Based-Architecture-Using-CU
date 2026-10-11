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
)
from research.stage19_detector import (
    MultiScaleDirectionalConfig,
    MultiScaleDirectionalDetector,
    ScalarPageHinkleyConfig,
    ScalarPageHinkleyDetector,
    SingleScaleDirectionalConfig,
    SingleScaleDirectionalDetector,
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
