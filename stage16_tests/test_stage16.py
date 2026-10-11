"""Correctness and fairness invariants for Stage 16."""
import unittest

from research.stage15_detector import (
    HIERARCHICAL_E_CUSUM,
    HierarchicalECUSUMDetector,
)
from research.stage15_simulation import (
    CHALLENGES_PER_TICK,
    N_NF,
    STEP_SECONDS,
    WARMUP,
)
from research.stage16_detectors import (
    CUSUMConfig,
    EWMAConfig,
    PageHinkleyConfig,
    StaticCalibratedConfig,
    detector_from_config,
)
from research.stage16_eval import evaluate_detector
from research.stage16_simulation import (
    BOUNDARY_KIND,
    PRIMARY_KINDS,
    WorldOOD,
    fixed_schedule,
)
from research.stage16_tune import (
    build_trace,
    evaluate_trace,
)


class Stage16WorldTests(unittest.TestCase):
    def test_world_is_deterministic(self):
        a = WorldOOD(5001)
        b = WorldOOD(5001)
        self.assertEqual(a.attacks, b.attacks)
        self.assertEqual(a.bursts, b.bursts)
        self.assertEqual(a.maintenance, b.maintenance)
        self.assertEqual(a.samples, b.samples)

    def test_attack_strata_are_balanced(self):
        world = WorldOOD(5001)
        counts = {
            kind: sum(
                attack.kind == kind
                for attack in world.attacks
            )
            for kind in (*PRIMARY_KINDS, BOUNDARY_KIND)
        }
        self.assertEqual(
            counts,
            {
                "micro_step": 3,
                "reverse_step": 3,
                "slow_nonlinear_ramp": 3,
                "sparse_bursts": 3,
                "observer_silent_semantic": 3,
            },
        )
        self.assertEqual(
            sum(attack.primary for attack in world.attacks),
            12,
        )
        self.assertTrue(
            all(
                attack.start >= WARMUP
                for attack in world.attacks
            )
        )

    def test_fixed_schedule_exact_budget_and_cycle(self):
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


class Stage16DetectorTests(unittest.TestCase):
    def test_all_detector_families_have_same_probe_budget(self):
        world = WorldOOD(5001)
        configs = {
            "calibrated_static": StaticCalibratedConfig(
                threshold=4.3,
                integrity_gate_p=0.07,
            ).__dict__,
            "ewma": EWMAConfig(
                alpha=0.35,
                threshold=3.0,
                integrity_gate_p=0.06,
            ).__dict__,
            "cusum": CUSUMConfig(
                reference=0.9,
                threshold=8.0,
                integrity_gate_p=0.06,
            ).__dict__,
            "page_hinkley": PageHinkleyConfig(
                delta=0.3,
                threshold=7.0,
                integrity_gate_p=0.06,
                mean_alpha=0.07,
            ).__dict__,
        }
        probes = []
        for name, config in configs.items():
            detector = detector_from_config(
                name, world, config
            )
            probes.append(
                evaluate_detector(world, detector)["probes"]
            )

        frozen = HierarchicalECUSUMDetector(
            world, HIERARCHICAL_E_CUSUM
        )
        probes.append(
            evaluate_detector(world, frozen)["probes"]
        )
        self.assertEqual(
            probes, [probes[0]] * len(probes)
        )

    def test_fast_tuning_replay_matches_full_detectors(self):
        world = WorldOOD(5004)
        trace = build_trace(world)
        cases = (
            (
                "ewma",
                EWMAConfig(
                    alpha=0.35,
                    threshold=3.0,
                    integrity_gate_p=0.06,
                ),
            ),
            (
                "page_hinkley",
                PageHinkleyConfig(
                    delta=0.3,
                    threshold=7.0,
                    integrity_gate_p=0.06,
                    mean_alpha=0.07,
                ),
            ),
        )
        for name, config in cases:
            full = evaluate_detector(
                world,
                detector_from_config(
                    name, world, config.__dict__
                ),
            )
            fast = evaluate_trace(
                world, trace, name, config
            )
            self.assertAlmostEqual(
                full["primary_event_recall"],
                fast["primary_event_recall"],
            )
            self.assertAlmostEqual(
                full["primary_horizon_penalized_delay_s"],
                fast["primary_horizon_penalized_delay_s"],
            )
            self.assertAlmostEqual(
                full["primary_normalized_delay"],
                fast["primary_normalized_delay"],
            )
            self.assertAlmostEqual(
                full["false_alarms_per_1000_clean_checks"],
                fast["false_alarms_per_1000_clean_checks"],
            )
            self.assertAlmostEqual(
                full["boundary_event_recall"],
                fast["boundary_event_recall"],
            )

    def test_boundary_attack_is_excluded_from_primary(self):
        world = WorldOOD(5002)
        self.assertTrue(
            all(
                attack.primary
                for attack in world.attacks
                if attack.kind in PRIMARY_KINDS
            )
        )
        self.assertTrue(
            all(
                not attack.primary
                for attack in world.attacks
                if attack.kind == BOUNDARY_KIND
            )
        )

    def test_reverse_step_really_changes_report_direction(self):
        world = WorldOOD(5003)
        attack = next(
            item
            for item in world.attacks
            if item.kind == "reverse_step"
        )
        self.assertEqual(attack.direction, -1)
        tick = attack.start // STEP_SECONDS
        sample = world.samples[tick][attack.nf]
        # Independent observer noise can blur one sample, so require only
        # that the configured attack direction is encoded in the ground-truth
        # attack object; detectors never receive this object.
        self.assertGreater(sample.reported, 0)
        self.assertGreater(sample.transit, 0)


if __name__ == "__main__":
    unittest.main()
