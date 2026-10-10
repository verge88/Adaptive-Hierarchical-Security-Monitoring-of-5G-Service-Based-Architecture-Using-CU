"""Determinism, authenticity and fairness invariants for the research model."""
import dataclasses
import random
import unittest
from research.simulation import (
    N_NF, STEP_SECONDS, DURATION, WARMUP, CU_BYTES, CHALLENGES_PER_TICK,
    make_control_unit, verify_control_unit, World, run_policy, choose_policy,
)
from research.experiment import run, summarize

class ControlUnitTests(unittest.TestCase):
    def test_mac_and_replay(self):
        key = b'test-only-key'
        cu = make_control_unit(1, 1, 100, 175, 1.8, key, random.Random(7))
        self.assertTrue(verify_control_unit(cu, key, 100, 0))
        self.assertFalse(verify_control_unit(cu, key, 100, 1))
        self.assertFalse(verify_control_unit(cu, key, 200, 0))
        self.assertFalse(verify_control_unit(cu, b'wrong', 100, 0))
        self.assertFalse(verify_control_unit(dataclasses.replace(cu, reported=176), key, 100, 0))

    def test_valid_mac_does_not_mean_honest_report(self):
        world = World(101)
        attack = world.attacks[0]
        tick = attack.start // STEP_SECONDS
        s = world.samples[tick][attack.nf]
        cu = make_control_unit(attack.nf, 1, attack.start, s.reported,
                               s.processing, world.keys[attack.nf], random.Random(7))
        self.assertTrue(verify_control_unit(cu, world.keys[attack.nf], attack.start, 0))
        self.assertNotEqual(s.reported, s.transit)

class ExperimentTests(unittest.TestCase):
    def test_fixed_schedule_covers_every_node(self):
        counts = [0]*N_NF
        for tick in range(N_NF // CHALLENGES_PER_TICK):
            ids = choose_policy('fixed', [0]*N_NF, [-10]*N_NF, tick*STEP_SECONDS, tick)
            self.assertEqual(len(set(ids)), CHALLENGES_PER_TICK)
            for nf in ids: counts[nf] += 1
        self.assertEqual(counts, [1]*N_NF)

    def test_all_cu_policies_have_identical_budget(self):
        world = World(101)
        policies = [run_policy(world, p) for p in ('fixed','local_adaptive','zone_adaptive')]
        exp_probes = ((DURATION - WARMUP)//STEP_SECONDS)*CHALLENGES_PER_TICK
        self.assertEqual([p['probes'] for p in policies], [exp_probes]*3)
        self.assertEqual([p['cu_bytes'] for p in policies], [exp_probes*CU_BYTES]*3)
        for p in policies:
            self.assertTrue(0 <= p['event_recall'] <= 1)
            self.assertGreaterEqual(p['mean_censored_delay_s'], 0)

    def test_deterministic_paired_experiment(self):
        a = run([101,102])
        b = run([101,102])
        self.assertEqual(a, b)
        self.assertEqual(summarize(a), summarize(b))

if __name__ == '__main__':
    unittest.main()