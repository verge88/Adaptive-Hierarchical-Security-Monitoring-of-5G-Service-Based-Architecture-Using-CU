"""Stage 12 pre-registration, strict factorial and small-sample statistics tests."""
import json
import random
import unittest
from collections import Counter

from research.stage11_hedged import ATTACKS,ALIGNMENTS,BUDGETED,TICKS,BUDGET
from research.stage11_report import sign_p
from research.stage12_scale import (
    RUNNERS,REPEATS_PER_CELL,EPISODES_PER_RUNNER,EXPECTED_EPISODES,
    SEED_START,factorial
)


class PreRegisteredScaling(unittest.TestCase):
    def test_locked_sample_size_not_a_promised_fiction(self):
        self.assertEqual(RUNNERS,12)
        self.assertEqual(REPEATS_PER_CELL,6)
        self.assertEqual(EPISODES_PER_RUNNER,48)
        self.assertEqual(EXPECTED_EPISODES,576)
        self.assertEqual(TICKS*BUDGET,46)

    def test_each_seed_balanced_and_reproducible(self):
        for seed in range(SEED_START,SEED_START+RUNNERS):
            cases=factorial(seed)
            self.assertEqual(cases,factorial(seed))
            self.assertEqual(len(cases),EPISODES_PER_RUNNER)
            hist=Counter((x["attack"],x["regime"]) for x in cases)
            for attack in ATTACKS:
                for risk in ALIGNMENTS:
                    self.assertEqual(hist[(attack,risk)],REPEATS_PER_CELL)
            self.assertEqual([x["case"] for x in cases],list(range(48)))
            self.assertEqual(len({(x["attack"],x["regime"],x["repetition"])
                                  for x in cases}),48)
            self.assertTrue(all(0<=x["target_context"]<4
                                for x in cases))

    def test_seeds_all_distinct_strata_orders(self):
        scenarios=[factorial(seed) for seed in range(SEED_START,SEED_START+RUNNERS)]
        orders=[tuple((s["attack"],s["regime"],s["repetition"]) for s in x)
                for x in scenarios]
        self.assertEqual(len(set(orders)),RUNNERS)

    def test_no_undefined_runner_seeds(self):
        with self.assertRaises(ValueError):
            factorial(SEED_START-1)
        with self.assertRaises(ValueError):
            factorial(SEED_START+RUNNERS)

    def test_exact_sign_test_uses_runner_count(self):
        self.assertAlmostEqual(sign_p([1.]*12),2/2**12)
        self.assertAlmostEqual(sign_p([1.]*6+[-1.]*6),1.)
        self.assertEqual(sign_p([0.]*12),1.)

    def test_comparators_retained(self):
        self.assertEqual(len(BUDGETED),6)
        self.assertIn("trusted_plain",BUDGETED)
        self.assertIn("cu_hedged",BUDGETED)
        self.assertIn("ordinary_active",BUDGETED)
