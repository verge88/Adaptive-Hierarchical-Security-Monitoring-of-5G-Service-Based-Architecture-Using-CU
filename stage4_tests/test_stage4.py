"""Property tests for guaranteed bounded checks; no lab attack labels used."""
import random
import unittest
from research.bounded_scheduler import bounded_choose
from research.stage4_experiment import choose, POLICIES, TRAIN, N, BUDGET

class HardDeadlineSchedulerProperties(unittest.TestCase):
    def test_infeasible_request_rejected(self):
        with self.assertRaises(ValueError):
            bounded_choose(12,[0]*6,[0]*6,[-100]*6,
                           warmup_end=12,budget=1,max_gap=4)

    def test_bound_under_1000_independent_risk_traces(self):
        for seed in range(1000):
            r=random.Random(seed)
            last=[-100]*6
            for tick in range(TRAIN,TRAIN+96):
                local=[14*r.random() for _ in range(6)]
                spatial=[12*r.random() for _ in range(6)]
                selected=bounded_choose(tick,local,spatial,last,
                                        warmup_end=TRAIN,budget=2,max_gap=4)
                self.assertEqual(len(selected),2)
                self.assertEqual(len(set(selected)),2)
                for nf in selected:
                    former=last[nf] if last[nf]>=TRAIN else TRAIN-1
                    self.assertLessEqual(tick-former,4)
                    last[nf]=tick
            self.assertLessEqual(max(TRAIN+95-v for v in last),4)

    def test_equal_budget_all_policies(self):
        for policy in POLICIES:
            got=choose(policy,TRAIN+1,[.2,.4,.3,2,.1,0],
                       [0,1,1,0,0,0],[-100]*N,random.Random(31))
            self.assertEqual(len(got),BUDGET)
            self.assertEqual(len(set(got)),BUDGET)

    def test_bound_changes_risk_order_when_deadlines_require(self):
        last=[20,20,23,23,23,23]
        for p in ("bounded_zone","bounded_local"):
            got=choose(p,24,[.1,.1,12,12,12,12],[0,0,12,12,12,12],
                       last,random.Random(1))
            self.assertEqual(set(got),{0,1})
