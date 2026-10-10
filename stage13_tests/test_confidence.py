"""Stage13 offline prior-test separation and authenticated-feedback controls."""
import unittest
from collections import Counter
import random

from research.stage13_confidence import (
    TrustedRiskCalibrator,schedule,N,MAX_GAP,BUDGET,
    Origin,LabSCP,CUAgent,lab_req,receipt_from_origin,signed_check,sha,verify_receipt
)
from research.stage13_trial import (
    RUNNERS,SEED_START,CAL_REPS,EVAL_REPS,CAL_EVENTS,EVAL_EVENTS,
    TRAINING_TOTAL,TEST_TOTAL,create_cases
)
from research.h2_wire import h2_request


class BlindedConfidence(unittest.TestCase):
    def test_pre_registered_pools_are_disjoint_and_balanced(self):
        self.assertEqual((RUNNERS,CAL_REPS,EVAL_REPS,CAL_EVENTS,EVAL_EVENTS),
                         (12,2,3,16,24))
        self.assertEqual((TRAINING_TOTAL,TEST_TOTAL),(192,288))
        self.assertEqual(BUDGET,2)
        for seed in range(SEED_START,SEED_START+RUNNERS):
            a=create_cases(seed,"calibration")
            b=create_cases(seed,"heldout")
            self.assertEqual(len(a),16)
            self.assertEqual(len(b),24)
            self.assertFalse({x["episode_id"] for x in a}&
                             {x["episode_id"] for x in b})
            self.assertEqual(Counter((x["attack"],x["regime"]) for x in a),
                             Counter({(a,r):2 for a in
                                      ("plausible_choice_change","stale_choice_field")
                                      for r in ("aligned","misleading","neutral","switch")}))
            self.assertEqual(set(Counter((x["attack"],x["regime"]) for x in b).values()),
                             {3})
        with self.assertRaises(ValueError):
            create_cases(SEED_START-1,"calibration")
        with self.assertRaises(ValueError):
            create_cases(SEED_START+RUNNERS,"heldout")

    def test_wilson_and_safe_default_are_monotonic_and_label_blind(self):
        c=TrustedRiskCalibrator()
        self.assertFalse(c.choose_risk())
        self.assertEqual(c.snapshot()["authenticated_calibration_episodes"],0)
        for _ in range(16):
            c.observe_verified_mismatch(0,1)
        self.assertFalse(c.choose_risk())
        first=c.lower_bound()
        self.assertLess(first,.56)
        for _ in range(60):
            c.observe_verified_mismatch(0,0)
        self.assertGreater(c.lower_bound(),first)
        self.assertTrue(c.choose_risk())

    def test_guarded_schedule_equals_fixed_on_uncertain_prior(self):
        for tick in range(45):
            local=[99.,0.,0.,0.]
            zone=[100.,100.,0.,0.]
            fixed=schedule("cu_fixed",tick,[-1]*N,local,zone)
            guarded=schedule("cu_guarded",tick,[-1]*N,local,zone,
                             trust_risk=False)
            self.assertEqual(fixed,guarded)
            self.assertEqual(len(fixed),BUDGET)

    def test_guarded_uses_bounded_hier_when_authorized(self):
        for seed in range(30):
            rng=random.Random(seed)
            last=[-1]*N
            for tick in range(40):
                local=[rng.uniform(.0,5.) for _ in range(N)]
                zone=[(local[0]+local[1])/2]*2+[(local[2]+local[3])/2]*2
                chosen=schedule("cu_guarded",tick,last,local,zone,
                                trust_risk=True)
                self.assertEqual(len(set(chosen)),BUDGET)
                for ctx in chosen:
                    self.assertLessEqual(tick-last[ctx],MAX_GAP)
                    last[ctx]=tick


class SignedEvidence(unittest.IsolatedAsyncioTestCase):
    async def test_one_verified_producer_discrepancy_is_real(self):
        origin=Origin(912)
        await origin.server.start()
        proxy=LabSCP(origin)
        await proxy.server.start()
        agent=CUAgent(origin)
        await agent.server.start()
        try:
            proxy.active_context=2
            proxy.attack="plausible_choice_change"
            url=f"http://127.0.0.1:{proxy.server.port}"
            req=lab_req(2,"training-proof-1")
            status,response,_,_=await h2_request(
                url,"/lab/scp/select","POST",req,timeout=3)
            self.assertEqual(status,200)
            original,wire=await signed_check(agent,"test-guard",req["transaction_id"],1)
            self.assertNotEqual(sha(response),original["response_hash"])
            direct,_=await receipt_from_origin(
                f"http://127.0.0.1:{origin.server.port}",req["transaction_id"])
            self.assertEqual(verify_receipt(origin,direct),original)
            self.assertGreater(wire,0)
        finally:
            await agent.server.close()
            await proxy.server.close()
            await origin.server.close()
