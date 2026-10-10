"""Stage 11 provenance and equal-budget regression tests with real HTTP/2 h2c."""
import random
import unittest
from research.h2_wire import h2_request
from research.stage11_hedged import (
    Origin,LabSCP,CUAgent,lab_req,sha,receipt_from_origin,verify_receipt,
    signed_check,schedule,N,BUDGET,MAX_GAP)

class Fairness(unittest.TestCase):
    def test_hierarchical_and_fixed_budgets_equal(self):
        for seed in range(200):
            r=random.Random(seed)
            last={name:[-1]*N for name in ("cu_fixed","trusted_plain","cu_local","cu_hier","cu_hedged")}
            for tick in range(50):
                risk=[r.uniform(.0,5.) for _ in range(N)]
                zone=[(risk[0]+risk[1])/2]*2+[(risk[2]+risk[3])/2]*2
                for policy in last:
                    batch=schedule(policy,tick,last[policy],risk,zone)
                    self.assertEqual(len(set(batch)),BUDGET)
                    for nf in batch:
                        if policy in ("cu_local","cu_hier","cu_hedged"):
                            self.assertLessEqual(tick-last[policy][nf],MAX_GAP)
                        last[policy][nf]=tick

    def test_hedged_complete_two_tick_coverage_despite_adversarial_signal(self):
        for seed in range(200):
            rng=random.Random(seed)
            last=[-1]*N
            for tick in range(50):
                false_risk=[rng.uniform(0,5) for _ in range(N)]
                picked=schedule("cu_hedged",tick,last,false_risk,false_risk)
                self.assertEqual(len(set(picked)),BUDGET)
                if tick%2==0:
                    first=set(picked)
                else:
                    self.assertEqual(first|set(picked),set(range(N)))
                    self.assertFalse(first&set(picked))
                for i in picked:
                    self.assertLessEqual(tick-last[i],MAX_GAP)
                    last[i]=tick

class GenuineH2(unittest.IsolatedAsyncioTestCase):
    async def test_scp_corrupts_only_forwarded_copy_and_issuer_receipt_catches_it(self):
        origin=Origin(10)
        await origin.server.start()
        proxy=LabSCP(origin)
        await proxy.server.start()
        agent=CUAgent(origin)
        await agent.server.start()
        direct=f"http://127.0.0.1:{origin.server.port}"
        routed=f"http://127.0.0.1:{proxy.server.port}"
        try:
            req=lab_req(0,"test-first")
            code,first,_,_=await h2_request(routed,"/lab/scp/select","POST",req)
            self.assertEqual(code,200)
            self.assertEqual(first["request_hash"],sha(req))
            producer,wire=await receipt_from_origin(direct,"test-first")
            original=verify_receipt(origin,producer)
            self.assertEqual(original["response_hash"],sha(first))
            proxy.active_context=0
            proxy.attack="plausible_choice_change"
            req=lab_req(0,"test-second")
            code,tampered,_,_=await h2_request(routed,"/lab/scp/select","POST",req)
            self.assertEqual(code,200)
            self.assertIn(tampered["selected_slice"],("slice_A","slice_B"))
            self.assertEqual(tampered["transaction_id"],"test-second")
            self.assertEqual(tampered["request_hash"],sha(req))
            cert,wire=await signed_check(agent,"unit-1","test-second",1)
            self.assertNotEqual(cert["response_hash"],sha(tampered))
            self.assertGreater(wire,0)
            producer,_=await receipt_from_origin(direct,"test-second")
            self.assertEqual(producer["receipt"],cert)
            # A trusted direct-origin comparator is just as capable:
            self.assertNotEqual(producer["receipt"]["response_hash"],sha(tampered))
            req=lab_req(2,"unaffected-third")
            code,good,_,_=await h2_request(routed,"/lab/scp/select","POST",req)
            self.assertEqual(code,200)
            source,_=await receipt_from_origin(direct,"unaffected-third")
            self.assertEqual(source["receipt"]["response_hash"],sha(good))
            self.assertEqual(proxy.fault_ids,{"test-second"})
        finally:
            await agent.server.close()
            await proxy.server.close()
            await origin.server.close()

    async def test_stale_choice_mutates_dynamic_reply_but_keeps_plausible_format(self):
        origin=Origin(21)
        await origin.server.start()
        proxy=LabSCP(origin)
        await proxy.server.start()
        url=f"http://127.0.0.1:{proxy.server.port}"
        try:
            code,first,*_=await h2_request(url,"/lab/scp/select","POST",lab_req(3,"t1"))
            self.assertEqual(code,200)
            proxy.active_context=3
            proxy.attack="stale_choice_field"
            code,second,*_=await h2_request(url,"/lab/scp/select","POST",lab_req(3,"t2"))
            self.assertEqual(code,200)
            self.assertEqual(first["selected_slice"],second["selected_slice"])
            self.assertNotEqual(first["transaction_id"],second["transaction_id"])
            source,_=await receipt_from_origin(
                f"http://127.0.0.1:{origin.server.port}","t2")
            self.assertNotEqual(source["receipt"]["response_hash"],sha(second))
        finally:
            await proxy.server.close()
            await origin.server.close()
