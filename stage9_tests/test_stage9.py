"""Stage 9 conditional NSSF-like lab policy tests."""
import random
import unittest
from research.h2_wire import h2_request
from research.stage9_conditional import (
    LabSliceService,SignedResearchAttestor,active_request,
    expected_decision,query,select,ACTIVE,BUDGET,MAX_GAP,MODES,ALIGNMENTS,N)

class OracleAndPolicy(unittest.TestCase):
    def test_common_and_rare_policy_are_consistent(self):
        self.assertEqual(expected_decision(query(2,False)),"ALLOW")
        self.assertEqual(expected_decision(query(2,True)),"ALLOW")
        self.assertEqual(expected_decision(dict(nf=2,sst=3,sd="bad")),"DENY")
        self.assertEqual(MODES,("zero_rare","sparse_rare"))
        self.assertEqual(ALIGNMENTS,("aligned","unaligned"))
    def test_equal_budget_and_deadline_for_many_risks(self):
        for seed in range(120):
            rng=random.Random(seed)
            last={p:[-1]*N for p in ACTIVE}
            for tick in range(40):
                local=[rng.uniform(0,4.9) for _ in range(N)]
                zone=[(local[0]+local[1])/2]*2+[(local[2]+local[3])/2]*2
                for p in ACTIVE:
                    xs=select(p,tick,last[p],local,zone)
                    self.assertEqual(len(xs),BUDGET)
                    self.assertEqual(len(set(xs)),BUDGET)
                    for i in xs:
                        if p in ("cu_local","cu_hier"):
                            self.assertLessEqual(tick-last[p][i],MAX_GAP)
                        last[p][i]=tick

class ActualH2Conditional(unittest.IsolatedAsyncioTestCase):
    async def test_rare_forgery_preserves_common_and_plain_matches_cu(self):
        lab=LabSliceService(15,1)
        await lab.server.start()
        url=f"http://127.0.0.1:{lab.server.port}"
        agent=SignedResearchAttestor(url)
        await agent.server.start()
        try:
            code,baseline,*_=await h2_request(
                url,"/research/nnssf/select","POST",query(2,True))
            self.assertEqual(code,200)
            self.assertEqual(baseline["decision"],"ALLOW")
            lab.fault_target=2
            lab.fault_enabled=True
            code,ordinary,*_=await h2_request(
                url,"/research/nnssf/select","POST",query(2,False))
            self.assertEqual(code,200)
            self.assertEqual(ordinary["decision"],"ALLOW")
            code,fault,*_=await h2_request(
                url,"/research/nnssf/select","POST",query(2,True))
            self.assertEqual(code,200)
            self.assertEqual(fault["decision"],"DENY")
            plain,_=await active_request(url,agent,"plain_fixed",2,1)
            signed,_=await active_request(url,agent,"cu_fixed",2,1)
            self.assertEqual(plain["decision"],"DENY")
            self.assertEqual(signed["decision"],"DENY")
            self.assertNotEqual(plain["route_token"],signed["route_token"])
        finally:
            await agent.server.close()
            await lab.server.close()
    async def test_external_agent_hmac_is_not_native_nf_signature(self):
        lab=LabSliceService(20,0)
        await lab.server.start()
        url=f"http://127.0.0.1:{lab.server.port}"
        agent=SignedResearchAttestor(url)
        await agent.server.start()
        try:
            result,wire=await active_request(url,agent,"cu_hier",1,5)
            self.assertEqual(result["decision"],"ALLOW")
            self.assertGreater(wire,0)
        finally:
            await agent.server.close()
            await lab.server.close()
