import random
import secrets
import unittest
import time
from research.h2_wire import H2Server, h2_request
from research.stage5_native import NF,NativeAttestor,native_h2_status,mac,select,POLICIES,MAX_GAP_TICKS

class NativeH2CUChecks(unittest.IsolatedAsyncioTestCase):
    async def test_h2_native_4xx_is_alive_and_attested(self):
        native=H2Server(lambda *_:(405,{"real_service":True}))
        await native.start()
        agent=NativeAttestor([NF("stub","AUSF",f"http://127.0.0.1:{native.port}","/native")])
        await agent.server.start()
        try:
            alive=await native_h2_status(agent.nfs[0])
            self.assertTrue(alive["reachable"])
            self.assertEqual(alive["http_status"],405)
            original=dict(policy="fixed",nf=0,cycle=1,issued_ns=time.monotonic_ns(),nonce=secrets.token_hex(16))
            signed={**original,"mac":mac(agent.key,original)}
            url=f"http://127.0.0.1:{agent.server.port}"
            endpoint="/research-cu/v1/challenge"
            status,report,*_=await h2_request(url,endpoint,"POST",signed)
            self.assertEqual(status,200)
            self.assertTrue(report["reachable"])
            self.assertEqual(report["http_status"],405)
            unsigned={k:v for k,v in report.items() if k!="mac"}
            self.assertEqual(report["mac"],mac(agent.key,unsigned))
            status,*_=await h2_request(url,endpoint,"POST",signed)
            self.assertEqual(status,409)
            signed["nonce"]="x"*32
            status,*_=await h2_request(url,endpoint,"POST",signed)
            self.assertEqual(status,401)
        finally:
            await agent.server.close()
            await native.close()

    async def test_genuine_transport_outage(self):
        server=H2Server(lambda *_:(404,{}))
        await server.start()
        target=NF("f","AUSF",f"http://127.0.0.1:{server.port}","/x")
        self.assertTrue((await native_h2_status(target))["reachable"])
        await server.close()
        self.assertFalse((await native_h2_status(target,timeout=.4))["reachable"])

class SchedulerChecks(unittest.TestCase):
    def test_1000_random_risk_runs(self):
        for seed in range(1000):
            rng=random.Random(seed)
            last=[-1]*4
            for tick in range(60):
                local=[rng.random()*10 for _ in range(4)]
                zone=[rng.random()*10 for _ in range(4)]
                chosen=select("bounded_zone",tick,last,local,zone,rng)
                self.assertEqual(len(set(chosen)),2)
                for nf in chosen:
                    self.assertLessEqual(tick-last[nf],MAX_GAP_TICKS)
                    last[nf]=tick
            self.assertLessEqual(max(59-v for v in last),MAX_GAP_TICKS)
    def test_equal_probe_budget(self):
        for policy in POLICIES:
            self.assertEqual(len(set(select(policy,0,[-1]*4,[0]*4,[0]*4,random.Random(1)))),2)
