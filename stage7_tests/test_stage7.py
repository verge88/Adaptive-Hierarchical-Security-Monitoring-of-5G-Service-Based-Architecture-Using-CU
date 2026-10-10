"""Strict unit and transport checks for stage 7, no Docker required."""
import random
import secrets
import time
import unittest
from unittest.mock import patch

from research.h2_wire import H2Server,h2_request
import research.stage7_integrity as stage7
from research.stage5_native import NF


class Stage7MethodologyTests(unittest.TestCase):
    def test_same_length_crafted_gateway_change_hides_from_metadata(self):
        base={"nfInstance":"ausf","upstreamHTTPStatus":404,"reachable":True}
        manipulated=stage7.corrupt(base,"same_length_instance")
        self.assertNotEqual(manipulated,base)
        self.assertEqual(len(stage7.encode(base)),len(stage7.encode(manipulated)))
        self.assertEqual(manipulated["upstreamHTTPStatus"],base["upstreamHTTPStatus"])
        self.assertEqual(stage7.corrupt(base,"status_rewrite")["upstreamHTTPStatus"],201)

    def test_online_nrf_instance_set_detection_not_just_counts(self):
        old={"AUSF":{"real-a","real-b"},"NSSF":{"nssf-a","nssf-b"}}
        replaced={"AUSF":{"real-a","ATTACKER-X"},"NSSF":{"nssf-a","nssf-b"}}
        self.assertTrue(stage7.check_ids(old,replaced))
        self.assertFalse(stage7.check_ids(old,dict(old)))

    def test_scheduler_exact_budget_and_deadline_under_risk(self):
        for seed in range(120):
            rng=random.Random(seed)
            ls={p:[-1]*4 for p in stage7.ACTIVE}
            for tick in range(25):
                local=[rng.random()*3 for _ in range(4)]
                spatial=[rng.random()*3 for _ in range(4)]
                for p in stage7.ACTIVE:
                    selected=stage7.scheduler(p,tick,ls[p],local,spatial)
                    self.assertEqual(len(selected),stage7.BUDGET)
                    self.assertEqual(len(set(selected)),stage7.BUDGET)
                    for nf in selected:
                        last=ls[p][nf]
                        if p!="kie_fixed":
                            self.assertLessEqual(tick-last,stage7.BOUND)
                        ls[p][nf]=tick


class Stage7RealH2ControlTests(unittest.IsolatedAsyncioTestCase):
    async def test_proxy_transformation_and_independent_authenticated_kie(self):
        native=H2Server(lambda *_:(404,{"error":"expected native NF safe GET"}))
        await native.start()
        original=stage7.NFS
        fake=(NF("ausf","AUSF",f"http://127.0.0.1:{native.port}","/native-get"),)
        with patch.object(stage7,"NFS",fake):
            gateway=stage7.LabSBIProxy()
            agent=stage7.IntegrityAgent()
            await gateway.server.start()
            await agent.server.start()
            try:
                url=f"http://127.0.0.1:{gateway.server.port}"
                code,payload,*_=await h2_request(url,"/consumer-sbi/0")
                self.assertEqual(code,200)
                self.assertEqual(payload["nfInstance"],"ausf")
                self.assertEqual(payload["upstreamHTTPStatus"],404)
                certified,_=await stage7.kie(agent,0,"unit-test",1)
                self.assertEqual(payload,certified)
                gateway.active_nf=0
                gateway.attack_kind="same_length_instance"
                code,altered,*_=await h2_request(url,"/consumer-sbi/0")
                self.assertEqual(code,200)
                self.assertNotEqual(payload,altered)
                self.assertEqual(len(stage7.encode(payload)),len(stage7.encode(altered)))
                certified,_=await stage7.kie(agent,0,"unit-test",2)
                self.assertEqual(certified,payload)
                self.assertNotEqual(certified,altered)
            finally:
                await agent.server.close()
                await gateway.server.close()
        await native.close()

    async def test_nrf_real_id_set_parsing(self):
        async def respondent(headers,body):
            path=headers[":path"]
            kind="AUSF" if "AUSF" in path else "NSSF"
            return 200,{"nfInstances":[
                {"nfType":kind,"nfInstanceId":kind+"-1"},
                {"nfType":kind,"nfInstanceId":kind+"-2"}]}
        nrf=H2Server(respondent)
        await nrf.start()
        try:
            got=await stage7.nrf_instance_sets(f"http://127.0.0.1:{nrf.port}")
            self.assertEqual(got["AUSF"],{"AUSF-1","AUSF-2"})
            self.assertEqual(got["NSSF"],{"NSSF-1","NSSF-2"})
        finally:
            await nrf.close()
