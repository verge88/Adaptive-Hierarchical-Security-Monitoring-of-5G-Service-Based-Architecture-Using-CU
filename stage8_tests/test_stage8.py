"""Stage 8 native NRF and dynamic semantic-control tests."""
import unittest
from research.h2_wire import H2Server,h2_request
import research.stage8_dynamic_nrf as stage8

A1={"nfType":"AUSF","nfStatus":"REGISTERED","nfInstanceId":"00000000-0000-0000-0000-000000000001"}
A2={"nfType":"AUSF","nfStatus":"REGISTERED","nfInstanceId":"00000000-0000-0000-0000-000000000002"}
N1={"nfType":"NSSF","nfStatus":"REGISTERED","nfInstanceId":"00000000-0000-0000-0000-000000000003"}
N2={"nfType":"NSSF","nfStatus":"REGISTERED","nfInstanceId":"00000000-0000-0000-0000-000000000004"}

class SemanticProperties(unittest.TestCase):
    def test_order_is_benign_but_raw_bytes_are_dynamic(self):
        original={"nfInstances":[A1,A2],"validityPeriod":3600}
        shuffled={"validityPeriod":3600,"nfInstances":[A2,A1]}
        self.assertNotEqual(stage8.encode(original),stage8.encode(shuffled))
        self.assertEqual(stage8.canonical(original),stage8.canonical(shuffled))
    def test_realistic_nrf_profile_edits_cannot_be_normalized_away(self):
        native={"nfInstances":[A1,A2]}
        for mode in stage8.ATTACKS:
            tampered=stage8.mutate_body(native,A1["nfInstanceId"],mode)
            self.assertNotEqual(stage8.canonical(native),stage8.canonical(tampered))
            self.assertEqual(native["nfInstances"][0]["nfInstanceId"],A1["nfInstanceId"])
    def test_equal_cu_count_and_gap_for_risk(self):
        for policy in ("cu_fixed","cu_local","cu_zone"):
            last=[-1]*4
            for tick in range(60):
                batch=stage8.select(policy,tick,last,[.5,2,0,.9],[.1,0,.4,1])
                self.assertEqual(len(set(batch)),2)
                for nf in batch:
                    if policy!="cu_fixed":
                        self.assertLessEqual(tick-last[nf],stage8.GAP_LIMIT)
                    last[nf]=tick

class H2ResearchChecks(unittest.IsolatedAsyncioTestCase):
    async def test_actual_h2_relay_and_independent_signature(self):
        async def handler(headers,raw):
            kind="AUSF" if "AUSF" in headers.get(":path","") else "NSSF"
            return 200,{"nfInstances":[A1,A2] if kind=="AUSF" else [N1,N2]}
        nrf=H2Server(handler)
        await nrf.start()
        url=f"http://127.0.0.1:{nrf.port}"
        gateway=stage8.DiscoveryGateway(url,3)
        agent=stage8.ExternalNrfAttestor(url)
        await gateway.server.start()
        await agent.server.start()
        try:
            payload,_=await stage8.native_discovery(url,"AUSF")
            live=payload
            self.assertEqual(len(live["nfInstances"]),2)
            status,base,*_=await h2_request(
                f"http://127.0.0.1:{gateway.server.port}","/gateway/discover/AUSF")
            self.assertEqual(status,200)
            signed,_=await stage8.signed_cu(agent,"AUSF","test1",1)
            self.assertEqual(stage8.canonical(base),stage8.canonical(signed))
            gateway.target_kind="AUSF"
            gateway.target_id=A1["nfInstanceId"]
            gateway.kind="profile_id_substitute"
            status,altered,*_=await h2_request(
                f"http://127.0.0.1:{gateway.server.port}","/gateway/discover/AUSF")
            self.assertEqual(status,200)
            self.assertNotEqual(stage8.canonical(altered),stage8.canonical(signed))
        finally:
            await agent.server.close()
            await gateway.server.close()
            await nrf.close()
