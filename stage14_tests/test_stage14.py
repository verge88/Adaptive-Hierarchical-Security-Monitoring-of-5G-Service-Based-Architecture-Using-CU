"""Stage 14: native SCP transit protocol checks before starting Docker."""
import json
import unittest

from research.h2_wire import H2Server
from research.stage14_native_scp import (
    H2Observed,NRF_PATH,NSSF_PATH,discovered_nssf_ids,
    assert_nssf_proxy_native,h2_exchange,COMPOSE,NATIVE_PROBES
)


class NativeSCPProtocolTests(unittest.TestCase):
    def test_routing_scope_uses_real_3gpp_target_header(self):
        self.assertIn("live/stage14-scp-compose.yaml",COMPOSE)
        self.assertEqual(NATIVE_PROBES,12)
        self.assertTrue(NRF_PATH.startswith("/nnrf-disc/v1/nf-instances"))
        self.assertTrue(NSSF_PATH.startswith("/nnssf-nsselection/v1/"))
        self.assertTrue(all(x.startswith("-f") or isinstance(x,str) for x in COMPOSE))

    def test_require_real_nrf_profiles_not_generic_status(self):
        doc={"nfInstances":[
            {"nfType":"NSSF","nfInstanceId":"native-nssf2"},
            {"nfType":"NSSF","nfInstanceId":"native-nssf1"},
            {"nfType":"AUSF","nfInstanceId":"native-ausf1"}]}
        msg=H2Observed(200,json.dumps(doc).encode(),{},144,.1)
        self.assertEqual(discovered_nssf_ids(msg),["native-nssf1","native-nssf2"])
        with self.assertRaises(AssertionError):
            discovered_nssf_ids(H2Observed(200,b'{"nfInstances":[]}',{},0,.1))
        with self.assertRaises(AssertionError):
            discovered_nssf_ids(H2Observed(404,msg.body,{},0,.1))

    def test_dont_call_nssf_error_a_valid_slice_decision(self):
        valid=H2Observed(400,b'{"cause":"MISSING_PARAMETER"}',{},200,.03)
        assert_nssf_proxy_native(valid,valid)
        with self.assertRaises(AssertionError):
            assert_nssf_proxy_native(valid,H2Observed(200,b"{}",{},20,.01))
        with self.assertRaises(AssertionError):
            assert_nssf_proxy_native(H2Observed(200,b"{}",{},20,.01),valid)


class H2TargetHeaderOnWire(unittest.IsolatedAsyncioTestCase):
    async def test_real_http2_target_apiroot_is_present(self):
        async def handle(headers,body):
            return 200,dict(target=headers.get("3gpp-sbi-target-apiroot"),
                            path=headers.get(":path"))
        server=H2Server(handle)
        await server.start()
        try:
            response=await h2_exchange(
                f"http://127.0.0.1:{server.port}",
                "/nnrf-disc/v1/nf-instances",
                target="http://nrf:80")
            self.assertEqual(response.status,200)
            doc=json.loads(response.body)
            self.assertEqual(doc["target"],"http://nrf:80")
            self.assertEqual(doc["path"],"/nnrf-disc/v1/nf-instances")
            self.assertGreater(response.h2_bytes,0)
        finally:
            await server.close()
