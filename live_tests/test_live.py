import asyncio
import json
import unittest
from research.h2_wire import H2Server, h2_request
from research.live_experiment import NFSidecar, SCPObserver, mac, policy_trial, summarize


class H2IntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_h2_wire_is_real_frame_exchange(self):
        server = H2Server(lambda h, b: (200, {'echo': json.loads(b)['hello']}))
        await server.start()
        try:
            status, body, wire, headers = await h2_request(
                f'http://127.0.0.1:{server.port}', '/test', 'POST', {'hello': 42})
            self.assertEqual(status, 200)
            self.assertEqual(body['echo'], 42)
            self.assertGreater(wire, len(json.dumps(body)))
            self.assertEqual(headers['content-type'], 'application/json')
        finally:
            await server.close()

    async def test_authenticated_cu_rejects_tamper_and_replay(self):
        nf = NFSidecar(0, 777)
        await nf.server.start()
        url = f'http://127.0.0.1:{nf.server.port}'
        try:
            fields = {'nf': 0, 'cycle': 1, 'created': 5, 'nonce': 'abc'*10+'01'}
            signed = {**fields, 'mac': mac(nf.key, fields)}
            status, response, *_ = await h2_request(url, '/cu', 'POST', signed)
            self.assertEqual(status, 200)
            self.assertEqual(response['mac'], mac(nf.key, {k: response[k] for k in
                ('nf','cycle','created','nonce','reported')}))
            status, *_ = await h2_request(url, '/cu', 'POST', signed)
            self.assertEqual(status, 409)
            signed['nonce'] = 'changed'
            status, *_ = await h2_request(url, '/cu', 'POST', signed)
            self.assertEqual(status, 401)
        finally:
            await nf.server.close()

    async def test_independent_http2_proxy_catches_validly_signed_forgery(self):
        peers = [NFSidecar(i, 55) for i in range(6)]
        observer = SCPObserver(peers)
        for p in peers:
            await p.server.start()
        await observer.server.start()
        try:
            proxy = f'http://127.0.0.1:{observer.server.port}'
            nfurl = f'http://127.0.0.1:{peers[0].server.port}'
            for _ in range(24):
                status, *_ = await h2_request(proxy, '/forward/0', 'POST', {'test': 1})
                self.assertEqual(status, 200)
            peers[0].compromised = True
            fields = {'nf': 0, 'cycle': 10, 'created': 5, 'nonce': 'a'*32}
            status, report, *_ = await h2_request(nfurl, '/cu', 'POST', {**fields, 'mac': mac(peers[0].key, fields)})
            self.assertEqual(status, 200)
            status, stat, *_ = await h2_request(proxy, '/stats')
            self.assertEqual(status, 200)
            self.assertLess(report['reported'], stat['counts'][0])
            self.assertEqual(report['mac'], mac(peers[0].key, {k: report[k] for k in
                ('nf','cycle','created','nonce','reported')}))
        finally:
            await observer.server.close()
            for p in peers:
                await p.server.close()

    async def test_equal_probe_budget_by_policy(self):
        first = await policy_trial(701, 'fixed')
        second = await policy_trial(701, 'zone_adaptive')
        self.assertEqual(first['cu_probes'], second['cu_probes'])
        self.assertEqual(first['cu_probes'], 2*(96-16))
        self.assertEqual(first['false_alarms'], 0)
        self.assertEqual(second['false_alarms'], 0)
        self.assertIn('event_recall', second)


if __name__ == '__main__':
    unittest.main()
