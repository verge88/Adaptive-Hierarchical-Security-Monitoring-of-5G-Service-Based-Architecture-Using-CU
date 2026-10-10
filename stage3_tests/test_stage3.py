import random
import unittest
from research.h2_wire import h2_request
from research.stage3_experiment import (ScenarioNF, ColludingObserver,
    choose, challenge, scenario, BUDGET, TRAIN, N)

class SchedulerChecks(unittest.TestCase):
    def test_fixed_budget_and_unique_target(self):
        for name in ("fixed", "random", "local_adaptive", "zone_adaptive"):
            xs = choose(name, TRAIN+2, [0., 0., 4., 0., 1., 0.],
                        [0., 0., 3., 0., 0., 0.], [-100]*N, random.Random(7))
            self.assertEqual(len(xs), BUDGET)
            self.assertEqual(len(set(xs)), BUDGET)
    def test_blind_attack_schedule(self):
        for seed in range(801, 825):
            xs = scenario(seed)
            self.assertEqual(len({a["nf"] for a in xs}), 4)
            self.assertEqual({a["kind"] for a in xs},
                             {"slow", "stealth", "mimic", "collusion"})

class NegativeControls(unittest.IsolatedAsyncioTestCase):
    async def test_signed_mimic_report_is_not_truth(self):
        nf = ScenarioNF(0, 801)
        await nf.server.start()
        try:
            nf.count = 30
            nf.compromised = True
            nf.strategy = "mimic"
            data = challenge(0, 1, 5, random.Random(11), nf.key)
            code, p, *_ = await h2_request(
                f"http://127.0.0.1:{nf.server.port}", "/cu", "POST", data)
            self.assertEqual(code, 200)
            self.assertEqual(p["reported"], 26)
        finally:
            await nf.server.close()

    async def test_collusion_conceals_forgery(self):
        peers = [ScenarioNF(i, 802) for i in range(N)]
        proxy = ColludingObserver(peers)
        for x in peers:
            await x.server.start()
        await proxy.server.start()
        try:
            peers[0].count = 30
            peers[0].compromised = True
            peers[0].strategy = "collusion"
            proxy.counts[0] = 30
            code, p, *_ = await h2_request(
                f"http://127.0.0.1:{proxy.server.port}", "/stats")
            self.assertEqual(code, 200)
            self.assertEqual(p["counts"][0], 24)
            msg = challenge(0, 1, 6, random.Random(12), peers[0].key)
            code, cu, *_ = await h2_request(
                f"http://127.0.0.1:{peers[0].server.port}", "/cu", "POST", msg)
            self.assertEqual(code, 200)
            self.assertEqual(cu["reported"], p["counts"][0])
        finally:
            await proxy.server.close()
            for nf in peers:
                await nf.server.close()
