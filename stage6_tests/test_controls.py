import unittest
import random
from research.stage6_native import (LiveFeed, zone_features, policy_batch,
    POLICIES, SLOTS, BOUND, NFS)
from research.bounded_scheduler import bounded_choose

class Stage6PreRegisteredControls(unittest.TestCase):
    def test_nrf_mask_is_not_an_actual_core_outage(self):
        live=LiveFeed("http://unused",mask=False)
        mask=LiveFeed("http://unused",mask=True)
        live.latest={"AUSF":1,"NSSF":2}
        mask.latest={"AUSF":1,"NSSF":2}
        self.assertEqual(live.observed()["AUSF"],1)
        self.assertEqual(mask.observed()["AUSF"],2)
        self.assertEqual(zone_features(mask.observed()),[0.]*len(NFS))
        self.assertEqual(zone_features(live.observed()),[4.,0.,4.,0.])

    def test_masked_zone_equals_local_for_identical_internal_state(self):
        last=[0,1,0,1]
        local=[.3,.2,.4,.1]
        for tick in range(2,10):
            choose1=policy_batch("bounded_local",tick,last,local,{"AUSF":2,"NSSF":2})
            choose2=policy_batch("bounded_zone",tick,last,local,{"AUSF":2,"NSSF":2})
            self.assertEqual(choose1,choose2)
            for n in choose1: last[n]=tick
        self.assertEqual(len(POLICIES),3)

    def test_hard_check_gap_for_200_random_risk_streams(self):
        for seed in range(200):
            rng=random.Random(seed)
            last=[-1]*len(NFS)
            for tick in range(45):
                local=[rng.random()*8 for _ in NFS]
                zone={"AUSF":rng.choice([1,2]),"NSSF":rng.choice([1,2])}
                selected=policy_batch("bounded_zone",tick,last,local,zone)
                self.assertEqual(len(set(selected)),SLOTS)
                for nf in selected:
                    self.assertLessEqual(tick-last[nf],BOUND)
                    last[nf]=tick

    def test_actual_nrf_only_not_same_resolution_as_instance_cu(self):
        self.assertEqual(len([n for n in NFS if n.kind=="AUSF"]),2)
        self.assertEqual(len([n for n in NFS if n.kind=="NSSF"]),2)
