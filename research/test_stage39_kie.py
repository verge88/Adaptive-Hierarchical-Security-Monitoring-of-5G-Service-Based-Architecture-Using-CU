import copy
import hashlib
import tempfile
import time
import unittest
from pathlib import Path

from stage39_kie import (
    FullProfilePolicy,
    FreshnessAnchor,
    KIERequest,
    KIEResponse,
    PersistentRegistry,
    SecurityError,
    StreamRelationalVerifier,
    default_profiles,
    lifecycle_case,
    mutate,
    nearest_rank,
    sha256_json,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "stage39" / "full_profile_policy.json"


class Stage39Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = FullProfilePolicy.load(POLICY)

    def setUp(self):
        self.profiles, self.witnesses = default_profiles(self.policy)
        self.verifier = StreamRelationalVerifier(self.policy)

    def test_all_nine_nf_types_are_in_independent_policy(self):
        expected = {"NSSF","AUSF","BSF","UDM","AMF","SMF","PCF","NRF","SCP"}
        self.assertEqual(expected,{v["nf_type"] for v in self.policy.slots.values()})

    def test_stage38_two_instance_types_are_preserved(self):
        for typ in ("NSSF","AUSF","BSF","UDM"):
            with self.subTest(nf_type=typ):
                self.assertEqual(2,sum(1 for row in self.policy.slots.values() if row["nf_type"]==typ))
        self.assertEqual(13,len(self.policy.slots))

    def test_clean_profiles_are_accepted(self):
        self.assertEqual([],self.verifier.verify(self.profiles,self.witnesses))

    def test_article_mutations_and_duplicate_boundary_are_detected_on_every_slot(self):
        for slot in sorted(self.policy.slots):
            for kind in ("identity","endpoint","service","fqdn","type","compound","duplicate"):
                with self.subTest(slot=slot,kind=kind):
                    self.assertTrue(
                        StreamRelationalVerifier(self.policy).verify(
                            mutate(self.profiles,slot,kind),
                            self.witnesses,
                        )
                    )

    def test_exact_duplicate_is_detected_even_during_transition(self):
        for slot in sorted(self.policy.slots):
            with self.subTest(slot=slot):
                verifier=StreamRelationalVerifier(self.policy)
                verifier.begin_transition("restart",slot)
                alerts=verifier.verify(mutate(self.profiles,slot,"duplicate"),self.witnesses)
                self.assertIn("duplicate_nfInstanceId",alerts)

    def test_stable_slot_absence_is_rejected_during_transition(self):
        moving="nssf1"
        stable="nssf2"
        self.verifier.begin_transition("restart",moving)
        profiles=[p for p in self.profiles if p["slot"]!=stable]
        witness={k:v for k,v in self.witnesses.items() if k!=stable}
        self.assertIn("missing_stable_slot:"+stable,self.verifier.verify(profiles,witness))

    def test_stop_start_restart_are_causal_on_every_slot(self):
        for slot in sorted(self.policy.slots):
            with self.subTest(slot=slot):
                self.assertEqual(
                    {"stop":True,"start":True,"restart":True},
                    lifecycle_case(self.policy,self.profiles,self.witnesses,slot),
                )

    def test_persistent_fqdn_and_service_poisoning_detected_on_every_slot(self):
        with tempfile.TemporaryDirectory() as td:
            for slot in sorted(self.policy.slots):
                for kind in ("fqdn","service"):
                    with self.subTest(slot=slot,kind=kind):
                        path=Path(td)/f"{slot}-{kind}.json"
                        reg=PersistentRegistry(path)
                        reg.write(mutate(self.profiles,slot,kind))
                        reopened=PersistentRegistry(path).read()
                        alerts=StreamRelationalVerifier(self.policy).verify(reopened,self.witnesses)
                        self.assertIn("semantic_mismatch:"+slot,alerts)

    def test_witness_uuid_mismatch_is_rejected(self):
        for slot in sorted(self.policy.slots):
            with self.subTest(slot=slot):
                witness=copy.deepcopy(self.witnesses)
                witness[slot]["nf_instance_id"]="ffffffff-ffff-ffff-ffff-ffffffffffff"
                self.assertIn("witness_uuid:"+slot,self.verifier.verify(self.profiles,witness))

    def test_freshness_anchor_recovers_primary_from_sealed_mirror(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            primary,mirror=td/"primary.json",td/"mirror.json"
            seal=hashlib.sha256(b"seal").digest()
            now=int(time.time()*1000)
            a=FreshnessAnchor(primary,mirror,seal)
            a.check_and_commit("v","nssf1",1,"55"*16,now,now)
            primary.unlink()
            recovered=FreshnessAnchor(primary,mirror,seal)
            self.assertTrue(primary.exists())
            with self.assertRaises(SecurityError):
                recovered.check_and_commit("v","nssf1",1,"55"*16,now,now)

    def test_total_freshness_state_loss_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            primary,mirror=td/"primary.json",td/"mirror.json"
            seal=hashlib.sha256(b"seal").digest()
            now=int(time.time()*1000)
            a=FreshnessAnchor(primary,mirror,seal)
            a.check_and_commit("v","nssf1",1,"66"*16,now,now)
            primary.unlink()
            mirror.unlink()
            with self.assertRaises(SecurityError):
                FreshnessAnchor(primary,mirror,seal,must_recover=True)

    def test_kie_tamper_stale_and_replay_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            key=hashlib.sha256(b"controller").digest()
            now=int(time.time()*1000)
            digest=sha256_json(self.profiles)
            req=KIERequest.create("v","nssf1",5,self.policy.digest,digest,key,now,"00"*16)
            anchor_path=Path(td)/"anchor.json"
            req.verify(key,FreshnessAnchor(anchor_path),self.policy.digest,digest,now)
            with self.assertRaises(SecurityError):
                req.verify(key,FreshnessAnchor(anchor_path),self.policy.digest,digest,now)
            tampered=KIERequest(
                req.controller_id,req.subject_id,req.cycle+1,req.issued_at_ms,
                "11"*16,req.policy_sha256,"0"*64,req.mac
            )
            with self.assertRaises(SecurityError):
                tampered.verify(
                    key,FreshnessAnchor(Path(td)/"tamper.json"),
                    self.policy.digest,"0"*64,now
                )
            stale=KIERequest.create(
                "v","nssf2",1,self.policy.digest,digest,key,now-60_000,"22"*16
            )
            with self.assertRaises(SecurityError):
                stale.verify(
                    key,FreshnessAnchor(Path(td)/"stale.json"),
                    self.policy.digest,digest,now
                )

    def test_kie_response_is_bound_to_request(self):
        subject_key=hashlib.sha256(b"subject").digest()
        controller_key=hashlib.sha256(b"controller").digest()
        now=int(time.time()*1000)
        digest=sha256_json(self.profiles)
        req=KIERequest.create(
            "v","nssf1",1,self.policy.digest,digest,controller_key,now,"33"*16
        )
        response=KIEResponse.create(req,{"profile_digest":digest},subject_key,now)
        response.verify(subject_key,req,now)
        wrong=KIERequest.create(
            "v","nssf1",2,self.policy.digest,digest,controller_key,now,"44"*16
        )
        with self.assertRaises(SecurityError):
            response.verify(subject_key,wrong,now)

    def test_p95_uses_nearest_rank_on_nontrivial_sample(self):
        values=list(range(1,92))
        self.assertEqual(87,nearest_rank(values,0.95))


if __name__ == "__main__":
    unittest.main()
