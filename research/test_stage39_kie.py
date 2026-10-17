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
    mutate,
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

    def test_clean_profiles_are_accepted(self):
        self.assertEqual([],self.verifier.verify(self.profiles,self.witnesses))

    def test_six_profile_mutations_are_detected(self):
        for kind in ("identity","endpoint","service","fqdn","type","duplicate"):
            with self.subTest(kind=kind):
                self.assertTrue(self.verifier.verify(mutate(self.profiles,"nssf1",kind),self.witnesses))

    def test_exact_duplicate_is_detected_even_during_transition(self):
        self.verifier.begin_transition("restart","nssf1")
        self.assertIn("duplicate_nfInstanceId",self.verifier.verify(mutate(self.profiles,"nssf1","duplicate"),self.witnesses))

    def test_stable_slot_absence_is_rejected_during_transition(self):
        self.verifier.begin_transition("restart","nssf1")
        profiles=[p for p in self.profiles if p["slot"]!="nssf2"]
        witness={k:v for k,v in self.witnesses.items() if k!="nssf2"}
        self.assertIn("missing_stable_slot:nssf2",self.verifier.verify(profiles,witness))

    def test_moving_slot_absence_and_new_uuid_are_causally_allowed(self):
        self.verifier.begin_transition("restart","nssf1")
        profiles=[p for p in self.profiles if p["slot"]!="nssf1"]
        witness={k:v for k,v in self.witnesses.items() if k!="nssf1"}
        self.assertEqual([],self.verifier.verify(profiles,witness))
        changed=copy.deepcopy(self.profiles)
        p=next(x for x in changed if x["slot"]=="nssf1")
        p["nfInstanceId"]="11111111-1111-1111-1111-111111111111"
        witness=copy.deepcopy(self.witnesses)
        witness["nssf1"]["nf_instance_id"]=p["nfInstanceId"]
        self.assertEqual([],self.verifier.verify(changed,witness))

    def test_persistent_registry_poisoning_survives_reopen_and_is_detected(self):
        with tempfile.TemporaryDirectory() as td:
            reg=PersistentRegistry(Path(td)/"registry.json")
            reg.write(self.profiles)
            reg.write(mutate(reg.read(),"nssf1","fqdn"))
            reopened=PersistentRegistry(reg.path).read()
            self.assertIn("semantic_mismatch:nssf1",self.verifier.verify(reopened,self.witnesses))

    def test_witness_uuid_mismatch_is_rejected(self):
        witness=copy.deepcopy(self.witnesses)
        witness["nssf1"]["nf_instance_id"]="ffffffff-ffff-ffff-ffff-ffffffffffff"
        self.assertIn("witness_uuid:nssf1",self.verifier.verify(self.profiles,witness))

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
            tampered=KIERequest(req.controller_id,req.subject_id,req.cycle+1,req.issued_at_ms,"11"*16,req.policy_sha256,"0"*64,req.mac)
            with self.assertRaises(SecurityError):
                tampered.verify(key,FreshnessAnchor(Path(td)/"tamper.json"),self.policy.digest,"0"*64,now)
            stale=KIERequest.create("v","nssf2",1,self.policy.digest,digest,key,now-60_000,"22"*16)
            with self.assertRaises(SecurityError):
                stale.verify(key,FreshnessAnchor(Path(td)/"stale.json"),self.policy.digest,digest,now)

    def test_kie_response_is_bound_to_request(self):
        subject_key=hashlib.sha256(b"subject").digest()
        controller_key=hashlib.sha256(b"controller").digest()
        now=int(time.time()*1000)
        digest=sha256_json(self.profiles)
        req=KIERequest.create("v","nssf1",1,self.policy.digest,digest,controller_key,now,"33"*16)
        response=KIEResponse.create(req,{"profile_digest":digest},subject_key,now)
        response.verify(subject_key,req,now)
        wrong=KIERequest.create("v","nssf1",2,self.policy.digest,digest,controller_key,now,"44"*16)
        with self.assertRaises(SecurityError):
            response.verify(subject_key,wrong,now)


if __name__ == "__main__":
    unittest.main()
