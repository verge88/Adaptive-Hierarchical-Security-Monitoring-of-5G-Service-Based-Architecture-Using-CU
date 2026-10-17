from __future__ import annotations

import argparse
import copy
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import statistics
import tempfile
import time
from pathlib import Path

NF_TYPES = ("NSSF","AUSF","BSF","UDM","AMF","SMF","PCF","NRF","SCP")
KIE_VERSION = 1
MAX_CLOCK_SKEW_MS = 30_000


def canonical_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()


def sha256_json(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def hmac_hex(key, value):
    return hmac.new(key, canonical_bytes(value), hashlib.sha256).hexdigest()


class SecurityError(ValueError):
    pass


def normalize_service(service):
    endpoints = [{
        "ip": str(e.get("ip","")),
        "port": int(e.get("port",0)),
        "transport": str(e.get("transport","TCP")).upper(),
    } for e in service.get("endpoints",[])]
    endpoints.sort(key=lambda x:(x["ip"],x["port"],x["transport"]))
    return {
        "serviceName": str(service.get("serviceName","")),
        "scheme": str(service.get("scheme","http")).lower(),
        "status": str(service.get("status","REGISTERED")),
        "versions": sorted(str(v) for v in service.get("versions",[])),
        "endpoints": endpoints,
    }


def normalize_profile(profile):
    services = [normalize_service(s) for s in profile.get("nfServices",[])]
    services.sort(key=canonical_bytes)
    return {
        "slot": str(profile.get("slot","")),
        "nfInstanceId": str(profile.get("nfInstanceId","")).lower(),
        "nfType": str(profile.get("nfType","")),
        "nfStatus": str(profile.get("nfStatus","REGISTERED")),
        "fqdn": str(profile.get("fqdn","")),
        "ipv4Addresses": sorted(str(x) for x in profile.get("ipv4Addresses",[])),
        "nfServices": services,
    }


class FullProfilePolicy:
    def __init__(self, doc):
        self.document = copy.deepcopy(doc)
        self.slots = doc.get("slots")
        if int(doc.get("version",0)) != 1 or not isinstance(self.slots,dict) or not self.slots:
            raise ValueError("invalid policy")
        for slot,item in self.slots.items():
            if item.get("nf_type") not in NF_TYPES or not item.get("endpoint") or not item.get("fqdn"):
                raise ValueError("invalid slot policy: "+slot)
        self.digest = sha256_json(doc)

    @classmethod
    def load(cls,path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def expected_profile(self,slot,nf_instance_id):
        p=self.slots[slot]
        return normalize_profile({
            "slot":slot,
            "nfInstanceId":nf_instance_id,
            "nfType":p["nf_type"],
            "nfStatus":"REGISTERED",
            "fqdn":p["fqdn"],
            "ipv4Addresses":[p["endpoint"]],
            "nfServices":p.get("services",[]),
        })

    def matches(self,profile):
        slot=str(profile.get("slot",""))
        if slot not in self.slots:
            return False
        n=normalize_profile(profile)
        return n == self.expected_profile(slot,n["nfInstanceId"])


class PersistentRegistry:
    def __init__(self,path):
        self.path=Path(path)

    def write(self,profiles):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        self.path.write_text(json.dumps(profiles,sort_keys=True),encoding="utf-8")

    def read(self):
        return json.loads(self.path.read_text(encoding="utf-8"))


class FreshnessAnchor:
    def __init__(self,path,mirror_path=None,seal_key=None):
        self.path=Path(path)
        self.mirror_path=Path(mirror_path) if mirror_path else None
        self.seal_key=seal_key
        self.state={"generation":1,"subjects":{}}
        if self.path.exists():
            self.state=json.loads(self.path.read_text(encoding="utf-8"))
            self._validate()
        elif self.mirror_path and self.mirror_path.exists():
            if not seal_key:
                raise SecurityError("mirror requires seal key")
            env=json.loads(self.mirror_path.read_text(encoding="utf-8"))
            state,mac=env.get("state"),env.get("mac")
            if not isinstance(state,dict) or not hmac.compare_digest(str(mac),hmac_hex(seal_key,state)):
                raise SecurityError("bad recovery mirror")
            self.state=state
            self._validate()
            self._save_primary()

    def _validate(self):
        if not isinstance(self.state,dict) or not isinstance(self.state.get("subjects"),dict):
            raise SecurityError("corrupt freshness anchor")

    def _save_primary(self):
        self.path.parent.mkdir(parents=True,exist_ok=True)
        tmp=self.path.with_suffix(self.path.suffix+".tmp")
        tmp.write_text(json.dumps(self.state,sort_keys=True),encoding="utf-8")
        os.replace(tmp,self.path)

    def _save(self):
        self._save_primary()
        if self.mirror_path:
            if not self.seal_key:
                raise SecurityError("mirror requires seal key")
            self.mirror_path.parent.mkdir(parents=True,exist_ok=True)
            env={"state":self.state,"mac":hmac_hex(self.seal_key,self.state)}
            tmp=self.mirror_path.with_suffix(self.mirror_path.suffix+".tmp")
            tmp.write_text(json.dumps(env,sort_keys=True),encoding="utf-8")
            os.replace(tmp,self.mirror_path)

    def check_and_commit(self,controller,subject,cycle,nonce,issued_at_ms,now_ms):
        if abs(now_ms-issued_at_ms) > MAX_CLOCK_SKEW_MS:
            raise SecurityError("stale KIE")
        key=controller+"|"+subject
        row=self.state["subjects"].setdefault(key,{"last_cycle":-1,"nonce_hashes":[]})
        if int(cycle) <= int(row["last_cycle"]):
            raise SecurityError("replayed cycle")
        nh=hashlib.sha256(nonce.encode()).hexdigest()
        if nh in row["nonce_hashes"]:
            raise SecurityError("replayed nonce")
        row["last_cycle"]=int(cycle)
        row["nonce_hashes"]=(row["nonce_hashes"][-255:]+[nh])
        self._save()


@dataclasses.dataclass(frozen=True)
class KIERequest:
    controller_id:str
    subject_id:str
    cycle:int
    issued_at_ms:int
    nonce:str
    policy_sha256:str
    telemetry_digest:str
    mac:str

    @classmethod
    def create(cls,controller_id,subject_id,cycle,policy_sha256,telemetry_digest,key,now_ms=None,nonce=None):
        core={
            "kind":"KIE_REQUEST","version":KIE_VERSION,
            "controller_id":controller_id,"subject_id":subject_id,"cycle":int(cycle),
            "issued_at_ms":int(now_ms if now_ms is not None else time.time()*1000),
            "nonce":nonce or secrets.token_hex(16),
            "policy_sha256":policy_sha256,"telemetry_digest":telemetry_digest,
        }
        return cls(controller_id,subject_id,int(cycle),core["issued_at_ms"],core["nonce"],policy_sha256,telemetry_digest,hmac_hex(key,core))

    def core(self):
        return {
            "kind":"KIE_REQUEST","version":KIE_VERSION,
            "controller_id":self.controller_id,"subject_id":self.subject_id,"cycle":self.cycle,
            "issued_at_ms":self.issued_at_ms,"nonce":self.nonce,
            "policy_sha256":self.policy_sha256,"telemetry_digest":self.telemetry_digest,
        }

    def verify(self,key,anchor,expected_policy,expected_telemetry_digest,now_ms=None):
        if not hmac.compare_digest(self.mac,hmac_hex(key,self.core())):
            raise SecurityError("invalid KIE MAC")
        if self.policy_sha256 != expected_policy or self.telemetry_digest != expected_telemetry_digest:
            raise SecurityError("KIE binding mismatch")
        anchor.check_and_commit(
            self.controller_id,self.subject_id,self.cycle,self.nonce,self.issued_at_ms,
            int(now_ms if now_ms is not None else time.time()*1000)
        )


@dataclasses.dataclass(frozen=True)
class KIEResponse:
    controller_id:str
    subject_id:str
    cycle:int
    request_nonce:str
    issued_at_ms:int
    report:dict
    mac:str

    @classmethod
    def create(cls,request,report,key,now_ms=None):
        core={
            "kind":"KIE_RESPONSE","version":KIE_VERSION,
            "controller_id":request.controller_id,"subject_id":request.subject_id,
            "cycle":request.cycle,"request_nonce":request.nonce,
            "issued_at_ms":int(now_ms if now_ms is not None else time.time()*1000),
            "report":copy.deepcopy(report),
        }
        return cls(core["controller_id"],core["subject_id"],core["cycle"],core["request_nonce"],core["issued_at_ms"],core["report"],hmac_hex(key,core))

    def core(self):
        return {
            "kind":"KIE_RESPONSE","version":KIE_VERSION,
            "controller_id":self.controller_id,"subject_id":self.subject_id,
            "cycle":self.cycle,"request_nonce":self.request_nonce,
            "issued_at_ms":self.issued_at_ms,"report":self.report,
        }

    def verify(self,key,request,now_ms=None):
        if not hmac.compare_digest(self.mac,hmac_hex(key,self.core())):
            raise SecurityError("invalid KIE response MAC")
        if (self.controller_id,self.subject_id,self.cycle,self.request_nonce)!=(request.controller_id,request.subject_id,request.cycle,request.nonce):
            raise SecurityError("KIE response mismatch")
        now=int(now_ms if now_ms is not None else time.time()*1000)
        if abs(now-self.issued_at_ms)>MAX_CLOCK_SKEW_MS:
            raise SecurityError("stale KIE response")


class StreamRelationalVerifier:
    def __init__(self,policy):
        self.policy=policy
        self.active_slots=set(policy.slots)
        self.transition=None

    def begin_transition(self,operation,slot):
        if operation not in {"stop","start","restart"} or slot not in self.policy.slots or self.transition:
            raise ValueError("invalid transition")
        if operation=="stop" and slot not in self.active_slots:
            raise ValueError("stop absent")
        if operation=="start" and slot in self.active_slots:
            raise ValueError("start active")
        if operation=="restart" and slot not in self.active_slots:
            raise ValueError("restart absent")
        self.transition={"operation":operation,"slot":slot}

    def end_transition(self):
        if not self.transition:
            raise ValueError("no transition")
        op,slot=self.transition["operation"],self.transition["slot"]
        if op=="stop":
            self.active_slots.remove(slot)
        elif op=="start":
            self.active_slots.add(slot)
        self.transition=None

    def verify(self,profiles,witness_rows):
        alerts=[]
        rows=[normalize_profile(p) for p in profiles]
        ids=[p["nfInstanceId"] for p in rows]
        if len(ids)!=len(set(ids)):
            alerts.append("duplicate_nfInstanceId")
        by_slot={}
        for p in rows:
            by_slot.setdefault(p["slot"],[]).append(p)
            if p["slot"] not in self.policy.slots:
                alerts.append("unknown_slot:"+p["slot"])

        moving=self.transition["slot"] if self.transition else None
        expected=set(self.active_slots)
        if self.transition and self.transition["operation"]=="start":
            expected.add(moving)

        for slot in sorted(self.policy.slots):
            candidates=by_slot.get(slot,[])
            if len(candidates)>1:
                alerts.append("ambiguous_slot:"+slot)
                continue
            present=len(candidates)==1
            if slot==moving and self.transition:
                if not present:
                    continue
            elif slot in expected and not present:
                alerts.append("missing_stable_slot:"+slot)
                continue
            elif slot not in expected and present:
                alerts.append("unexpected_inactive_slot:"+slot)

            if present:
                profile=candidates[0]
                if not self.policy.matches(profile):
                    alerts.append("semantic_mismatch:"+slot)
                w=witness_rows.get(slot)
                if not isinstance(w,dict):
                    alerts.append("missing_witness:"+slot)
                else:
                    p=self.policy.slots[slot]
                    if w.get("nf_type")!=p["nf_type"]: alerts.append("witness_type:"+slot)
                    if w.get("endpoint")!=p["endpoint"]: alerts.append("witness_endpoint:"+slot)
                    if str(w.get("nf_instance_id","")).lower()!=profile["nfInstanceId"]: alerts.append("witness_uuid:"+slot)
                    if w.get("process_alive") is not True: alerts.append("witness_process:"+slot)
                    if w.get("direct_sbi_tcp_reachable") is not True: alerts.append("witness_reachability:"+slot)
        return sorted(set(alerts))


def default_profiles(policy):
    profiles,witnesses=[],{}
    for i,slot in enumerate(sorted(policy.slots),1):
        uid=f"00000000-0000-0000-0000-{i:012d}"
        profiles.append(policy.expected_profile(slot,uid))
        p=policy.slots[slot]
        witnesses[slot]={
            "slot":slot,"nf_type":p["nf_type"],"endpoint":p["endpoint"],"nf_instance_id":uid,
            "process_alive":True,"direct_sbi_tcp_reachable":True,
        }
    return profiles,witnesses


def mutate(profiles,slot,kind):
    out=copy.deepcopy(profiles)
    p=next(x for x in out if x["slot"]==slot)
    if kind=="identity":
        p["nfInstanceId"]="ffffffff-ffff-ffff-ffff-ffffffffffff"
    elif kind=="endpoint":
        p["ipv4Addresses"]=["203.0.113.99"]
    elif kind=="service":
        p.setdefault("nfServices",[]).append({"serviceName":"unauthorized","scheme":"http","status":"REGISTERED","versions":["v1"],"endpoints":[{"ip":"203.0.113.99","port":80,"transport":"TCP"}]})
    elif kind=="fqdn":
        p["fqdn"]="poisoned.invalid"
    elif kind=="type":
        p["nfType"]="SMF" if p["nfType"]!="SMF" else "AMF"
    elif kind=="duplicate":
        out.append(copy.deepcopy(p))
    else:
        raise ValueError(kind)
    return out


def run_ci(policy,output,soak_seconds):
    output=Path(output)
    output.mkdir(parents=True,exist_ok=True)
    profiles,witnesses=default_profiles(policy)
    verifier=StreamRelationalVerifier(policy)
    if verifier.verify(profiles,witnesses):
        raise RuntimeError("clean baseline rejected")

    slot="nssf1" if "nssf1" in policy.slots else sorted(policy.slots)[0]
    attack_results={}
    latencies=[]
    for kind in ("identity","endpoint","service","fqdn","type","duplicate"):
        attacked=mutate(profiles,slot,kind)
        t0=time.perf_counter_ns()
        alerts=verifier.verify(attacked,witnesses)
        ms=(time.perf_counter_ns()-t0)/1_000_000
        if not alerts:
            raise RuntimeError("missed "+kind)
        attack_results[kind]={"detected":True,"alerts":alerts,"attack_to_alert_ms":ms}
        latencies.append(ms)

    with tempfile.TemporaryDirectory() as td:
        registry=PersistentRegistry(Path(td)/"nrf_registry.json")
        registry.write(profiles)
        registry.write(mutate(registry.read(),slot,"service"))
        poisoned=PersistentRegistry(registry.path).read()
        poison_alerts=verifier.verify(poisoned,witnesses)
        if not any(a.startswith("semantic_mismatch") for a in poison_alerts):
            raise RuntimeError("persistent poisoning survived policy")

    verifier.begin_transition("restart",slot)
    missing=[p for p in profiles if p["slot"]!=slot]
    if verifier.verify(missing,{k:v for k,v in witnesses.items() if k!=slot}):
        raise RuntimeError("moving absence rejected")
    new_profiles=copy.deepcopy(profiles)
    p=next(x for x in new_profiles if x["slot"]==slot)
    p["nfInstanceId"]="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    new_witnesses=copy.deepcopy(witnesses)
    new_witnesses[slot]["nf_instance_id"]=p["nfInstanceId"]
    if verifier.verify(new_profiles,new_witnesses):
        raise RuntimeError("causal restart rejected")
    verifier.end_transition()
    profiles,witnesses=new_profiles,new_witnesses

    with tempfile.TemporaryDirectory() as td:
        primary=Path(td)/"anchor.json"
        mirror=Path(td)/"anchor_mirror.json"
        seal=hashlib.sha256(b"stage39-anchor-seal").digest()
        ckey=hashlib.sha256(b"stage39-controller").digest()
        skey=hashlib.sha256(b"stage39-subject").digest()
        now=int(time.time()*1000)
        digest=sha256_json(profiles)
        req=KIERequest.create("verifier-a",slot,1,policy.digest,digest,ckey,now,"0123456789abcdef0123456789abcdef")
        anchor=FreshnessAnchor(primary,mirror,seal)
        req.verify(ckey,anchor,policy.digest,digest,now)
        primary.unlink()
        recovered=FreshnessAnchor(primary,mirror,seal)
        response=KIEResponse.create(req,{"profile_digest":digest,"witness_digest":sha256_json(witnesses[slot]),"process_alive":True,"sbi_reachable":True},skey,now)
        response.verify(skey,req,now)
        try:
            recovered.check_and_commit(req.controller_id,req.subject_id,req.cycle,req.nonce,req.issued_at_ms,now)
            raise RuntimeError("replay accepted")
        except SecurityError:
            pass
        tampered=dataclasses.replace(req,telemetry_digest="0"*64)
        try:
            tampered.verify(ckey,FreshnessAnchor(Path(td)/"tamper.json"),policy.digest,"0"*64,now)
            raise RuntimeError("tamper accepted")
        except SecurityError:
            pass

    started=time.perf_counter()
    iterations=false_alerts=0
    while time.perf_counter()-started < max(0.0,float(soak_seconds)):
        iterations+=1
        false_alerts+=int(bool(verifier.verify(profiles,witnesses)))
        time.sleep(0.005)
    if false_alerts:
        raise RuntimeError("clean soak false alert")

    p95=sorted(latencies)[-1]
    report={
        "stage":39,
        "analysis_kind":"GitHub Actions CI integration harness; not a new Open5GS production trial",
        "policy_sha256":policy.digest,
        "nf_types":sorted({x["nf_type"] for x in policy.slots.values()}),
        "slots":len(policy.slots),
        "kie":{
            "version":KIE_VERSION,
            "auth":"HMAC-SHA256",
            "freshness":["timestamp_window","monotonic_cycle","nonce_cache","persistent_anchor","sealed_recovery_mirror"],
            "telemetry_binding":True,"policy_binding":True,
            "replay_after_restart_rejected":True,
            "primary_anchor_loss_recovered":True,
            "tamper_rejected":True,
        },
        "streaming":{"uses_future_post_reference":False,"authorized_restart_without_post_reference":True},
        "independent_full_profile_policy":{"fqdn":True,"services":True,"endpoint":True,"nf_type":True},
        "persistent_reference_poisoning":{"file_backed_registry_survived_reopen":True,"detected":True,"alerts":poison_alerts},
        "attacks":attack_results,
        "latency_ms":{"samples":latencies,"median":statistics.median(latencies),"p95":p95,"max":max(latencies)},
        "soak":{"requested_seconds":float(soak_seconds),"iterations":iterations,"false_alerts":false_alerts},
        "limitations":[
            "CI harness, not a new live Open5GS measurement.",
            "Test keys are ephemeral; production key custody and hardware attestation are not established.",
            "Repository policy is independent of NRF observations, but repository compromise remains a common risk.",
            "Recovery mirror covers single-anchor loss, not simultaneous destruction of all copies.",
        ],
    }
    (output/"stage39_report.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    (output/"stage39_report.md").write_text(
        "# Stage39 KIE / streaming CI report\n\n"
        f"- NF types: {', '.join(report['nf_types'])}\n"
        f"- Future post-reference used: {report['streaming']['uses_future_post_reference']}\n"
        f"- KIE replay after restart rejected: {report['kie']['replay_after_restart_rejected']}\n"
        f"- Persistent registry poisoning detected: {report['persistent_reference_poisoning']['detected']}\n"
        f"- Attack families detected: {len(attack_results)}/{len(attack_results)}\n"
        f"- Median / p95 verifier latency: {report['latency_ms']['median']:.3f} / {report['latency_ms']['p95']:.3f} ms\n"
        f"- Clean soak: {iterations} iterations, {false_alerts} false alerts\n",
        encoding="utf-8"
    )
    return report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--policy",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--soak-seconds",type=float,default=2.0)
    args=ap.parse_args()
    print(json.dumps(run_ci(FullProfilePolicy.load(args.policy),args.output,args.soak_seconds),indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
