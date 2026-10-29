#!/usr/bin/env python3
"""Final live-NF integrity experiment: genuine NRF profiles, controlled attack overlays.
Attack fixtures DO NOT alter the running NRF; authority and verifier keys are local
test keys, not hardware or external trust roots. Process PIDs are genuine Open5GS.
"""
import argparse
import asyncio
import copy
import hashlib
import hmac
import importlib.util
import json
import math
import os
from pathlib import Path
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

BASE=Path("/opt/stage54e_driver.py")
OUT_SCHEMA="stage56-final-live-4000-integrity-v1"
GROUPS=4
REPEATS=3
DEEP_MOD=16
CASES=("benign","profile_uuid","common_mode_uuid","service_poison",
       "status_poison","lifecycle_replay","lifecycle_signature",
       "witness_liveness","cross_group_duplicate")

def encoded(o):
    return json.dumps(o,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()

def digest(o):
    return hashlib.sha256(encoded(o)).hexdigest()

def sign(o,key):
    return hmac.new(key,encoded(o),hashlib.sha256).hexdigest()

def expected_policy(p):
    return {
        "nf_type":p["nfType"],
        "services":sorted(s["serviceName"] for s in p.get("nfServices",[])),
        "status":"REGISTERED",
    }

def new_bad_uuid(i,case):
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_URL,"stage56-final/%s/%d"%(case,i)))

def enroll(docs,witness):
    id_to_pid={str(v["nf_instance_id"]).lower():pid for pid,v in witness.items()}
    if len(id_to_pid)!=len(witness):
        raise AssertionError("duplicate UUID in runtime witness")
    rows=[]
    for slot,uid in enumerate(sorted(docs)):
        p=docs[uid]
        if uid not in id_to_pid:
            raise AssertionError("profile UUID lacks native runtime witness")
        pid=id_to_pid[uid]
        live=Path("/proc/%d/status"%pid).exists()
        endpoint="127.0.0.12"
        pol=expected_policy(p)
        rows.append({
            "slot":slot,"pid":pid,
            "profile":{"nfInstanceId":p["nfInstanceId"].lower(),
                       "nfType":p["nfType"],"nfStatus":p["nfStatus"],
                       "services":list(pol["services"])},
            "witness":{"uuid":uid,"pid":pid,"process_alive":live,
                       "endpoint":endpoint},
            "policy":pol,
            "anchor":{"uuid":uid,"cycle":56,"policy_sha":digest(pol)},
        })
    return rows

def attach_authority(rows,key):
    for row in rows:
        row["anchor_signature"]=sign(row["anchor"],key)
        row["enrolled_signature"]=row["anchor_signature"]
    return rows

def perturb(original,case,ordinal):
    rows=copy.deepcopy(original)
    n=len(rows)
    # Every attack case modifies a deterministic disjoint subset, not all 4000.
    targets=[(ordinal*101+13+j*83)%n for j in range(20)]
    if case=="cross_group_duplicate":
        # Make one UUID occur in two different groups, with *consistent*
        # profile, witness and correctly re-signed lifecycle evidence.
        targets=[0,n-1]
        donor=rows[0]["anchor"]["uuid"]
        for i in targets[1:]:
            rows[i]["profile"]["nfInstanceId"]=donor
            rows[i]["witness"]["uuid"]=donor
            rows[i]["anchor"]["uuid"]=donor
            rows[i]["anchor_signature"]=sign(rows[i]["anchor"],_authority_key)
        return rows,targets
    for i in targets:
        x=rows[i]
        if case=="profile_uuid":
            x["profile"]["nfInstanceId"]=new_bad_uuid(i,case)
        elif case=="common_mode_uuid":
            bad=new_bad_uuid(i,case)
            x["profile"]["nfInstanceId"]=bad
            x["witness"]["uuid"]=bad
        elif case=="service_poison":
            x["profile"]["services"].append("forged-nf-service")
        elif case=="status_poison":
            x["profile"]["nfStatus"]="DEREGISTERED"
        elif case=="lifecycle_replay":
            x["anchor"]["cycle"]=55
        elif case=="lifecycle_signature":
            x["anchor_signature"]="0"*64
        elif case=="witness_liveness":
            x["witness"]["process_alive"]=False
    return rows,targets if case!="benign" else []

def cheap_violations(x):
    p=x["profile"];w=x["witness"];a=x["anchor"];policy=x["policy"];out=[]
    if p["nfType"]!=policy["nf_type"]:out.append("nf_type")
    if p["nfStatus"]!=policy["status"]:out.append("nf_status")
    if sorted(p["services"])!=policy["services"]:out.append("nf_service")
    if p["nfInstanceId"]!=w["uuid"]:out.append("runtime_uuid")
    if p["nfInstanceId"]!=a["uuid"]:out.append("lifecycle_uuid")
    if a["cycle"]!=56:out.append("lifecycle_cycle")
    if a["policy_sha"]!=digest(policy):out.append("policy_digest")
    if not w["process_alive"]:out.append("runtime_not_alive")
    if x["anchor_signature"]!=x["enrolled_signature"]:out.append("signature_changed")
    return out

def deep_violations(x,key):
    out=cheap_violations(x)
    if not hmac.compare_digest(x["anchor_signature"],sign(x["anchor"],key)):
        out.append("authority_hmac_invalid")
    if x["witness"]["pid"]!=x["pid"]:
        out.append("witness_pid")
    return out

def scan(rows,method,key,case_ix):
    alarms=[];deep_count=0;screened_count=0
    for x in rows:
        screened_count+=1
        hints=cheap_violations(x)
        if method=="adaptive":
            d=bool(hints) or (x["slot"]+case_ix)%DEEP_MOD==0
            findings=deep_violations(x,key) if d else hints
        else:
            d=True
            findings=deep_violations(x,key)
        deep_count+=int(d)
        for kind in sorted(set(findings)):
            alarms.append((x["slot"],kind))
    return sorted(alarms),screened_count,deep_count

def summarize_group(i,rows,method,key,cycle,authority_key):
    t=time.perf_counter()
    alerts,screened,deep=scan(rows,method,authority_key,cycle)
    body={"schema":"stage56-group-summary-v1","group":i,"cycle":cycle,
          "mode":method,"count":len(rows),"screened":screened,"deep":deep,
          "uuid_sha256":[[x["slot"],hashlib.sha256(x["profile"]["nfInstanceId"].encode()).hexdigest()] for x in rows],
          "alerts":alerts}
    blob={"body":body,"hmac_sha256":sign(body,key)}
    return encoded(blob),time.perf_counter()-t

def validate_groups(blobs,keys,method,cycle,n):
    ids=[];alarms=[];deep=0;screen=0;received=0
    for group,raw in enumerate(blobs):
        received+=len(raw)
        msg=json.loads(raw);body=msg["body"]
        if not hmac.compare_digest(msg["hmac_sha256"],sign(body,keys[group])):
            raise AssertionError("group authentication invalid")
        if (body["group"],body["cycle"],body["mode"])!=(group,cycle,method):
            raise AssertionError("cross-cycle/group/method replay")
        if body["count"]!=len(body["uuid_sha256"]):
            raise AssertionError("incomplete group proof")
        ids.extend((int(i),u) for i,u in body["uuid_sha256"])
        alarms.extend((int(i),str(reason)) for i,reason in body["alerts"])
        deep+=body["deep"];screen+=body["screened"]
    if len(ids)!=n or len({i for i,_ in ids})!=n:
        raise AssertionError("not every NF was covered exactly once")
    by_uid={}
    for slot,u in ids:
        if u in by_uid:
            alarms.extend([(by_uid[u],"cross_group_uuid"),(slot,"cross_group_uuid")])
        else:by_uid[u]=slot
    return sorted(set(alarms)),screen,deep,received

def central(rows,key,cycle):
    t=time.perf_counter()
    alerts,screen,deep=scan(rows,"central",key,cycle)
    seen={};extra=[]
    for x in rows:
        h=hashlib.sha256(x["profile"]["nfInstanceId"].encode()).hexdigest()
        if h in seen:
            extra.extend([(seen[h],"cross_group_uuid"),(x["slot"],"cross_group_uuid")])
        else:seen[h]=x["slot"]
    return sorted(set(alerts+extra)),screen,deep,time.perf_counter()-t,len(encoded(rows))

def experiment(docs,witness,out,base):
    global _authority_key
    out.mkdir(parents=True,exist_ok=True)
    _authority_key=os.urandom(32)
    group_keys=[os.urandom(32) for _ in range(GROUPS)]
    rows=attach_authority(enroll(docs,witness),_authority_key)
    n=len(rows)
    if n!=4000:raise AssertionError("final experiment requires exactly 4000 true NF profiles")
    if not all(x["witness"]["process_alive"] for x in rows):
        raise AssertionError("native process died before end-to-end method")
    original_sha=digest(rows)
    report={"schema":OUT_SCHEMA,"real_open5gs_nf_count":n,
            "real_nrf_individual_nfm_profiles":n,
            "real_native_runtime_witnesses":len(witness),
            "nf_type":"NSSF","nrf_count":1,"scp_count":1,
            "groups":GROUPS,"repeats":REPEATS,"deep_audit_period":DEEP_MOD,
            "evidence_source":"actual NFM GET + actual native witness; attack overlays in memory",
            "lifecycle_source":"locally signed enrollment fixture, NOT independent authority",
            "quorum":"none in this run; group HMAC verification only",
            "physical_separation":"none; all verifiers on one runner/VM",
            "network_measurement":"serialized coordinator input/output bytes, NOT wire captures",
            "method_latency_measurement":"local CPU verification and thread scheduling, not WAN RTT",
            "attack_count_per_case":20,
            "source_snapshot_sha256":original_sha,
            "scenarios":[]}
    all_pass=True
    for case_ix,case in enumerate(CASES):
        for repeat in range(REPEATS):
            fixture,targets=perturb(rows,case,repeat)
            ca,cs,cd,ct,cb=central(fixture,_authority_key,case_ix)
            groups=[fixture[(n*i)//GROUPS:(n*(i+1))//GROUPS] for i in range(GROUPS)]
            modes={}
            for mode in ("fixed","adaptive"):
                t=time.perf_counter()
                with ThreadPoolExecutor(max_workers=GROUPS) as pool:
                    jobs=[pool.submit(summarize_group,i,g,mode,group_keys[i],case_ix,_authority_key)
                          for i,g in enumerate(groups)]
                    results=[j.result() for j in jobs]
                msgs=[a for a,_ in results]
                alerts,screen,deep,summary_bytes=validate_groups(
                    msgs,group_keys,mode,case_ix,n)
                modes[mode]={"alarms":len(alerts),"alert_digest":digest(alerts),
                             "exact_central_equivalence":alerts==ca,
                             "screened":screen,"deep_checks":deep,
                             "coordinator_bytes":summary_bytes,
                             "elapsed_seconds":time.perf_counter()-t}
                if alerts!=ca:all_pass=False
            matched_slots={i for i,_ in ca}
            expected=set(targets)
            hit=(matched_slots>=expected) if case!="benign" else not bool(ca)
            if not hit:all_pass=False
            item={"scenario":case,"repeat":repeat,"injected_slots":len(targets),
                  "injection_locations_sha256":digest(sorted(targets)),
                  "central":{"alarms":len(ca),"alert_digest":digest(ca),
                             "screened":cs,"deep_checks":cd,
                             "coordinator_bytes":cb,"elapsed_seconds":ct},
                  "fixed":modes["fixed"],"adaptive":modes["adaptive"],
                  "all_expected_slots_detected":hit}
            report["scenarios"].append(item)
            print("STAGE56_CASE "+json.dumps({
                "scenario":case,"repeat":repeat,"central_alarms":len(ca),
                "fixed_equal":modes["fixed"]["exact_central_equivalence"],
                "adaptive_equal":modes["adaptive"]["exact_central_equivalence"],
                "hit":hit},sort_keys=True),flush=True)
    report["all_checks_passed"]=all_pass
    report["all_cases_central_equivalence"]=all(
        a[m]["exact_central_equivalence"] for a in report["scenarios"]
        for m in ("fixed","adaptive"))
    report["all_expected_attacks_detected"]=all(a["all_expected_slots_detected"]
                                               for a in report["scenarios"])
    report["mean_deep_checks"]={
        m:statistics.mean(a[m]["deep_checks"] for a in report["scenarios"])
        for m in ("central","fixed","adaptive")}
    report["mean_coordinator_bytes"]={
        m:statistics.mean(a[m]["coordinator_bytes"] for a in report["scenarios"])
        for m in ("central","fixed","adaptive")}
    report["reduction_percent"]=100*(1-report["mean_coordinator_bytes"]["adaptive"]/
                                      report["mean_coordinator_bytes"]["central"])
    (out/"stage56_result.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("STAGE56_SUMMARY "+json.dumps({
        k:report[k] for k in ("real_open5gs_nf_count","all_checks_passed",
             "all_cases_central_equivalence","all_expected_attacks_detected",
             "mean_deep_checks","mean_coordinator_bytes","reduction_percent")},
             sort_keys=True),flush=True)
    if not all_pass:raise AssertionError("Stage56 end-to-end method mismatches")
    return report

async def main_async(args):
    spec=importlib.util.spec_from_file_location("stage54_live",BASE)
    base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
    original=base.verify_registered_profiles
    out=Path(args.output)
    async def instrument(ids,deadline):
        docs,pending,nbytes,last=await original(ids,deadline)
        if not pending:
            witness=base.read_witness()
            experiment(docs,witness,out,base)
        return docs,pending,nbytes,last
    base.verify_registered_profiles=instrument
    # Original Stage54 driver also verifies 4000 live processes and SBI endpoints
    # after our experiment, and holds them simultaneously for 60 s.
    await base.main_async(args)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--count",type=int,default=4000)
    p.add_argument("--worker",type=int,default=0)
    p.add_argument("--hold-seconds",type=float,default=60)
    p.add_argument("--output",required=True)
    p.add_argument("--batch",type=int,default=25)
    p.add_argument("--batch-pause",type=float,default=.05)
    p.add_argument("--converge-timeout",type=float,default=1800)
    args=p.parse_args()
    if args.count!=4000:raise SystemExit("Stage56 requires exactly 4000 live NF")
    asyncio.run(main_async(args))

if __name__=="__main__":
    main()
