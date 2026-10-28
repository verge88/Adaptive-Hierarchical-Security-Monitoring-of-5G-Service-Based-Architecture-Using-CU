#!/usr/bin/env python3
"""Stage49: common-mode poisoning of profile+witness sources.

Baseline Stage44 accepts a consistently poisoned NF instance UUID when both the NRF
profile and the independent witness are modified together. A hardened variant binds
the UUID to an independently retained lifecycle authorization anchor. The experiment
measures both the baseline escape and the hardened detector, and explicitly tests
the boundary where all three sources are compromised together.
"""
import argparse, hashlib, json, sys, uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import check_group, records_for_node, sha

NODES=4
SIZES=(13,1040,4160)
TRIALS=8

def poison_uuid(rows,trial,group,poison_anchor=False):
    rows=json.loads(json.dumps(rows))
    if not rows:return rows,[]
    # Select deterministic positions; enough to test scaling without changing other fields.
    k=max(1,len(rows)//64)
    picked=[]
    for i in range(k):
        idx=(trial*17+group*7+i*31)%len(rows)
        row=rows[idx]
        original=str(row["profile"]["nfInstanceId"]).lower()
        new=str(uuid.UUID(hashlib.md5(f"stage49/{trial}/{group}/{i}/{row['slot']}".encode()).hexdigest()))
        row["profile"]["nfInstanceId"]=new
        row["witness"]["nf_instance_id"]=new
        row["lifecycle_anchor"]={"authorized_nf_instance_id":new if poison_anchor else original,
                                 "source":"independent_authorization_log","sequence":trial+1}
        picked.append([row["slot"],original,new])
    # Non-poisoned rows receive their original independent anchor too.
    poisoned_slots={x[0] for x in picked}
    for row in rows:
        if row["slot"] not in poisoned_slots:
            row["lifecycle_anchor"]={"authorized_nf_instance_id":str(row["profile"]["nfInstanceId"]).lower(),
                                     "source":"independent_authorization_log","sequence":trial+1}
    return rows,picked

def hardened_check(rows):
    base_alerts,ids=check_group(rows)
    alerts=set(tuple(x) for x in base_alerts)
    for row in rows:
        expected=str(row["lifecycle_anchor"]["authorized_nf_instance_id"]).lower()
        actual=str(row["profile"]["nfInstanceId"]).lower()
        witness=str(row["witness"]["nf_instance_id"]).lower()
        if actual!=expected or witness!=expected:
            alerts.add((row["slot"],"lifecycle_uuid_anchor"))
    return sorted(alerts),ids

def run(seed_path,out):
    seed=json.loads(Path(seed_path).read_text())
    cases=[]
    total_poisoned=0
    baseline_escaped=0
    hardened_detected=0
    all_three_escaped=0
    benign_false=0
    for n in SIZES:
        for trial in range(TRIALS):
            for group in range(NODES):
                clean=records_for_node(seed,n,trial,False,group)
                # Establish an independent lifecycle authorization anchor before poisoning.
                anchored,_=poison_uuid(clean,trial,group,False)
                # poison_uuid already poisons; create clean anchored version separately
                clean_anchored=json.loads(json.dumps(clean))
                for row in clean_anchored:
                    row["lifecycle_anchor"]={"authorized_nf_instance_id":str(row["profile"]["nfInstanceId"]).lower(),
                                             "source":"independent_authorization_log","sequence":trial+1}
                ba,_=check_group(clean_anchored);ha,_=hardened_check(clean_anchored)
                if ba or ha: benign_false+=1

                poisoned,picked=poison_uuid(clean,trial,group,False)
                total_poisoned+=len(picked)
                b_alerts,_=check_group(poisoned)
                h_alerts,_=hardened_check(poisoned)
                baseline_escape=(len(b_alerts)==0)
                hardened_hit=any(a[1]=="lifecycle_uuid_anchor" for a in h_alerts)
                baseline_escaped+=int(baseline_escape)
                hardened_detected+=int(hardened_hit)

                triple,picked2=poison_uuid(clean,trial,group,True)
                th,_=hardened_check(triple)
                triple_escape=(len(th)==0)
                all_three_escaped+=int(triple_escape)
                cases.append({"n":n,"trial":trial,"group":group,"poisoned_records":len(picked),
                              "baseline_alerts":len(b_alerts),"baseline_common_mode_escape":baseline_escape,
                              "hardened_alerts":len(h_alerts),"hardened_detected":hardened_hit,
                              "all_three_sources_poisoned_escape":triple_escape,
                              "poison_sha256":sha(picked),"triple_poison_sha256":sha(picked2)})
    total=len(cases)
    report={
      "schema":"stage49-common-mode-source-poisoning-v1",
      "cases":total,"total_poisoned_records":total_poisoned,
      "baseline_common_mode_escapes":baseline_escaped,
      "hardened_detections":hardened_detected,
      "all_three_sources_poisoned_escapes":all_three_escaped,
      "benign_false_alert_cases":benign_false,
      "baseline_escape_rate":baseline_escaped/total,
      "hardened_detection_rate":hardened_detected/total,
      "three_source_boundary_escape_rate":all_three_escaped/total,
      "interpretation":{
        "baseline":"profile and witness can agree on the same false UUID; Stage44 has no independent UUID anchor in the lifecycle record",
        "hardened":"bind each authorized NF instance UUID to an independently retained lifecycle authorization record",
        "boundary":"if profile, witness, and lifecycle authorization anchor are all compromised consistently, this detector cannot distinguish the fabricated state"
      },
      "limitations":[
        "The lifecycle anchor is modeled as an independent trusted authorization log; this experiment does not implement PKI/TEE protection for that log.",
        "The experiment targets UUID substitution because it is a meaningful field not statically pinned by policy across authorized restarts.",
        "Scaled NF records above the original Stage42 live seed are deterministic replicas."
      ],
      "case_results":cases}
    if baseline_escaped!=total: raise AssertionError("baseline unexpectedly detected some common-mode UUID poison")
    if hardened_detected!=total: raise AssertionError("hardened detector missed common-mode poison")
    if all_three_escaped!=total: raise AssertionError("expected boundary control to escape when all sources poisoned")
    if benign_false!=0: raise AssertionError("false positives on clean anchored input")
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("cases","total_poisoned_records","baseline_common_mode_escapes",
      "hardened_detections","all_three_sources_poisoned_escapes","benign_false_alert_cases",
      "baseline_escape_rate","hardened_detection_rate","three_source_boundary_escape_rate")},indent=2))

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--seed",required=True);ap.add_argument("--out",required=True)
    a=ap.parse_args();run(a.seed,a.out)
if __name__=="__main__":main()
