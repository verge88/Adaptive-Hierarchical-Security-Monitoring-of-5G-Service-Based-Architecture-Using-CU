#!/usr/bin/env python3
"""Stage48: compromised-coordinator detection from signed verifier transcripts.

A malicious coordinator may alter, omit or replay decisions. The defense is to
make the signed per-group quorum transcript available to an independent auditor,
which deterministically recomputes the global result and verifies case binding.
"""
import argparse, hashlib, hmac, json, sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import canon, merge, sha

NODES=4
REPLICAS=3

def consensus_material(body):
    return {"case_id":body["case_id"],"n":body["n"],"trial":body["trial"],"attack":body["attack"],
            "group":body["group"],"count":body["count"],"source_sha256":body["source_sha256"],
            "alerts":body["alerts"],"uuid_tags":body["uuid_tags"]}

def verify_env(env,g,r,key):
    body=env["body"]
    mac=hmac.new(key,canon(body),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac,env["mac_sha256"]):
        raise AssertionError("invalid verifier signature")
    if body["group"]!=g or body["replica"]!=r:
        raise AssertionError("identity mismatch")
    return body

def load_transcript(root):
    reports=[]
    for p in sorted(Path(root).rglob("stage46-g*-r*.json")):
        reports.append(json.loads(p.read_text()))
    if len(reports)!=NODES*REPLICAS:
        raise AssertionError(f"expected {NODES*REPLICAS} reports, got {len(reports)}")
    idx=defaultdict(dict)
    for rep in reports:
        g,r=int(rep["group"]),int(rep["replica"])
        key=bytes.fromhex(rep["verification_key_hex"])
        for env in rep["signed_summaries"]:
            b=verify_env(env,g,r,key)
            idx[(b["case_id"],g)][r]=b
    return idx

def group_quorum(reps):
    if len(reps)!=REPLICAS: raise AssertionError("incomplete replicas")
    items=[reps[r] for r in range(REPLICAS)]
    hs=[sha(consensus_material(x)) for x in items]
    c=Counter(hs); winner,n=c.most_common(1)[0]
    if n<2: raise AssertionError("no 2/3 quorum")
    b=next(x for x,h in zip(items,hs) if h==winner)
    return b,winner

def reconstruct(idx,case_id):
    alerts=[]; ids=[]; gh=[]
    meta=None
    for g in range(NODES):
        b,h=group_quorum(idx[(case_id,g)])
        if meta is None: meta=(b["n"],b["trial"],b["attack"])
        alerts.extend(b["alerts"]); ids.extend(b["uuid_tags"]); gh.append([g,h])
    global_alerts=merge(alerts,ids)
    digest=sha({"case_id":case_id,"group_quorum_hashes":gh,"alerts":global_alerts})
    return {"case_id":case_id,"n":meta[0],"trial":meta[1],"attack":meta[2],
            "group_quorum_hashes":gh,"alerts":global_alerts,"transcript_digest":digest}

def all_cases(idx):
    return sorted({cid for cid,g in idx})

def make_claims(root,out):
    idx=load_transcript(root); cases=all_cases(idx)
    truths={c:reconstruct(idx,c) for c in cases}
    claims=[]
    for i,cid in enumerate(cases):
        t=truths[cid]
        claims.append({"kind":"honest","case_id":cid,"groups_present":[0,1,2,3],
                       "transcript_digest":t["transcript_digest"],"alerts":t["alerts"]})
        # 1) malicious verdict: suppress one real alert, or fabricate one on benign input.
        altered=json.loads(json.dumps(t["alerts"]))
        if altered: altered=altered[1:]
        else: altered=[["coordinator","fabricated_alert"]]
        claims.append({"kind":"alter_verdict","case_id":cid,"groups_present":[0,1,2,3],
                       "transcript_digest":t["transcript_digest"],"alerts":altered})
        # 2) omit one group but keep a claimed global result.
        claims.append({"kind":"omit_group","case_id":cid,"groups_present":[0,1,2],
                       "transcript_digest":t["transcript_digest"],"alerts":t["alerts"]})
        # 3) replay prior/next case transcript under current case id.
        other=truths[cases[(i+1)%len(cases)]]
        claims.append({"kind":"replay_other_case","case_id":cid,"groups_present":[0,1,2,3],
                       "transcript_digest":other["transcript_digest"],"alerts":other["alerts"]})
        # 4) substitute one group quorum hash.
        bad=json.loads(json.dumps(t["group_quorum_hashes"]))
        bad[0][1]="00"*32
        bad_digest=sha({"case_id":cid,"group_quorum_hashes":bad,"alerts":t["alerts"]})
        claims.append({"kind":"substitute_group","case_id":cid,"groups_present":[0,1,2,3],
                       "transcript_digest":bad_digest,"alerts":t["alerts"]})
    report={"schema":"stage48-coordinator-claims-v1","cases":len(cases),"claims":claims}
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({"cases":len(cases),"honest_claims":len(cases),
                      "malicious_claims":len(claims)-len(cases)},indent=2))

def audit(root,claims_path,out):
    idx=load_transcript(root); cases=all_cases(idx)
    truths={c:reconstruct(idx,c) for c in cases}
    data=json.loads(Path(claims_path).read_text())
    results=[]; honest_ok=0; malicious_rejected=0
    by_kind=Counter()
    for c in data["claims"]:
        t=truths[c["case_id"]]
        valid=(c.get("groups_present")==[0,1,2,3] and
               c.get("transcript_digest")==t["transcript_digest"] and
               c.get("alerts")==t["alerts"])
        if c["kind"]=="honest":
            if not valid: raise AssertionError("honest coordinator rejected")
            honest_ok+=1
        else:
            if valid: raise AssertionError("malicious coordinator claim escaped audit: "+c["kind"])
            malicious_rejected+=1; by_kind[c["kind"]]+=1
        results.append({"kind":c["kind"],"case_id":c["case_id"],"accepted":valid})
    report={"schema":"stage48-independent-auditor-v1","cases":len(cases),
            "honest_claims_accepted":honest_ok,
            "malicious_claims_rejected":malicious_rejected,
            "malicious_claims_total":sum(1 for x in data["claims"] if x["kind"]!="honest"),
            "rejected_by_kind":dict(by_kind),
            "all_honest_accepted":honest_ok==len(cases),
            "all_malicious_rejected":malicious_rejected==sum(1 for x in data["claims"] if x["kind"]!="honest"),
            "defense":"independent deterministic recomputation from complete signed 2-of-3 group-quorum transcript",
            "limitations":[
                "If the independent auditor is compromised together with the coordinator, this two-party defense can fail.",
                "The experiment reuses Stage46 signed verifier evidence; it does not create a new live Open5GS run.",
                "Availability is not guaranteed when the complete transcript is unavailable; the intended behavior is fail closed."
            ],
            "results":results}
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("cases","honest_claims_accepted","malicious_claims_rejected",
          "malicious_claims_total","rejected_by_kind","all_honest_accepted","all_malicious_rejected")},indent=2))

def main():
    ap=argparse.ArgumentParser(); sub=ap.add_subparsers(dest="op",required=True)
    m=sub.add_parser("make-claims");m.add_argument("--transcript",required=True);m.add_argument("--out",required=True)
    a=sub.add_parser("audit");a.add_argument("--transcript",required=True);a.add_argument("--claims",required=True);a.add_argument("--out",required=True)
    x=ap.parse_args()
    if x.op=="make-claims":make_claims(x.transcript,x.out)
    else:audit(x.transcript,x.claims,x.out)
if __name__=="__main__":main()
