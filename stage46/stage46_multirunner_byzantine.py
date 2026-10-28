#!/usr/bin/env python3
"""Stage46: multi-runner Byzantine-quorum experiment.

Three independently scheduled GitHub-hosted verifier jobs check every logical group.
One key-holding Byzantine verifier per case emits a validly authenticated false summary.
The coordinator accepts only a 2-of-3 identical verdict quorum and compares the
result with a centralized recomputation from the same immutable Stage44 seed.

This demonstrates tolerance to ONE compromised verifier replica per group. It does
not prove physical-host separation of GitHub-hosted VMs and does not tolerate two
colluding verifier replicas in the same group.
"""
import argparse, hashlib, hmac, json, os, socket, sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import canon, check_group, merge, records_for_node, sha

NODES=4
REPLICAS=3
SIZES=(13,1040,4160)
TRIALS=4

def key(group,replica):
    # Test-only independent verifier keys. A Byzantine replica is assumed to possess its own valid key.
    return hashlib.sha256(f"stage46/verifier/{group}/{replica}".encode()).digest()

def sign(body,group,replica):
    return hmac.new(key(group,replica),canon(body),hashlib.sha256).hexdigest()

def verify(env,group,replica):
    body=env["body"]
    if not hmac.compare_digest(sign(body,group,replica),env["mac_sha256"]):
        raise AssertionError("invalid verifier signature")
    if body["group"]!=group or body["replica"]!=replica:
        raise AssertionError("verifier identity mismatch")
    return body

def machine_meta():
    try:
        mid=Path("/etc/machine-id").read_text().strip()
    except Exception:
        mid=""
    return {
        "hostname":socket.gethostname(),
        "machine_id_sha256":hashlib.sha256(mid.encode()).hexdigest() if mid else None,
        "runner_name":os.getenv("RUNNER_NAME"),
        "runner_os":os.getenv("RUNNER_OS"),
        "runner_arch":os.getenv("RUNNER_ARCH"),
        "github_job":os.getenv("GITHUB_JOB"),
        "github_run_id":os.getenv("GITHUB_RUN_ID"),
        "github_run_attempt":os.getenv("GITHUB_RUN_ATTEMPT"),
    }

def worker(seed_path,group,replica,out):
    seed=json.loads(Path(seed_path).read_text())
    rows_out=[]
    injected=0
    for n in SIZES:
        for trial in range(TRIALS):
            for attack in (False,True):
                case_id=f"n{n}-t{trial}-a{int(attack)}"
                rows=records_for_node(seed,n,trial,attack,group)
                alerts,ids=check_group(rows)
                honest={"case_id":case_id,"n":n,"trial":trial,"attack":attack,
                        "group":group,"replica":replica,"count":len(rows),
                        "source_sha256":sha(rows),"alerts":alerts,"uuid_tags":ids}
                body=json.loads(json.dumps(honest))
                # Exactly one Byzantine replica is selected per case. It has a valid signing key.
                # Benign case: inject a false alert. Attacked case: suppress all local alerts.
                bad_replica=(trial+n+int(attack))%REPLICAS
                if replica==bad_replica:
                    if attack:
                        body["alerts"]=[]
                    else:
                        body["alerts"]=list(body["alerts"])+[[f"byzantine-group-{group}","fabricated_alert"]]
                    body["byzantine_injected"]=True
                    injected+=1
                else:
                    body["byzantine_injected"]=False
                rows_out.append({"body":body,"mac_sha256":sign(body,group,replica)})
    report={"schema":"stage46-verifier-v1","group":group,"replica":replica,
            "runner":machine_meta(),"signed_summaries":rows_out,
            "byzantine_summaries_emitted":injected}
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({"group":group,"replica":replica,"cases":len(rows_out),
                      "byzantine_summaries_emitted":injected,"runner":report["runner"]},indent=2))

def consensus_material(body):
    # Replica identity and injection marker are excluded; only security-relevant verdict content votes.
    return {"case_id":body["case_id"],"n":body["n"],"trial":body["trial"],"attack":body["attack"],
            "group":body["group"],"count":body["count"],"source_sha256":body["source_sha256"],
            "alerts":body["alerts"],"uuid_tags":body["uuid_tags"]}

def choose_quorum(bodies):
    hashes=[sha(consensus_material(x)) for x in bodies]
    counts=Counter(hashes)
    winner,n=counts.most_common(1)[0]
    if n<2:
        raise AssertionError("no 2-of-3 quorum")
    selected=next(x for x,h in zip(bodies,hashes) if h==winner)
    return selected,n,len(set(hashes))

def centralized(seed,n,trial,attack):
    all_rows=[]
    for group in range(NODES):
        all_rows.extend(records_for_node(seed,n,trial,attack,group))
    alerts,ids=check_group(all_rows)
    return merge(alerts,ids)

def coordinator(seed_path,input_dir,out):
    seed=json.loads(Path(seed_path).read_text())
    reports=[]
    for p in sorted(Path(input_dir).glob("stage46-g*-r*.json")):
        reports.append(json.loads(p.read_text()))
    if len(reports)!=NODES*REPLICAS:
        raise AssertionError(f"expected {NODES*REPLICAS} verifier reports, got {len(reports)}")
    by_gr={(r["group"],r["replica"]):r for r in reports}
    if set(by_gr)!={(g,r) for g in range(NODES) for r in range(REPLICAS)}:
        raise AssertionError("missing/duplicate verifier identity")

    # Verify every signed message before voting.
    indexed=defaultdict(dict)
    total_signed=0
    total_injected=0
    for (g,r),rep in by_gr.items():
        for env in rep["signed_summaries"]:
            body=verify(env,g,r)
            indexed[(body["case_id"],g)][r]=body
            total_signed+=1
            total_injected+=int(body.get("byzantine_injected") is True)

    case_results=[]
    split_votes=0
    quorum2=0
    for n in SIZES:
        for trial in range(TRIALS):
            for attack in (False,True):
                cid=f"n{n}-t{trial}-a{int(attack)}"
                group_bodies=[]
                for g in range(NODES):
                    reps=indexed[(cid,g)]
                    if len(reps)!=REPLICAS: raise AssertionError("incomplete replicas")
                    selected,q,variants=choose_quorum([reps[r] for r in range(REPLICAS)])
                    if variants>1: split_votes+=1
                    if q==2: quorum2+=1
                    group_bodies.append(selected)
                alerts=[];ids=[]
                for b in group_bodies:
                    alerts.extend(b["alerts"]);ids.extend(b["uuid_tags"])
                actual=merge(alerts,ids)
                expected=centralized(seed,n,trial,attack)
                if actual!=expected:
                    raise AssertionError("quorum result differs from centralized truth "+cid)
                if not attack and actual:
                    raise AssertionError("false alert after quorum "+cid)
                if attack and not actual:
                    raise AssertionError("attack escaped quorum "+cid)
                case_results.append({"case_id":cid,"n":n,"trial":trial,"attack":attack,
                                     "equivalent":True,"alerts":len(actual),"alert_sha256":sha(actual)})

    # Coordinator fail-closed controls.
    controls={}
    sample=indexed[("n1040-t0-a1",0)]
    env0=by_gr[(0,0)]["signed_summaries"][8] if len(by_gr[(0,0)]["signed_summaries"])>8 else by_gr[(0,0)]["signed_summaries"][0]
    tampered=json.loads(json.dumps(env0));tampered["body"]["count"]+=1
    try: verify(tampered,0,0); controls["tampered_signature"]=False
    except AssertionError: controls["tampered_signature"]=True
    try: choose_quorum([sample[0]]); controls["two_missing_replicas_fail_closed"]=False
    except AssertionError: controls["two_missing_replicas_fail_closed"]=True
    # One missing replica is tolerated if the two remaining honest-equivalent votes agree.
    honest_by_hash=defaultdict(list)
    for b in sample.values(): honest_by_hash[sha(consensus_material(b))].append(b)
    honest_pair=max(honest_by_hash.values(),key=len)[:2]
    controls["one_missing_replica_tolerated"]=choose_quorum(honest_pair)[1]>=2
    # Explicit threshold boundary: two colluding signed replicas can form a false quorum.
    base=json.loads(json.dumps(honest_pair[0]))
    base["alerts"]=[["colluding","fabricated-majority"]]
    fakes=[]
    for replica in (0,1):
        b=json.loads(json.dumps(base));b["replica"]=replica;b["byzantine_injected"]=True
        fakes.append(b)
    selected,q,_=choose_quorum(fakes+[sample[2]])
    controls["two_colluding_replicas_can_defeat_quorum"]=(q>=2 and selected["alerts"]==[["colluding","fabricated-majority"]])

    runners=[r["runner"] for r in reports]
    hostnames=[x.get("hostname") for x in runners if x.get("hostname")]
    machine_ids=[x.get("machine_id_sha256") for x in runners if x.get("machine_id_sha256")]
    report={
        "schema":"stage46-multirunner-byzantine-quorum-v1",
        "source_seed":"Stage44 seed derived from Stage42 live Open5GS evidence",
        "architecture":"4 logical groups x 3 independent GitHub-hosted verifier jobs; 2-of-3 per-group quorum",
        "cases":len(case_results),"group_case_votes":len(case_results)*NODES,
        "signed_summaries":total_signed,"byzantine_signed_summaries":total_injected,
        "split_vote_group_cases":split_votes,"two_of_three_quorums":quorum2,
        "all_quorum_results_equal_centralized":all(x["equivalent"] for x in case_results),
        "benign_false_alert_cases":sum(bool(x["alerts"]) for x in case_results if not x["attack"]),
        "attacked_detected_cases":sum(bool(x["alerts"]) for x in case_results if x["attack"]),
        "runner_observation":{"reports":len(runners),"unique_hostnames":len(set(hostnames)),
                              "unique_machine_id_hashes":len(set(machine_ids)),
                              "hostnames":hostnames},
        "controls":controls,
        "limitations":[
            "GitHub-hosted jobs are separate runner VMs/jobs, but GitHub does not expose or guarantee distinct physical hosts.",
            "This is a fault-injection experiment: compromise is emulated by a key-holding replica producing a validly signed false summary.",
            "Tolerance is f=1 per group. Two colluding replicas can create a false 2-of-3 majority.",
            "The immutable seed is Open5GS-derived, while scaled records above the original 13 logical slots are deterministic replicas.",
            "No hardware/TEE attestation of verifier execution is claimed."
        ],
        "case_results":case_results,
        "runner_reports":[{"group":r["group"],"replica":r["replica"],"runner":r["runner"]} for r in reports]
    }
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("cases","signed_summaries","byzantine_signed_summaries",
          "split_vote_group_cases","two_of_three_quorums","all_quorum_results_equal_centralized",
          "benign_false_alert_cases","attacked_detected_cases","runner_observation","controls")},indent=2))

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="op",required=True)
    w=sub.add_parser("worker");w.add_argument("--seed",required=True);w.add_argument("--group",type=int,required=True)
    w.add_argument("--replica",type=int,required=True);w.add_argument("--out",required=True)
    c=sub.add_parser("coordinator");c.add_argument("--seed",required=True);c.add_argument("--input-dir",required=True);c.add_argument("--out",required=True)
    a=ap.parse_args()
    if a.op=="worker": worker(a.seed,a.group,a.replica,a.out)
    else: coordinator(a.seed,a.input_dir,a.out)
if __name__=="__main__": main()
