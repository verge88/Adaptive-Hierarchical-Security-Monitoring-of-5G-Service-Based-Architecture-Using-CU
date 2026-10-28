#!/usr/bin/env python3
"""Stage47 GitHub-to-Render cross-host validation experiment."""
import argparse
import hashlib
import json
import os
import socket
import statistics
import sys
import time
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import check_group, merge, records_for_node, sha

NODES=4
SIZES=(13,1040,4160)
TRIALS=4

def gh_host():
    def fh(p):
        try:return hashlib.sha256(Path(p).read_bytes()).hexdigest()
        except Exception:return None
    return {"provider":"github-actions","hostname":socket.gethostname(),
            "machine_id_sha256":fh("/etc/machine-id"),
            "runner_name":os.getenv("RUNNER_NAME"),"runner_os":os.getenv("RUNNER_OS"),
            "runner_arch":os.getenv("RUNNER_ARCH"),"github_run_id":os.getenv("GITHUB_RUN_ID")}

def post(url,obj,timeout=90):
    raw=json.dumps(obj,separators=(",",":"),sort_keys=True).encode()
    req=urllib.request.Request(url.rstrip("/")+"/verify",data=raw,
                               headers={"Content-Type":"application/json"},method="POST")
    t0=time.perf_counter_ns()
    with urllib.request.urlopen(req,timeout=timeout) as r:
        response_bytes=r.read()
    return json.loads(response_bytes),(time.perf_counter_ns()-t0)/1e6,len(raw),len(response_bytes)

def health(url):
    with urllib.request.urlopen(url.rstrip("/")+"/health",timeout=60) as r:
        return json.loads(r.read())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--seed",required=True)
    ap.add_argument("--render-url",required=True)
    ap.add_argument("--output",default="stage47_report.json")
    a=ap.parse_args()
    seed=json.loads(Path(a.seed).read_text())
    h0=health(a.render_url)
    first_host=h0["host"]
    records_out=[]
    global_results=[]
    for n in SIZES:
        for trial in range(TRIALS):
            for attack in (False,True):
                cid=f"n{n}-t{trial}-a{int(attack)}"
                remote_alerts=[];remote_ids=[]
                local_alerts=[];local_ids=[]
                for group in range(NODES):
                    rows=records_for_node(seed,n,trial,attack,group)
                    la,li=check_group(rows)
                    local_alerts.extend(la);local_ids.extend(li)
                    challenge=uuid.uuid4().hex
                    request={"schema":"stage47-verify-request-v1","case_id":cid,"group":group,
                             "challenge":challenge,"records_sha256":sha(rows),"records":rows}
                    response,rtt_ms,tx,rx=post(a.render_url,request)
                    if response.get("challenge")!=challenge:
                        raise AssertionError("challenge mismatch")
                    sec=response["security"]
                    if sec["case_id"]!=cid or sec["group"]!=group or sec["records_sha256"]!=sha(rows):
                        raise AssertionError("response binding mismatch")
                    if response["verdict_sha256"]!=sha(sec):
                        raise AssertionError("response verdict hash mismatch")
                    if (sec["alerts"],sec["uuid_tags"])!=(la,li):
                        raise AssertionError("Render/local group mismatch "+cid+" g"+str(group))
                    if response["host"].get("process_nonce_sha256")!=first_host.get("process_nonce_sha256"):
                        raise AssertionError("Render service instance changed during experiment")
                    remote_alerts.extend(sec["alerts"]);remote_ids.extend(sec["uuid_tags"])
                    records_out.append({"case_id":cid,"n":n,"trial":trial,"attack":attack,
                                        "group":group,"checked":len(rows),"match":True,
                                        "rtt_ms":round(rtt_ms,6),"request_bytes":tx,"response_bytes":rx,
                                        "render_compute_ms":response["compute_ms"],
                                        "render_host":response["host"]})
                actual=merge(remote_alerts,remote_ids)
                expected=merge(local_alerts,local_ids)
                if actual!=expected:
                    raise AssertionError("global Render/local mismatch "+cid)
                if not attack and actual:
                    raise AssertionError("false alert "+cid)
                if attack and not actual:
                    raise AssertionError("attack escaped "+cid)
                global_results.append({"case_id":cid,"n":n,"trial":trial,"attack":attack,
                                       "match":True,"alerts":len(actual),"alert_sha256":sha(actual)})
                print("STAGE47_CASE",cid,"alerts",len(actual),flush=True)
    h1=health(a.render_url)
    if h1["host"].get("process_nonce_sha256")!=first_host.get("process_nonce_sha256"):
        raise AssertionError("Render instance changed before final health")
    report={
        "schema":"stage47-render-external-host-v1",
        "render_url":a.render_url,
        "github_host":gh_host(),
        "render_host":first_host,
        "global_cases":len(global_results),
        "remote_group_checks":len(records_out),
        "all_group_results_equal_local":all(x["match"] for x in records_out),
        "all_global_results_equal_local":all(x["match"] for x in global_results),
        "benign_false_alert_cases":sum(x["alerts"]>0 for x in global_results if not x["attack"]),
        "attacked_detected_cases":sum(x["alerts"]>0 for x in global_results if x["attack"]),
        "network":{"https_requests":len(records_out)+2,
                   "request_bytes_total":sum(x["request_bytes"] for x in records_out),
                   "response_bytes_total":sum(x["response_bytes"] for x in records_out),
                   "rtt_ms_median":round(statistics.median(x["rtt_ms"] for x in records_out),4),
                   "rtt_ms_p95":round(sorted(x["rtt_ms"] for x in records_out)[int(.95*(len(records_out)-1))],4)},
        "limitations":[
            "Render is an external managed-cloud execution host; this experiment does not expose or attest its underlying physical machine.",
            "GitHub Actions and Render are separate administrative/execution platforms, but physical-host identity is not available from either provider.",
            "The Render verifier is reached over public HTTPS and independently implements the semantic group checks.",
            "No TEE, TPM quote, cloud instance attestation, or dedicated bare-metal identity is claimed.",
            "The Stage44 seed is derived from Stage42 live Open5GS evidence; scales above 13 logical slots use deterministic replicas."
        ],
        "global_results":global_results,
        "records":records_out
    }
    Path(a.output).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps({k:report[k] for k in ("global_cases","remote_group_checks",
          "all_group_results_equal_local","all_global_results_equal_local",
          "benign_false_alert_cases","attacked_detected_cases","network",
          "github_host","render_host")},indent=2,ensure_ascii=False))
if __name__=="__main__":main()
