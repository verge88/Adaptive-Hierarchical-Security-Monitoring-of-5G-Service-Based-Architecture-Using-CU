#!/usr/bin/env python3
"""Stage50 client: fail-closed handling of delay, drop, replay and tampering."""
import argparse,json,hashlib,os,socket,statistics,sys,time,urllib.request,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"stage44"))
from stage44_multinode_tcp import records_for_node,sha

FAULTS=("delay_timeout","drop","replay_previous","wrong_challenge","tamper_hash","duplicate_response")
REPS=10

def get(url):
    with urllib.request.urlopen(url.rstrip("/")+"/health",timeout=30) as r:return json.loads(r.read())
def post(url,obj,timeout):
    raw=json.dumps(obj,separators=(",",":"),sort_keys=True).encode()
    req=urllib.request.Request(url.rstrip("/")+"/verify",data=raw,headers={"Content-Type":"application/json"},method="POST")
    t=time.perf_counter()
    with urllib.request.urlopen(req,timeout=timeout) as r:body=r.read()
    return json.loads(body),(time.perf_counter()-t)*1000

def validate(resp,req,seen):
    if resp.get("schema")!="stage50-response-v1":return False,"schema"
    if resp.get("challenge")!=req["challenge"]:return False,"challenge"
    sec=resp.get("security",{})
    if sec.get("case_id")!=req["case_id"] or sec.get("cycle_id")!=req["cycle_id"]:return False,"cycle"
    if sec.get("records_sha256")!=req["records_sha256"]:return False,"records"
    if resp.get("verdict_sha256")!=sha(sec):return False,"verdict_hash"
    if req["challenge"] in seen:return False,"duplicate"
    seen.add(req["challenge"]);return True,"accepted"

def base_req(rows,case,session):
    return {"schema":"stage50-request-v1","session_id":session,"case_id":case,
            "cycle_id":uuid.uuid4().hex,"challenge":uuid.uuid4().hex,
            "records_sha256":sha(rows),"records":rows,"fault":"normal"}

def run(seed_path,url,out):
    seed=json.loads(Path(seed_path).read_text());h0=get(url);seen=set();normal=[];faults=[]
    # Normal path across three scales and both benign/attack seed variants.
    for n in (13,1040,4160):
      for trial in range(2):
       for attack in (False,True):
        rows=records_for_node(seed,n,trial,attack,0)
        q=base_req(rows,f"normal-{n}-{trial}-{int(attack)}",uuid.uuid4().hex)
        resp,rtt=post(url,q,60);ok,why=validate(resp,q,seen)
        if not ok:raise AssertionError("normal rejected "+why)
        normal.append(rtt)

    small=records_for_node(seed,13,0,False,0)
    rejected={k:0 for k in FAULTS};reasons={}
    for rep in range(REPS):
      # timeout from real server-side delay
      q=base_req(small,f"delay-{rep}",uuid.uuid4().hex);q["fault"]="delay";q["delay_s"]=0.8
      try:
        resp,rtt=post(url,q,0.15);ok,why=validate(resp,q,seen)
        if ok:raise AssertionError("delayed response accepted")
        rejected["delay_timeout"]+=1;reasons.setdefault("delay_timeout",why)
      except Exception as e:
        rejected["delay_timeout"]+=1;reasons.setdefault("delay_timeout",type(e).__name__)

      q=base_req(small,f"drop-{rep}",uuid.uuid4().hex);q["fault"]="drop"
      try:
        resp,rtt=post(url,q,5)
        ok,why=validate(resp,q,seen)
        if ok:raise AssertionError("dropped connection accepted")
        rejected["drop"]+=1;reasons.setdefault("drop",why)
      except Exception as e:
        rejected["drop"]+=1;reasons.setdefault("drop",type(e).__name__)

      # Prime session with a fresh accepted response, then request replay under new challenge/cycle.
      session=uuid.uuid4().hex
      prime=base_req(small,f"prime-{rep}",session);pr,_=post(url,prime,10);ok,why=validate(pr,prime,seen)
      if not ok:raise AssertionError("prime rejected")
      q=base_req(small,f"replay-{rep}",session);q["fault"]="replay_previous"
      resp,_=post(url,q,10);ok,why=validate(resp,q,seen)
      if ok:raise AssertionError("replay accepted")
      rejected["replay_previous"]+=1;reasons.setdefault("replay_previous",why)

      for name,wire in (("wrong_challenge","wrong_challenge"),("tamper_hash","tamper_hash")):
        q=base_req(small,f"{name}-{rep}",uuid.uuid4().hex);q["fault"]=wire
        resp,_=post(url,q,10);ok,why=validate(resp,q,seen)
        if ok:raise AssertionError(name+" accepted")
        rejected[name]+=1;reasons.setdefault(name,why)

      q=base_req(small,f"duplicate-{rep}",uuid.uuid4().hex)
      resp,_=post(url,q,10);ok,why=validate(resp,q,seen)
      if not ok:raise AssertionError("first duplicate test response rejected")
      ok2,why2=validate(resp,q,seen)
      if ok2:raise AssertionError("duplicate response accepted twice")
      rejected["duplicate_response"]+=1;reasons.setdefault("duplicate_response",why2)

    h1=get(url)
    if h1["host"].get("render_instance_id")!=h0["host"].get("render_instance_id"):
        raise AssertionError("Render instance changed")
    if any(rejected[k]!=REPS for k in FAULTS):raise AssertionError("fault not consistently rejected")
    report={"schema":"stage50-network-fault-replay-v1","normal_cases":len(normal),
            "normal_all_accepted":True,"normal_rtt_ms_median":round(statistics.median(normal),4),
            "normal_rtt_ms_p95":round(sorted(normal)[int(.95*(len(normal)-1))],4),
            "fault_repetitions_each":REPS,"faults_rejected":rejected,"rejection_reasons":reasons,
            "all_faults_fail_closed":all(v==REPS for v in rejected.values()),
            "render_host":h0["host"],
            "limitations":[
              "Delay and connection-drop faults are intentionally injected by the Render endpoint; they are not measurements of spontaneous Internet failure rates.",
              "The experiment verifies fail-closed transport freshness/integrity controls, not availability under a regional provider outage.",
              "TLS endpoint authentication is provided by the managed HTTPS service; no mutual TLS or hardware attestation is tested."
            ]}
    Path(out).write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n")
    print(json.dumps(report,indent=2,ensure_ascii=False))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--seed",required=True);ap.add_argument("--url",required=True);ap.add_argument("--out",required=True)
    a=ap.parse_args();run(a.seed,a.url,a.out)
if __name__=="__main__":main()
