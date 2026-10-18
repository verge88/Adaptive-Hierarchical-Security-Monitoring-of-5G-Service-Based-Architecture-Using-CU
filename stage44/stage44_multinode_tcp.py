#!/usr/bin/env python3
"""Stage44: actual HTTP/TCP multi-NAMESPACE benchmark, not multi-physical-host deployment.
Five Docker containers: four data/validation nodes and one independent root.
The 13 seed slots originate from actual Stage42 Open5GS; >13 are deterministic logical replicas.
No hardware-backed attestation; reproducible HMAC keys cannot attest a compromised node.
"""
import argparse, base64, copy, hashlib, hmac, json, os, random, socket, statistics
import time, uuid, urllib.request, concurrent.futures
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NODES=4
NF_TYPES=("nssf1","ausf1","bsf1","udm1","amf1","smf1","pcf1","scp1")
def canon(x): return json.dumps(x,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def sha(x): return hashlib.sha256(canon(x)).hexdigest()
def uuid_tag(u): return hashlib.sha256(str(u).lower().encode()).hexdigest()[:32]
def secret(seed,index=0):
    keydir=os.environ.get("STAGE44_KEYS_DIR")
    if keydir: return bytes.fromhex(Path(keydir,f"node{index}.key").read_text().strip())
    # Deterministic fallback only for local reproduction, not CI.
    return hashlib.sha256(("stage44-multinode/"+seed+"/"+str(index)).encode()).digest()
def sign(body,key): return hmac.new(key,canon(body),hashlib.sha256).hexdigest()
def envelope(body,key): return canon({"body":body,"mac_sha256":sign(body,key)})
def verify(blob,key,mode,cycle,index,policy_hash):
    d=json.loads(blob); b=d["body"]
    if not hmac.compare_digest(sign(b,key),d["mac_sha256"]): raise AssertionError("tamper/HMAC")
    if (b["mode"],b["cycle"],b["node"],b["policy_sha256"])!=(mode,cycle,index,policy_hash):
        raise AssertionError("stale cycle/policy/node")
    return b
def mutate_endpoint(profile,endpoint):
    p=copy.deepcopy(profile)
    p["ipv4Addresses"]=[endpoint]
    for svc in p.get("nfServices",[]):
        for ep in svc.get("ipEndPoints",[]):
            if "ipv4Address" in ep:ep["ipv4Address"]=endpoint
    return p
def slot_uuid(slot,rep,trial,global_i,seed):
    if rep==0: u=seed["seed_profiles"][slot]["profile"]["nfInstanceId"]
    else: u=str(uuid.uuid5(uuid.NAMESPACE_DNS,f"stage43/{slot}@{rep:04d}/{trial}"))
    if (global_i+11*trial)%23==0:
        u=str(uuid.uuid5(uuid.NAMESPACE_URL,f"restart/{slot}@{rep:04d}/{trial}"))
    return u
def records_for_node(seed,n,trial,attacked,node):
    keys=sorted(seed["seed_profiles"]);k=len(keys)
    a=(n*node)//NODES;b=(n*(node+1))//NODES
    end_i=n-1;end_rep,end_slot=divmod(end_i,k)
    last_uuid=slot_uuid(keys[end_slot],end_rep,trial,end_i,seed)
    # Bind cross-node duplicate to the final, independently mutated last UUID.
    if attacked and end_i%59==trial%59:
        last_uuid=str(uuid.uuid5(uuid.NAMESPACE_OID,f"spoof/{trial}/{end_i}"))
    out=[]
    for i in range(a,b):
        rep,si=divmod(i,k);slot=keys[si];src=seed["seed_profiles"][slot]
        p=copy.deepcopy(src["profile"]);policy=copy.deepcopy(src["policy"]);w=copy.deepcopy(src["witness"])
        endpoint=policy["endpoint"]
        if rep:
            addr=1+(rep*k+si)
            endpoint=f"198.{18+((addr>>16)&1)}.{(addr>>8)&255}.{addr&255}"
            p=mutate_endpoint(p,endpoint)
            policy["endpoint"]=endpoint;w["endpoint"]=endpoint
        u=slot_uuid(slot,rep,trial,i,seed)
        p["nfInstanceId"]=u;w["nf_instance_id"]=u
        lifecycle={"authorized":True,"transition":"completed_restart" if (i+11*trial)%23==0 else "active",
                   "cycle":trial,"policy_version":1}
        if attacked:
            if i%59==trial%59: p["nfInstanceId"]=str(uuid.uuid5(uuid.NAMESPACE_OID,f"spoof/{trial}/{i}"))
            if i%101==(trial*5+3)%101:p.setdefault("nfServices",[]).append({"serviceName":"injected-stage44-service"})
            if i%307==(trial*11+2)%307:p["nfStatus"]="DEREGISTERED"
            if n>64 and i==0:p["nfInstanceId"]=last_uuid  # explicit CROSS-NODE duplicate
        out.append({"slot":f"{slot}@{rep:04d}","profile":p,"policy":policy,
                    "witness":w,"lifecycle":lifecycle})
    return out
def check_group(records):
    alerts=[];claims=[]
    for row in records:
        slot=row["slot"];p=row["profile"];spec=row["policy"];w=row["witness"];ev=row["lifecycle"]
        if p.get("nfType")!=spec["nf_type"]:alerts.append((slot,"nf_type"))
        if sorted(p.get("ipv4Addresses",[]))!=[spec["endpoint"]]:alerts.append((slot,"endpoint"))
        if (p.get("fqdn") or "")!=(spec.get("fqdn") or ""): alerts.append((slot,"fqdn"))
        if sorted(x.get("serviceName","") for x in p.get("nfServices",[]))!=sorted(spec.get("service_names",[])):
            alerts.append((slot,"services"))
        if p.get("nfStatus")!="REGISTERED":alerts.append((slot,"nf_status"))
        if str(p.get("nfInstanceId","")).lower()!=str(w.get("nf_instance_id","")).lower():
            alerts.append((slot,"witness_uuid"))
        if w.get("nf_type")!=spec["nf_type"] or w.get("endpoint")!=spec["endpoint"]:
            alerts.append((slot,"witness_metadata"))
        if not w.get("process_alive") or not w.get("direct_sbi_tcp_reachable"):
            alerts.append((slot,"witness_liveness"))
        if ev.get("authorized") is not True or ev.get("policy_version")!=1:
            alerts.append((slot,"lifecycle"))
        claims.append((slot,uuid_tag(p.get("nfInstanceId",""))))
    return alerts,claims
def merge(alerts,claims):
    groups=defaultdict(list)
    for slot,tag in claims:groups[tag].append(slot)
    for slots in groups.values():
        if len(slots)>1:
            for slot in slots:alerts.append((slot,"duplicate_uuid"))
    return sorted(set(tuple(a) for a in alerts))
def central_parallel(records_groups,pool):
    # Persistent process pool, removes per-trial fork/startup penalty.
    return list(pool.map(check_group,records_groups))
def prepare_seed(artifact_dir,output):
    import zipfile
    d=Path(artifact_dir)
    report=json.loads((d/"stage42_report.json").read_text())
    snaps=json.loads((d/"stage42_witness_snapshots.json").read_text())
    policy=json.loads((d/"independent_live_policy.json").read_text())
    found={};seen_cycle={}
    for case in report["cases"]:
        if case["kind"]!="benign_real_restart":continue
        cycle=case["cycle"]
        for profile in case["observed_discovery_rows"]:
            addrs=profile.get("ipv4Addresses") or []
            for slot,spec in policy["slots"].items():
                if spec["endpoint"] in addrs:found[slot]=copy.deepcopy(profile);seen_cycle[slot]=cycle
    rec={}
    for slot,spec in policy["slots"].items():
        cycle=seen_cycle.get(slot,80)
        witness=copy.deepcopy(snaps[cycle]["snapshot"]["slots"][slot])
        p=found.get(slot)
        native=p is not None
        if not native:
            p={"nfInstanceId":witness["nf_instance_id"],"nfType":spec["nf_type"],
               "nfStatus":"REGISTERED","ipv4Addresses":[spec["endpoint"]],"fqdn":spec["fqdn"],
               "nfServices":[{"serviceName":v,"scheme":"http","nfServiceStatus":"REGISTERED",
                              "ipEndPoints":[{"ipv4Address":spec["endpoint"]}]} for v in spec["service_names"]]}
        if str(p["nfInstanceId"]).lower()!=str(witness["nf_instance_id"]).lower():
            raise AssertionError("seed UUID does not match signed witness "+slot)
        rec[slot]={"source_cycle":cycle,"profile_origin":"stage42_live_http2" if native else "constructed_nrf_from_policy",
                   "profile":p,"policy":spec,"witness":witness}
    seed={"schema":"stage44-seed-v1","source_run":39148421353,
          "source_sha256_report":hashlib.sha256((d/"stage42_report.json").read_bytes()).hexdigest(),
          "seed_profiles":rec}
    if len(rec)!=13 or sum(x["profile_origin"]=="stage42_live_http2" for x in rec.values())!=12:
        raise AssertionError("expected 12 observed live discovery profiles and one modeled NRF")
    Path(output).write_text(json.dumps(seed,sort_keys=True,indent=2,ensure_ascii=False)+"\n")
    print("STAGE44_SEED",len(rec),"12 live discovered profiles + NRF modeled",flush=True)

def worker_server(seed,index,port):
    key=secret(seed["source_sha256_report"],index);ph=sha(seed["seed_profiles"])
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path=="/health":
                self.send_response(200);self.end_headers();self.wfile.write(b"ok");return
            try:
                from urllib.parse import urlsplit,parse_qs
                q=parse_qs(urlsplit(self.path).query)
                mode=q["mode"][0]; n=int(q["n"][0]);trial=int(q["trial"][0]);attacked=q["attack"][0]=="1"
                if mode not in ("central","hier") or n not in (13,1040,4160,8320):raise ValueError("invalid run")
                t0=time.perf_counter_ns(); c0=time.process_time_ns()
                records=records_for_node(seed,n,trial,attacked,index)
                if mode=="central":
                    body={"schema":"stage44-raw-v1","mode":mode,"node":index,
                          "cycle":trial,"policy_sha256":ph,"items":records}
                else:
                    alerts,ids=check_group(records)
                    body={"schema":"stage44-summary-v1","mode":mode,"node":index,
                          "cycle":trial,"policy_sha256":ph,"count":len(records),
                          "source_sha256":sha(records),"alerts":alerts,"uuid_tags":ids}
                # Timing is kept in HTTP headers, NOT in the signed security payload.
                encoded=envelope(body,key)
                wall=(time.perf_counter_ns()-t0)/1e6;cpu=(time.process_time_ns()-c0)/1e6
                self.send_response(200);self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(encoded)))
                self.send_header("X-Worker-Compute-Wall-Ms",f"{wall:.5f}")
                self.send_header("X-Worker-Compute-Cpu-Ms",f"{cpu:.5f}")
                self.end_headers();self.wfile.write(encoded)
            except Exception as e:
                b=str(e).encode();self.send_response(500);self.end_headers();self.wfile.write(b)
        def log_message(self,format,*args):pass
    server=ThreadingHTTPServer(("0.0.0.0",port),Handler)
    print("STAGE44_WORKER_READY",index,socket.gethostname(),flush=True)
    server.serve_forever()

def fetch_node(index,mode,n,trial,attack):
    url=f"http://stage44-node-{index}:8080/run?mode={mode}&n={n}&trial={trial}&attack={int(attack)}"
    with urllib.request.urlopen(url,timeout=240) as r:
        body=r.read();meta=dict(r.headers.items())
    return body,meta

def network_trial(seed,n,trial,attack,mode,executor,compute_pool):
    ph=sha(seed["seed_profiles"])
    t0=time.perf_counter_ns(); c0=time.process_time_ns()
    futs=[executor.submit(fetch_node,i,mode,n,trial,attack) for i in range(NODES)]
    packets=[f.result(timeout=250) for f in futs]
    ingress_end=time.perf_counter_ns()
    received=[]; bytes_to_root=0;cpu_worker=[];wall_worker=[]
    for index,(packet,headers) in enumerate(packets):
        b=verify(packet,secret(seed["source_sha256_report"],index),mode,trial,index,ph)
        bytes_to_root+=len(packet)
        cpu_worker.append(float(headers["X-Worker-Compute-Cpu-Ms"]))
        wall_worker.append(float(headers["X-Worker-Compute-Wall-Ms"]))
        received.append(b)
    if mode=="central":
        data=[p["items"] for p in received]
        count=sum(len(v) for v in data)
        # Process pool created PER trial, symmetrical four processes but includes startup overhead.
        partial=central_parallel(data,compute_pool)
        alerts=[x for a,_ in partial for x in a];ids=[x for _,c in partial for x in c]
    else:
        count=sum(p["count"] for p in received)
        alerts=[x for p in received for x in p["alerts"]]
        ids=[x for p in received for x in p["uuid_tags"]]
    if count!=n or len(ids)!=n or len(set(slot for slot,_ in ids))!=n:
        raise AssertionError("incomplete/duplicate slot coverage")
    verdict=merge(alerts,ids)
    return {"n":n,"trial":trial,"attack":attack,"mode":mode,
            "node_count":NODES,"checked":count,"alerts":len(verdict),"alert_sha256":sha(verdict),
            "has_cross_node_duplicate": any(v=="duplicate_uuid" for _,v in verdict),
            "root_ingress_bytes":bytes_to_root,
            "elapsed_ms":(time.perf_counter_ns()-t0)/1e6,
            "network_receive_ms":(ingress_end-t0)/1e6,
            "coordinator_main_cpu_ms":(time.process_time_ns()-c0)/1e6,
            "worker_cpu_ms_sum":sum(cpu_worker),"worker_prepare_wall_ms_max":max(wall_worker)}

def security_negative_tests(seed):
    key=secret(seed["source_sha256_report"],0);ph=sha(seed["seed_profiles"])
    b={"mode":"hier","node":0,"cycle":991,"policy_sha256":ph}
    raw=envelope(b,key);broken=json.loads(raw);broken["body"]["node"]=1
    tests={}
    for name,blob,cycle,policy_hash in (
        ("tampered_mac",canon(broken),991,ph),
        ("replayed_cycle",raw,992,ph),
        ("wrong_policy_hash",raw,991,"0"*64)):
        try:verify(blob,key,"hier",cycle,0,policy_hash)
        except AssertionError:tests[name]=True
        else:raise AssertionError("negative check accepted "+name)
    return tests

def run_coordinator(args):
    seed=json.loads(Path(args.seed).read_text())
    security=security_negative_tests(seed)
    records=[];comparisons=[]
    nodes={f"stage44-node-{i}":socket.gethostbyname(f"stage44-node-{i}") for i in range(NODES)}
    print("STAGE44_NETWORK_NODES",nodes,flush=True)
    for i in range(NODES):
        with urllib.request.urlopen(f"http://stage44-node-{i}:8080/health",timeout=30) as r:
            assert r.read()==b"ok"
    with concurrent.futures.ThreadPoolExecutor(max_workers=NODES) as pool, concurrent.futures.ProcessPoolExecutor(max_workers=NODES) as compute_pool:
        for n in (13,1040,4160,8320):
            for attack in (False,True):
                for trial in range(args.repeats):
                    # Deterministic paired data: both workers derive the same immutable seed
                    if trial%2==0:
                        c=network_trial(seed,n,trial,attack,"central",pool,compute_pool)
                        h=network_trial(seed,n,trial,attack,"hier",pool,compute_pool)
                    else:
                        h=network_trial(seed,n,trial,attack,"hier",pool,compute_pool)
                        c=network_trial(seed,n,trial,attack,"central",pool,compute_pool)
                    if (c["alert_sha256"],c["alerts"],c["checked"])!=(h["alert_sha256"],h["alerts"],h["checked"]):
                        raise AssertionError("non-identical verdicts "+str((n,trial,attack)))
                    if attack and n>64 and not c["has_cross_node_duplicate"]:
                        raise AssertionError("cross-node duplicate escaped")
                    if not attack and (c["alerts"] or h["alerts"]):
                        raise AssertionError("false alarm in benign run")
                    records.extend([c,h]);comparisons.append({"n":n,"attack":attack,"trial":trial,"match":True})
                    print("PAIR",n,attack,trial,"bytes",c["root_ingress_bytes"],h["root_ingress_bytes"],
                          "wall_ms",round(c["elapsed_ms"],2),round(h["elapsed_ms"],2),flush=True)
    summary={}
    for n in (13,1040,4160,8320):
        sub=[r for r in records if r["n"]==n]
        base=statistics.median(r["root_ingress_bytes"] for r in sub if r["mode"]=="central")
        hier=statistics.median(r["root_ingress_bytes"] for r in sub if r["mode"]=="hier")
        summary[str(n)]={"central_bytes_median":base,"hier_bytes_median":hier,
                          "bytes_reduction_pct":round(100*(1-hier/base),4)}
        for attack in (False,True):
            for mode in ("central","hier"):
                rows=[r for r in sub if r["attack"]==attack and r["mode"]==mode]
                prefix=("attacked_" if attack else "benign_")+mode
                summary[str(n)][prefix+"_latency_ms_median"]=round(statistics.median(x["elapsed_ms"] for x in rows),4)
                summary[str(n)][prefix+"_worker_cpu_ms_sum_median"]=round(statistics.median(x["worker_cpu_ms_sum"] for x in rows),4)
    report={"schema":"stage44-five-node-real-tcp-v2","network_profile":args.profile,
            "topology":{"coordinator":"Docker isolated namespace, python 3.11","workers":nodes,
                        "physical_hosts":1,"isolated_network_namespaces":5,
                        "transport":"Docker bridge virtual Ethernet + real HTTP/TCP, no physical WAN",
                        "capacity":"4 central validation processes vs 4 group-node validation processes"},
            "seed":{"source":"Stage42 live Open5GS v2.7.6, 80 confirmed restarts",
                    "real_slots":13,"native_live_discovery_profiles":12,
                    "modelled_nrf_profile":1,"source_report_sha256":seed["source_sha256_report"]},
            "limitations":["Only one runner physical host; Docker network namespaces are NOT 5 physical machines.",
                          "Counts above 13 are synthetically replicated profiles, not running Open5GS functions.",
                          "Both paths use the same semantic detector but place computation differently.",
                          "HMAC is benchmark integrity, not independently attested truth or a TEE.",
                          "Application-layer HTTP body length measures payload, not Ethernet/TCP/IP headers.",
                          "Central root uses persistent four-process pool, not per-trial process startup.",
                          "No shared unpredictable external traffic or fault-tolerant orchestrator."],
            "security_negative_tests":security,"paired_cases":len(comparisons),
            "individually_processed":len(records),"verdict_equivalence":all(x["match"] for x in comparisons),
            "summary":summary,"records":records}
    Path(args.output).mkdir(parents=True,exist_ok=True)
    Path(args.output,"stage44_report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    lines=[f"# Stage44 five-node real TCP benchmark — {args.profile}","",
           f"- 5 Docker containers/network namespaces, 1 physical host; 4 remote validation nodes",
           f"- {len(comparisons)} paired trials; {len(records)} observations; ALL decisions equal",
           f"- Negative cryptographic controls: {security}","","| Logical NF | Central bytes | Hierarchy bytes | Saved | Central clean ms | Hier clean ms |"]
    lines.append("|---:|---:|---:|---:|---:|---:|")
    for n,row in summary.items():
        lines.append(f"| {n} | {row['central_bytes_median']:.0f} | {row['hier_bytes_median']:.0f} | "
                     f"{row['bytes_reduction_pct']:.2f}% | {row['benign_central_latency_ms_median']:.2f} | "
                     f"{row['benign_hier_latency_ms_median']:.2f} |")
    lines.extend(["","The measurements are from a containerized 5-node real TCP network on one CI host;",
                  "the 8320 replicas are synthetic, not 8320 real 5G network functions."])
    Path(args.output,"STAGE44_RESULT.md").write_text("\n".join(lines)+"\n")
    print("\n".join(lines),flush=True)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("operation",choices=("prepare-seed","worker","coordinator"))
    ap.add_argument("--artifact-dir",default="/stage42")
    ap.add_argument("--seed",default="/data/stage44_seed.json")
    ap.add_argument("--output",default="/out")
    ap.add_argument("--node",type=int,default=0)
    ap.add_argument("--port",type=int,default=8080)
    ap.add_argument("--repeats",type=int,default=5)
    ap.add_argument("--profile",choices=("lan","wan15ms25mbit"),default="lan")
    args=ap.parse_args()
    if args.operation=="prepare-seed":prepare_seed(args.artifact_dir,args.seed)
    elif args.operation=="worker":worker_server(json.loads(Path(args.seed).read_text()),args.node,args.port)
    else:run_coordinator(args)
if __name__=="__main__":main()
