#!/usr/bin/env python3
from __future__ import annotations
import argparse,asyncio,hashlib,json,math,os,signal,socket,statistics,subprocess,time
from pathlib import Path
from urllib.parse import urlencode
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived,ResponseReceived,StreamEnded,StreamReset
from h2.settings import SettingCodes

ROOT=Path("/tmp/stage54")
WITNESS=Path("/run/stage54/witness")
NRF_BIN="/src/open5gs/build/src/nrf/open5gs-nrfd"
NSSF_BIN="/src/open5gs/build/src/nssf/open5gs-nssfd"
NRF_HOST="127.0.0.10"; PORT=80

def tcp_ready(host,port=80,timeout=.15):
    try:
        with socket.create_connection((host,port),timeout=timeout): return True
    except OSError: return False

def wait_tcp(host,port=80,seconds=30):
    d=time.time()+seconds
    while time.time()<d:
        if tcp_ready(host,port): return
        time.sleep(.05)
    raise RuntimeError(f"TCP not ready {host}:{port}")

def endpoint_for(worker,index):
    # Use the exact loopback address proven in Stage42/52 and make each live
    # NF endpoint unique by port. Worker ranges do not overlap.
    port=10000+worker*1000+(index-1)
    if port>65535: raise ValueError("worker/index exceeds port allocation")
    return "127.0.0.12",port

def nrf_config(peer_limit):
    return f"""logger:
  level: error
global:
  max:
    peer: {peer_limit}
nrf:
  serving:
    - plmn_id:
        mcc: 999
        mnc: 70
  sbi:
    server:
      - address: 127.0.0.10
        port: 80
"""

def scp_config(peer_limit):
    return f"""logger:
  level: error
global:
  max:
    peer: {peer_limit}
scp:
  sbi:
    server:
      - address: 127.0.0.11
        port: 80
    client:
      nrf:
        - uri: http://127.0.0.10:80
"""

def nssf_config(address,port):
    return f"""logger:
  level: error
global:
nssf:
  sbi:
    server:
      - address: {address}
        port: {port}
    client:
      nrf:
        - uri: http://127.0.0.10:80
      nsi:
        - uri: http://127.0.0.10:80
          s_nssai:
            sst: 1
            sd: 1
"""

async def h2_get(path,timeout=15,window_bytes=None):
    reader,writer=await asyncio.open_connection(NRF_HOST,PORT)
    conn=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
    body=bytearray();status=None
    try:
        conn.initiate_connection()
        if window_bytes:
            conn.update_settings({SettingCodes.INITIAL_WINDOW_SIZE:int(window_bytes)})
            if int(window_bytes) > 65535:
                conn.increment_flow_control_window(int(window_bytes)-65535)
        stream=conn.get_next_available_stream_id()
        conn.send_headers(stream,[(":method","GET"),(":scheme","http"),
          (":authority",f"{NRF_HOST}:{PORT}"),(":path",path),
          ("accept","application/json"),("user-agent","stage54-scale-worker")],end_stream=True)
        writer.write(conn.data_to_send());await writer.drain()
        while True:
            chunk=await asyncio.wait_for(reader.read(1<<20),timeout)
            if not chunk: raise RuntimeError("HTTP/2 peer closed")
            for ev in conn.receive_data(chunk):
                if isinstance(ev,ResponseReceived) and ev.stream_id==stream:
                    status=int(dict(ev.headers)[":status"])
                elif isinstance(ev,DataReceived) and ev.stream_id==stream:
                    body.extend(ev.data);conn.acknowledge_received_data(ev.flow_controlled_length,ev.stream_id)
                elif isinstance(ev,StreamReset) and ev.stream_id==stream:
                    raise RuntimeError("HTTP/2 stream reset")
                elif isinstance(ev,StreamEnded) and ev.stream_id==stream:
                    return status,bytes(body)
            out=conn.data_to_send()
            if out: writer.write(out);await writer.drain()
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

async def discover_nssf(limit=None,window_bytes=None,timeout=30):
    params={"target-nf-type":"NSSF","requester-nf-type":"AMF"}
    if limit is not None:
        params["limit"]=str(int(limit))
    q=urlencode(params)
    st,body=await h2_get("/nnrf-disc/v1/nf-instances?"+q,timeout=timeout,window_bytes=window_bytes)
    if st!=200: raise RuntimeError(f"discovery status {st}: {body[:300]!r}")
    doc=json.loads(body)
    rows=doc.get("nfInstances")
    if not isinstance(rows,list): raise RuntimeError("missing nfInstances")
    return rows,len(body),doc

async def run_discovery_sweep():
    limits=[10,25,50,100,200,400,800,1200,1600,2000,3000,4000,None]
    modes=[("baseline",None),("window16m",16*1024*1024)]
    probes=[]
    for mode,window in modes:
        for limit in limits:
            t=time.time()
            rec={"mode":mode,"limit":limit,"window_bytes":window}
            try:
                rows,n,doc=await discover_nssf(limit=limit,window_bytes=window,timeout=30)
                rec.update({
                    "ok":True,
                    "status":200,
                    "returned_profiles":len(rows),
                    "response_bytes":n,
                    "elapsed_seconds":time.time()-t,
                    "num_nf_inst_complete":doc.get("numNfInstComplete"),
                })
            except Exception as exc:
                rec.update({
                    "ok":False,
                    "elapsed_seconds":time.time()-t,
                    "error":f"{type(exc).__name__}: {exc}",
                })
            probes.append(rec)
            print("DISCOVERY_PROBE "+json.dumps(rec,sort_keys=True),flush=True)
    return probes


async def nfm_get_profile(nf_id):
    st,body=await h2_get(f"/nnrf-nfm/v1/nf-instances/{nf_id}",timeout=8)
    if st!=200:
        raise RuntimeError(f"NFM GET {nf_id} status={st} body={body[:300]!r}")
    doc=json.loads(body)
    if str(doc.get("nfInstanceId","")).lower()!=str(nf_id).lower():
        raise RuntimeError(f"NFM UUID mismatch for {nf_id}")
    if doc.get("nfType")!="NSSF":
        raise RuntimeError(f"NFM type mismatch for {nf_id}: {doc.get('nfType')}")
    if doc.get("nfStatus")!="REGISTERED":
        raise RuntimeError(f"NFM status mismatch for {nf_id}: {doc.get('nfStatus')}")
    return doc,len(body)

async def verify_registered_profiles(nf_ids,deadline):
    pending=set(str(x).lower() for x in nf_ids)
    docs={};bytes_total=0;last_errors={}
    while pending and time.time()<deadline:
        for nf_id in list(pending):
            if time.time()>=deadline: break
            try:
                doc,n=await nfm_get_profile(nf_id)
                docs[nf_id]=doc
                bytes_total+=n
                pending.remove(nf_id)
                last_errors.pop(nf_id,None)
            except Exception as exc:
                last_errors[nf_id]=f"{type(exc).__name__}: {exc}"
        if pending:
            await asyncio.sleep(.2)
    return docs,pending,bytes_total,last_errors

def proc_status(pid):
    d={}
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if ":" in line:
                k,v=line.split(":",1);d[k]=v.strip()
        stat=Path(f"/proc/{pid}/stat").read_text().split()
        return {
          "rss_kib":int(d.get("VmRSS","0 kB").split()[0]),
          "threads":int(d.get("Threads","0")),
          "fds":len(list(Path(f"/proc/{pid}/fd").iterdir())),
          "cpu_ticks":int(stat[13])+int(stat[14]),
        }
    except Exception:
        return None

def cgroup_memory_current():
    for p in (Path("/sys/fs/cgroup/memory.current"),):
        try:return int(p.read_text())
        except Exception:pass
    return None

def read_witness():
    rows={}
    for p in WITNESS.glob("*.tsv"):
        try:
            pid_s,enum_s,u=p.read_text().strip().split("\t")
            rows[int(pid_s)]={"nf_enum":int(enum_s),"nf_instance_id":u.lower()}
        except Exception: pass
    return rows

def host_mem():
    m={}
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if ":" in line:
                k,v=line.split(":",1);m[k]=int(v.strip().split()[0])
    except Exception:pass
    return m

def pct(values,p):
    if not values:return None
    a=sorted(values);return a[max(0,min(len(a)-1,math.ceil(p*len(a))-1))]

def tail(path,n=12000):
    try:return Path(path).read_text(errors="replace")[-n:]
    except Exception:return ""

def terminate(procs):
    for p in procs:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGTERM)
            except ProcessLookupError:pass
    d=time.time()+8
    while time.time()<d and any(p.poll() is None for p in procs):time.sleep(.05)
    for p in procs:
        if p.poll() is None:
            try:os.killpg(p.pid,signal.SIGKILL)
            except ProcessLookupError:pass

async def main_async(args):
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    ROOT.mkdir(parents=True,exist_ok=True);WITNESS.mkdir(parents=True,exist_ok=True)
    for p in WITNESS.glob("*.tsv"):p.unlink()
    peer_limit=max(8192,args.count+2048)
    (ROOT/"nrf.yaml").write_text(nrf_config(peer_limit))
    env={**os.environ,"STAGE38_WITNESS_DIR":str(WITNESS)}
    nrf_log_path=out/"nrf.log";nssf_log_path=out/"nssf.log"
    nrf_log=open(nrf_log_path,"ab",buffering=0);nssf_log=open(nssf_log_path,"ab",buffering=0)
    nrf=subprocess.Popen([NRF_BIN,"-c",str(ROOT/"nrf.yaml")],stdout=nrf_log,stderr=subprocess.STDOUT,start_new_session=True,env=env)
    workers=[]
    t0=time.time()
    try:
        wait_tcp(NRF_HOST,PORT,30)
        time.sleep(.5)
        endpoints=[]
        for i in range(1,args.count+1):
            host,port=endpoint_for(args.worker,i);endpoints.append((host,port))
            cfg=ROOT/f"nssf-{i:04d}.yaml";cfg.write_text(nssf_config(host,port))
            p=subprocess.Popen([NSSF_BIN,"-c",str(cfg)],stdout=nssf_log,stderr=subprocess.STDOUT,start_new_session=True,env=env)
            workers.append(p)
            if i%args.batch==0: time.sleep(args.batch_pause)
        launch_done=time.time()
        deadline=time.time()+args.converge_timeout
        pids=[p.pid for p in workers]

        # First prove that every launched NSSF emitted a native runtime UUID.
        while time.time()<deadline:
            if nrf.poll() is not None:
                diag={"schema":"stage54-control-process-exit-v1","component":"nrf","returncode":nrf.returncode,
                  "worker":args.worker,"requested":args.count,"witness_files":len(read_witness()),
                  "nrf_log_tail":tail(nrf_log_path)}
                (out/"failure_diagnostic.json").write_text(json.dumps(diag,indent=2)+"\n")
                print(json.dumps(diag,indent=2),flush=True)
                raise RuntimeError(f"NRF exited rc={nrf.returncode}")
            dead=sum(p.poll() is not None for p in workers)
            if dead:
                raise RuntimeError(f"{dead} NSSF processes exited before convergence")
            wit=read_witness()
            if all(pid in wit for pid in pids):
                break
            await asyncio.sleep(.1)
        else:
            raise RuntimeError(
                f"native witness timeout "
                f"{sum(pid in read_witness() for pid in pids)}/{args.count}"
            )

        wit=read_witness()
        witness_ids=[wit[pid]["nf_instance_id"] for pid in pids]
        docs,pending,nfm_bytes,last_nfm_errors=await verify_registered_profiles(
            witness_ids,deadline
        )
        if pending:
            diag={"schema":"stage54-nfm-timeout-v1","worker":args.worker,
              "requested":args.count,"verified_nfm_profiles":len(docs),
              "pending_profiles":len(pending),
              "sample_pending_uuid_hashes":[
                  hashlib.sha256(x.encode()).hexdigest()
                  for x in sorted(pending)[:10]
              ],
              "sample_errors":dict(list(last_nfm_errors.items())[:10]),
              "live_processes":sum(p.poll() is None for p in workers),
              "nrf_returncode":nrf.poll(),
              "nrf_log_tail":tail(nrf_log_path)}
            (out/"failure_diagnostic.json").write_text(
                json.dumps(diag,indent=2)+"\n"
            )
            print(json.dumps(diag,indent=2),flush=True)
            raise RuntimeError(
                f"NFM registration verification timeout "
                f"{len(docs)}/{args.count}"
            )

        # Stage55 maps the SearchResult boundary explicitly. Each probe opens a
        # fresh HTTP/2 connection and tests both the default receive window and
        # a 16 MiB initial stream/connection window.
        discovery_sweep=await run_discovery_sweep()
        (out/"discovery_sweep.json").write_text(
            json.dumps(discovery_sweep,indent=2,sort_keys=True)+"\n"
        )
        full_baseline=next(
            (x for x in discovery_sweep
             if x["mode"]=="baseline" and x["limit"] is None),None)
        bulk_discovery_ok=bool(
            full_baseline and full_baseline.get("ok") and
            full_baseline.get("returned_profiles")==args.count
        )
        bulk_discovery_count=(
            full_baseline.get("returned_profiles")
            if full_baseline and full_baseline.get("ok") else None
        )
        discovery_bytes=(
            full_baseline.get("response_bytes")
            if full_baseline and full_baseline.get("ok") else 0
        )
        bulk_discovery_error=(
            None if bulk_discovery_ok else
            (full_baseline or {}).get("error","full baseline did not return all profiles")
        )

        ready=time.time()
        discovered_ids=sorted(docs)
        reachable=sum(tcp_ready(h,p,.12) for h,p in endpoints)
        before={pid:proc_status(pid) for pid in pids}
        before={k:v for k,v in before.items() if v}
        mem_before=cgroup_memory_current()
        ready_doc={"schema":"stage54-worker-ready-v1","worker":args.worker,"count":args.count,
          "ready_unix":ready,"launch_start_unix":t0,"launch_done_unix":launch_done,
          "registration_convergence_seconds":ready-t0,"hold_seconds":args.hold_seconds}
        (out/"ready.json").write_text(json.dumps(ready_doc,indent=2)+"\n")
        time.sleep(args.hold_seconds)
        stop=time.time()
        after={pid:proc_status(pid) for pid in pids}
        after={k:v for k,v in after.items() if v}
        mem_after=cgroup_memory_current()
        clk=os.sysconf(os.sysconf_names["SC_CLK_TCK"])
        common=sorted(set(before)&set(after))
        cpu_delta=sum(after[p]["cpu_ticks"]-before[p]["cpu_ticks"] for p in common)/clk
        rss=[after[p]["rss_kib"] for p in common]
        fds=[after[p]["fds"] for p in common]
        threads=[after[p]["threads"] for p in common]
        result={
          "schema":"stage55-single-nrf-discovery-boundary-v1","open5gs_ref":"v2.7.6",
          "worker":args.worker,"requested_nf":args.count,"nrf_scp_peer_limit":peer_limit,
          "single_nrf_process": True, "scp_present": False,
          "nrf_pid": nrf.pid, "nrf_alive_at_measurement": nrf.poll() is None,
          "live_processes":sum(p.poll() is None for p in workers),
          "unique_pids":len(set(pids)),"witness_records":len(witness_ids),
          "unique_witness_uuids":len(set(witness_ids)),
          "nrf_individually_verified_profiles":len(docs),
          "unique_nfm_profile_uuids":len(set(discovered_ids)),
          "witness_nfm_uuid_sets_equal":set(witness_ids)==set(discovered_ids),
          "nfm_response_bytes_total":nfm_bytes,
          "bulk_discovery_ok":bulk_discovery_ok,
          "bulk_discovery_count":bulk_discovery_count,
          "bulk_discovery_response_bytes":discovery_bytes,
          "bulk_discovery_error":bulk_discovery_error,
          "discovery_probe_count":len(discovery_sweep),
          "discovery_probe_successes":sum(bool(x.get("ok")) for x in discovery_sweep),
          "direct_sbi_reachable":reachable,
          "registration_convergence_seconds":ready-t0,
          "launch_seconds":launch_done-t0,
          "hold_seconds":args.hold_seconds,
          "ready_unix":ready,"stop_unix":stop,
          "rss_kib_total":sum(rss),"rss_kib_median":statistics.median(rss) if rss else None,
          "rss_kib_p95":pct(rss,.95),"rss_kib_max":max(rss) if rss else None,
          "fds_total":sum(fds),"fds_median":statistics.median(fds) if fds else None,
          "threads_total":sum(threads),"threads_median":statistics.median(threads) if threads else None,
          "nssf_cpu_seconds_during_hold":cpu_delta,
          "nssf_cpu_cores_average_during_hold":cpu_delta/max(args.hold_seconds,.001),
          "cgroup_memory_current_before_hold":mem_before,
          "cgroup_memory_current_after_hold":mem_after,
          "host_meminfo_kib":host_mem(),
          "binary_sha256":hashlib.sha256(Path(NSSF_BIN).read_bytes()).hexdigest(),
          "endpoint_first":f"{endpoints[0][0]}:{endpoints[0][1]}","endpoint_last":f"{endpoints[-1][0]}:{endpoints[-1][1]}",
        }
        checks={
          "all_processes_live":result["live_processes"]==args.count,
          "all_pids_unique":result["unique_pids"]==args.count,
          "all_witnesses_present":result["witness_records"]==args.count,
          "all_witness_uuids_unique":result["unique_witness_uuids"]==args.count,
          "all_profiles_individually_verified":result["nrf_individually_verified_profiles"]==args.count,
          "all_nfm_uuids_unique":result["unique_nfm_profile_uuids"]==args.count,
          "witness_matches_nrf":result["witness_nfm_uuid_sets_equal"],
          "all_sbi_reachable":result["direct_sbi_reachable"]==args.count,
          "single_nrf_alive":result["single_nrf_process"] and result["nrf_alive_at_measurement"],
          "discovery_sweep_complete":len(discovery_sweep)==26,
        }
        result["checks"]=checks;result["all_checks_passed"]=all(checks.values())
        (out/"uuid_hashes.txt").write_text(
            "\n".join(sorted(hashlib.sha256(x.encode()).hexdigest() for x in witness_ids))+"\n"
        )
        (out/"result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        (out/"STAGE54_RESULT.md").write_text(
          "# Stage55 single-NRF bulk discovery boundary\n"+
          "\n".join(f"- {k}: {v}" for k,v in result.items() if k not in {"host_meminfo_kib","checks"})+
          "\n- checks: "+json.dumps(checks,sort_keys=True)+"\n")
        if not result["all_checks_passed"]: raise RuntimeError("Stage54 integrity checks failed")
        print(json.dumps(result,indent=2,sort_keys=True))
    finally:
        terminate(workers+[nrf])
        for fh in (nssf_log,nrf_log):
            try:fh.close()
            except Exception:pass

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--count",type=int,required=True);ap.add_argument("--worker",type=int,default=0)
    ap.add_argument("--hold-seconds",type=float,default=20);ap.add_argument("--output",required=True)
    ap.add_argument("--batch",type=int,default=25);ap.add_argument("--batch-pause",type=float,default=.05)
    ap.add_argument("--converge-timeout",type=float,default=240)
    args=ap.parse_args()
    if not (1<=args.count<=4000):raise SystemExit("count must be 1..4000 for Stage54F single-NRF no-SCP scale")
    asyncio.run(main_async(args))
if __name__=="__main__":main()
