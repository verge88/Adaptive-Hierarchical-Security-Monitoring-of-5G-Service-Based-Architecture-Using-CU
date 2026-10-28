#!/usr/bin/env python3
from __future__ import annotations
import argparse,asyncio,hashlib,json,math,os,signal,socket,statistics,subprocess,time
from pathlib import Path
from urllib.parse import urlencode
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived,ResponseReceived,StreamEnded,StreamReset

ROOT=Path("/tmp/stage53")
WITNESS=Path("/run/stage53/witness")
NRF_BIN="/src/open5gs/build/src/nrf/open5gs-nrfd"
SCP_BIN="/src/open5gs/build/src/scp/open5gs-scpd"
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

async def h2_get(path,timeout=15):
    reader,writer=await asyncio.open_connection(NRF_HOST,PORT)
    conn=H2Connection(H2Configuration(client_side=True,header_encoding="utf-8"))
    body=bytearray();status=None
    try:
        conn.initiate_connection();stream=conn.get_next_available_stream_id()
        conn.send_headers(stream,[(":method","GET"),(":scheme","http"),
          (":authority",f"{NRF_HOST}:{PORT}"),(":path",path),
          ("accept","application/json"),("user-agent","stage53-scale-worker")],end_stream=True)
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

async def discover_nssf():
    q=urlencode({"target-nf-type":"NSSF","requester-nf-type":"AMF"})
    st,body=await h2_get("/nnrf-disc/v1/nf-instances?"+q)
    if st!=200: raise RuntimeError(f"discovery status {st}: {body[:300]!r}")
    doc=json.loads(body)
    rows=doc.get("nfInstances")
    if not isinstance(rows,list): raise RuntimeError("missing nfInstances")
    return rows,len(body)

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
    peer_limit=max(1024,args.count+128)
    (ROOT/"nrf.yaml").write_text(nrf_config(peer_limit))
    (ROOT/"scp.yaml").write_text(scp_config(peer_limit))
    env={**os.environ,"STAGE38_WITNESS_DIR":str(WITNESS)}
    nrf=subprocess.Popen([NRF_BIN,"-c",str(ROOT/"nrf.yaml")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
    workers=[];scp=None
    t0=time.time()
    try:
        wait_tcp(NRF_HOST,PORT,30)
        time.sleep(.5)
        scp=subprocess.Popen([SCP_BIN,"-c",str(ROOT/"scp.yaml")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
        wait_tcp("127.0.0.11",80,30)
        time.sleep(.5)
        endpoints=[]
        for i in range(1,args.count+1):
            host,port=endpoint_for(args.worker,i);endpoints.append((host,port))
            cfg=ROOT/f"nssf-{i:04d}.yaml";cfg.write_text(nssf_config(host,port))
            p=subprocess.Popen([NSSF_BIN,"-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
            workers.append(p)
            if i%args.batch==0: time.sleep(args.batch_pause)
        launch_done=time.time()
        last_count=0;discovery_bytes=0;rows=[];last_error=None
        deadline=time.time()+args.converge_timeout
        while time.time()<deadline:
            dead=sum(p.poll() is not None for p in workers)
            if dead: raise RuntimeError(f"{dead} NSSF processes exited before convergence")
            try:
                rows,discovery_bytes=await discover_nssf();last_count=len(rows);last_error=None
                wit=read_witness()
                if len(rows)==args.count and all(p.pid in wit for p in workers): break
            except Exception as exc:
                last_error=f"{type(exc).__name__}: {exc}"
            await asyncio.sleep(.25)
        else:
            diag={"schema":"stage53-timeout-v1","worker":args.worker,"requested":args.count,
              "discovery_count":last_count,"witness_files":len(read_witness()),
              "live_processes":sum(p.poll() is None for p in workers),
              "last_discovery_error":last_error}
            (out/"failure_diagnostic.json").write_text(json.dumps(diag,indent=2)+"\n")
            print(json.dumps(diag,indent=2),flush=True)
            raise RuntimeError(f"convergence timeout discovery={last_count} witness={len(read_witness())} error={last_error}")
        ready=time.time()
        pids=[p.pid for p in workers]
        wit=read_witness()
        discovered_ids=[str(r.get("nfInstanceId","")).lower() for r in rows]
        witness_ids=[wit[p]["nf_instance_id"] for p in pids if p in wit]
        reachable=sum(tcp_ready(h,p,.12) for h,p in endpoints)
        before={pid:proc_status(pid) for pid in pids}
        before={k:v for k,v in before.items() if v}
        mem_before=cgroup_memory_current()
        ready_doc={"schema":"stage53-worker-ready-v1","worker":args.worker,"count":args.count,
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
          "schema":"stage53-live-open5gs-scale-v1","open5gs_ref":"v2.7.6",
          "worker":args.worker,"requested_nf":args.count,"nrf_scp_peer_limit":peer_limit,
          "live_processes":sum(p.poll() is None for p in workers),
          "unique_pids":len(set(pids)),"witness_records":len(witness_ids),
          "unique_witness_uuids":len(set(witness_ids)),
          "nrf_discovered_profiles":len(rows),
          "unique_discovered_uuids":len(set(discovered_ids)),
          "witness_discovery_uuid_sets_equal":set(witness_ids)==set(discovered_ids),
          "direct_sbi_reachable":reachable,
          "discovery_response_bytes":discovery_bytes,
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
          "all_profiles_discovered":result["nrf_discovered_profiles"]==args.count,
          "all_discovered_uuids_unique":result["unique_discovered_uuids"]==args.count,
          "witness_matches_nrf":result["witness_discovery_uuid_sets_equal"],
          "all_sbi_reachable":result["direct_sbi_reachable"]==args.count,
        }
        result["checks"]=checks;result["all_checks_passed"]=all(checks.values())
        (out/"result.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        (out/"STAGE53_RESULT.md").write_text(
          "# Stage53 live Open5GS scale worker\n"+
          "\n".join(f"- {k}: {v}" for k,v in result.items() if k not in {"host_meminfo_kib","checks"})+
          "\n- checks: "+json.dumps(checks,sort_keys=True)+"\n")
        if not result["all_checks_passed"]: raise RuntimeError("Stage53 integrity checks failed")
        print(json.dumps(result,indent=2,sort_keys=True))
    finally:
        terminate(workers+([scp] if scp is not None else [])+[nrf])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--count",type=int,required=True);ap.add_argument("--worker",type=int,default=0)
    ap.add_argument("--hold-seconds",type=float,default=20);ap.add_argument("--output",required=True)
    ap.add_argument("--batch",type=int,default=25);ap.add_argument("--batch-pause",type=float,default=.05)
    ap.add_argument("--converge-timeout",type=float,default=240)
    args=ap.parse_args()
    if not (1<=args.count<=500):raise SystemExit("count must be 1..500 per worker")
    asyncio.run(main_async(args))
if __name__=="__main__":main()
