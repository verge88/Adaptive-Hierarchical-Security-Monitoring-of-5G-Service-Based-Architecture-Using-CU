"""Stage 5: real Open5GS NF outage/recovery and externally attested CU over HTTP/2.

Native Open5GS AUSF/NSSF binary code remains UNMODIFIED. The research CU
agent probes *actual* native NF HTTP/2 endpoints and HMAC-signs evidence.
It cannot attest internal NF integrity, and its HMAC is NOT native NF output.
All outage detection times are measured via monotonic WALL time.
"""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
from pathlib import Path
import random
import secrets
import statistics
import time

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ResponseReceived, StreamEnded, DataReceived, StreamReset
from .h2_wire import H2Server, encode, h2_request
from .bounded_scheduler import bounded_choose

# Two independently running instances each for AUSF and NSSF.
@dataclass(frozen=True)
class NF:
    service: str
    kind: str
    url: str
    endpoint: str

NFS = (
    NF("ausf", "AUSF", "http://127.0.0.1:7788", "/nausf-auth/v1/ue-authentications"),
    NF("nssf", "NSSF", "http://127.0.0.1:7789", "/nnssf-nsselection/v1/network-slice-information"),
    NF("ausf2", "AUSF", "http://127.0.0.1:7790", "/nausf-auth/v1/ue-authentications"),
    NF("nssf2", "NSSF", "http://127.0.0.1:7791", "/nnssf-nsselection/v1/network-slice-information"),
)
POLICIES = ("fixed", "random", "bounded_local", "bounded_zone")
PROBES_PER_TICK = 2
MAX_GAP_TICKS = 3
DOWN_TICKS = 12
BENIGN_TICKS = 4
TICK_WALL_S = 0.30


async def native_h2_status(nf: NF, timeout: float = 1.2):
    """Prove a response from Open5GS's own SBI socket; response 4xx is alive.

    The method intentionally does not parse service-specific JSON or mistake
    HTTP 400/404/405 (often expected for incomplete safe GET) for downtime.
    """
    from urllib.parse import urlsplit
    addr = urlsplit(nf.url)
    start = time.perf_counter()
    async def visit():
        reader, writer = await asyncio.open_connection(addr.hostname, addr.port or 80)
        h = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        status = None
        wire = 0
        try:
            h.initiate_connection()
            stream = h.get_next_available_stream_id()
            h.send_headers(stream, [
                (":method","GET"), (":scheme","http"),
                (":authority", addr.netloc), (":path", nf.endpoint),
                ("accept", "application/json")], end_stream=True)
            data = h.data_to_send()
            wire += len(data)
            writer.write(data)
            await writer.drain()
            while True:
                packet = await reader.read(65535)
                if not packet:
                    raise ConnectionError("NF socket closed before HTTP/2 response")
                wire += len(packet)
                for event in h.receive_data(packet):
                    if isinstance(event, ResponseReceived) and event.stream_id == stream:
                        status = int(dict(event.headers)[":status"])
                    elif isinstance(event, DataReceived):
                        h.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamReset) and event.stream_id == stream:
                        raise ConnectionError("NF reset HTTP/2 stream")
                    elif isinstance(event, StreamEnded) and event.stream_id == stream:
                        if status is None:
                            raise ConnectionError("No native NF HTTP status")
                        return dict(reachable=True, http_status=status, h2_bytes=wire)
                out = h.data_to_send()
                wire += len(out)
                writer.write(out)
                await writer.drain()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ConnectionError):
                pass
    try:
        x = await asyncio.wait_for(visit(),timeout)
    except (ConnectionError, OSError, asyncio.TimeoutError, ValueError, KeyError) as exc:
        x = dict(reachable=False, http_status=None, h2_bytes=0,
                 observation_error=type(exc).__name__)
    x["rtt_ms"] = round((time.perf_counter() - start)*1000,3)
    return x


def mac(key: bytes, data: dict) -> str:
    return hmac.new(key, encode(data), hashlib.sha256).hexdigest()


class NativeAttestor:
    """Research-only authenticated H2 agent, *not inside* a native Open5GS NF.

    It observes real NF responses, not simulated NF server state.
    """
    def __init__(self, nfs=NFS, key=None):
        self.nfs = tuple(nfs)
        self.key = key if key is not None else secrets.token_bytes(32)
        self.last_cycle = {}
        self.server = H2Server(self.handle)

    async def handle(self, headers, body):
        if headers.get(":path") != "/research-cu/v1/challenge" or headers.get(":method") != "POST":
            return 404, dict(error="Unknown research CU operation")
        try:
            ch = json.loads(body)
            unsigned = {k:ch[k] for k in ("policy","nf","cycle","issued_ns","nonce")}
            key = (unsigned["policy"], unsigned["nf"])
            if (not isinstance(unsigned["nf"],int) or
                not 0 <= unsigned["nf"] < len(self.nfs) or
                not isinstance(unsigned["cycle"],int) or
                not isinstance(unsigned["issued_ns"],int) or
                not isinstance(unsigned["nonce"],str) or
                len(unsigned["nonce"]) != 32 or
                not hmac.compare_digest(ch["mac"],mac(self.key,unsigned))):
                return 401, dict(error="Incorrect authenticated CU challenge")
            now = time.monotonic_ns()
            if abs(now-unsigned["issued_ns"]) > 5_000_000_000:
                return 400, dict(error="Expired CU timestamp")
            if unsigned["cycle"] <= self.last_cycle.get(key,-1):
                return 409, dict(error="CU replay")
            self.last_cycle[key] = unsigned["cycle"]
        except (TypeError, ValueError, KeyError):
            return 400, dict(error="Malformed CU challenge")
        native = await native_h2_status(self.nfs[unsigned["nf"]])
        result = {**unsigned, "checked_ns":time.monotonic_ns(), **native}
        return 200, {**result,"mac":mac(self.key,result)}


async def signed_observation(agent:NativeAttestor,policy:str,nf:int,cycle:int):
    fields = dict(policy=policy,nf=nf,cycle=cycle,
                  issued_ns=time.monotonic_ns(),nonce=secrets.token_hex(16))
    signed={**fields,"mac":mac(agent.key,fields)}
    status,report,wire,_=await h2_request(
        f"http://127.0.0.1:{agent.server.port}",
        "/research-cu/v1/challenge","POST",signed,timeout=3.0)
    if status != 200:
        raise AssertionError(f"CU agent returned HTTP {status}: {report}")
    raw={k:v for k,v in report.items() if k!="mac"}
    if (any(raw.get(k)!=v for k,v in fields.items())
       or not hmac.compare_digest(report["mac"],mac(agent.key,raw))
       or report["checked_ns"] < fields["issued_ns"]):
        raise AssertionError("CU observation failed HMAC/freshness test")
    return report,wire


COMPOSE=["docker","compose","-f","live/compose.yaml","-f","live/stage5-compose.yaml"]


async def docker(action:str,service:str):
    if action not in ("stop","start"):
        raise ValueError(action)
    cmd=COMPOSE+[action]
    if action=="stop":
        cmd+=["-t","1"]
    cmd+=[service]
    proc=await asyncio.create_subprocess_exec(*cmd,stdout=asyncio.subprocess.PIPE,
                                              stderr=asyncio.subprocess.PIPE)
    try:
        stdout,stderr=await asyncio.wait_for(proc.communicate(),timeout=35)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise RuntimeError(f"Open5GS {action} {service} timed out")
    if proc.returncode:
        raise RuntimeError(f"Open5GS {action} {service}: {stderr.decode()[-450:]}")
    return stdout.decode()[-350:]


async def nrf_counts(nrf_url:str):
    counts={}
    for typ in ("AUSF","NSSF"):
        path=f"/nnrf-disc/v1/nf-instances?target-nf-type={typ}&requester-nf-type=AMF"
        try:
            status,data,_,_=await h2_request(nrf_url,path,timeout=2.0)
        except (ConnectionError,OSError,asyncio.TimeoutError,ValueError) as exc:
            raise RuntimeError(f"Native NRF HTTP2 unavailable: {exc}")
        if status==200:
            profiles=data.get("nfInstances",[])
            counts[typ]=len({p.get("nfInstanceId") for p in profiles if p.get("nfType")==typ})
        elif status==404:
            counts[typ]=0
        else:
            raise RuntimeError(f"Unexpected real NRF discovery status {status} for {typ}: {str(data)[:200]}")
    return counts


async def wait_core(nrf_url,require_registered=True,timeout=65):
    end=time.monotonic()+timeout
    last=None
    while time.monotonic()<end:
        reach=await asyncio.gather(*(native_h2_status(n) for n in NFS))
        try:
            counts=await nrf_counts(nrf_url)
            if (all(p["reachable"] for p in reach)
                and (not require_registered or min(counts.values())>=2)):
                return dict(native_statuses=reach,registry_counts=counts)
            last=dict(native_statuses=reach,registry_counts=counts)
        except RuntimeError as exc:
            last=str(exc)
        await asyncio.sleep(.55)
    raise TimeoutError(f"Real Open5GS NF readiness failed: {str(last)[:1200]}")


def select(policy,tick,last,local,zone,rng):
    if policy=="fixed":
        return [(2*tick+j)%len(NFS) for j in range(PROBES_PER_TICK)]
    if policy=="random":
        return rng.sample(range(len(NFS)),PROBES_PER_TICK)
    if policy in ("bounded_local","bounded_zone"):
        spatial=zone if policy=="bounded_zone" else [0.0]*len(NFS)
        return bounded_choose(tick,local,spatial,last,warmup_end=0,
                              budget=PROBES_PER_TICK,max_gap=MAX_GAP_TICKS)
    raise ValueError(policy)


async def single_outage(agent, target:int, episode:int, seed:int, nrf_url:str):
    # Scheduler state contains no target index or injected event label.
    state={p:dict(last=[-1]*len(NFS),cycle=(episode+1)*100000,
                  local=[0.]*len(NFS),probes=0,cu_bytes=0,
                  gaps=[],alarms=0,clean_probes=0,detected_ns=None,
                  rtt_ms=[],rng=random.Random(seed*100+episode*7+i))
           for i,p in enumerate(POLICIES)}
    evidence=[]
    service=NFS[target].service
    await docker("stop",service)
    onset_ns=time.monotonic_ns()  # Conservative stop-COMPLETED timestamp.
    stop_registry_seen=0
    policy_order_rng=random.Random(seed*331+episode)
    fault_started=True
    try:
        for tick in range(DOWN_TICKS+BENIGN_TICKS):
            if tick==DOWN_TICKS:
                await docker("start",service)
                await wait_core(nrf_url,require_registered=True,timeout=65)
            in_outage=tick<DOWN_TICKS
            counts=await nrf_counts(nrf_url)
            if in_outage and counts.get(NFS[target].kind,0)>=2:
                stop_registry_seen+=1
            # Each NF type is a zone (2 true Open5GS instances per type).
            spatial=[4. if counts[n.kind]<2 else 0. for n in NFS]
            tick_started=time.monotonic()
            shuffled=list(POLICIES)
            policy_order_rng.shuffle(shuffled)
            for policy in shuffled:
                s=state[policy]
                choice=select(policy,tick,s["last"],s["local"],spatial,s["rng"])
                if len(set(choice))!=PROBES_PER_TICK:
                    raise AssertionError("Unequal CU budget")
                for nf in choice:
                    s["cycle"]+=1
                    report,wire=await signed_observation(agent,policy,nf,s["cycle"])
                    s["probes"]+=1
                    s["cu_bytes"]+=wire
                    s["rtt_ms"].append(report["rtt_ms"])
                    prior=s["last"][nf]
                    s["gaps"].append(tick-(prior if prior>=0 else -1))
                    s["last"][nf]=tick
                    # Streaming robustly bounded unsupervised latency score;
                    # outage status is a prior authenticated *observation*, not a label.
                    loss=5.0 if not report["reachable"] else max(
                        0.,min(5.,(report["rtt_ms"]-3.0)/4.0))
                    s["local"][nf]=.60*s["local"][nf]+.40*loss
                    if not in_outage:
                        s["clean_probes"]+=1
                        if not report["reachable"]:
                            s["alarms"]+=1
                    if in_outage and nf==target and not report["reachable"]:
                        if s["detected_ns"] is None:
                            s["detected_ns"]=time.monotonic_ns()
                if policy.startswith("bounded_"):
                    if tick<=DOWN_TICKS+BENIGN_TICKS-1 and max(
                        tick-v for v in s["last"])>MAX_GAP_TICKS:
                        raise AssertionError(f"CU deadline missed for {policy}")
            evidence.append(dict(tick=tick,outage_active=in_outage,registry_counts=counts))
            to_sleep=TICK_WALL_S-(time.monotonic()-tick_started)
            if to_sleep>0:
                await asyncio.sleep(to_sleep)
    finally:
        # Never leave a native Open5GS NF stopped if an assertion fails.
        if fault_started:
            await docker("start",service)
    end_ns=time.monotonic_ns()
    rows=[]
    for p,s in state.items():
        deadline= (end_ns-onset_ns)/1e9
        observed= ((s["detected_ns"]-onset_ns)/1e9
                   if s["detected_ns"] is not None else None)
        gap=max(s["gaps"]+[DOWN_TICKS+BENIGN_TICKS-1-v for v in s["last"]])
        if p.startswith("bounded_") and gap>MAX_GAP_TICKS:
            raise AssertionError(f"Hard bound violated for {p}: {gap}")
        rows.append(dict(seed=seed,episode=episode,service=service,
                         nf_type=NFS[target].kind,policy=p,
                         detected=observed is not None,
                         detection_wall_s=observed,
                         observation_window_wall_s=deadline,
                         probes=s["probes"],cu_wire_bytes=s["cu_bytes"],
                         max_intercheck_gap_ticks=gap,
                         benign_false_alarms=s["alarms"],
                         benign_checks=s["clean_probes"],
                         mean_native_h2_rtt_ms=statistics.mean(s["rtt_ms"]),
                         nrf_reported_type_complete_during_outage=
                             stop_registry_seen/DOWN_TICKS))
    return rows,evidence


async def main_async(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    agent=NativeAttestor()
    await agent.server.start()
    rng=random.Random(args.seed)
    targets=list(range(len(NFS)))
    rng.shuffle(targets)
    records=[]
    logs=[]
    try:
        for i,target in enumerate(targets):
            await wait_core(args.nrf_url,require_registered=True)
            print(f"Actual Open5GS NF stop/start: {NFS[target].service} "
                  f"(episode {i+1}/4)",flush=True)
            data,evidence=await single_outage(agent,target,i,args.seed,args.nrf_url)
            records.extend(data)
            logs.append(dict(target=NFS[target].service,episode=i,evidence=evidence))
    finally:
        await agent.server.close()
        # Restore all native NF containers even if experiment aborted.
        for n in NFS:
            await docker("start",n.service)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"events.json").write_text(json.dumps(records,indent=2))
    (out/"registry_trace.json").write_text(json.dumps(logs,indent=2))
    (out/"manifest.json").write_text(json.dumps(dict(
        research_stage=5,native_nf_faults=True,
        cu_in_native_open5gs_binary=False,
        attestation="external HMAC-authenticated HTTP2 native NF reachability probe",
        nf_services=[n.service for n in NFS],
        stop_timestamp="after docker compose stop completed",
        time_basis="wall time from time.monotonic_ns; CU schedule paced",
        scenarios="real stop and restart, not malicious NF compromise",
        seed=args.seed,policy=list(POLICIES)),indent=2))
    print(f"Finished native NF events={len(targets)}, per-policy records={len(records)}",flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=1501)
    p.add_argument("--output",default="stage5_results")
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    a=p.parse_args()
    asyncio.run(main_async(a))


if __name__=="__main__":
    main()
