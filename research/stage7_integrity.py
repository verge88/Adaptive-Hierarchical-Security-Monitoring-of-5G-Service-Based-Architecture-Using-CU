"""Stage 7: registered native Open5GS NF, corrupted lab HTTP/2 gateway envelope.

This is a CONTROLLED LAB PROXY RESPONSE ATTACK, *not* a compromised Open5GS NF.
No Open5GS binary or NRF registration is modified. The gateway forwards
information derived from a real native NF HTTP/2 response in an experimental
JSON envelope; only this envelope is mutated. External HMAC CU attests a
separately sampled native NF status/identity. It does NOT attest NF internals.

Stronger controls: online NRF nfInstanceId sets, passive metadata anomaly,
passive full-payload digest, active fixed/local/zone KIE with equal budgets.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import hmac
import json
import random
import secrets
import statistics
import time
from pathlib import Path

from .h2_wire import H2Server,h2_request,encode
from .stage5_native import NFS,mac,native_h2_status,wait_core
from .bounded_scheduler import bounded_choose

BUDGET=2
TICK_WALL_S=.19
TICKS=24
WARMUP=5
BOUND=3
ATTACK_MODES=("same_length_instance", "status_rewrite")
ACTIVE=("kie_fixed","kie_local","kie_zone")
PASSIVE=("nrf_instance_only","passive_metadata","passive_payload")
ALL=PASSIVE+ACTIVE


def envelope(nf,obs):
    return {"nfInstance":NFS[nf].service,"upstreamHTTPStatus":obs["http_status"],
            "reachable":obs["reachable"]}


def corrupt(value,kind):
    x=dict(value)
    if kind=="same_length_instance":
        v=x["nfInstance"]
        x["nfInstance"]=("z" if v[0]!="z" else "y")+v[1:]
        if len(encode(x))!=len(encode(value)):
            raise AssertionError("Same-length mutation changed metadata length")
    elif kind=="status_rewrite":
        v=x["upstreamHTTPStatus"]
        if not isinstance(v,int) or v<100:
            raise AssertionError("No valid upstream native status")
        x["upstreamHTTPStatus"]=201 if v!=201 else 202
    else:
        raise ValueError(kind)
    return x


class LabSBIProxy:
    """HTTP/2 consumer-facing gateway: real NF observation in lab JSON envelope."""
    def __init__(self):
        self.active_nf=None
        self.attack_kind=None
        self.server=H2Server(self.handle)

    async def handle(self,headers,body):
        path=headers.get(":path","")
        if headers.get(":method")!="GET" or not path.startswith("/consumer-sbi/"):
            return 404,{"error":"not a lab SBI proxy endpoint"}
        try:
            nf=int(path.split("/")[-1])
        except (ValueError,TypeError):
            return 400,{"error":"invalid nf"}
        if not (0<=nf<len(NFS)):
            return 404,{"error":"nf not present"}
        obs=await native_h2_status(NFS[nf])
        if not obs["reachable"]:
            return 503,{"error":"native NF unavailable"}
        answer=envelope(nf,obs)
        if self.active_nf==nf:
            answer=corrupt(answer,self.attack_kind)
        return 200,answer


class IntegrityAgent:
    """External agent, independent path to the actual native NF h2 socket."""
    def __init__(self):
        self.key=secrets.token_bytes(32)
        self.seen={}
        self.server=H2Server(self.handle)

    async def handle(self,headers,body):
        if headers.get(":path")!="/research-kie/v1/verify" or headers.get(":method")!="POST":
            return 404,{"error":"unknown operation"}
        try:
            signed=json.loads(body)
            fields={k:signed[k] for k in ("scope","nf","sequence","nonce","issued_ns")}
            if (not isinstance(fields["nf"],int) or not 0<=fields["nf"]<len(NFS)
                or not isinstance(fields["sequence"],int)
                or not isinstance(fields["scope"],str)
                or not isinstance(fields["issued_ns"],int)
                or not isinstance(fields["nonce"],str)
                or len(fields["nonce"])!=32
                or not hmac.compare_digest(signed["mac"],mac(self.key,fields))):
                return 401,{"error":"unauthenticated"}
            if abs(time.monotonic_ns()-fields["issued_ns"])>5_000_000_000:
                return 400,{"error":"expired"}
            index=(fields["scope"],fields["nf"])
            if fields["sequence"]<=self.seen.get(index,-1):
                return 409,{"error":"replayed"}
            self.seen[index]=fields["sequence"]
        except (KeyError,ValueError,TypeError):
            return 400,{"error":"bad challenge"}
        native=await native_h2_status(NFS[fields["nf"]])
        reply={**fields,"native":envelope(fields["nf"],native),
               "checked_ns":time.monotonic_ns()}
        return 200,{**reply,"mac":mac(self.key,reply)}


async def kie(agent,nf,policy,seq):
    data=dict(scope=policy,nf=nf,sequence=seq,nonce=secrets.token_hex(16),
              issued_ns=time.monotonic_ns())
    request={**data,"mac":mac(agent.key,data)}
    status,result,nbytes,_=await h2_request(
        f"http://127.0.0.1:{agent.server.port}",
        "/research-kie/v1/verify","POST",request,timeout=3)
    if status!=200:
        raise AssertionError(f"Signed KIE agent error: {status}, {result}")
    payload={k:v for k,v in result.items() if k!="mac"}
    if (any(payload[k]!=v for k,v in data.items())
        or result["mac"]!=mac(agent.key,payload)
        or payload["checked_ns"]<data["issued_ns"]):
        raise AssertionError("KIE challenge signature/freshness verification failed")
    return result["native"],nbytes


async def nrf_instance_sets(url):
    ids={}
    for kind in ("AUSF","NSSF"):
        code,data,_,_=await h2_request(
            url,f"/nnrf-disc/v1/nf-instances?target-nf-type={kind}&requester-nf-type=AMF",timeout=3)
        if code!=200:
            raise RuntimeError(f"Real NRF discovery failed {kind}: status {code}")
        ids[kind]=set(p["nfInstanceId"] for p in data.get("nfInstances",[])
                      if p.get("nfType")==kind and p.get("nfInstanceId"))
    return ids


def check_ids(baseline,current):
    return any(current.get(k,set())!=v for k,v in baseline.items())


def scheduler(name,tick,last,local,spatial):
    if name=="kie_fixed":
        return [(tick*BUDGET+j)%len(NFS) for j in range(BUDGET)]
    if name not in ACTIVE:
        raise ValueError(name)
    return bounded_choose(tick,local,spatial if name=="kie_zone" else [0.]*len(NFS),
                          last,warmup_end=0,budget=BUDGET,max_gap=BOUND)


def calculate_risk(latencies,reference,meta_flags,prev):
    residual=[max(0.,min(8.,(latencies[i]-reference[i])/max(.5,reference[i])))
              + 3.*meta_flags[i] for i in range(len(NFS))]
    local=[.55*prev[i]+.45*residual[i] for i in range(len(NFS))]
    # Hierarchical zonal context is peer-relative anomaly, NOT injected target ID.
    spatial=[]
    for i,n in enumerate(NFS):
        peers=[residual[j] for j,m in enumerate(NFS) if m.kind==n.kind]
        spatial.append(max(0.,residual[i]-statistics.median(peers)))
    return local,spatial


async def episode(seed,case,nf,kind,nrf_url):
    await wait_core(nrf_url,require_registered=True,timeout=75)
    registry_baseline=await nrf_instance_sets(nrf_url)
    if any(len(x)<2 for x in registry_baseline.values()):
        raise AssertionError("Native NRF should register two NFs per type")
    proxy=LabSBIProxy()
    agent=IntegrityAgent()
    await proxy.server.start()
    await agent.server.start()
    proxy_url=f"http://127.0.0.1:{proxy.server.port}"
    rng=random.Random(720000 + 17*seed + case)
    attack_started=None
    attack_ended=None
    # Randomize onset relative to already-running 190 ms scheduler.
    start_s=(WARMUP+2+rng.uniform(.15,.85))*TICK_WALL_S
    duration_s=(7.3+rng.uniform(.1,1.1))*TICK_WALL_S
    detected={m:None for m in ALL}
    false={m:0 for m in ALL}
    clean={m:0 for m in ALL}
    samples={m:0 for m in ALL}
    wire={m:0 for m in ALL}
    last={m:[-1]*len(NFS) for m in ACTIVE}
    local={m:[0.]*len(NFS) for m in ACTIVE}
    seq={m:0 for m in ACTIVE}
    worst={m:0 for m in ACTIVE}
    baseline=None
    mean_latency=None
    registry_changed=False
    trace=[]
    origin=time.monotonic()
    origin_ns=time.monotonic_ns()

    async def injection():
        nonlocal attack_started,attack_ended
        await asyncio.sleep(max(0,origin+start_s-time.monotonic()))
        attack_started=time.monotonic_ns()
        proxy.active_nf=nf
        proxy.attack_kind=kind
        await asyncio.sleep(duration_s)
        proxy.active_nf=None
        proxy.attack_kind=None
        attack_ended=time.monotonic_ns()

    async def monitor():
        nonlocal baseline,mean_latency,registry_changed
        for tick in range(TICKS):
            await asyncio.sleep(max(0,origin+tick*TICK_WALL_S-time.monotonic()))
            async def get_gateway(i):
                st=time.perf_counter()
                status,payload,nbytes,_=await h2_request(
                    proxy_url,f"/consumer-sbi/{i}",timeout=3)
                if status!=200:
                    raise RuntimeError(f"Native-backed lab gateway unavailable {i}: {status}")
                return payload,nbytes,(time.perf_counter()-st)*1000
            observations=await asyncio.gather(*(get_gateway(i) for i in range(len(NFS))))
            payload=[x[0] for x in observations]
            lat=[x[2] for x in observations]
            if baseline is None:
                baseline=payload
                mean_latency=lat
            if tick<WARMUP:
                # No attack allowed in warmup; require native response semantic stability.
                if any(payload[i]!=baseline[i] for i in range(len(NFS))):
                    raise AssertionError("Native envelope unstable in warmup; cannot use fingerprint baseline")
                mean_latency=[.75*mean_latency[i]+.25*lat[i] for i in range(len(NFS))]
            is_attack=attack_started is not None and attack_ended is None
            is_clean=(attack_started is None or attack_ended is not None)
            meta=[int(payload[i]["upstreamHTTPStatus"]!=baseline[i]["upstreamHTTPStatus"]
                      or len(encode(payload[i]))!=len(encode(baseline[i])))
                  for i in range(len(NFS))]
            passive_alarm={
                "passive_metadata":any(meta),
                "passive_payload":any(payload[i]!=baseline[i] for i in range(len(NFS)))
            }
            curr_ids=await nrf_instance_sets(nrf_url)
            change=check_ids(registry_baseline,curr_ids)
            registry_changed=registry_changed or change
            passive_alarm["nrf_instance_only"]=change
            for name,flag in passive_alarm.items():
                samples[name]+=1
                if is_attack and flag and detected[name] is None:
                    detected[name]=time.monotonic_ns()
                if is_clean:
                    clean[name]+=1
                    false[name]+=int(flag)
            for name in ACTIVE:
                local[name],spatial=calculate_risk(lat,mean_latency,meta,local[name])
                chosen=scheduler(name,tick,last[name],local[name],spatial)
                if len(set(chosen))!=BUDGET:
                    raise AssertionError("Incorrect KIE budget")
                for i in chosen:
                    seq[name]+=1
                    attested,b=await kie(agent,i,f"stage7-{seed}-{case}-{name}",seq[name])
                    wire[name]+=b
                    samples[name]+=1
                    prior=last[name][i]
                    worst[name]=max(worst[name],tick-(prior if prior>=0 else -1))
                    last[name][i]=tick
                    mismatch=(payload[i]!=attested)
                    if is_attack and mismatch and detected[name] is None:
                        detected[name]=time.monotonic_ns()
                    if is_clean:
                        clean[name]+=1
                        false[name]+=int(mismatch)
            trace.append(dict(tick=tick,time_wall_s=round(time.monotonic()-origin,5),
                              native_nrf_ids={k:sorted(v) for k,v in curr_ids.items()},
                              consumer_observations=payload,
                              active_cu_choices={p:[last[p][i]==tick for i in range(len(NFS))] for p in ACTIVE}))
        for name in ACTIVE:
            worst[name]=max(worst[name],max(TICKS-1-v for v in last[name]))
            if name!="kie_fixed" and worst[name]>BOUND:
                raise AssertionError("KIE hard check-gap bound violated")
    try:
        await asyncio.gather(injection(),monitor())
    finally:
        proxy.active_nf=None
        await proxy.server.close()
        await agent.server.close()
    if attack_started is None or attack_ended is None:
        raise AssertionError("Attack timeline missing")
    duration=(attack_ended-attack_started)/1e9
    rows=[]
    for name in ALL:
        found=detected[name] is not None
        delay=(detected[name]-attack_started)/1e9 if found else None
        rows.append(dict(seed=seed,case=case,nf=NFS[nf].service,attack=kind,detector=name,
           detected=found,delay_wall_s=delay,
           censored_delay_wall_s=delay if found else duration,
           attack_duration_wall_s=duration,clean_checks=clean[name],
           false_alerts=false[name],sample_count=samples[name],
           cu_checks=samples[name] if name in ACTIVE else 0,
           cu_http2_bytes=wire[name],max_cu_gap_ticks=worst.get(name),
           native_nrf_id_set_changed=registry_changed))
    return rows,dict(case=case,nf=NFS[nf].service,attack=kind,
        attack_start_wall_s=(attack_started-origin_ns)/1e9,
        attack_end_wall_s=(attack_ended-origin_ns)/1e9,observations=trace)


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    rnd=random.Random(args.seed)
    scenarios=[(i,kind) for i in range(len(NFS)) for kind in ATTACK_MODES]
    rnd.shuffle(scenarios)
    rows,traces=[],[]
    for k,(i,kind) in enumerate(scenarios):
        print(f"Stage7 real Open5GS native-backed gateway test {k+1}/8: "
              f"{NFS[i].service} {kind}",flush=True)
        a,b=await episode(args.seed,k,i,kind,args.nrf_url)
        rows.extend(a)
        traces.append(b)
    target=Path(args.output)
    target.mkdir(parents=True,exist_ok=True)
    (target/"events.json").write_text(json.dumps(rows,indent=2))
    (target/"traces.json").write_text(json.dumps(traces,indent=2))
    (target/"manifest.json").write_text(json.dumps(dict(
        research_stage=7,seed=args.seed,scenario_count=len(scenarios),
        native_NFs_unmodified=True,NRF_registration_untouched=True,
        mutation_target="research HTTP/2 gateway JSON envelope only",
        KIE_signed_by="separate trusted research agent",
        detector_set=list(ALL),tick_wall_s=TICK_WALL_S,
        safe_native_gets=True,real_attack_onset_randomized=True),indent=2))
    print(f"Stage7 completed {len(scenarios)} gateway-fault episodes; "
          f"{len(rows)} per-detector results",flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=2001)
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    p.add_argument("--output",default="stage7_results")
    a=p.parse_args()
    asyncio.run(run(a))


if __name__=="__main__":
    main()
