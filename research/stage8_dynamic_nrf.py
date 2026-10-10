"""Stage 8: dynamic native NRF discovery *body* through a lab consumer gateway.

REAL Open5GS NRF discovery JSON is fetched on EVERY request. The laboratory
gateway benignly reorders nfInstances and, only during a controlled episode,
mutates one NF PROFILE in the proxied discovery response. Native Open5GS NF
binaries, their actual NRF registrations, and direct native NRF responses
remain untouched. This is NOT compromise of an Open5GS binary or actual
3GPP-compliant MITM. Research CU signatures are issued by a separate agent.

A strong semantic PASSIVE baseline is explicitly included, to test whether
active CUs provide incremental ability over learned order-invariant profiles.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import hmac
import json
from pathlib import Path
import random
import secrets
import statistics
import time

from .h2_wire import H2Server, h2_request, encode
from .stage5_native import NFS, mac, wait_core
from .bounded_scheduler import bounded_choose

KINDS=("AUSF","NSSF")
METHODS=("nrf_direct","passive_bytes","passive_semantic",
         "cu_fixed","cu_local","cu_zone")
ACTIVES=("cu_fixed","cu_local","cu_zone")
ATTACKS=("profile_id_substitute","profile_status_rewrite")
TICKS=26
WARMUP=5
CU_BUDGET=2
GAP_LIMIT=3
TICK_S=.20


async def native_discovery(nrf_url,kind):
    path=f"/nnrf-disc/v1/nf-instances?target-nf-type={kind}&requester-nf-type=AMF"
    status,body,wire,_=await h2_request(nrf_url,path,timeout=3)
    if status!=200 or not isinstance(body,dict) or not isinstance(body.get("nfInstances"),list):
        raise AssertionError(f"Native Open5GS NRF discovery failed {kind}: {status}")
    profiles=[x for x in body["nfInstances"] if x.get("nfType")==kind]
    if len(profiles)<2 or any(not p.get("nfInstanceId") for p in profiles):
        raise AssertionError("Expected 2 registered real NRF NF profiles")
    return body,wire


def canonical(payload):
    """Normalize arbitrary object-key and nfInstances array ordering only.

    No profile field is ignored: even a semantically valid attacker-changed
    status or UUID is observable to strong passive semantic baseline.
    """
    x=copy.deepcopy(payload)
    x["nfInstances"]=sorted(x["nfInstances"],
        key=lambda p: (str(p.get("nfInstanceId","")),str(p.get("nfType",""))))
    return encode(x)


def native_id_sets(ausf,nssf):
    return {k:sorted(p["nfInstanceId"] for p in x["nfInstances"] if p.get("nfType")==k)
            for k,x in (("AUSF",ausf),("NSSF",nssf))}


def mutate_body(body,nf_id,attack):
    result=copy.deepcopy(body)
    matches=[p for p in result["nfInstances"] if p.get("nfInstanceId")==nf_id]
    if len(matches)!=1:
        raise ValueError("Mutation target must be present exactly once")
    p=matches[0]
    if attack=="profile_id_substitute":
        old=p["nfInstanceId"]
        p["nfInstanceId"]=("f" if old[0].lower()!="f" else "e")+old[1:]
        if p["nfInstanceId"]==old:
            raise AssertionError("Identity change was a no-op")
    elif attack=="profile_status_rewrite":
        old=p.get("nfStatus","REGISTERED")
        p["nfStatus"]="SUSPENDED" if old!="SUSPENDED" else "REGISTERED"
    else:
        raise ValueError(attack)
    return result


class DiscoveryGateway:
    def __init__(self,nrf_url,seed):
        self.nrf_url=nrf_url
        self.rng=random.Random(seed)
        self.target_id=None
        self.target_kind=None
        self.kind=None
        self.server=H2Server(self.handle)

    async def handle(self,headers,raw):
        if headers.get(":method")!="GET":
            return 405,{"error":"GET required"}
        kind=headers.get(":path","").split("/")[-1]
        if kind not in KINDS:
            return 404,{"error":"unknown NF type"}
        body,_=await native_discovery(self.nrf_url,kind)
        body=copy.deepcopy(body)
        # BENIGN proxy serialization variation: real profiles unchanged.
        self.rng.shuffle(body["nfInstances"])
        if kind==self.target_kind and self.target_id:
            body=mutate_body(body,self.target_id,self.kind)
        return 200,body


class ExternalNrfAttestor:
    """Experimental agent signs an independent direct NRF profile observation."""
    def __init__(self,nrf_url):
        self.url=nrf_url
        self.key=secrets.token_bytes(32)
        self.seen={}
        self.server=H2Server(self.handle)

    async def handle(self,headers,raw):
        if headers.get(":method")!="POST" or headers.get(":path")!="/research-cu/nrf":
            return 404,{"error":"not supported"}
        try:
            ch=json.loads(raw)
            data={k:ch[k] for k in ("policy","target_kind","cycle","nonce","issued_ns")}
            scope=(data["policy"],data["target_kind"])
            if (data["target_kind"] not in KINDS or
                not isinstance(data["cycle"],int) or
                not isinstance(data["issued_ns"],int) or
                not isinstance(data["nonce"],str) or len(data["nonce"])!=32 or
                not hmac.compare_digest(ch["mac"],mac(self.key,data))):
                return 401,{"error":"bad HMAC"}
            if abs(time.monotonic_ns()-data["issued_ns"])>5_000_000_000:
                return 400,{"error":"stale CU"}
            if data["cycle"]<=self.seen.get(scope,-1):
                return 409,{"error":"replay"}
            self.seen[scope]=data["cycle"]
        except (KeyError,ValueError,TypeError):
            return 400,{"error":"invalid challenge"}
        body,_=await native_discovery(self.url,data["target_kind"])
        response={**data,"checked_ns":time.monotonic_ns(),"native_body":body}
        return 200,{**response,"mac":mac(self.key,response)}


async def signed_cu(agent,kind,method,cycle):
    data=dict(policy=method,target_kind=kind,cycle=cycle,
              nonce=secrets.token_hex(16),issued_ns=time.monotonic_ns())
    code,out,wire,_=await h2_request(
        f"http://127.0.0.1:{agent.server.port}","/research-cu/nrf","POST",
        {**data,"mac":mac(agent.key,data)},timeout=4)
    if code!=200:
        raise AssertionError(f"Native NRF independent CU failed: {code}")
    body={k:v for k,v in out.items() if k!="mac"}
    if any(body[k]!=v for k,v in data.items()) or not hmac.compare_digest(
            out["mac"],mac(agent.key,body)):
        raise AssertionError("Research CU HMAC not authentic")
    return out["native_body"],wire


def select(policy,tick,last,local,spatial):
    # Four real NF instances as scheduling targets. Both AUSF probes reach
    # the same type-level NRF API; they are distinct CU checks by contract.
    if policy=="cu_fixed":
        return [(tick*CU_BUDGET+i)%len(NFS) for i in range(CU_BUDGET)]
    return bounded_choose(tick,local,
        spatial if policy=="cu_zone" else [0.]*len(NFS),
        last,warmup_end=0,budget=CU_BUDGET,max_gap=GAP_LIMIT)


async def episode(seed,number,kind,attack,nrf_url):
    await wait_core(nrf_url,require_registered=True,timeout=70)
    base_a,_=await native_discovery(nrf_url,"AUSF")
    base_n,_=await native_discovery(nrf_url,"NSSF")
    origin_ids=native_id_sets(base_a,base_n)
    ids=origin_ids[kind]
    rng=random.Random(seed*7919+number*307)
    target_id=rng.choice(ids)
    gateway=DiscoveryGateway(nrf_url,seed*63+number)
    attestor=ExternalNrfAttestor(nrf_url)
    await gateway.server.start()
    await attestor.server.start()
    g_url=f"http://127.0.0.1:{gateway.server.port}"
    results={m:dict(alarm=None,clean=0,false=0,prior_false=False,checks=0,bytes=0,gap=0) for m in METHODS}
    last={m:[-1]*len(NFS) for m in ACTIVES}
    local={m:[0.]*len(NFS) for m in ACTIVES}
    cycles={m:0 for m in ACTIVES}
    baseline_bytes={}
    baseline_semantics={}
    start_ns=None
    end_ns=None
    traces=[]
    clock=time.monotonic()
    onset=(WARMUP+1.4+rng.uniform(0.15,0.80))*TICK_S
    duration=(8+rng.uniform(0,1.3))*TICK_S

    async def inject():
        nonlocal start_ns,end_ns
        await asyncio.sleep(max(0,clock+onset-time.monotonic()))
        start_ns=time.monotonic_ns()
        gateway.target_kind=kind
        gateway.target_id=target_id
        gateway.kind=attack
        await asyncio.sleep(duration)
        gateway.target_id=None
        gateway.target_kind=None
        gateway.kind=None
        end_ns=time.monotonic_ns()

    async def sample():
        for tick in range(TICKS):
            await asyncio.sleep(max(0,clock+tick*TICK_S-time.monotonic()))
            obs={}
            for k in KINDS:
                status,body,bytes_used,_=await h2_request(g_url,f"/gateway/discover/{k}",timeout=4)
                if status!=200:
                    raise AssertionError("Real NRF-backed gateway did not answer")
                obs[k]=body
                if tick==0:
                    baseline_bytes[k]=encode(body)
                    baseline_semantics[k]=canonical(body)
            # Live true NRF registration used by the label-blind online control.
            live_a,_=await native_discovery(nrf_url,"AUSF")
            live_n,_=await native_discovery(nrf_url,"NSSF")
            stable=native_id_sets(live_a,live_n)==origin_ids
            if not stable:
                raise AssertionError("Native NRF nfInstanceId changed during injected gateway corruption")
            active_now=(start_ns is not None and end_ns is None)
            clean_now=(start_ns is None or end_ns is not None)
            flags={
                "nrf_direct":not stable,
                "passive_bytes":any(encode(obs[k])!=baseline_bytes[k] for k in KINDS),
                "passive_semantic":any(canonical(obs[k])!=baseline_semantics[k] for k in KINDS)
            }
            for method,flag in flags.items():
                r=results[method]
                # Pre-onset alerts invalidate a clean first-detection
                # claim for this same event; bytewise ordering noise should
                # not be credited as a new true positive.
                if clean_now:
                    r["clean"]+=1
                    r["false"]+=int(flag)
                    if start_ns is None and flag:
                        r["prior_false"]=True
                if active_now and flag and r["alarm"] is None and not r["prior_false"]:
                    r["alarm"]=time.monotonic_ns()
            # Risk features are metadata/status deviations + latency proxy.
            metadata={k:int(canonical(obs[k])!=baseline_semantics[k]) for k in KINDS}
            for method in ACTIVES:
                r=results[method]
                feats=[float(metadata[n.kind]) for n in NFS]
                local[method]=[.7*a+.3*b for a,b in zip(local[method],feats)]
                # Peers share the type-level NRF response, so a zonal context
                # is not expected to add information; negative control.
                spatial=[max(0.,feats[i]-statistics.median(
                         [feats[j] for j,n in enumerate(NFS) if n.kind==NFS[i].kind]))
                         for i in range(len(NFS))]
                batch=select(method,tick,last[method],local[method],spatial)
                if len(set(batch))!=CU_BUDGET:
                    raise AssertionError("CU policy unequal budget")
                for nf in batch:
                    cycles[method]+=1
                    original,wire=await signed_cu(attestor,NFS[nf].kind,
                        f"s8-{seed}-{number}-{method}",cycles[method])
                    r["checks"]+=1
                    r["bytes"]+=wire
                    old=last[method][nf]
                    r["gap"]=max(r["gap"],tick-(old if old>=0 else -1))
                    last[method][nf]=tick
                    mismatch=canonical(original)!=canonical(obs[NFS[nf].kind])
                    if active_now and mismatch and r["alarm"] is None:
                        r["alarm"]=time.monotonic_ns()
                    if clean_now:
                        r["clean"]+=1
                        r["false"]+=int(mismatch)
            traces.append(dict(tick=tick,attack_active=active_now,
                real_nrf_instance_ids=origin_ids,
                gateway_semantic_deviations=metadata,flags=flags))
        for method in ACTIVES:
            results[method]["gap"]=max(results[method]["gap"],
                                      max(TICKS-1-v for v in last[method]))
            if method!="cu_fixed" and results[method]["gap"]>GAP_LIMIT:
                raise AssertionError("CU scheduling deadline exceeded")
    try:
        await asyncio.gather(inject(),sample())
    finally:
        gateway.target_id=None
        await gateway.server.close()
        await attestor.server.close()
    if start_ns is None or end_ns is None:
        raise AssertionError("Did not complete attack episode")
    rows=[]
    for name,r in results.items():
        yes=r["alarm"] is not None
        dl=(r["alarm"]-start_ns)/1e9 if yes else None
        rows.append(dict(seed=seed,case=number,attack=attack,kind=kind,
            method=name,detected=yes,delay_wall_s=dl,
            horizon_penalized_s=dl if yes else (end_ns-start_ns)/1e9,
            false_alerts=r["false"],clean_checks=r["clean"],
            false_alert_before_attack=r["prior_false"],
            cu_checks=r["checks"],cu_bytes=r["bytes"],
            max_gap_ticks=r["gap"] if name in ACTIVES else None,
            real_nrf_id_sets_unchanged=True))
    return rows,dict(seed=seed,case=number,attack=attack,kind=kind,
        target_native_nrf_id=target_id,trace=traces)


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    r=random.Random(args.seed)
    cases=[(kind,attack) for kind in KINDS for attack in ATTACKS]
    r.shuffle(cases)
    rows,traces=[],[]
    for index,(kind,attack) in enumerate(cases):
        print(f"Stage8 native NRF dynamic discovery case {index+1}/{len(cases)} "
              f"{kind}/{attack}",flush=True)
        a,b=await episode(args.seed,index,kind,attack,args.nrf_url)
        rows+=a
        traces.append(b)
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    (output/"events.json").write_text(json.dumps(rows,indent=2))
    (output/"traces.json").write_text(json.dumps(traces,indent=2))
    (output/"manifest.json").write_text(json.dumps({
        "stage":8,"seed":args.seed,"real_nrf_http2":True,
        "real_nf_registration_mutated":False,
        "native_nrf_binary_mutated":False,
        "mutation":"research gateway relays real NRF discovery JSON and changes one NF profile",
        "legitimate_variation":"gateway permutes native nfInstances list",
        "native_nf_compromise":False,
        "cu_attested_by":"separate research HMAC agent, not native NF",
        "cases":len(cases),"methods":METHODS,"cu_budget":TICKS*CU_BUDGET
    },indent=2))
    print(f"Finished {len(cases)} native NRF-backed gateway corruption trials",flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=2401)
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    p.add_argument("--output",default="stage8_shard")
    a=p.parse_args()
    asyncio.run(run(a))


if __name__=="__main__":
    main()
