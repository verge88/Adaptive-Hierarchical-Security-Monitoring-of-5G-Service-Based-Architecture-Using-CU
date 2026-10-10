"""Stage 9: conditional NSSF-like LAB fault with registered native Open5GS NSSF.

Real Open5GS NRF/NSSF binaries remain UNMODIFIED. A research HTTP/2 policy
service (NOT native NSSF) implements an explicit deterministic slice decision.
Its selected rare branch can be faulted without changing NRF registration or
ordinary answers. Passive semantic, ordinary active HTTP2, fixed HMAC-CU,
local and hierarchical HMAC-CU are evaluated on the same injected episode.

An external challenge-response attestor signs the LAB service's observation;
this proves the attestor's provenance, NOT native NF internal integrity.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
from pathlib import Path
import random
import secrets
import statistics
import time

from .h2_wire import H2Server, h2_request, encode
from .stage5_native import NFS, mac, native_h2_status, wait_core
from .stage7_integrity import nrf_instance_sets
from .bounded_scheduler import bounded_choose

N=4
BUDGET=2
TICKS=27
TICK_S=.20
WARMUP=5
MAX_GAP=3
MODES=("zero_rare","sparse_rare")
ALIGNMENTS=("aligned","unaligned")
ACTIVE=("plain_fixed","cu_fixed","cu_local","cu_hier")
METHODS=("nrf_ids","passive_semantic")+ACTIVE
RARE_P={"zero_rare":0.0,"sparse_rare":0.12}


def expected_decision(request):
    """The external reference policy, provided to ALL detectors equally."""
    if request["sst"]==1 and request["sd"] in ("000001","000002"):
        return "ALLOW"
    if request["sst"]==2 and request["sd"]=="0000FF":
        return "ALLOW"
    return "DENY"


def query(nf,rare=False):
    return dict(nf=nf,sst=2 if rare else 1,
                sd="0000FF" if rare else "000001")


class LabSliceService:
    """Instrumented research service, not a real NSSF/Nnssf handler."""
    def __init__(self,seed,stressed_zone):
        self.server=H2Server(self.handle)
        self.random=random.Random(seed)
        self.stressed_zone=stressed_zone
        self.fault_target=None
        self.fault_enabled=False
        self.count=0

    async def handle(self,headers,raw):
        if headers.get(":method")!="POST" or headers.get(":path")!="/research/nnssf/select":
            return 404,dict(error="LAB policy only")
        try:
            request=json.loads(raw)
            nf=request["nf"]
            if type(nf) is not int or not 0<=nf<N:
                return 400,dict(error="NF research context outside 0..3")
            if request["sst"] not in (1,2) or not isinstance(request["sd"],str):
                return 400,dict(error="invalid parameters")
        except (ValueError,KeyError,TypeError):
            return 400,dict(error="invalid JSON")
        self.count+=1
        output=expected_decision(request)
        if (self.fault_enabled and self.fault_target==nf
            and request["sst"]==2 and request["sd"]=="0000FF"):
            output="DENY"
        # Benign fields vary with each response. They MUST NOT be treated as
        # policy failures by any strong passive or active detector.
        zone=nf//2
        load=4.5 if zone==self.stressed_zone else .5
        return 200,dict(nf=nf,decision=output,route_token=f"{self.random.getrandbits(64):016x}",
                        observed_load=round(load+self.random.random()*.2,4))


class SignedResearchAttestor:
    """HMAC signs a fresh independently made request to the LAB service."""
    def __init__(self,url):
        self.url=url
        self.key=secrets.token_bytes(32)
        self.seen={}
        self.server=H2Server(self.handle)

    async def handle(self,headers,raw):
        if headers.get(":method")!="POST" or headers.get(":path")!="/research/cu/check":
            return 404,dict(error="unknown operation")
        try:
            obj=json.loads(raw)
            signed={k:obj[k] for k in ("policy","nf","sequence","nonce","issued_ns","sst","sd")}
            if (type(signed["nf"]) is not int or not 0<=signed["nf"]<N
                or type(signed["sequence"]) is not int
                or type(signed["issued_ns"]) is not int
                or not isinstance(signed["nonce"],str) or len(signed["nonce"])!=32
                or not hmac.compare_digest(obj["mac"],mac(self.key,signed))):
                return 401,dict(error="invalid HMAC")
            if abs(time.monotonic_ns()-signed["issued_ns"])>5_000_000_000:
                return 400,dict(error="expired")
            identity=(signed["policy"],signed["nf"])
            if signed["sequence"]<=self.seen.get(identity,-1):
                return 409,dict(error="replayed")
            self.seen[identity]=signed["sequence"]
        except (KeyError,TypeError,ValueError):
            return 400,dict(error="bad challenge")
        request={k:signed[k] for k in ("nf","sst","sd")}
        status,response,_,_=await h2_request(
            self.url,"/research/nnssf/select","POST",request,timeout=3)
        if status!=200:
            return 503,dict(error="LAB NF service not available")
        answer={**signed,"native_lab_answer":response,
                "checked_ns":time.monotonic_ns()}
        return 200,{**answer,"mac":mac(self.key,answer)}


async def active_request(service_url,agent,policy,nf,seq):
    payload=query(nf,rare=True)
    if policy=="plain_fixed":
        st,answer,bytes_used,_=await h2_request(
            service_url,"/research/nnssf/select","POST",payload,timeout=3)
        if st!=200:
            raise RuntimeError("Ordinary active HTTP/2 service query failed")
        return answer,bytes_used
    req={**payload,"policy":policy,"sequence":seq,
         "nonce":secrets.token_hex(16),"issued_ns":time.monotonic_ns()}
    status,reply,wire,_=await h2_request(
        f"http://127.0.0.1:{agent.server.port}",
        "/research/cu/check","POST",{**req,"mac":mac(agent.key,req)},timeout=3)
    if status!=200:
        raise AssertionError(f"Research CU error {status}")
    data={k:v for k,v in reply.items() if k!="mac"}
    if not hmac.compare_digest(reply["mac"],mac(agent.key,data)):
        raise AssertionError("CU HMAC verification failed")
    if any(reply[k]!=v for k,v in req.items()):
        raise AssertionError("CU replay/substitution mismatch")
    return reply["native_lab_answer"],wire


def select(policy,tick,last,local,zone):
    if policy in ("plain_fixed","cu_fixed"):
        return [(BUDGET*tick+i)%N for i in range(BUDGET)]
    spatial=zone if policy=="cu_hier" else [0.]*N
    return bounded_choose(tick,local,spatial,last,warmup_end=0,
                          budget=BUDGET,max_gap=MAX_GAP)


async def episode(seed,number,mode,alignment,instance,stressed_zone,nrf_url):
    """The label is used ONLY by the injector and retrospective evaluator."""
    await wait_core(nrf_url,require_registered=True,timeout=60)
    pre=await nrf_instance_sets(nrf_url)
    native=[await native_h2_status(NFS[i]) for i in (1,3)]
    if not all(x["reachable"] for x in native):
        raise AssertionError("Native Open5GS NSSF service unavailable")

    service=LabSliceService(seed*233+number,stressed_zone)
    await service.server.start()
    service_url=f"http://127.0.0.1:{service.server.port}"
    agent=SignedResearchAttestor(service_url)
    await agent.server.start()
    rng=random.Random(seed*53111+number)
    start_after=(WARMUP+1.3+rng.uniform(.15,.85))*TICK_S
    end_after=start_after+(11+rng.uniform(0,2))*TICK_S
    results={p:dict(detected=None,false=0,clean=0,checked=0,bytes=0,gap=0,
                    last=[-1]*N,local=[0.]*N,seq=0) for p in METHODS}
    origin=time.monotonic()
    fault_start=None
    fault_end=None
    label_count=0
    trace=[]
    random_traffic=random.Random(seed*191+number*31)
    probe_order_rng=random.Random(seed*5021+number*83+71)

    async def inject():
        nonlocal fault_start,fault_end
        await asyncio.sleep(max(0.,origin+start_after-time.monotonic()))
        fault_start=time.monotonic_ns()
        service.fault_target=instance
        service.fault_enabled=True
        await asyncio.sleep(max(0.,origin+end_after-time.monotonic()))
        service.fault_enabled=False
        service.fault_target=None
        fault_end=time.monotonic_ns()

    async def observe():
        nonlocal label_count
        zone_scores=[0.]*N
        for tick in range(TICKS):
            await asyncio.sleep(max(0.,origin+tick*TICK_S-time.monotonic()))
            attacked=(fault_start is not None and fault_end is None)
            clean=(fault_start is None or fault_end is not None)
            # Real passive traffic: strong semantic validator gets every
            # observed legitimate transaction, including rare ones if sampled.
            for nf in range(N):
                rare=random_traffic.random()<RARE_P[mode]
                q=query(nf,rare)
                status,answer,nbytes,_=await h2_request(
                    service_url,"/research/nnssf/select","POST",q,timeout=3)
                if status!=200:
                    raise AssertionError("Lab NSSF request failed")
                bad=answer["decision"]!=expected_decision(q)
                if attacked and nf==instance and rare:
                    label_count+=1
                r=results["passive_semantic"]
                r["checked"]+=1 # visible passive messages, not active probes
                if attacked and bad and r["detected"] is None:
                    r["detected"]=time.monotonic_ns()
                if clean:
                    r["clean"]+=1
                    r["false"]+=int(bad)
                # Data-mining input ONLY: benign load conditions, no fault label.
                zone_scores[nf]=.65*zone_scores[nf]+.35*float(answer["observed_load"])
            # NRF-only checks REAL instance IDs, never receives fault labels.
            post=await nrf_instance_sets(nrf_url)
            drift=post!=pre
            rr=results["nrf_ids"]
            rr["checked"]+=1
            if attacked and drift and rr["detected"] is None:
                rr["detected"]=time.monotonic_ns()
            if clean:
                rr["clean"]+=1
                rr["false"]+=int(drift)
            # Both local and hierarchical algorithms use the same observations.
            # Hierarchy aggregates the 2 neighboring NF-context load signals.
            zone=[statistics.mean(zone_scores[(i//2)*2:(i//2)*2+2]) for i in range(N)]
            # Randomized policy execution order prevents fixed first/last
            # privilege in monotonic wall-clock detection times. Seed does not
            # depend on hidden target, attack onset or outcome labels.
            execution=list(ACTIVE)
            probe_order_rng.shuffle(execution)
            for policy in execution:
                r=results[policy]
                chosen=select(policy,tick,r["last"],zone_scores,zone)
                if len(set(chosen))!=BUDGET:
                    raise AssertionError("Unequal active budget")
                for nf in chosen:
                    r["seq"]+=1
                    answer,wire=await active_request(service_url,agent,policy,nf,r["seq"])
                    r["bytes"]+=wire
                    r["checked"]+=1
                    previous=r["last"][nf]
                    r["gap"]=max(r["gap"],tick-(previous if previous>=0 else -1))
                    r["last"][nf]=tick
                    # Oracle known to every detector; not the attack label.
                    bad=answer["decision"]!=expected_decision(query(nf,True))
                    if attacked and bad and r["detected"] is None:
                        r["detected"]=time.monotonic_ns()
                    if clean:
                        r["clean"]+=1
                        r["false"]+=int(bad)
            trace.append(dict(tick=tick,real_NRF_registry_unchanged=not drift,
                              passive_rare_requests=label_count,
                              zone_load_features=[round(v,2) for v in zone],
                              active_check_selection={p:[i for i in range(N)
                                    if results[p]["last"][i]==tick] for p in ACTIVE}))
        for policy in ACTIVE:
            r=results[policy]
            r["gap"]=max(r["gap"],max(TICKS-1-x for x in r["last"]))
            if policy in ("cu_local","cu_hier") and r["gap"]>MAX_GAP:
                raise AssertionError("Maximum KIE gap violated")
    try:
        await asyncio.gather(inject(),observe())
    finally:
        service.fault_enabled=False
        await agent.server.close()
        await service.server.close()
    if fault_start is None or fault_end is None:
        raise AssertionError("Fault never injected")
    post=await nrf_instance_sets(nrf_url)
    if post!=pre:
        raise AssertionError("Actual NRF profiles changed during LAB fault")
    rows=[]
    duration=(fault_end-fault_start)/1e9
    for method,r in results.items():
        observed=r["detected"]
        delay=(observed-fault_start)/1e9 if observed is not None else None
        rows.append(dict(seed=seed,episode=number,mode=mode,alignment=alignment,
            stress_zone=stressed_zone,faulted_lab_context=instance,
            method=method,detected=observed is not None,
            detection_wall_s=delay,censored_wall_s=delay if delay is not None else duration,
            false_alarms=r["false"],clean_checks=r["clean"],
            active_checks=r["checked"] if method in ACTIVE else 0,
            observed_passive_messages=r["checked"] if method=="passive_semantic" else 0,
            observed_nrf_queries=r["checked"] if method=="nrf_ids" else 0,
            active_http2_bytes=r["bytes"],max_check_gap_ticks=r["gap"] if method in ACTIVE else None,
            genuine_native_NSSF_reachable=True,real_NRF_ids_unchanged=True,
            rare_attacked_passive_transactions=label_count))
    return rows,dict(seed=seed,episode=number,mode=mode,alignment=alignment,
        stressed_zone=stressed_zone,target_lab_context=instance,
        target_native_NSSF_service=NFS[1+(instance%2)*2].service,
        native_nssf_http2_statuses=[n["http_status"] for n in native],
        fault_start_wall_s=(fault_start-int(origin*1e9))/1e9,
        fault_end_wall_s=(fault_end-int(origin*1e9))/1e9,trace=trace)


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=60)
    r=random.Random(args.seed)
    cases=[(mode,alignment,rep) for mode in MODES
           for alignment in ALIGNMENTS for rep in range(2)]
    r.shuffle(cases)
    rows,traces=[],[]
    for i,(mode,alignment,rep) in enumerate(cases):
        stress=r.randrange(2)
        target_zone=stress if alignment=="aligned" else 1-stress
        target=2*target_zone+r.randrange(2)
        print(f"Stage 9 real-NSSF-anchored LAB conditional fault {i+1}/{len(cases)} "
              f"{mode}/{alignment} stress={stress}",flush=True)
        data,trace=await episode(args.seed,i,mode,alignment,target,stress,args.nrf_url)
        rows.extend(data)
        traces.append(trace)
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=True)
    (output/"events.json").write_text(json.dumps(rows,indent=2))
    (output/"traces.json").write_text(json.dumps(traces,indent=2))
    (output/"manifest.json").write_text(json.dumps(dict(
        stage=9,native_Open5GS_NSSF_running=True,
        native_Open5GS_NSSF_modified=False,
        NF_fault_is_lab_policy_sidecar_only=True,
        real_NRF_discovery_verified=True,
        experiment="conditional rare SST/SD policy error",
        research_attestor_HMAC_not_native_NF_signature=True,
        fault_labels_excluded_from_scheduling=True,
        explicit_synthetic_stress_target_coupling=True,
        policy_oracle_provided_equally=True,
        seed=args.seed,scenarios=len(cases),active_methods=list(ACTIVE),
        slots_per_tick=BUDGET,ticks=TICKS),indent=2))
    print(f"Stage9 finished {len(cases)} real-NSSF-anchored lab faults and "
          f"{len(rows)} detector records",flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=2901)
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    p.add_argument("--output",default="stage9_shard")
    args=p.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
