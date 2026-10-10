"""Stage 11: hedged risk scheduling for selective alteration by a LAB SCP with producer-bound transaction receipts.

Real Open5GS NRF/NSSF binaries run and register but DO NOT serve these lab
slice-decision requests. Research-only dynamic NF producer and HTTP/2 SCP
implement the controlled message integrity fault. The producer signs the
original transaction's exact response digest with an isolated test key; the
SCP never receives this key. A separate challenge-response CU attestor signs
the original producer receipt. These signatures do not attest native NF code.

The stronger "trusted two-sided passive" and "trusted ordinary direct"
controls are included to avoid creating a false unique CU advantage.
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

from .h2_wire import H2Server,h2_request,encode
from .stage5_native import NFS,mac,native_h2_status,wait_core
from .stage7_integrity import nrf_instance_sets
from .stage9_conditional import observation_phase
from .bounded_scheduler import bounded_choose

N=4
BUDGET=2
TICKS=23
TICK_S=.21
WARMUP=5
MAX_GAP=3
ATTACKS=("plausible_choice_change","stale_choice_field")
ALIGNMENTS=("aligned","misleading","neutral","switch")
METHODS=("nrf_only","passive_consumer","ordinary_active",
         "trusted_plain","cu_fixed","cu_local","cu_hier","cu_hedged","trusted_both_ends")
BUDGETED=("ordinary_active","trusted_plain","cu_fixed","cu_local","cu_hier","cu_hedged")
SCHEDULED=("trusted_plain","cu_fixed","cu_local","cu_hier","cu_hedged")


def sha(obj):
    return hashlib.sha256(encode(obj)).hexdigest()


def lab_req(context,transaction):
    return {"context":context,"transaction_id":transaction}


class Origin:
    """Separate research producer; not a native Open5GS NF."""
    def __init__(self,seed):
        self.server=H2Server(self.handle)
        self.key=secrets.token_bytes(32)
        self.rng=random.Random(seed)
        self.sequence=[0]*N
        self.previous={}
        self.receipts={}

    async def handle(self,headers,body):
        path=headers.get(":path","")
        try: request=json.loads(body)
        except (TypeError,ValueError): return 400,{"error":"bad request"}
        if path=="/lab/nssf/select" and headers.get(":method")=="POST":
            try:
                ctx=request["context"]
                tx=request["transaction_id"]
                if type(ctx) is not int or not 0<=ctx<N or not isinstance(tx,str):
                    raise ValueError("invalid identity")
                if tx in self.receipts:
                    return 409,{"error":"duplicate transaction"}
            except (KeyError,TypeError,ValueError):
                return 400,{"error":"invalid transaction"}
            previous=self.previous.get(ctx)
            # Alternation is a PRIVATE dynamic choice of this laboratory
            # producer, not a static public policy oracle.
            choice="slice_A" if self.sequence[ctx]%2==0 else "slice_B"
            self.sequence[ctx]+=1
            self.previous[ctx]=choice
            payload={"context":ctx,"transaction_id":tx,"selected_slice":choice,
                     "request_hash":sha(request),
                     "producer_nonce":f"{self.rng.getrandbits(96):024x}"}
            receipt={"transaction_id":tx,"request_hash":sha(request),
                     "response_hash":sha(payload),"producer_context":ctx}
            self.receipts[tx]={"receipt":receipt,
                              "producer_mac":mac(self.key,receipt),
                              "prior_choice":previous}
            return 200,payload
        if path=="/lab/producer/receipt" and headers.get(":method")=="POST":
            tx=request.get("transaction_id")
            stored=self.receipts.get(tx)
            if stored is None:return 404,{"error":"no original receipt"}
            return 200,{"receipt":stored["receipt"],"producer_mac":stored["producer_mac"]}
        return 404,{"error":"not a lab endpoint"}


class LabSCP:
    """Only modifies the consumer-facing returned copy of a real lab reply."""
    def __init__(self,origin):
        self.origin=origin
        self.url=f"http://127.0.0.1:{origin.server.port}"
        self.server=H2Server(self.handle)
        self.active_context=None
        self.attack=None
        self.fault_ids=set()
        self.observed=0

    async def handle(self,headers,body):
        if headers.get(":path")!="/lab/scp/select" or headers.get(":method")!="POST":
            return 404,{"error":"not SCP endpoint"}
        request=json.loads(body)
        status,answer,_,_=await h2_request(self.url,"/lab/nssf/select",
                                            "POST",request,timeout=3)
        if status!=200:return status,answer
        self.observed+=1
        if request["context"]==self.active_context and self.attack is not None:
            copy=dict(answer)
            original=copy["selected_slice"]
            if self.attack=="plausible_choice_change":
                choice="slice_B" if original=="slice_A" else "slice_A"
            elif self.attack=="stale_choice_field":
                previous=self.origin.receipts[request["transaction_id"]]["prior_choice"]
                choice=previous if previous and previous!=original else (
                    "slice_B" if original=="slice_A" else "slice_A")
            else:raise ValueError("unknown attack")
            copy["selected_slice"]=choice
            self.fault_ids.add(request["transaction_id"])
            return 200,copy
        return 200,answer


async def receipt_from_origin(origin_url,transaction):
    st,x,wire,_=await h2_request(origin_url,"/lab/producer/receipt","POST",
                                {"transaction_id":transaction},timeout=3)
    if st!=200:raise AssertionError("Independent producer record missing")
    return x,wire


def verify_receipt(origin,stored):
    body=stored["receipt"]
    if not hmac.compare_digest(stored["producer_mac"],mac(origin.key,body)):
        raise AssertionError("Producer origin MAC invalid")
    return body


class CUAgent:
    """External attestor over independent producer-origin channel."""
    def __init__(self,producer):
        self.producer=producer
        self.origin_url=f"http://127.0.0.1:{producer.server.port}"
        self.key=secrets.token_bytes(32)
        self.seen={}
        self.server=H2Server(self.handle)

    async def handle(self,headers,body):
        if headers.get(":path")!="/lab/cu/verify" or headers.get(":method")!="POST":
            return 404,{"error":"bad CU URL"}
        try:
            obj=json.loads(body)
            signed={k:obj[k] for k in ("scope","transaction_id","cycle",
                                       "nonce","issued_ns")}
            if (not isinstance(signed["scope"],str) or
                not isinstance(signed["transaction_id"],str) or
                type(signed["cycle"]) is not int or
                type(signed["issued_ns"]) is not int or
                not isinstance(signed["nonce"],str) or len(signed["nonce"])!=32 or
                not hmac.compare_digest(obj["mac"],mac(self.key,signed))):
                return 401,{"error":"invalid challenge"}
            if abs(time.monotonic_ns()-signed["issued_ns"])>5_000_000_000:
                return 400,{"error":"expired challenge"}
            if signed["cycle"]<=self.seen.get(signed["scope"],-1):
                return 409,{"error":"replay challenge"}
            self.seen[signed["scope"]]=signed["cycle"]
        except (ValueError,KeyError,TypeError):
            return 400,{"error":"bad challenge"}
        stored,_=await receipt_from_origin(
            self.origin_url,signed["transaction_id"])
        verify_receipt(self.producer,stored)
        response={**signed,"checked_ns":time.monotonic_ns(),
                  "producer_attestation":stored}
        return 200,{**response,"mac":mac(self.key,response)}


async def signed_check(agent,method,tx,cycle):
    fields=dict(scope=method,transaction_id=tx,cycle=cycle,
                nonce=secrets.token_hex(16),issued_ns=time.monotonic_ns())
    code,ans,wire,_=await h2_request(
        f"http://127.0.0.1:{agent.server.port}","/lab/cu/verify","POST",
        {**fields,"mac":mac(agent.key,fields)},timeout=4)
    if code!=200:raise AssertionError(f"Failed challenge {code}")
    body={k:v for k,v in ans.items() if k!="mac"}
    if any(ans[k]!=v for k,v in fields.items()) or not hmac.compare_digest(
        ans["mac"],mac(agent.key,body)):
        raise AssertionError("Invalid authenticated CU response")
    rec=verify_receipt(agent.producer,ans["producer_attestation"])
    return rec,wire


def schedule(method,tick,last,local,zone):
    if method in ("cu_fixed","trusted_plain"):
        return [(tick*BUDGET+i)%N for i in range(BUDGET)]
    if method=="cu_hedged":
        # Complete coverage of all four contexts every TWO scheduler ticks.
        # Alternate risk-informed with fixed frames; do not use attack labels.
        if tick%2:
            return [i for i in range(N) if last[i]!=tick-1]
        if (tick//2)%2:
            return list(range(BUDGET))
        return sorted(range(N),key=lambda i:(-zone[i],i))[:BUDGET]
    return bounded_choose(tick,local,zone if method=="cu_hier" else [0.]*N,
                          last,warmup_end=0,budget=BUDGET,max_gap=MAX_GAP)


async def episode(seed,episode_id,attack,alignment,target_context,stress_zone,nrf_url):
    await wait_core(nrf_url,require_registered=True,timeout=60)
    initial_ids=await nrf_instance_sets(nrf_url)
    native=[await native_h2_status(NFS[i]) for i in (1,3)]
    if not all(x["reachable"] for x in native):
        raise AssertionError("Native Open5GS NSSF unhealthy")

    origin=Origin(seed*151+episode_id)
    await origin.server.start()
    proxy=LabSCP(origin)
    await proxy.server.start()
    attestor=CUAgent(origin)
    await attestor.server.start()
    origin_url=f"http://127.0.0.1:{origin.server.port}"
    proxy_url=f"http://127.0.0.1:{proxy.server.port}"
    rng=random.Random(seed*42077+episode_id*31)
    phase=(WARMUP+1.2+rng.uniform(.1,.9))*TICK_S
    end_phase=phase+(9+rng.uniform(0,1))*TICK_S
    start_ns=None
    end_ns=None
    result={m:dict(alarm=None,clean=0,false=0,checks=0,bytes=0,
                   last=[-1]*N,local=[0.]*N,maxgap=0,seq=0)
            for m in METHODS}
    origin_clock=time.monotonic()
    traces=[]
    order_rng=random.Random(seed*131+episode_id*19+7)

    async def attack_task():
        nonlocal start_ns,end_ns
        await asyncio.sleep(max(0,origin_clock+phase-time.monotonic()))
        start_ns=time.monotonic_ns()
        proxy.active_context=target_context
        proxy.attack=attack
        await asyncio.sleep(max(0,origin_clock+end_phase-time.monotonic()))
        proxy.active_context=None
        proxy.attack=None
        end_ns=time.monotonic_ns()

    async def monitor():
        for tick in range(TICKS):
            await asyncio.sleep(max(0,origin_clock+tick*TICK_S-time.monotonic()))
            replies=[]
            for ctx in range(N):
                req=lab_req(ctx,f"consumer-{seed}-{episode_id}-{tick}-{ctx}")
                sent=time.monotonic_ns()
                code,answer,_,_=await h2_request(
                    proxy_url,"/lab/scp/select","POST",req,timeout=3)
                ended=time.monotonic_ns()
                if code!=200:raise AssertionError("Consumer lab SBI failed")
                replies.append(dict(request=req,body=answer,sent=sent,ended=ended,
                                    phase=observation_phase(sent,ended,start_ns,end_ns)))
                valid=(answer["transaction_id"]==req["transaction_id"] and
                       answer["context"]==ctx and
                       answer["request_hash"]==sha(req) and
                       answer["selected_slice"] in ("slice_A","slice_B") and
                       isinstance(answer["producer_nonce"],str))
                m=result["passive_consumer"]
                if m["alarm"] is None and not valid and replies[-1]["phase"]=="attack":
                    m["alarm"]=ended
                if replies[-1]["phase"]=="clean":
                    m["clean"]+=1
                    m["false"]+=int(not valid)

            ids=await nrf_instance_sets(nrf_url)
            drift=ids!=initial_ids
            nrf=result["nrf_only"]
            if drift and nrf["alarm"] is None and start_ns is not None and end_ns is None:
                nrf["alarm"]=time.monotonic_ns()
            if start_ns is None or end_ns is not None:
                nrf["clean"]+=1
                nrf["false"]+=int(drift)

            # Consumer-accessible, benign load hint; no fault label passed to
            # any scheduler. Correlation is deliberately aligned or reversed
            # across symmetric experimental strata.
            hinted=(stress_zone if alignment!="switch" or tick<TICKS//2
                    else 1-stress_zone)
            # No target ID is sent to a scheduler. Synthetic hints may be
            # correct, actively misleading, neutral or flip at a fixed tick.
            measurements=[(.5 if alignment=="neutral" else
                          4.5 if ctx//2==hinted else .5)+rng.random()*.15
                          for ctx in range(N)]
            zone=[statistics.mean(measurements[2*(i//2):2*(i//2)+2])
                  for i in range(N)]

            async def compare_producer(method,ctx,producer_receipt,wire):
                r=result[method]
                r["checks"]+=1
                r["bytes"]+=wire
                match=producer_receipt["response_hash"]==sha(replies[ctx]["body"])
                phase_now=replies[ctx]["phase"]
                checked=time.monotonic_ns()
                if phase_now=="attack" and not match and r["alarm"] is None:
                    r["alarm"]=checked
                if phase_now=="clean":
                    r["clean"]+=1
                    r["false"]+=int(not match)
                return not match

            # Shuffle all competitors to avoid fixed in-tick wall-time order.
            order=list(("ordinary_active","trusted_both_ends",
                        "trusted_plain","cu_fixed","cu_local","cu_hier","cu_hedged"))
            order_rng.shuffle(order)
            for method in order:
                r=result[method]
                if method=="trusted_both_ends":
                    for ctx in range(N):
                        raw,wire=await receipt_from_origin(
                            origin_url,replies[ctx]["request"]["transaction_id"])
                        original=verify_receipt(origin,raw)
                        await compare_producer(method,ctx,original,wire)
                    continue
                if method=="ordinary_active":
                    # A matched-budget ACTIVE request to the same compromised
                    # SCP. Dynamic responses are semantically valid and have
                    # no known producer-origin reference at this vantage.
                    chosen=[(tick*BUDGET+i)%N for i in range(BUDGET)]
                    for ctx in chosen:
                        req=lab_req(ctx,f"probe-{seed}-{episode_id}-{tick}-{ctx}")
                        sent=time.monotonic_ns()
                        status,response,wire,_=await h2_request(
                            proxy_url,"/lab/scp/select","POST",req,timeout=3)
                        finished=time.monotonic_ns()
                        if status!=200:raise AssertionError("Active proxy probe failed")
                        r["checks"]+=1
                        r["bytes"]+=wire
                        valid=(response["context"]==ctx and
                               response["transaction_id"]==req["transaction_id"] and
                               response["request_hash"]==sha(req) and
                               response["selected_slice"] in ("slice_A","slice_B"))
                        phase_now=observation_phase(sent,finished,start_ns,end_ns)
                        if phase_now=="attack" and not valid and r["alarm"] is None:
                            r["alarm"]=finished
                        if phase_now=="clean":
                            r["clean"]+=1
                            r["false"]+=int(not valid)
                    continue
                # Each other active policy verifies TWO original
                # consumer transactions, not extra artificially selected
                # inputs; equal transaction-integrity budget.
                r["local"]=[.65*a+.35*b for a,b in zip(r["local"],measurements)]
                chosen=schedule(method,tick,r["last"],r["local"],zone)
                if len(set(chosen))!=BUDGET:
                    raise AssertionError("Active verification budget incorrect")
                for ctx in chosen:
                    r["seq"]+=1
                    tx=replies[ctx]["request"]["transaction_id"]
                    if method=="trusted_plain":
                        source,wire=await receipt_from_origin(origin_url,tx)
                        rec=source["receipt"] # an already trusted direct path,
                                              # unlike public consumer-only data
                    else:
                        rec,wire=await signed_check(attestor,
                            f"s10-{seed}-{episode_id}-{method}",tx,r["seq"])
                    prior=r["last"][ctx]
                    r["maxgap"]=max(r["maxgap"],tick-(prior if prior>=0 else -1))
                    r["last"][ctx]=tick
                    await compare_producer(method,ctx,rec,wire)
            traces.append(dict(tick=tick,real_nrf_sets_unchanged=not drift,
                benign_zone_hints=[round(x,3) for x in zone],
                original_consumer_tx=[r["request"]["transaction_id"] for r in replies],
                verifier_last={p:list(result[p]["last"]) for p in SCHEDULED}))
        for method in SCHEDULED:
            r=result[method]
            r["maxgap"]=max(r["maxgap"],max(TICKS-1-n for n in r["last"]))
            if method in ("cu_local","cu_hier","cu_hedged") and r["maxgap"]>MAX_GAP:
                raise AssertionError("Hard max-check-gap violated")

    try:
        await asyncio.gather(attack_task(),monitor())
    finally:
        proxy.active_context=None
        proxy.attack=None
        await attestor.server.close()
        await proxy.server.close()
        await origin.server.close()
    if start_ns is None or end_ns is None:
        raise AssertionError("Missing fault on/off timeline")
    if await nrf_instance_sets(nrf_url)!=initial_ids:
        raise AssertionError("Native NRF registrations changed")
    if not proxy.fault_ids:
        raise AssertionError("No actual laboratory SCP message corruption!")
    rows=[]
    duration=(end_ns-start_ns)/1e9
    for m,r in result.items():
        detected=r["alarm"] is not None
        delay=(r["alarm"]-start_ns)/1e9 if detected else None
        rows.append(dict(seed=seed,episode=episode_id,attack=attack,
            alignment=alignment,method=m,detected=detected,
            detection_wall_s=delay,
            horizon_penalized_wall_s=delay if detected else duration,
            clean_checks=r["clean"],false_alarms=r["false"],
            control_checks=r["checks"],h2_control_wire_bytes=r["bytes"],
            max_check_gap_ticks=r["maxgap"] if m in SCHEDULED else None,
            tampered_transactions=len(proxy.fault_ids),
            native_NSSF_healthy=True,real_NRF_unchanged=True))
    return rows,dict(seed=seed,episode=episode_id,attack=attack,
        alignment=alignment,synthetic_stress_zone=stress_zone,
        attacked_lab_context=target_context,
        tampered_txids=sorted(proxy.fault_ids),trace=traces)


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    rng=random.Random(args.seed)
    cases=[(a,b,i) for a in ATTACKS for b in ALIGNMENTS for i in range(1)]
    rng.shuffle(cases)
    rows,traces=[],[]
    for idx,(attack,alignment,rep) in enumerate(cases):
        stressed=rng.randrange(2)
        target_zone=(1-stressed if alignment=="misleading" else
                     rng.randrange(2) if alignment=="neutral" else stressed)
        target=2*target_zone+rng.randrange(2)
        print(f"Stage11 {idx+1}/8: lab SCP selectively rewrites dynamic "
              f"{attack}, {alignment}",flush=True)
        a,b=await episode(args.seed,idx,attack,alignment,target,stressed,
                          args.nrf_url)
        rows.extend(a)
        traces.append(b)
    root=Path(args.output)
    root.mkdir(parents=True,exist_ok=True)
    (root/"events.json").write_text(json.dumps(rows,indent=2))
    (root/"traces.json").write_text(json.dumps(traces,indent=2))
    (root/"manifest.json").write_text(json.dumps(dict(
        research_stage=11,source="real native Open5GS NRF/NSSF reachability only",
        native_open5gs_NF_compromised=False,native_open5gs_SCP_compromised=False,
        producer="independent research-only dynamic NSSF-like producer",
        attack_target="lab HTTP/2 SCP consumer response COPY",
        attestation="producer HMAC on original tx hash + independent research CU agent",
        producer_origin_key_never_exposed_to_lab_scp=True,
        trusted_plain_also_has_original_producer_channel=True,
        positive_endpoint_passive_two_sided_control=True,
        sample_count=len(cases),control_budget_per_tick=BUDGET,
        seed=args.seed,
        hedged_policy="alternating fixed and risk-prioritized two-tick frames",
        adversarial_risk_conditions=list(ALIGNMENTS)),indent=2))
    print(f"Stage10 completed {len(cases)} selective SCP response tampering "
          f"episodes and {len(rows)} detector records",flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,default=3301)
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    p.add_argument("--output",default="stage11_shard")
    args=p.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
