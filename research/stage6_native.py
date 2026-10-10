"""Stage 6: randomized-phase REAL Open5GS NF outages; NRF-only control.

Native Open5GS binaries are unmodified. A separate HMAC CU agent checks their
real HTTP/2 sockets. NRF is an independent *already informative* baseline.
"masked" is a blinded experimental telemetric-feed intervention; Open5GS NRF
still runs normally and its true responses are separately logged.

The scheduler starts BEFORE the outage. Detection uses measured monotonic
wall time after Docker stop returns; no label enters the scheduler.
"""
from __future__ import annotations
import argparse
import asyncio
import json
from pathlib import Path
import random
import statistics
import time

from .stage5_native import (NFS, NativeAttestor, signed_observation, native_h2_status,
                            wait_core, nrf_counts, docker)
from .bounded_scheduler import bounded_choose

TICK_S=0.30
TICKS=29
HOLD_DOWN_S=2.20
SLOTS=2
BOUND=3
POLICIES=("fixed","bounded_local","bounded_zone")
MODES=("live","masked")


def zone_features(counts):
    """Risk from observed NRF registration counts; never from an attack label."""
    return [4.0 if counts.get(n.kind, 2)<2 else 0.0 for n in NFS]


def policy_batch(policy,tick,last,local,counts):
    if policy=="fixed":
        return [(SLOTS*tick+i)%len(NFS) for i in range(SLOTS)]
    spatial=zone_features(counts) if policy=="bounded_zone" else [0.0]*len(NFS)
    return bounded_choose(tick,local,spatial,last,warmup_end=0,
                          budget=SLOTS,max_gap=BOUND)


class LiveFeed:
    def __init__(self,url,mask):
        self.url=url
        self.mask=mask
        self.latest={"AUSF":2,"NSSF":2}
        self.trace=[]
        self.errors=[]
        self.stop=False

    async def loop(self,origin):
        while not self.stop:
            try:
                actual=await nrf_counts(self.url)
                stamp=time.monotonic_ns()
                self.latest=actual
                self.trace.append(dict(elapsed_wall_s=round((stamp-origin)/1e9,5),
                                       native_nrf_counts=actual))
            except (ConnectionError,RuntimeError,TimeoutError,OSError) as e:
                self.errors.append(type(e).__name__)
            await asyncio.sleep(.08)

    def observed(self):
        return {"AUSF":2,"NSSF":2} if self.mask else dict(self.latest)


class Fault:
    def __init__(self,target):
        self.target=target
        self.started_ns=None
        self.ended_ns=None
        self.start_delay_s=None
        self.stop_completed_ns=None


async def run_episode(agent,seed,episode,target,mode,nrf_url):
    """Concurrent policies all see the SAME actual native outage."""
    if mode not in MODES:
        raise ValueError(mode)
    await wait_core(nrf_url,require_registered=True,timeout=70)
    origin=time.monotonic_ns()
    origin_wall=time.monotonic()
    randomizer=random.Random(670000+seed*100+episode)
    # Start all monitoring first. Fault phase is independently randomized.
    offset_ticks=5 + randomizer.uniform(.15, .95)
    fault=Fault(target)
    fault.start_delay_s=offset_ticks*TICK_S
    feed=LiveFeed(nrf_url,mask=(mode=="masked"))
    feed_task=asyncio.create_task(feed.loop(origin))
    results={p:dict(last=[-1]*len(NFS),local=[0.0]*len(NFS),probes=0,
                    bytes=0,max_gap=0,misses=0,detected_ns=None,
                    false_alarms=0,clean_checks=0,rtts=[],trace=[],cycles=0)
             for p in POLICIES}
    # Shuffle which worker gets the earlier initial phase to reduce order bias.
    order=list(POLICIES)
    randomizer.shuffle(order)
    phase={p:.014*i for i,p in enumerate(order)}

    async def worker(policy):
        record=results[policy]
        for tick in range(TICKS):
            deadline=origin_wall+tick*TICK_S+phase[policy]
            await asyncio.sleep(max(0,deadline-time.monotonic()))
            # Only the signed native HTTP/2 observations feed NF-local risk.
            selected=policy_batch(policy,tick,record["last"],record["local"],
                                  feed.observed())
            if len(set(selected))!=SLOTS:
                raise AssertionError("Invalid equal-budget CU selection")
            for nf in selected:
                record["cycles"]+=1
                report,wire=await signed_observation(agent,
                    f"stage6-{seed}-{episode}-{policy}",nf,record["cycles"])
                record["probes"]+=1
                record["bytes"]+=wire
                record["rtts"].append(report["rtt_ms"])
                old=record["last"][nf]
                record["max_gap"]=max(record["max_gap"],tick-(old if old>=0 else -1))
                record["last"][nf]=tick
                # Data-Mining proxy: online exponentially weighted latency risk;
                # does not use attack labels or fault.target.
                feature=5.0 if not report["reachable"] else max(
                    0.0,min(5.0,(report["rtt_ms"]-3.0)/4.0))
                record["local"][nf]=.65*record["local"][nf]+.35*feature
                inspected_ns=report["checked_ns"]
                if (fault.started_ns is not None and
                    fault.ended_ns is None and nf==target and
                    not report["reachable"] and
                    inspected_ns>=fault.started_ns and
                    record["detected_ns"] is None):
                    record["detected_ns"]=inspected_ns
                if (fault.started_ns is None or
                    fault.ended_ns is not None):
                    record["clean_checks"]+=1
                    if not report["reachable"]:
                        record["false_alarms"]+=1
                record["trace"].append(dict(tick=tick,nf=nf,
                    reachable=report["reachable"],status=report["http_status"],
                    elapsed_wall_s=round((inspected_ns-origin)/1e9,5)))
        last_tick=TICKS-1
        record["max_gap"]=max(record["max_gap"],max(last_tick-v for v in record["last"]))
        if policy.startswith("bounded") and record["max_gap"]>BOUND:
            raise AssertionError(f"Bound violated for {policy}")

    async def inject():
        await asyncio.sleep(max(0,origin_wall+fault.start_delay_s-time.monotonic()))
        await docker("stop",NFS[target].service)
        fault.started_ns=time.monotonic_ns()
        fault.stop_completed_ns=fault.started_ns
        await asyncio.sleep(HOLD_DOWN_S)
        await docker("start",NFS[target].service)
        await wait_core(nrf_url,require_registered=True,timeout=70)
        fault.ended_ns=time.monotonic_ns()

    try:
        tasks=[asyncio.create_task(worker(p)) for p in POLICIES]
        injection=asyncio.create_task(inject())
        try:
            await asyncio.gather(injection,*tasks)
        finally:
            if not injection.done():
                injection.cancel()
            for t in tasks:
                if not t.done(): t.cancel()
    finally:
        feed.stop=True
        await feed_task
        # Do not leave a native Open5GS instance stopped in CI.
        await docker("start",NFS[target].service)

    if fault.started_ns is None or fault.ended_ns is None:
        raise AssertionError("Real NF stop+restore incomplete")
    if any(x["probes"]!=TICKS*SLOTS for x in results.values()):
        raise AssertionError("CU budget differs between scheduler policies")

    # A fair, separate NRF-only detector has only type-level resolution.
    # The live feed always retains genuine NRF responses, even in masked mode.
    target_kind=NFS[target].kind
    nrf_first=next((r["elapsed_wall_s"] for r in feed.trace
        if r["native_nrf_counts"].get(target_kind,2)<2 and
           (origin+int(r["elapsed_wall_s"]*1e9))>=fault.started_ns and
           (origin+int(r["elapsed_wall_s"]*1e9))<=fault.ended_ns),None)
    stop_s=(fault.started_ns-origin)/1e9
    end_s=(fault.ended_ns-origin)/1e9
    nrf_delay=max(0,nrf_first-stop_s) if nrf_first is not None else None
    result=[]
    for p,record in results.items():
        detected=record["detected_ns"] is not None
        delay=((record["detected_ns"]-fault.started_ns)/1e9
               if detected else None)
        result.append(dict(seed=seed,episode=episode,mode=mode,
            faulted_native_nf=NFS[target].service,nf_type=target_kind,
            detector=p,classification_resolution="NF_INSTANCE",
            detected=detected, detection_wall_s=delay,
            censored_wall_s=delay if detected else (fault.ended_ns-fault.started_ns)/1e9,
            cu_checks=record["probes"],cu_http2_bytes=record["bytes"],
            max_cu_gap_ticks=record["max_gap"],
            false_alarms=record["false_alarms"],
            clean_checks=record["clean_checks"],
            actual_fault_duration_wall_s=(fault.ended_ns-fault.started_ns)/1e9,
            randomized_fault_phase_s=fault.start_delay_s,
            native_h2_probe_mean_wall_ms=statistics.mean(record["rtts"])))
    for masked in (False, True):
        is_detected=nrf_delay is not None and not masked
        result.append(dict(seed=seed,episode=episode,mode=mode,
            faulted_native_nf=NFS[target].service,nf_type=target_kind,
            detector=("nrf_only_live" if not masked else "nrf_only_masked"),
            classification_resolution="NF_TYPE",
            detected=is_detected,
            detection_wall_s=nrf_delay if is_detected else None,
            censored_wall_s=(nrf_delay if is_detected
                else (fault.ended_ns-fault.started_ns)/1e9),
            cu_checks=0,cu_http2_bytes=0,max_cu_gap_ticks=None,
            false_alarms=0,clean_checks=0,
            actual_fault_duration_wall_s=(fault.ended_ns-fault.started_ns)/1e9,
            randomized_fault_phase_s=fault.start_delay_s,
            native_h2_probe_mean_wall_ms=None))
    return result,dict(seed=seed,episode=episode,mode=mode,
        faulted_native_nf=NFS[target].service,stop_completed_wall_s=stop_s,
        restoration_completed_wall_s=end_s,nrf_observations=feed.trace,
        per_policy_http2_observation={p:x["trace"] for p,x in results.items()},
        nrf_probe_errors=feed.errors)


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    agent=NativeAttestor()
    await agent.server.start()
    r=random.Random(args.seed)
    scenarios=[(i,m) for m in MODES for i in range(len(NFS))]
    r.shuffle(scenarios)
    events,traces=[],[]
    try:
        for episode,(nf,mode) in enumerate(scenarios):
            print(f"Native NF fault episode {episode+1}/{len(scenarios)}: "
                  f"{NFS[nf].service}, feed={mode}",flush=True)
            rows,trace=await run_episode(agent,args.seed,episode,nf,mode,args.nrf_url)
            events.extend(rows)
            traces.append(trace)
    finally:
        await agent.server.close()
        for nf in NFS:
            await docker("start",nf.service)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"events.json").write_text(json.dumps(events,indent=2))
    (out/"native_traces.json").write_text(json.dumps(traces,indent=2))
    (out/"manifest.json").write_text(json.dumps(dict(
        stage=6,source="real Open5GS native NF HTTP/2 sockets",
        cu_in_open5gs_binary=False,cu_attestor_external=True,
        independent_baseline="NRF-only NF-type registration loss",
        two_telemetry_modes=["live NRF to zone scheduler","masked NRF to zone scheduler"],
        seed=args.seed,native_faults=len(scenarios),tick_wall_s=TICK_S,
        nf_count=len(NFS),cu_slots_per_tick=SLOTS,
        randomized_onset=True,attack_type="administrative outage, NOT compromise"),indent=2))
    print(f"Completed {len(scenarios)} actual Open5GS container outages, "
          f"{len(events)} baseline/policy evaluations",flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--seed",type=int,default=1801)
    parser.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    parser.add_argument("--output",default="stage6_result")
    args=parser.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
