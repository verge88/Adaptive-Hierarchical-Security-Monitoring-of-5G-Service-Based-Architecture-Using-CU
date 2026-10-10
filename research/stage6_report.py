"""Stage 6 report: NRF-only ablation, randomized onset and runner-cluster CIs."""
import argparse
import json
from pathlib import Path
import random
import statistics

from .stage6_native import MODES,POLICIES,TICKS,SLOTS,BOUND,NFS


def cluster_bootstrap(xs,n_boot=8000,seed=343100):
    if len(xs)<2:
        raise AssertionError("Need >=2 genuinely independent CI runners")
    r=random.Random(seed)
    means=sorted(statistics.mean(r.choice(xs) for _ in xs) for _ in range(n_boot))
    return [means[int(.025*(n_boot-1))],means[int(.975*(n_boot-1))]]


def analyze(root):
    files=sorted(Path(root).rglob("events.json"))
    if len(files)<3:
        raise AssertionError("Insufficient independent native Open5GS runners")
    rows=[]
    for file in files:
        if not file.with_name("native_traces.json").exists():
            raise AssertionError("Missing native NRF / CU observation trace")
        rows+=json.loads(file.read_text())
    seeds=sorted({r["seed"] for r in rows})
    if len(seeds)!=len(files):
        raise AssertionError("Duplicate runner seed")
    by_episode={}
    expected=set(POLICIES)|{"nrf_only_live","nrf_only_masked"}
    for r in rows:
        key=(r["seed"],r["episode"])
        group=by_episode.setdefault(key,{})
        if r["detector"] in group:
            raise AssertionError("Duplicate detector/episode")
        group[r["detector"]]=r
    if len(by_episode)!=len(seeds)*len(NFS)*len(MODES):
        raise AssertionError("Incomplete native outage factorial")
    for episode,group in by_episode.items():
        if set(group)!=expected:
            raise AssertionError("Missing control policy")
        cu=[group[p] for p in POLICIES]
        if {r["cu_checks"] for r in cu}!={TICKS*SLOTS}:
            raise AssertionError("Unfair CU check budget")
        if any(group[p]["max_cu_gap_ticks"]>BOUND for p in ("bounded_zone","bounded_local")):
            raise AssertionError("Missed hard probe-interval bound")
        if any(group[p]["cu_checks"]!=0 for p in ("nrf_only_live","nrf_only_masked")):
            raise AssertionError("NRF-only improperly spent CU probes")
        if group["nrf_only_masked"]["detected"]:
            raise AssertionError("Masked NRF negative control should be inert")
    if set(r["mode"] for r in rows)!=set(MODES):
        raise AssertionError("No masked vs live experiment")
    for seed in seeds:
        rs=[g["fixed"] for (s,_),g in by_episode.items() if s==seed]
        if len(rs)!=8 or {r["mode"] for r in rs}!=set(MODES):
            raise AssertionError("Each runner must have 4 real faults per mode")
        if len({(r["mode"],r["faulted_native_nf"]) for r in rs})!=8:
            raise AssertionError("Not all native NF types tested per mode")

    policies={}
    for mode in MODES:
        policies[mode]={}
        for p in expected:
            subset=[r for r in rows if r["mode"]==mode and r["detector"]==p]
            detected=[r["detection_wall_s"] for r in subset if r["detected"]]
            policies[mode][p]=dict(
                events=len(subset),
                recall=sum(r["detected"] for r in subset)/len(subset),
                mean_censored_wall_s=statistics.mean(r["censored_wall_s"] for r in subset),
                mean_detected_wall_s=statistics.mean(detected) if detected else None,
                p95_detected_wall_s=sorted(detected)[int(.95*(len(detected)-1))] if detected else None,
                worst_cu_gap_ticks=max((r["max_cu_gap_ticks"] or 0) for r in subset),
                mean_cu_probes=statistics.mean(r["cu_checks"] for r in subset),
                mean_cu_wire_bytes=statistics.mean(r["cu_http2_bytes"] for r in subset),
                false_alarms=sum(r["false_alarms"] for r in subset),
                classification_resolution=subset[0]["classification_resolution"])

    # Use the RUNNER as independent unit (8 real faults are correlated within runner).
    # Primary endpoint interaction: effect of allowing real NRF to enter
    # bounded zone scheduler versus masking NRF, each ablated against bounded local.
    contrasts={}
    for mode in MODES:
        deltas=[]
        for seed in seeds:
            subsets=[g for (s,_),g in by_episode.items()
                     if s==seed and g["fixed"]["mode"]==mode]
            deltas.append(statistics.mean(
                g["bounded_local"]["censored_wall_s"] -
                g["bounded_zone"]["censored_wall_s"] for g in subsets))
        contrasts[mode]=dict(mean_bounded_local_minus_zone_s=statistics.mean(deltas),
                             paired_cluster_ci95_s=cluster_bootstrap(deltas),
                             runner_effects_s=deltas)
    interaction=[a-b for a,b in zip(contrasts["live"]["runner_effects_s"],
                                   contrasts["masked"]["runner_effects_s"])]
    interaction_obj=dict(mean_incremental_nrf_zone_gain_s=statistics.mean(interaction),
                         ci95_s=cluster_bootstrap(interaction,seed=202314),
                         runner_effects_s=interaction)
    # NRF-only is type-level; can identify lost TYPE, but not instance.
    nrf_control={}
    for mode in MODES:
        records=[r for r in rows if r["mode"]==mode and r["detector"]=="nrf_only_live"]
        nrf_control[mode]=dict(recall=sum(r["detected"] for r in records)/len(records),
            mean_type_alert_wall_s=statistics.mean(r["censored_wall_s"] for r in records))
    return dict(
        design="Real native Open5GS NF stop/restart with randomized onset, NRF-only comparator and masked NRF feed",
        n_runners=len(seeds),n_real_outages=len(by_episode),seeds=seeds,
        note="NRF-only is NF-TYPE alarm; CU target checks identify INSTANCE; latency is not equivalent granularity.",
        time_basis="real monotonic wall seconds after docker stop completed",
        cu_is_native_open5gs=False,masked_mode_is_experimental_feed_mask=True,
        policies=policies,zone_feature_ablation=contrasts,
        primary_interaction=interaction_obj,nrf_type_alarm=nrf_control),rows


def markdown(s):
    lines=["# Stage 6: NRF-only baseline and randomized fault timing on actual Open5GS",
           "", "**Test boundaries:** Real NF containers stopped/restarted and direct "
           "native HTTP/2 status probed. Research KIE is externally HMAC signed, "
           "not executed by any native Open5GS NF binary. Masked NRF means "
           "experimentally **withheld from schedulers**, not physical NRF failure.",
           f"Native NF failures: {s['n_real_outages']}, independent runner shards: {s['n_runners']}.",
           "Fault onset randomized after the already-running monitors start. "
           "All times below measured with a real monotonic wall clock.",
           "", "## Detection by feed and policy","",
           "| NRF feed | Detector | Recall | Mean censored detection wall s | "
           "Worst CU gap (ticks) | CU checks / event | Alarm resolution |",
           "|---|---|---:|---:|---:|---:|---|"]
    for mode in MODES:
        for name in ("fixed","bounded_local","bounded_zone","nrf_only_live","nrf_only_masked"):
            x=s["policies"][mode][name]
            lines.append(f"| {mode} | {name} | {x['recall']:.3f} | "
                         f"{x['mean_censored_wall_s']:.3f} | {x['worst_cu_gap_ticks']} | "
                         f"{x['mean_cu_probes']:.0f} | {x['classification_resolution']} |")
    lines+=["", "## Pre-registered spatial-feature ablation",""]
    for mode,x in s["zone_feature_ablation"].items():
        lo,hi=x["paired_cluster_ci95_s"]
        status="positive" if lo>0 else "negative" if hi<0 else "inconclusive"
        lines.append(f"- {mode}: bounded_local minus bounded_zone = "
                     f"{x['mean_bounded_local_minus_zone_s']:+.3f} wall s; "
                     f"95% runner-cluster CI [{lo:+.3f}, {hi:+.3f}] ({status}).")
    x=s["primary_interaction"]
    lo,hi=x["ci95_s"]
    status="positive" if lo>0 else "negative" if hi<0 else "inconclusive"
    lines.append(f"- PRIMARY interaction (live minus masked spatial benefit) = "
                 f"{x['mean_incremental_nrf_zone_gain_s']:+.3f} wall s; "
                 f"95% runner-cluster CI [{lo:+.3f}, {hi:+.3f}]; {status}.")
    lines+=["", "## Interpretation safeguards","",
        "- NRF-only detects an **NF type count decrease**, not the identity "
        "of the exact failed instance among two instances of the same type. "
        "This baseline must not be equated to instance-specific attestation.",
        "- Native NRF remains live in both modes; the masked mode hides its "
        "telemetry from scheduler ranking. Genuine NRF results are recorded "
        "independently for the NRF-only comparator.",
        "- A positive primary interaction demonstrates dependence on an "
        "existing NRF status signal, NOT a novel Data Mining anomaly detector.",
        "- If an attack does not impact NRF registration and the external "
        "agent or its key is compromised, this experiment provides no "
        "validated internal integrity detection. Controlled Docker outages "
        "are not malicious compromise of an NF.",
        "- Active-check bound is in scheduling TICKS. Slow CI runners can "
        "increase actual wall-clock times; do not convert into an SLA.",
        "- HMAC is produced by an independent monitoring agent, NOT by "
        "native Open5GS NF, and is not a 3GPP standardized SBI extension.",
        "- Four runner clusters give limited generalization. The experiment "
        "does not establish scientific novelty priority or operator security.",
        ""]
    return "\n".join(lines)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage6_batches")
    p.add_argument("--output",default="stage6_report")
    a=p.parse_args()
    result,events=analyze(a.input)
    out=Path(a.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(result,indent=2))
    (out/"raw_events.json").write_text(json.dumps(events,indent=2))
    (out/"REPORT.md").write_text(markdown(result))
    print(markdown(result))

if __name__=="__main__":
    main()
