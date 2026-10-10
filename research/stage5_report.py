"""Stage 5 native-NF wall-time report; bootstrap resamples CI runner shards."""
import argparse,json,random,statistics
from pathlib import Path
from .stage5_native import POLICIES,MAX_GAP_TICKS,PROBES_PER_TICK,DOWN_TICKS,BENIGN_TICKS

def ci_effect(xs,seed=5921,reps=5000):
    r=random.Random(seed)
    v=sorted(statistics.mean(r.choice(xs) for _ in xs) for _ in range(reps))
    return [v[int(.025*(reps-1))],v[int(.975*(reps-1))]]

def analyze(input_dir):
    files=sorted(Path(input_dir).rglob("events.json"))
    if len(files)<2: raise AssertionError("Require >=2 independent Open5GS runners")
    records=[item for f in files for item in json.loads(f.read_text())]
    seeds=sorted({x["seed"] for x in records})
    if len(seeds)!=len(files): raise AssertionError("Duplicated runner seed")
    groups={}
    for x in records:
        key=(x["seed"],x["episode"])
        if x["policy"] in groups.setdefault(key,{}): raise AssertionError("Duplicate policy")
        groups[key][x["policy"]]=x
    if len(groups)!=4*len(seeds): raise AssertionError("Missing native NF outage")
    for g in groups.values():
        if set(g)!=set(POLICIES): raise AssertionError("Incomplete policy observations")
        if {v["probes"] for v in g.values()}!={(DOWN_TICKS+BENIGN_TICKS)*PROBES_PER_TICK}:
            raise AssertionError("Mismatched authenticated CU budget")
        for p,v in g.items():
            if p.startswith("bounded_") and v["max_intercheck_gap_ticks"]>MAX_GAP_TICKS:
                raise AssertionError("Hard deadline failed")
    tab={}
    for p in POLICIES:
        rows=[x for x in records if x["policy"]==p]
        observed=sorted(x["detection_wall_s"] for x in rows if x["detected"])
        tab[p]=dict(detected=len(observed),outages=len(rows),
            recall=len(observed)/len(rows),
            mean_detection_wall_s=statistics.mean(observed) if observed else None,
            p95_detection_wall_s=observed[int(.95*(len(observed)-1))] if observed else None,
            mean_censored_wall_s=statistics.mean(x["detection_wall_s"] if x["detected"]
                else x["observation_window_wall_s"] for x in rows),
            maximum_check_gap_ticks=max(x["max_intercheck_gap_ticks"] for x in rows),
            cu_probes_per_outage=statistics.mean(x["probes"] for x in rows),
            h2_cu_bytes_per_outage=statistics.mean(x["cu_wire_bytes"] for x in rows),
            false_alarms=sum(x["benign_false_alarms"] for x in rows),
            benign_checks=sum(x["benign_checks"] for x in rows))
    contrasts={}
    for baseline in ("bounded_local","fixed","random"):
        seed_means=[]
        for seed in seeds:
            vals=[]
            for (s,_),g in groups.items():
                if s!=seed: continue
                def dl(x):
                    return x["detection_wall_s"] if x["detected"] else x["observation_window_wall_s"]
                vals.append(dl(g[baseline])-dl(g["bounded_zone"]))
            seed_means.append(statistics.mean(vals))
        low,high=ci_effect(seed_means)
        contrasts[baseline+"_minus_bounded_zone"]=dict(
            mean_wall_s=statistics.mean(seed_means),
            cluster_ci95_wall_s=[low,high],
            decision="positive" if low>0 else "negative" if high<0 else "inconclusive",
            independent_runner_shards=len(seed_means))
    stale=statistics.mean(x["nrf_reported_type_complete_during_outage"] for x in records
                          if x["policy"]=="fixed")
    return dict(scope="real Open5GS NF stop/restart plus externally authenticated CU agent",
        native_cu_in_open5gs=False,real_wall_clock=True,shards=len(seeds),
        outages=len(groups), nrf_stale_full_type_fraction=stale, policies=tab,
        comparisons=contrasts),records

def markdown(s):
    lines=["# Stage 5 — actual Open5GS NF failure/recovery and external CU attestation","",
      "Native Open5GS AUSF and NSSF containers are really stopped and restarted. "
      "A separate authenticated HTTP/2 agent signs direct native NF HTTP status. "
      "**NF binaries do NOT process the CU themselves.**",
      "Detection latency is monotonic WALL time from completion of container stop, "
      "not accelerated synthetic logical time.",
      f"{s['outages']} real NF outage events across {s['shards']} independent GitHub runners.","",
      "| Policy | Real outages detected | Mean wall delay (s) | p95 delay (s) | "
      "Max CU interval (ticks) | CU/event | False clean alerts |",
      "|---|---:|---:|---:|---:|---:|---:|"]
    for name,p in s["policies"].items():
        avg=f"{p['mean_detection_wall_s']:.3f}" if p["mean_detection_wall_s"] is not None else "N/A"
        p95=f"{p['p95_detection_wall_s']:.3f}" if p["p95_detection_wall_s"] is not None else "N/A"
        lines.append(f"| {name} | {p['detected']}/{p['outages']} | {avg} | {p95} | "
                     f"{p['maximum_check_gap_ticks']} | {p['cu_probes_per_outage']:.0f} | "
                     f"{p['false_alarms']} |")
    lines+=["","## Prespecified paired tests (positive = bounded-zone faster)"]
    for n,r in s["comparisons"].items():
        lo,hi=r["cluster_ci95_wall_s"]
        lines.append(f"- {n}: {r['mean_wall_s']:+.3f} wall s, runner-cluster "
                     f"95% CI [{lo:+.3f},{hi:+.3f}], {r['decision']}.")
    lines+=["",f"NRF still advertised full NF-type counts in "
            f"{s['nrf_stale_full_type_fraction']:.1%} of samples during real NF outages.","",
      "## Scope and scientific limits",
      "- Availability faults are real container stops/starts, not insider data "
      "forgery, exploitation of Open5GS, nor internal NF compromise.",
      "- The research CU agent uses an HMAC challenge-response and obtains "
      "actual native NF HTTP/2 responses. The cryptographic attestation is "
      "made by the AGENT, not by the NF. No native NF executable is modified.",
      "- The 3-tick CU deadline is a scheduler-step guarantee, not a hard "
      "wall-time deadline under arbitrary runner overload.",
      "- Distinct fault episodes within one runner are correlated. Bootstrap "
      "resamples whole GitHub runner shards; few shards entail wide uncertainty.",
      "- Both NRF discovery and CU traffic add lab overhead. CU counts per "
      "policy are matched exactly; traffic-byte estimates exclude TCP/IP framing.",
      "- Results cannot establish security detection accuracy against real "
      "adversaries, 3GPP conformance, or scientific novelty priority.",""]
    return "\n".join(lines)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage5_batches")
    p.add_argument("--output",default="stage5_aggregate")
    a=p.parse_args()
    summary,records=analyze(a.input)
    root=Path(a.output)
    root.mkdir(parents=True,exist_ok=True)
    (root/"raw_events.json").write_text(json.dumps(records,indent=2))
    (root/"summary.json").write_text(json.dumps(summary,indent=2))
    (root/"REPORT.md").write_text(markdown(summary))
    print(markdown(summary))
if __name__=="__main__":
    main()
