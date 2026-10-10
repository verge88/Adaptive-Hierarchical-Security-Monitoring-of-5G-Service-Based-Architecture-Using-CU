"""Stage 4: registered endpoint analysis; no external attack labels in schedulers."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import statistics

from .experiment import paired_ci
from .stage4_experiment import POLICIES, POSITIVE_KINDS, BUDGET, TRAIN, TICKS

def load(root):
    files = sorted(Path(root).rglob("runs.json"))
    if not files: raise ValueError("No stage4 shard records")
    rows, nrf = [], []
    for f in files:
        datum = json.loads(f.read_text())
        check = f.with_name("nrf.json")
        if not check.exists(): raise AssertionError("Missing Open5GS NRF evidence")
        nrf.append(json.loads(check.read_text()))
        rows.extend(datum)
    seeds = sorted({r["seed"] for r in rows})
    if len(rows) != len(seeds)*len(POLICIES) or len(seeds) < 2:
        raise AssertionError("Incomplete matched policy data")
    if len({(r["seed"], r["policy"]) for r in rows}) != len(rows):
        raise AssertionError("Duplicate seed/policy")
    for seed in seeds:
        group = [r for r in rows if r["seed"] == seed]
        if set(r["policy"] for r in group) != set(POLICIES):
            raise AssertionError("Missing policy")
        if {r["probes"] for r in group} != {(TICKS-TRAIN)*BUDGET}:
            raise AssertionError("Unfair CU probe count")
        for r in group:
            if r["policy"].startswith("bounded_") and r["maximum_cu_gap_logical_ticks"] > 4:
                raise AssertionError("Max CU wait guarantee violated")
    return rows, nrf

def summarize(rows, nrf):
    samples = {p: sorted((r for r in rows if r["policy"] == p),
                         key=lambda r: r["seed"]) for p in POLICIES}
    stats = {}
    for policy, group in samples.items():
        events = [e for r in group for e in r["events"]]
        positive = [e for e in events if e["kind"] in POSITIVE_KINDS]
        collusions = [e for e in events if e["kind"] == "collusion"]
        delays = sorted(e["censored_delay_logical_s"] for e in positive)
        stats[policy] = dict(
            event_recall=sum(e["detected"] for e in positive) / len(positive),
            mean_censored_delay_logical_s=statistics.mean(delays),
            p95_censored_delay_logical_s=delays[min(len(delays)-1, int(.95*(len(delays)-1)))],
            mean_max_cu_gap_ticks=statistics.mean(
                r["maximum_cu_gap_logical_ticks"] for r in group),
            maximum_cu_gap_ticks=max(r["maximum_cu_gap_logical_ticks"] for r in group),
            false_alarms=sum(r["false_alarms"] for r in group),
            false_alarms_per_1000_clean_checks=1000*sum(r["false_alarms"] for r in group)
                    / max(1,sum(r["clean_checks"] for r in group)),
            probes_per_seed=statistics.mean(r["probes"] for r in group),
            mean_h2_cu_bytes_per_seed=statistics.mean(r["cu_h2_wire_bytes"] for r in group),
            mean_h2_cu_wall_rtt_ms=statistics.mean(r["cu_rtt_mean_ms"] for r in group),
            collusion_detected=sum(e["detected"] for e in collusions),
            collusion_total=len(collusions),
            by_attack={k:dict(
                recall=sum(e["detected"] for e in positive if e["kind"]==k) /
                       sum(e["kind"]==k for e in positive),
                mean_censored_delay_logical_s=statistics.mean(
                    e["censored_delay_logical_s"] for e in positive if e["kind"]==k))
                for k in POSITIVE_KINDS})
    index={p:{r["seed"]:r for r in group} for p,group in samples.items()}
    compare={}
    # Primary: deadline-bounded zone versus otherwise identical deadline-bounded local.
    # Secondary: bounded-zone versus unbounded zone, fixed, random.
    for base in ("bounded_local","zone_adaptive","fixed","random","local_adaptive"):
        delta=[index[base][s]["mean_censored_delay_s"] -
               index["bounded_zone"][s]["mean_censored_delay_s"] for s in sorted(index[base])]
        compare[base+"_minus_bounded_zone"]=dict(
            mean_reduction_logical_s=statistics.mean(delta),
            paired_bootstrap_ci95_logical_s=paired_ci(delta,seed=34812,n_boot=4000),
            wins=sum(d>0 for d in delta),losses=sum(d<0 for d in delta),
            ties=sum(d==0 for d in delta))
    return dict(
        scientific_scope="Native Open5GS NRF discovery + laboratory HTTP/2 CU sidecars, not patched Open5GS NF",
        seeds=len(index["fixed"]),seed_values=sorted(index["fixed"]),
        nrf_h2_checks=sum(v["samples"] for v in nrf),
        median_nrf_rtt_wall_ms=statistics.median(v["median_wall_rtt_ms"] for v in nrf),
        guaranteed_bound_ticks=4, baseline_fixed_max_gap_ticks=3,
        matched_probe_budget=(TICKS-TRAIN)*BUDGET,
        policies=stats,paired=compare)

def markdown(s):
    lines=["# Stage 4: deadline-constrained CU monitoring, Open5GS NRF + HTTP/2 overlay",
        "", "Native Open5GS NRF/AUSF/NSSF are present and discovery is verified via HTTP/2. "
        "**Actual CU attack targets remain lab-sidecars; native 5G NF binaries are unmodified.**",
        f"Matched seeds={s['seeds']}; verified NRF requests={s['nrf_h2_checks']}; "
        f"median NRF request wall RTT={s['median_nrf_rtt_wall_ms']:.2f} ms.",
        "", "**Primary:** bounded_zone versus bounded_local (spatial ablation, identical "
        "hard deadline and CU count). Positive paired reduction in censored detection "
        "delay denotes benefit for bounded_zone.",
        "", "| Policy | Event recall | Mean censored delay (logical s) | p95 delay | "
        "Worst CU gap (ticks) | CU per seed | CU wire bytes/seed | Collusion detected |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for name,x in s["policies"].items():
        lines.append(f"| {name} | {x['event_recall']:.3f} | "
                     f"{x['mean_censored_delay_logical_s']:.2f} | "
                     f"{x['p95_censored_delay_logical_s']:.1f} | "
                     f"{x['maximum_cu_gap_ticks']} | {x['probes_per_seed']:.0f} | "
                     f"{x['mean_h2_cu_bytes_per_seed']:.0f} | "
                     f"{x['collusion_detected']}/{x['collusion_total']} |")
    lines+=["", "## Seed-paired contrasts (positive = bounded-zone faster)"]
    for key,x in s["paired"].items():
        lo,hi=x["paired_bootstrap_ci95_logical_s"]
        decision="positive" if lo>0 else ("negative" if hi<0 else "inconclusive")
        lines.append(f"- {key}: {x['mean_reduction_logical_s']:+.2f} logical s, "
                     f"95% seed-bootstrap CI [{lo:+.2f}, {hi:+.2f}]; "
                     f"{decision}; wins/losses/ties = {x['wins']}/{x['losses']}/{x['ties']}.")
    lines+=["", "## Registered threat-model and inference limits",
      "- The mathematical guarantee is an **active CU check interval <= 4 logical ticks** "
      "with six laboratory NF sidecars and exactly two checks/tick; it holds only "
      "while the scheduler runs and enough CU capacity is available.",
      "- Equal CU check counts are enforced; actual HTTP/2 byte totals are separately "
      "measured and may vary with per-request JSON fields and session setup.",
      "- Attack onset jitter, benign common-mode bursts and validated-HMAC report "
      "forgeries are synthetic. Scheduling receives no attack ground-truth labels.",
      "- All reported detection delays are ACCELERATED LOGICAL TIME, not real 5G "
      "network measurement. Native NRF HTTP/2 timings are measured wall time.",
      "- Colluding NF+SCP can forge matching observations and signed CU reports; "
      "a third independent attestation source would be required.",
      "- High recall and zero false positives on controlled laboratory sidecars "
      "do not establish real network detection performance or scientific priority.",
      "- Do not assert bounded zonal superiority when the PRIMARY 95% CI includes zero.",
      ""]
    return "\n".join(lines)

def main():
    a=argparse.ArgumentParser()
    a.add_argument("--input",default="stage4_batches")
    a.add_argument("--output",default="stage4_aggregate")
    args=a.parse_args()
    rows,nrf=load(args.input)
    summary=summarize(rows,nrf)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(summary,indent=2))
    (out/"raw_runs.json").write_text(json.dumps(rows,indent=2))
    (out/"REPORT.md").write_text(markdown(summary))
    print(markdown(summary))
if __name__=="__main__":
    main()
