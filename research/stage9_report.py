"""Stage 9 report: paired seed-cluster evaluation with strict counterfactual audits."""
import argparse
import json
from pathlib import Path
import random
import statistics
from math import comb
from .stage9_conditional import (ACTIVE,METHODS,MODES,ALIGNMENTS,TICKS,BUDGET,MAX_GAP)

def bootstrap(xs,seed=9001,n=6000):
    rng=random.Random(seed)
    d=sorted(statistics.mean(rng.choice(xs) for _ in xs) for _ in range(n))
    return [d[int(.025*(n-1))],d[int(.975*(n-1))]]

def exact_sign_p(xs):
    a=[v for v in xs if abs(v)>1e-9]
    if not a:return 1.
    n=len(a)
    k=min(sum(v>0 for v in a),sum(v<0 for v in a))
    return min(1.,2*sum(comb(n,j) for j in range(k+1))/2**n)

def analyze(root):
    files=sorted(Path(root).rglob("events.json"))
    if len(files)<3:
        raise AssertionError("Missing independent GitHub runners")
    rows=[]
    for f in files:
        m=f.with_name("manifest.json")
        t=f.with_name("traces.json")
        if not m.exists() or not t.exists():
            raise AssertionError("Missing provenance or raw workload trace")
        manifest=json.loads(m.read_text())
        if (manifest.get("native_Open5GS_NSSF_modified") is not False or
            manifest.get("NF_fault_is_lab_policy_sidecar_only") is not True or
            manifest.get("fault_labels_excluded_from_scheduling") is not True):
            raise AssertionError("Incorrect native 5G/sidecar boundaries")
        rows.extend(json.loads(f.read_text()))
    seeds=sorted({r["seed"] for r in rows})
    if len(seeds)!=len(files):
        raise AssertionError("Duplicated seed across runner shards")
    groups={}
    for r in rows:
        key=(r["seed"],r["episode"])
        slot=groups.setdefault(key,{})
        if r["method"] in slot:
            raise AssertionError("Detector duplicated")
        slot[r["method"]]=r
    if len(groups)!=8*len(seeds):
        raise AssertionError("Expected 8 matched conditional faults per runner")
    for seed in seeds:
        points=[g["plain_fixed"] for (s,_),g in groups.items() if s==seed]
        for mode in MODES:
            for alignment in ALIGNMENTS:
                if sum(r["mode"]==mode and r["alignment"]==alignment for r in points)!=2:
                    raise AssertionError("Factorial workload not balanced")
    for g in groups.values():
        if set(g)!=set(METHODS):
            raise AssertionError("Incomplete comparison")
        if {g[m]["active_checks"] for m in ACTIVE}!={TICKS*BUDGET}:
            raise AssertionError("Active CUs/ordinary queries have unequal budgets")
        if g["passive_semantic"]["active_checks"] or g["nrf_ids"]["active_checks"]:
            raise AssertionError("Passive baseline improperly issued active checks")
        if any(g[m]["max_check_gap_ticks"]>MAX_GAP for m in ("cu_local","cu_hier")):
            raise AssertionError("Hard maximum check gap violated")
        if any(not g[m]["real_NRF_ids_unchanged"] or not
               g[m]["genuine_native_NSSF_reachable"] for m in METHODS):
            raise AssertionError("Native Open5GS NSSF or NRF failed")
        if (g["passive_semantic"]["mode"]=="zero_rare" and
            g["passive_semantic"]["rare_attacked_passive_transactions"]!=0):
            raise AssertionError("Rare probe leaked into passive-only zero-rare case")
    modes={}
    for mode in MODES:
        modes[mode]={}
        for p in METHODS:
            xs=[r for r in rows if r["mode"]==mode and r["method"]==p]
            delays=[x["detection_wall_s"] for x in xs if x["detected"]]
            modes[mode][p]=dict(
                trials=len(xs),detected=len(delays),recall=len(delays)/len(xs),
                observed_delay_wall_s=statistics.mean(delays) if delays else None,
                mean_horizon_penalized_wall_s=statistics.mean(x["censored_wall_s"] for x in xs),
                false_alarms=sum(x["false_alarms"] for x in xs),
                clean_checks=sum(x["clean_checks"] for x in xs),
                active_checks_per_trial=statistics.mean(x["active_checks"] for x in xs),
                active_h2_bytes_per_trial=statistics.mean(x["active_http2_bytes"] for x in xs),
                passive_messages_per_trial=statistics.mean(x["observed_passive_messages"] for x in xs),
                maximum_check_gap_ticks=max((x["max_check_gap_ticks"] or 0) for x in xs))
    comparisons={}
    for subset_name in ("all",)+MODES:
        eligible=[g for g in groups.values() if subset_name=="all" or
                  g["plain_fixed"]["mode"]==subset_name]
        for base,candidate in (("plain_fixed","cu_fixed"),
                               ("cu_local","cu_hier"),
                               ("plain_fixed","cu_hier"),
                               ("passive_semantic","cu_hier")):
            d=[]
            for seed in seeds:
                matched=[g for g in eligible if g["plain_fixed"]["seed"]==seed]
                d.append(statistics.mean(g[base]["censored_wall_s"] -
                      g[candidate]["censored_wall_s"] for g in matched))
            comparisons[subset_name+":"+base+"_minus_"+candidate]=dict(
                mean_reduction_wall_s=statistics.mean(d),
                bootstrap_ci95_s=bootstrap(d),
                exact_two_sided_sign_p=exact_sign_p(d),runner_effects=d)
    return dict(
        scope="Native Open5GS NSSF/NRF available, conditional malfunction ONLY in LAB NSSF-like side service",
        n_runners=len(seeds),seeds=seeds,lab_fault_episodes=len(groups),
        raw_detector_records=len(rows),equal_active_checks=TICKS*BUDGET,
        outcome_by_traffic=modes,paired=comparisons,
        synthetic_prior_note="Aligned faults target high benign-load zone, unaligned target the other zone; deliberately balanced, not real-world evidence",
        threat_note="Original native NSSF does not process slice selection fault or research CU. HMAC signature is from independent research attestor."),rows

def markdown(s):
    lines=["# Stage 9: conditional LAB NSSF-like policy fault; native Open5GS anchored","",
       "Actual Open5GS NRF and 2 native NSSFs were active, registered and "
       "their HTTP/2 health was tested. The rare-slice fault affected ONLY a "
       "separate research policy service. Native NSSF binaries do not run "
       "the conditional policy or parse/sign CU.",
       f"Independent runners={s['n_runners']}; lab episodes={s['lab_fault_episodes']}; "
       f"detector records={s['raw_detector_records']}.",
       "An ordinary active HTTP/2 probe gets the exact same information "
       "and number of probes as a signed CU, and every semantic detector "
       "uses the identical independent policy oracle.",
       "", "| Ordinary traffic | Detector | Recall | Penalized delay (wall s) | "
       "Clean false/total | Active checks/case | Active H2 bytes/case |",
       "|---|---|---:|---:|---:|---:|---:|"]
    for mode,methods in s["outcome_by_traffic"].items():
        for name,x in methods.items():
            lines.append(f"| {mode} | {name} | {x['detected']}/{x['trials']} | "
                         f"{x['mean_horizon_penalized_wall_s']:.3f} | "
                         f"{x['false_alarms']}/{x['clean_checks']} | "
                         f"{x['active_checks_per_trial']:.0f} | "
                         f"{x['active_h2_bytes_per_trial']:.0f} |")
    lines+=["","## Paired seed-level contrasts (positive -> second method faster)"]
    for k,v in s["paired"].items():
        lo,hi=v["bootstrap_ci95_s"]
        lines.append(f"- {k}: {v['mean_reduction_wall_s']:+.3f} wall s "
                     f"(95% cluster-bootstrap [{lo:+.3f},{hi:+.3f}], "
                     f"exact two-sided sign p={v['exact_two_sided_sign_p']:.3f}).")
    lines+=["","## Strict inference constraints",
       "- No rare legitimate requests means a passive semantic detector "
       "has no information about the hidden conditional branch. Active "
       "ordinary HTTP/2 can explore it, even without cryptographic CU.",
       "- Legitimate route tokens change per request; a full-byte fingerprint "
       "would be an inappropriate passive comparator. The chosen passive "
       "semantic oracle handles this benign variation.",
       "- Ordinary active HTTP/2 and signed CU methods share challenge "
       "budget, target query, and oracle. HMAC proves the external agent's "
       "message, not original NSSF internals.",
       "- The synthetic stress/target correlation is explicitly designed "
       "and balanced against an unaligned negative-control stratum.",
       "- On real 5G networks the NRC/NSSF may have different legal policies. "
       "The lab oracle is not native NSSF behavior or an operator policy.",
       "- Detection delays are real monotonic wall time. Missing events "
       "receive an episode-duration penalty, not a survival estimator.",
       "- Four independent runner seeds produce weak population-level "
       "significance; even 4/4 positive exact two-sided sign test p=0.125.",
       "- This study does not establish hardware remote attestation, "
       "actual NF compromise, NWDAF integration or scientific novelty.",""]
    return "\n".join(lines)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage9_batches")
    p.add_argument("--output",default="stage9_report")
    a=p.parse_args()
    summary,raw=analyze(a.input)
    root=Path(a.output)
    root.mkdir(parents=True,exist_ok=True)
    (root/"summary.json").write_text(json.dumps(summary,indent=2))
    (root/"raw_events.json").write_text(json.dumps(raw,indent=2))
    (root/"REPORT.md").write_text(markdown(summary))
    print(markdown(summary))

if __name__=="__main__":
    main()
