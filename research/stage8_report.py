"""Stage 8 reproducible data audit, false-alert analysis and cluster contrasts."""
import argparse
import json
from pathlib import Path
import random
import statistics

from .stage8_dynamic_nrf import (METHODS,ACTIVES,ATTACKS,KINDS,TICKS,CU_BUDGET,GAP_LIMIT)


def paired_interval(values,seed=8401,n=6000):
    rng=random.Random(seed)
    means=sorted(statistics.mean(rng.choice(values) for _ in values) for _ in range(n))
    return [means[int(.025*(n-1))],means[int(.975*(n-1))]]


def analyze(directory):
    sources=sorted(Path(directory).rglob("events.json"))
    if len(sources)<3:
        raise AssertionError("At least 3 independent Actions shards are required")
    items=[]
    for f in sources:
        if not f.with_name("manifest.json").exists() or not f.with_name("traces.json").exists():
            raise AssertionError("Missing raw native NRF trace or manifest")
        manifest=json.loads(f.with_name("manifest.json").read_text())
        if not (manifest.get("real_nrf_http2") and
                not manifest.get("real_nf_registration_mutated") and
                not manifest.get("native_nf_compromise")):
            raise AssertionError("Incorrect native Open5GS/attack provenance")
        items.extend(json.loads(f.read_text()))
    seeds=sorted({r["seed"] for r in items})
    if len(seeds)!=len(sources):
        raise AssertionError("Shards/seed mismatch")
    grouped={}
    for row in items:
        key=(row["seed"],row["case"])
        group=grouped.setdefault(key,{})
        if row["method"] in group:
            raise AssertionError("Duplicated detector")
        group[row["method"]]=row
    if len(grouped)!=len(seeds)*len(ATTACKS)*len(KINDS):
        raise AssertionError("Missing full paired native NRF scenario set")
    for seed in seeds:
        label={(g["cu_fixed"]["attack"],g["cu_fixed"]["kind"])
               for (s,_),g in grouped.items() if s==seed}
        if label!={(a,k) for a in ATTACKS for k in KINDS}:
            raise AssertionError("Unbalanced native NF attack kinds")
    for group in grouped.values():
        if set(group)!=set(METHODS):
            raise AssertionError("Incomplete comparator set")
        if any(not group[m]["real_nrf_id_sets_unchanged"] for m in METHODS):
            raise AssertionError("Native NRF registry changed during gateway attack")
        if {group[m]["cu_checks"] for m in ACTIVES}!={TICKS*CU_BUDGET}:
            raise AssertionError("Active CU budgets unequal")
        if any(group[m]["cu_checks"]!=0 for m in METHODS if m not in ACTIVES):
            raise AssertionError("Passive comparator spent CU checks")
        if any(group[m]["max_gap_ticks"]>GAP_LIMIT
               for m in ("cu_local","cu_zone")):
            raise AssertionError("KIE scheduler violated deadline")
    by_attack={}
    for attack in ATTACKS:
        by_attack[attack]={}
        for method in METHODS:
            rows=[r for r in items if r["attack"]==attack and r["method"]==method]
            by_attack[attack][method]=dict(
                cases=len(rows),recall=sum(r["detected"] for r in rows)/len(rows),
                horizon_penalized_delay_wall_s=statistics.mean(
                    r["horizon_penalized_s"] for r in rows),
                first_detection_wall_s=statistics.mean(r["delay_wall_s"] for r in rows
                                             if r["detected"]) if any(
                                             r["detected"] for r in rows) else None,
                false_alerts=sum(r["false_alerts"] for r in rows),
                clean_checks=sum(r["clean_checks"] for r in rows),
                cu_checks_per_case=statistics.mean(r["cu_checks"] for r in rows),
                h2_cu_bytes_per_case=statistics.mean(r["cu_bytes"] for r in rows))
    contrasts={}
    for comparator in ("passive_semantic","passive_bytes","nrf_direct",
                       "cu_fixed","cu_local"):
        shard_effects=[]
        for seed in seeds:
            pairs=[g for (s,_),g in grouped.items() if s==seed]
            shard_effects.append(statistics.mean(
                g[comparator]["horizon_penalized_s"]-g["cu_zone"]["horizon_penalized_s"]
                for g in pairs))
        contrasts[comparator+"_minus_cu_zone"]=dict(
            mean_difference_wall_s=statistics.mean(shard_effects),
            ci95_cluster_bootstrap_s=paired_interval(shard_effects),
            runner_effects_s=shard_effects)
    return dict(
        real_open5gs_nrf_http2=True, native_NF_compromise=False,
        attack_location="research lab relay of real NRF discovery response",
        legitimate_dynamics="reordering actual NRF nfInstances in lab relay",
        native_nf_id_sets_unchanged=True,
        independent_runners=len(seeds),seeds=seeds,
        scenarios=len(grouped),records=len(items),
        per_attack=by_attack,paired_cluster=contrasts,
        note="Native NRF does not sign CU. Separate research agent attests native NRF observation; no native NF compromise or trained NWDAF model."),items


def report(summary):
    result=["# Stage 8: dynamic live Open5GS NRF discovery body — strong semantic baseline","",
       "Real NRF HTTP/2 JSON was fetched on every request. A lab research "
       "gateway permuted the nfInstances list benignly and, during an "
       "episode, altered one forwarded NF profile. **Actual NRF NF profile "
       "registrations and native binaries were not changed or compromised.**",
       f"CI runner clusters: {summary['independent_runners']}; "
       f"tampering scenarios: {summary['scenarios']}.",
       "", "| Lab gateway edit | Detector | Recall | Mean horizon-penalized "
       "wall delay (s) | Clean false alerts / clean checks | CU checks / case |",
       "|---|---|---:|---:|---:|---:|"]
    for attack,methods in summary["per_attack"].items():
        for name,r in methods.items():
            result.append(f"| {attack} | {name} | {r['recall']:.3f} | "
                          f"{r['horizon_penalized_delay_wall_s']:.3f} | "
                          f"{r['false_alerts']}/{r['clean_checks']} | "
                          f"{r['cu_checks_per_case']:.0f} |")
    result+=["","## Matched contrasts: positive means CU zone faster",""]
    for k,r in summary["paired_cluster"].items():
        lo,hi=r["ci95_cluster_bootstrap_s"]
        result.append(f"- {k}: {r['mean_difference_wall_s']:+.3f} s "
                      f"(95% runner bootstrap [{lo:+.3f}, {hi:+.3f}]); "
                      f"individual runner means {r['runner_effects_s']}.")
    result+=["","## Model / research constraints",
      "- Benign profile order variation is produced by the LAB GATEWAY. "
      "Underlying actual native NRF profiles can remain stable; the experiment "
      "does not prove realistic volatile NF application-body properties.",
      "- Strong semantic passive baseline observes and normalizes full bodies; "
      "it is not intentionally weakened to improve CU. Bytewise fingerprint "
      "is a deliberately naive negative control with expected false alerts.",
      "- Native Open5GS NRF remains unmodified and registered. The attacker "
      "changes only a forwarded copy inside a lab HTTP/2 gateway; not native "
      "SBI socket traffic or a compromised 5G NF binary.",
      "- External HMAC CU agent independently fetches real NRF discovery; "
      "native NRF or NF functions do not generate or authenticate CU. "
      "Trusting this separate agent is a strong additional assumption.",
      "- Signed active CU comparators spend equal probe counts, but differ "
      "in observed wire traffic. Zero-CU passive comparisons are not "
      "equal-cost active monitors; overhead must be discussed.",
      "- A true NRF-only detector cannot detect a downstream laboratory "
      "gateway-only payload alteration, since actual NF registrations remain "
      "unchanged. This is a threat-model property, not failure of NRF.",
      "- Delay is actual monotonic wall time; missing detections receive "
      "an attack-duration penalty (not an unbiased survival estimator).",
      "- With few runners, cluster bootstrap CIs are descriptive, not proof "
      "of statistical priority or broad significance.",
      "- There is no validated machine-learning model / NWDAF integration. "
      "Semantic fingerprinting can dominate active CU; novelty is NOT proven.",""]
    return "\n".join(result)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--input",default="stage8_batches")
    parser.add_argument("--output",default="stage8_report")
    args=parser.parse_args()
    summary,data=analyze(args.input)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(summary,indent=2))
    (out/"raw_events.json").write_text(json.dumps(data,indent=2))
    (out/"REPORT.md").write_text(report(summary))
    print(report(summary))


if __name__=="__main__":
    main()
