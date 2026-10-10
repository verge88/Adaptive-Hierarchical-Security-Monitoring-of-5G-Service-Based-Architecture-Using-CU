"""Stage 7 statistical checks: NRF instance baseline and payload controls."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import random
import statistics

from .stage7_integrity import (ALL,ACTIVE,ATTACK_MODES,NFS,TICKS,BUDGET,BOUND)


def cluster_ci(values,seed=789122,reps=10000):
    if len(values)<3:
        raise AssertionError("Use at least three independent runner clusters")
    rng=random.Random(seed)
    dist=sorted(statistics.mean(rng.choice(values) for _ in values)
                for _ in range(reps))
    return [dist[int(.025*(reps-1))],dist[int(.975*(reps-1))]]


def analyze(root):
    paths=sorted(Path(root).rglob("events.json"))
    if len(paths)<3:
        raise AssertionError("Insufficient CI shard results")
    data=[]
    for f in paths:
        if not f.with_name("traces.json").exists() or not f.with_name("manifest.json").exists():
            raise AssertionError("Missing underlying real NRF and H2 observation data")
        data.extend(json.loads(f.read_text()))
    seeds=sorted({x["seed"] for x in data})
    if len(seeds)!=len(paths):
        raise AssertionError("Seed duplication")
    episodes={}
    for r in data:
        key=(r["seed"],r["case"])
        e=episodes.setdefault(key,{})
        if r["detector"] in e:
            raise AssertionError("Detector duplicated")
        e[r["detector"]]=r
    if len(episodes)!=len(seeds)*len(NFS)*len(ATTACK_MODES):
        raise AssertionError("Incomplete 4 x 2 native-backed gateway scenarios")
    for g in episodes.values():
        if set(g)!=set(ALL):
            raise AssertionError("Missing detector in trial")
        if len({g[x]["attack"] for x in ALL})!=1:
            raise AssertionError("Inconsistent attack label across control algorithms")
        if {g[x]["cu_checks"] for x in ACTIVE}!={TICKS*BUDGET}:
            raise AssertionError("Active CU probe budgets differ")
        if any(g[x]["cu_checks"]!=0 for x in ("nrf_instance_only",
                                            "passive_metadata","passive_payload")):
            raise AssertionError("Passive/NRF control incorrectly spent CU budget")
        if any(g[x]["max_cu_gap_ticks"]>BOUND for x in ("kie_local","kie_zone")):
            raise AssertionError("Deadline promise violated")
        if any(g[x]["native_nrf_id_set_changed"] for x in ALL):
            raise AssertionError("NRF registration changed: invalid silent-attack premise")
    for seed in seeds:
        base=[v["kie_fixed"] for (s,_),v in episodes.items() if s==seed]
        if len(base)!=8 or {(r["nf"],r["attack"]) for r in base} != {
            (n.service,m) for n in NFS for m in ATTACK_MODES}:
            raise AssertionError("Runner missing a native-backed gateway case")
    table={}
    for mode in ATTACK_MODES:
        table[mode]={}
        for m in ALL:
            xs=[r for r in data if r["detector"]==m and r["attack"]==mode]
            if not xs:
                raise AssertionError("Missing attack/detector combination")
            positives=[x["delay_wall_s"] for x in xs if x["detected"]]
            table[mode][m]=dict(
                events=len(xs),
                recall=len(positives)/len(xs),
                mean_detected_wall_s=statistics.mean(positives) if positives else None,
                mean_horizon_penalized_wall_s=statistics.mean(
                    x["censored_delay_wall_s"] for x in xs),
                max_cu_gap_ticks=max((x["max_cu_gap_ticks"] or 0) for x in xs),
                cu_checks_per_episode=statistics.mean(x["cu_checks"] for x in xs),
                cu_h2_bytes_per_episode=statistics.mean(x["cu_http2_bytes"] for x in xs),
                clean_checks=sum(x["clean_checks"] for x in xs),
                false_alerts=sum(x["false_alerts"] for x in xs))
    comparison={}
    for candidate,comparator in (("kie_zone","kie_local"),
                                 ("kie_zone","kie_fixed"),
                                 ("kie_zone","passive_payload"),
                                 ("kie_zone","passive_metadata"),
                                 ("kie_zone","nrf_instance_only")):
        diffs=[]
        for seed in seeds:
            gs=[e for (s,_),e in episodes.items() if s==seed]
            deltas=[e[comparator]["censored_delay_wall_s"]-
                    e[candidate]["censored_delay_wall_s"] for e in gs]
            diffs.append(statistics.mean(deltas))
        interval=cluster_ci(diffs,seed=199101)
        comparison[comparator+"_minus_"+candidate]=dict(
            mean_delay_reduction_s=statistics.mean(diffs),
            bootstrap_ci95_s=interval,runner_effects_s=diffs,
            direction=("candidate faster" if interval[0]>0
                       else "candidate slower" if interval[1]<0
                       else "inconclusive"))
    return dict(
        experiment="Native Open5GS response-backed research HTTP/2 gateway envelope tampering",
        scope="real NRF and native NF HTTP/2 observations; synthetic gateway envelope manipulation",
        native_NF_compromised=False,
        KIE_processed_by_native_NF=False,
        independent_runners=len(seeds),seed_values=seeds,
        experimental_tampering_events=len(episodes),
        positive_attack_modes=list(ATTACK_MODES),per_attack=table,
        paired_cluster_contrasts=comparison,
        methodological_warning="Payload-only passive detector also sees complete proxy envelope; NRF instance IDs are not altered; do not claim KIE uniquely detects the attack."),data


def markdown(s):
    rows=[
        "# Stage 7: registered native Open5GS and lab HTTP/2 gateway integrity",
        "",
        "Actual Open5GS NRF/AUSF/NSSF containers remained registered and "
        "were probed through real native HTTP/2 sockets. An EXPERIMENTAL "
        "consumer gateway forwarded a JSON envelope derived from native "
        "HTTP/2 status and NF identity; ONLY THE GATEWAY ENVELOPE was "
        "tampered. This is NOT genuine native NF binary compromise, native "
        "3GPP SBI payload mutation, or a native CU handler.",
        "",
        f"Runners: {s['independent_runners']}; integrity episodes: "
        f"{s['experimental_tampering_events']} (randomized onset per episode).",
        "All KIE active policies receive exactly 2 HMAC-authenticated checks "
        "per scheduler tick from an independent EXTERNAL research attestor.",
        "",
        "## Attack-mode-stratified baselines",
        "",
        "| Gateway envelope attack | Detector | Recall | Mean horizon-penalized "
        "wall delay s | CU/event | False/clean probes |",
        "|---|---|---:|---:|---:|---:|"
    ]
    for kind,methods in s["per_attack"].items():
        for name,v in methods.items():
            rows.append(f"| {kind} | {name} | {v['recall']:.3f} | "
                        f"{v['mean_horizon_penalized_wall_s']:.3f} | "
                        f"{v['cu_checks_per_episode']:.0f} | "
                        f"{v['false_alerts']}/{v['clean_checks']} |")
    rows+=["", "## Seed-paired mean delay contrasts (positive = KIE zone faster)"]
    for name,v in s["paired_cluster_contrasts"].items():
        l,h=v["bootstrap_ci95_s"]
        rows.append(f"- {name}: {v['mean_delay_reduction_s']:+.3f} s; "
                    f"95% runner-cluster bootstrap interval [{l:+.3f},{h:+.3f}], "
                    f"{v['direction']}.")
    rows+=["","## Scientific qualifications",
        "- NRF-only reads **nfInstanceId SETS** for both NF types online. "
        "This is a stronger instance-resolution NRF control than stage 6.",
        "- Passive metadata cannot in principle distinguish an unchanged "
        "HTTP status and same-length JSON field substitution; payload-level "
        "passive analysis DOES compare the entire envelope and can detect it.",
        "- The proxy's native response envelope includes an experimental "
        "nfInstance identity field, NOT necessarily a field in a standard "
        "Open5GS service response. HMAC validates only the separate external "
        "attestor's independent native observation.",
        "- An administrative NF shutdown is NOT used here. Neither registration "
        "nor native NF software is modified, so this cannot show detection "
        "of a compromised native NF or malicious real SBI bearer payloads.",
        "- Missed-attack 'horizon-penalized mean' substitutes event duration "
        "for unobserved detections; this is NOT unbiased survival estimation.",
        "- CIs are bootstrap estimates from very few independent runner "
        "clusters and must not be used alone for inferential certainty.",
        "- Information-theoretic novelty is not established; full passive "
        "payload fingerprinting may be as good as or better than active KIE.",
        ""]
    return "\n".join(rows)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage7_batches")
    p.add_argument("--output",default="stage7_aggregate")
    args=p.parse_args()
    result,events=analyze(args.input)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(result,indent=2))
    (out/"raw_events.json").write_text(json.dumps(events,indent=2))
    (out/"REPORT.md").write_text(markdown(result))
    print(markdown(result))


if __name__=="__main__":
    main()
