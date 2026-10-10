"""Stage 13 held-out-only statistical analysis.

Independent unit: one of twelve CI runners, NOT each of 288 nested attack
episodes. The calibration phase is never pooled into held-out detection
scores; no parameter threshold is tuned from test labels.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from math import comb
from pathlib import Path
import random
import statistics

from .stage13_trial import (RUNNERS,SEED_START,CAL_REPS,EVAL_REPS,
                            CAL_EVENTS,EVAL_EVENTS,TRAINING_TOTAL,TEST_TOTAL)
from .stage13_confidence import (
    METHODS,BUDGETED,SCHEDULED,ATTACKS,ALIGNMENTS,TICKS,BUDGET,N,MAX_GAP
)


def bootstrap(values, seed=13579, samples=8000):
    rng=random.Random(seed)
    out=sorted(statistics.mean(rng.choice(values) for _ in values)
               for _ in range(samples))
    return [out[int((samples-1)*.025)],out[int((samples-1)*.975)]]


def sign_p(values):
    v=[x for x in values if abs(x)>1e-10]
    if not v:
        return 1.
    n=len(v)
    count=min(sum(x>0 for x in v),sum(x<0 for x in v))
    return min(1.,2*sum(comb(n,i) for i in range(count+1))/2**n)


def verify_rows(items,per_runner,phase):
    groups={}
    for r in items:
        key=(r["seed"],r["episode"])
        dest=groups.setdefault(key,{})
        if r["method"] in dest:
            raise AssertionError("Duplicate method for incident")
        dest[r["method"]]=r
        if r["calibration_phase"]!=(phase=="calibration"):
            raise AssertionError("Training and heldout evidence mixed")
    if len(groups)!=RUNNERS*per_runner:
        raise AssertionError(f"Wrong number of {phase} incidents")
    for (seed,idx),g in groups.items():
        if set(g)!=set(METHODS):
            raise AssertionError("Baseline missing")
        if {g[m]["control_checks"] for m in BUDGETED}!={TICKS*BUDGET}:
            raise AssertionError("Unequal active integrity-check budget")
        if g["trusted_both_ends"]["control_checks"]!=TICKS*N:
            raise AssertionError("Two-sided comparator not fully observable")
        if g["nrf_only"]["control_checks"]!=0 or g["passive_consumer"]["control_checks"]!=0:
            raise AssertionError("Supposedly passive control issued challenges")
        if any(g[m]["max_check_gap_ticks"]>MAX_GAP
               for m in ("cu_local","cu_hier","cu_hedged","cu_guarded")):
            raise AssertionError("Bounded inspection deadline exceeded")
        if any(not g[m]["native_NSSF_healthy"] or
               not g[m]["real_NRF_unchanged"] or
               g[m]["tampered_transactions"]<=0 for m in METHODS):
            raise AssertionError("Real NF or research SCP evidence inconsistent")
        guard_values={g[m]["guarded_risk_authorized"] for m in METHODS}
        if len(guard_values)!=1:
            raise AssertionError("Frozen guard inconsistency")
        if phase=="calibration" and any(guard_values):
            raise AssertionError("Calibration must use independent fixed safe inspection")
        if (phase=="calibration" and idx>=CAL_EVENTS) or (
                phase=="heldout" and idx<CAL_EVENTS):
            raise AssertionError("Calibration and testing episode IDs overlap")
    return groups


def verify(root):
    shards=sorted(Path(root).rglob("events.json"))
    if len(shards)!=RUNNERS:
        raise AssertionError(f"Exactly {RUNNERS} independent experiment shards required")
    heldout=[]
    training=[]
    model_by_seed={}
    for f in shards:
        parent=f.parent
        m=json.loads((parent/"manifest.json").read_text())
        seed=m["seed"]
        if seed in model_by_seed or seed not in range(SEED_START,SEED_START+RUNNERS):
            raise AssertionError("Bad or duplicate independent runner seed")
        if not (m.get("research_stage")==13
                and m["native_open5gs_NF_compromised"] is False
                and m["native_open5gs_SCP_compromised"] is False
                and m["calibration_ground_truth_leaked_to_policy"] is False
                and m["heldout_weights_frozen"] is True
                and m["distinct_training_and_test_episodes"] is True
                and m["train_episodes"]==CAL_EVENTS
                and m["heldout_episodes"]==EVAL_EVENTS):
            raise AssertionError("Scientific provenance or blinded calibration failed")
        train_traces=json.loads((parent/"calibration_traces.json").read_text())
        holdout_traces=json.loads((parent/"traces.json").read_text())
        if (len(train_traces)!=CAL_EVENTS or len(holdout_traces)!=EVAL_EVENTS
                or any(not x["tampered_txids"] for x in train_traces+holdout_traces)
                or any(x["verified_feedback"] for x in holdout_traces)):
            raise AssertionError("Unobserved fault or leaked test feedback")
        if any(len(x["verified_feedback"])>1 for x in train_traces):
            raise AssertionError("Calibration uses more than first signed mismatch per event")
        count=sum(len(x["verified_feedback"]) for x in train_traces)
        positive_zone=sum(
            int(p["verified_producer_context"]//2==p["observed_high_zone"])
            for x in train_traces for p in x["verified_feedback"])
        model=m["verified_calibration_posterior"]
        if count!=model["authenticated_calibration_episodes"] or \
                positive_zone!=model["high_zone_confirmations"]:
            raise AssertionError("Frozen Wilson posterior disagrees with audit trail")
        if ((m["chosen_heldout_guard_policy"]=="risk_hierarchical") !=
                model["eligible_to_use_hierarchical_risk"]):
            raise AssertionError("Guard selection manipulated after calibration")
        train=json.loads((parent/"calibration_events.json").read_text())
        test=json.loads(f.read_text())
        if {x["seed"] for x in train+test}!={seed}:
            raise AssertionError("Seed mismatch between run and originals")
        model_by_seed[seed]=model
        training.extend(train)
        heldout.extend(test)
    if sorted(model_by_seed)!=list(range(SEED_START,SEED_START+RUNNERS)):
        raise AssertionError("Missing independent runner cluster")
    tgroups=verify_rows(training,CAL_EVENTS,"calibration")
    groups=verify_rows(heldout,EVAL_EVENTS,"heldout")
    for seed in model_by_seed:
        for label,frame,reps in [
            ("calibration",tgroups,CAL_REPS),
            ("heldout",groups,EVAL_REPS)]:
            subset=[g["cu_fixed"] for (s,_),g in frame.items() if s==seed]
            for attack in ATTACKS:
                for alignment in ALIGNMENTS:
                    if sum(g["attack"]==attack and g["alignment"]==alignment
                           for g in subset)!=reps:
                        raise AssertionError(f"{label} lacks a factorial cell")

    summary={}
    for condition in ("all",)+ALIGNMENTS:
        summary[condition]={}
        for method in METHODS:
            rows=[r for r in heldout if r["method"]==method and (
                condition=="all" or r["alignment"]==condition)]
            detected=[r["detection_wall_s"] for r in rows if r["detected"]]
            summary[condition][method]=dict(
                count=len(rows),
                detected=len(detected),
                mean_detected_wall_s=statistics.mean(detected) if detected else None,
                mean_penalized_s=statistics.mean(r["horizon_penalized_wall_s"]
                                                for r in rows),
                false_alerts=sum(r["false_alarms"] for r in rows),
                clean_checks=sum(r["clean_checks"] for r in rows),
                checks_per_event=statistics.mean(r["control_checks"] for r in rows),
                bytes_per_event=statistics.mean(r["h2_control_wire_bytes"]
                                                 for r in rows))

    # Two preregistered primary comparisons: worst risk condition, and pooled.
    comparisons={}
    for endpoint in ("worst_condition","pooled"):
        for reference,candidate in (("cu_fixed","cu_guarded"),
                                     ("cu_hier","cu_guarded"),
                                     ("trusted_plain","cu_guarded")):
            effects=[]
            for seed in sorted(model_by_seed):
                subset=[g for (s,_),g in groups.items() if s==seed]
                def stat(method):
                    if endpoint=="pooled":
                        return statistics.mean(g[method]["horizon_penalized_wall_s"]
                                               for g in subset)
                    return max(
                        statistics.mean(g[method]["horizon_penalized_wall_s"]
                                        for g in subset if
                                        g[method]["alignment"]==risk)
                        for risk in ALIGNMENTS)
                effects.append(stat(reference)-stat(candidate))
            comparisons[f"{endpoint}:{reference}_minus_{candidate}"]=dict(
                mean_effect_s=statistics.mean(effects),
                interval95_runner_cluster_bootstrap_s=bootstrap(effects),
                exact_two_sided_sign_p=sign_p(effects),
                runner_effects_s=effects)
    return dict(
        provenance="Research producer/research SCP only; genuine Open5GS NRF/NSSF healthy",
        pre_registered=dict(
            independent_runner_clusters=RUNNERS,
            calibration_episodes=TRAINING_TOTAL,
            frozen_heldout_episodes=TEST_TOTAL,
            attacks=["plausible_choice_change","stale_choice_field"],
            misleading_context_conditions=list(ALIGNMENTS),
            primary_comparisons=[
                "worst_condition:cu_fixed_minus_cu_guarded",
                "worst_condition:cu_hier_minus_cu_guarded",
                "worst_condition:trusted_plain_minus_cu_guarded"],
            primary_method_was_predefined=True,
            time_metric="horizon-penalized monotonic wall seconds",
            exact_sign_test_uses_runner_clusters=True),
        posterior_models_by_seed=model_by_seed,
        heldout_detector_records=len(heldout),
        calibration_detector_records=len(training),
        heldout_group_metrics=summary,
        heldout_worst_and_pooled_paired_comparisons=comparisons),heldout,training


def markdown(d):
    p=d["pre_registered"]
    lines=[
        "# Stage 13 — Confidence-gated CU: genuinely independent calibration vs heldout",
        "",
        "**Native scope:** Genuine Open5GS NRF/NSSF live and registered, but "
        "all selective corruptions happen in a RESEARCH HTTP/2 producer "
        "and RESEARCH SCP. Signed original transaction receipts are from "
        "the research producer and external KIE agent, NOT native NSSF.",
        f"Calibration={p['calibration_episodes']} separate incidents; "
        f"heldout={p['frozen_heldout_episodes']} independent LAB incidents; "
        f"total rows={d['calibration_detector_records'] + d['heldout_detector_records']}; "
        f"runner clusters={p['independent_runner_clusters']}.",
        "",
        "## Frozen risk authorization per runner"
    ]
    for seed,v in sorted(d["posterior_models_by_seed"].items()):
        lines.append(
            f"- seed {seed}: verified mismatch episodes "
            f"{v['authenticated_calibration_episodes']}, high-zone hits "
            f"{v['high_zone_confirmations']}, "
            f"Wilson lower {v['wilson_lower']:.3f}, "
            f"risk allowed={v['eligible_to_use_hierarchical_risk']}.")
    lines.extend(["","## Frozen heldout results",
                  "| Method | Recall | Mean censored wall s | False alert / clean | "
                  "Checks/event | Control H2 bytes/event |",
                  "|---|---:|---:|---:|---:|---:|"])
    for method,r in d["heldout_group_metrics"]["all"].items():
        lines.append(
            f"| {method} | {r['detected']}/{r['count']} | "
            f"{r['mean_penalized_s']:.3f} | "
            f"{r['false_alerts']}/{r['clean_checks']} | "
            f"{r['checks_per_event']:.0f} | {r['bytes_per_event']:.0f} |")
    lines+=["","## Risk regime ablation (heldout only)"]
    for regime in ALIGNMENTS:
        rs=d["heldout_group_metrics"][regime]
        lines.append("- "+regime+": "+", ".join(
            f"{m} {rs[m]['mean_penalized_s']*1000:.1f}ms"
            for m in ("cu_fixed","cu_hier","cu_hedged","cu_guarded","trusted_plain")))
    lines+=["","## Runner-cluster paired effects: positive -> guarded faster"]
    for key,x in d["heldout_worst_and_pooled_paired_comparisons"].items():
        lo,hi=x["interval95_runner_cluster_bootstrap_s"]
        lines.append(f"- {key}: {x['mean_effect_s']:+.4f}s, "
                     f"95% runner-bootstrap [{lo:+.4f},{hi:+.4f}]s, "
                     f"two-sided sign p={x['exact_two_sided_sign_p']:.5f}.")
    lines+=["","## Scientific restrictions",
      "- Calibration gets ONLY a first *cryptographically confirmed* "
      "producer-vs-consumer mismatch per CALIBRATION attack. No injected "
      "target labels, attack regimens, attack times, or evaluator outcome "
      "fields enter the risk controller. Test decisions freeze before any "
      "test sample is observed.",
      "- At first sight of a new attack, risk reliability is not identifiable "
      "from an unauthenticated load signal. Verified calibrations can estimate "
      "past predictive quality but cannot guarantee future benign/adversarial "
      "shift. A zero/low-confidence policy correctly defaults to fixed.",
      "- All baseline budgeted methods query exactly 2 original messages/tick "
      "(46 per case), while complete two-sided checks 4/tick.",
      "- Risk accuracy here is artificially engineered by alignment regimes; "
      "this is not real NWDAF telemetry or a trained field network model.",
      "- Bootstrap and exact sign tests operate on ONLY runner clusters, "
      "not hundreds of non-independent attacks. At least three preregistered "
      "primary comparisons; multiplicity correction needed.",
      "- Full end-to-end native SBI integrity, true compromised SCP, "
      "hardware NF attestation, and operator generalization untested.",
      "- HMAC-guarded CU competes against an independent trusted PLAIN "
      "origin receipt without CU overhead; cryptographic provenance "
      "is not automatically a unique CU advantage.",""]
    return "\n".join(lines)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--input",default="stage13_batches")
    ap.add_argument("--output",default="stage13_scientific")
    args=ap.parse_args()
    d,heldout,train=verify(args.input)
    out=Path(args.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(d,indent=2))
    (out/"heldout_events.json").write_text(json.dumps(heldout,indent=2))
    (out/"calibration_events.json").write_text(json.dumps(train,indent=2))
    (out/"REPORT.md").write_text(markdown(d))
    print(markdown(d))


if __name__=="__main__":
    main()
