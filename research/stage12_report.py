"""Stage 12 large-sample preregistered Stage11 robustness replication: strict provenance, equal verification budgets and CIs."""
import argparse
import json
from pathlib import Path
from math import comb
import random
import statistics
from .stage11_hedged import (METHODS,BUDGETED,SCHEDULED,ATTACKS,ALIGNMENTS,TICKS,BUDGET,MAX_GAP,N)
from .stage12_scale import (RUNNERS,REPEATS_PER_CELL,EPISODES_PER_RUNNER,
                             EXPECTED_EPISODES,SEED_START)

def boot(values,seed=90014,n=6000):
    rng=random.Random(seed)
    xs=sorted(statistics.mean(rng.choice(values) for _ in values) for _ in range(n))
    return [xs[int(.025*(n-1))],xs[int(.975*(n-1))]]

def sign_p(values):
    v=[x for x in values if abs(x)>1e-9]
    if not v:return 1.
    k=min(sum(x>0 for x in v),sum(x<0 for x in v))
    return min(1.0,2*sum(comb(len(v),i) for i in range(k+1))/2**len(v))

def analyze(root):
    files=sorted(Path(root).rglob("events.json"))
    if len(files)!=RUNNERS:raise AssertionError(f"Expected {RUNNERS} independent runner shards, got {len(files)}")
    data=[]
    for f in files:
        if not f.with_name("traces.json").exists():
            raise AssertionError("Missing unabridged HTTP/2 observation trace")
        mf=json.loads(f.with_name("manifest.json").read_text())
        if (mf.get("research_stage")!=12 or
            mf.get("protocol_frozen_from_stage")!=11 or
            mf.get("attacks_per_runner")!=EPISODES_PER_RUNNER or
            mf.get("repetitions_per_attack_risk_cell")!=REPEATS_PER_CELL or
            mf.get("predefined_total_attacks")!=EXPECTED_EPISODES or
            mf.get("native_open5gs_NF_compromised") is not False or
            mf.get("native_open5gs_SCP_compromised") is not False or
            mf.get("producer_origin_key_never_exposed_to_lab_scp") is not True):
            raise AssertionError("Missing honest research attack boundary")
        ts=json.loads(f.with_name("traces.json").read_text())
        if len(ts)!=EPISODES_PER_RUNNER or not all(x.get("tampered_txids") for x in ts):
            raise AssertionError("Missing evidence for actual proxy modifications")
        data.extend(json.loads(f.read_text()))
    seeds=sorted({x["seed"] for x in data})
    if seeds!=list(range(SEED_START,SEED_START+RUNNERS)):
        raise AssertionError("Missing a pre-registered independent runner seed")
    grouped={}
    for item in data:
        key=(item["seed"],item["episode"])
        row=grouped.setdefault(key,{})
        if item["method"] in row:
            raise AssertionError("Duplicate detector record")
        row[item["method"]]=item
    if len(grouped)!=EXPECTED_EPISODES:
        raise AssertionError("Incomplete 8 episodes per independent runner")
    for seed in seeds:
        gs=[r["cu_fixed"] for (s,_),r in grouped.items() if s==seed]
        for attack in ATTACKS:
            for align in ALIGNMENTS:
                if sum(g["attack"]==attack and g["alignment"]==align for g in gs)!=REPEATS_PER_CELL:
                    raise AssertionError("Unbalanced attack/risk telemetry design")
    for r in grouped.values():
        if set(r)!=set(METHODS):raise AssertionError("Missing scientific baseline")
        if {r[k]["control_checks"] for k in BUDGETED}!={TICKS*BUDGET}:
            raise AssertionError("Unequal active checks across CU and strong plain controls")
        if r["trusted_both_ends"]["control_checks"]!=TICKS*N:
            raise AssertionError("Two-sided full-visibility baseline incomplete")
        if r["passive_consumer"]["control_checks"] or r["nrf_only"]["control_checks"]:
            raise AssertionError("Passive comparator issued active checks")
        if any(r[k]["max_check_gap_ticks"]>MAX_GAP
               for k in ("cu_local","cu_hier","cu_hedged")):
            raise AssertionError("Bounded CU missed sampling guarantee")
        if any(not r[k]["native_NSSF_healthy"] or
               not r[k]["real_NRF_unchanged"] for k in METHODS):
            raise AssertionError("Real Open5GS NF availability/registration invalid")
        if any(r[k]["tampered_transactions"]<=0 for k in METHODS):
            raise AssertionError("No actual selective alteration")
    by={}
    for key in ("all",)+ATTACKS+ALIGNMENTS:
        by[key]={}
        for m in METHODS:
            xs=[x for x in data if x["method"]==m and
                (key=="all" or x["attack"]==key or x["alignment"]==key)]
            positive=[x["detection_wall_s"] for x in xs if x["detected"]]
            by[key][m]=dict(
                n=len(xs),detected=len(positive),recall=len(positive)/len(xs),
                observed_mean_s=statistics.mean(positive) if positive else None,
                horizon_penalized_mean_s=statistics.mean(x["horizon_penalized_wall_s"] for x in xs),
                false_alerts=sum(x["false_alarms"] for x in xs),
                clean_checks=sum(x["clean_checks"] for x in xs),
                checks_per_case=statistics.mean(x["control_checks"] for x in xs),
                wire_bytes_per_case=statistics.mean(x["h2_control_wire_bytes"] for x in xs))
    pairs={}
    for group in ("all",)+ALIGNMENTS:
        for reference,candidate in (("cu_fixed","cu_hier"),
                                    ("cu_local","cu_hier"),
                                    ("cu_fixed","cu_hedged"),
                                    ("cu_local","cu_hedged"),
                                    ("cu_hier","cu_hedged"),
                                    ("trusted_plain","cu_hedged"),
                                    ("trusted_plain","cu_hier"),
                                    ("trusted_both_ends","cu_hier"),
                                    ("trusted_both_ends","cu_hedged"),
                                    ("ordinary_active","cu_hedged"),
                                    ("ordinary_active","cu_hier")):
            effects=[]
            for seed in seeds:
                source=[v for (s,_),v in grouped.items() if s==seed and (
                    group=="all" or v["cu_hier"]["alignment"]==group)]
                effects.append(statistics.mean(
                    x[reference]["horizon_penalized_wall_s"]-
                    x[candidate]["horizon_penalized_wall_s"] for x in source))
            pairs[group+":"+reference+"_minus_"+candidate]=dict(
                mean_s=statistics.mean(effects),ci95_boot_s=boot(effects),
                exact_sign_p=sign_p(effects),runner_s=effects)
    # Robustness is judged by worst CONDITION-SPECIFIC measured delay, not
    # just global average: negative/misleading priors must be reported.
    robust_guardrail={}
    for policy in ("cu_fixed","cu_local","cu_hier","cu_hedged","trusted_plain"):
        conditional={mode:by[mode][policy]["horizon_penalized_mean_s"]
                     for mode in ALIGNMENTS}
        robust_guardrail[policy]=dict(
            worst_conditional_mean_wall_s=max(conditional.values()),
            mean_of_condition_means_wall_s=statistics.mean(conditional.values()),
            per_condition_s=conditional)
    # Cluster-level worst-case endpoint: avoid pseudo-replication across
    # 576 repeated episodes. Each runner contributes ONE worst mean over its
    # four 6-episode risk conditions, per method.
    runner_worst={}
    for policy in ("cu_fixed","cu_local","cu_hier","cu_hedged","trusted_plain"):
        runner_worst[policy]={}
        for seed in seeds:
            worst_by_regime=[]
            for risk in ALIGNMENTS:
                trials=[g[policy]["horizon_penalized_wall_s"]
                        for (s,_),g in grouped.items()
                        if s==seed and g[policy]["alignment"]==risk]
                if len(trials)!=len(ATTACKS)*REPEATS_PER_CELL:
                    raise AssertionError("Incomplete runner-level risk regime")
                worst_by_regime.append(statistics.mean(trials))
            runner_worst[policy][seed]=max(worst_by_regime)
    worst_paired={}
    for reference,candidate in (("cu_fixed","cu_hedged"),
                                ("cu_local","cu_hedged"),
                                ("cu_hier","cu_hedged"),
                                ("trusted_plain","cu_hedged"),
                                ("cu_fixed","cu_hier")):
        differences=[runner_worst[reference][seed]-
                     runner_worst[candidate][seed] for seed in seeds]
        worst_paired[reference+"_minus_"+candidate]=dict(
            effect_seconds=statistics.mean(differences),
            cluster_ci95_s=boot(differences),
            exact_two_sided_runner_sign_p=sign_p(differences),
            runner_effects_s=differences)
    # Fully crossed 2 attack types x 4 risk conditions. Each cell must
    # contain 12 runner clusters x 6 repetitions = 72 original faults.
    by_cell={}
    for attack in ATTACKS:
        by_cell[attack]={}
        for regime in ALIGNMENTS:
            cell=[g for g in grouped.values()
                  if g["cu_fixed"]["attack"]==attack and
                     g["cu_fixed"]["alignment"]==regime]
            if len(cell)!=RUNNERS*REPEATS_PER_CELL:
                raise AssertionError("Missing attack x risk cell")
            by_cell[attack][regime]={
                policy:dict(
                    detected=sum(g[policy]["detected"] for g in cell),
                    events=len(cell),
                    mean_censored_s=statistics.mean(
                        g[policy]["horizon_penalized_wall_s"] for g in cell))
                for policy in ("trusted_plain","cu_fixed","cu_local",
                               "cu_hier","cu_hedged","trusted_both_ends")}
    return dict(
        pre_registered_design=dict(
            independent_runners=RUNNERS,
            repeats_per_attack_risk_cell_per_runner=REPEATS_PER_CELL,
            attack_types=len(ATTACKS),risk_regimes=len(ALIGNMENTS),
            total_laboratory_corruption_events=EXPECTED_EPISODES,
            nine_detectors=len(METHODS),
            primary_endpoints=[
                "worst conditional mean delay per runner: fixed vs hedged",
                "worst conditional mean delay per runner: local vs hedged",
                "worst conditional mean delay per runner: trusted plain vs hedged"
            ]),
        per_attack_risk_cell=by_cell,
        worst_case_runner_paired=worst_paired,
        guardrail_risk_robustness=robust_guardrail,
        n_runners=len(seeds),seeds=seeds,proxy_attack_episodes=len(grouped),
        detector_rows=len(data),by_group=by,paired=pairs,
        actual_native_NSSF_attack=False,actual_native_SCP_attack=False,
        signed_receipt_producer_is_research_lab=True,
        same_budget_methods=list(BUDGETED),
        independent_trust_needed=True),data

def markdown(s):
    lines=["# Stage 12 — Large-sample (576 incidents) robustness replication","",
      "**Strict provenance:** real Open5GS NRF and native NSSFs remain running "
      "and registered. A research dynamic NSSF-like producer and separate "
      "research HTTP/2 SCP implement actual controlled laboratory response "
      "tampering; neither native 5G NF code nor native SCP is compromised. "
      "The independently signed origin receipt comes from the RESEARCH "
      "producer, not a native Open5GS NF.",
      f"{s['n_runners']} independent runners, {s['proxy_attack_episodes']} selective "
      f"LAB message-corruption episodes, {s['detector_rows']} detector rows.",
      "",
      "| Detector | Detected/episodes | Mean horizon-penalized wall s | "
      "False alarms / clean observations | Origin/active checks per episode | Control bytes per episode |",
      "|---|---:|---:|---:|---:|---:|"]
    for m,r in s["by_group"]["all"].items():
        lines.append(f"| {m} | {r['detected']}/{r['n']} | "
            f"{r['horizon_penalized_mean_s']:.3f} | "
            f"{r['false_alerts']}/{r['clean_checks']} | "
            f"{r['checks_per_case']:.0f} | {r['wire_bytes_per_case']:.0f} |")
    lines+=["","## Controlled stress-target alignment ablation"]
    for a in ALIGNMENTS:
        lines.append(f"### {a}")
        for m in ("cu_fixed","cu_local","cu_hier","cu_hedged","trusted_plain","trusted_both_ends"):
            x=s["by_group"][a][m]
            lines.append(f"- {m}: recall {x['detected']}/{x['n']}, "
                         f"mean penalized detection {x['horizon_penalized_mean_s']:.3f} s")
    lines+=["","## Pre-registered large sample",
        f"Independent runner clusters: {s['pre_registered_design']['independent_runners']}; "
        f"repetitions per attack/risk cell per runner: "
        f"{s['pre_registered_design']['repeats_per_attack_risk_cell_per_runner']}. "
        f"Total corruption events: {s['pre_registered_design']['total_laboratory_corruption_events']}.",
        "Every event has two scheduled active verifications per tick; "
        "strong two-ended control uses four. CI resamples RUNNERS.",
        "",
        "## Attack type × misleading-risk subgroup check"]
    for attack,riskdict in s["per_attack_risk_cell"].items():
        for regime,methods in riskdict.items():
            lines.append(f"- {attack} / {regime}: " +
                "; ".join(f"{m} {x['detected']}/{x['events']} at "
                          f"{x['mean_censored_s']:.3f}s"
                          for m,x in methods.items()))
    lines+=["","## PRE-REGISTERED primary worst-case runner-cluster contrasts"]
    for label,pair in s["worst_case_runner_paired"].items():
        lo,hi=pair["cluster_ci95_s"]
        lines.append(f"- {label}: effect {pair['effect_seconds']:+.4f}s; "
                     f"runner bootstrap CI95 [{lo:+.4f},{hi:+.4f}]; "
                     f"exact two-sided runner sign p="
                     f"{pair['exact_two_sided_runner_sign_p']:.4f}.")
    lines+=["","## Worst-case over deliberately controlled risk regimes"]
    for policy,v in s["guardrail_risk_robustness"].items():
        lines.append(f"- {policy}: max per-condition mean detection penalty "
                     f"{v['worst_conditional_mean_wall_s']:.3f} s; "
                     f"mean {v['mean_of_condition_means_wall_s']:.3f} s.")
    lines+=["","## Seed-cluster paired effects (positive means candidate faster)"]
    for name,c in s["paired"].items():
        lo,hi=c["ci95_boot_s"]
        lines.append(f"- {name}: {c['mean_s']:+.3f} wall s, "
            f"bootstrap CI95 [{lo:+.3f},{hi:+.3f}], "
            f"exact two-sided runner sign p={c['exact_sign_p']:.3f}.")
    lines+=["","## Critical baseline and threat caveats",
      "- A consumer-only semantic baseline sees dynamic plausible values and "
      "cannot authenticate their original provenance; this is an INFORMATION "
      "difference, not automatically a CU scheduling improvement.",
      "- Ordinary active proxy probes are sent to the very same SCP and also "
      "see plausibly modified dynamic results. They lack trusted producer "
      "provenance, but sending more ordinary queries alone does not restore it.",
      "- A budget-matched TRULY TRUSTED PLAIN DIRECT ORIGIN comparator obtains "
      "the same correct original transaction record without the CU wrapper. "
      "If a direct path is trusted, it may match KIE and be cheaper.",
      "- Trusted two-sided endpoint visibility compares EVERY transaction "
      "with the original producer (4 per tick vs 2 for CU); this stronger "
      "control should detect all attacks earlier. Its trust and bandwidth "
      "requirements differ and MUST NOT be hidden.",
      "- Producer HMAC and agent HMAC are separate research key domains; "
      "they authenticate a research producer record, NOT Open5GS NF process "
      "state, hardware, or operator 3GPP SBI traffic.",
      "- Correct, misleading, neutral, and time-FLIPPING telemetry are lab "
      "interventions, not real attacker-owned 5G NWDAF reports. They test "
      "sensitivity to unknown risk reliability. The hedged algorithm "
      "never observes hidden event labels.",
      "- The hedged policy always visits every context in each two-tick "
      "frame, but that guarantee costs opportunities to prioritize risk. "
      "It is NOT proven to be minimax optimal.",
      "- Non-detections receive observed attack duration as a penalty; this "
      "is NOT a proper survival/censoring estimator.",
      "- Only twelve independent CI runners: repeated attacks within the same "
      "runner are correlated; cluster bootstrap and exact sign p operate over RUNNERS, not 576 pseudo-independent events.",
      "- Real compromise of native SCP, inside-NF attacks, collusion, key "
      "exfiltration and 3GPP-standardized end-to-end provenance are untested.",
      ""]
    return "\n".join(lines)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage12_batches")
    p.add_argument("--output",default="stage12_report")
    a=p.parse_args()
    summary,rows=analyze(a.input)
    out=Path(a.output)
    out.mkdir(parents=True,exist_ok=True)
    (out/"summary.json").write_text(json.dumps(summary,indent=2))
    (out/"raw_events.json").write_text(json.dumps(rows,indent=2))
    (out/"REPORT.md").write_text(markdown(summary))
    print(markdown(summary))

if __name__=="__main__":
    main()
