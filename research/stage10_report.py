"""Stage 10 validation: strict provenance, equal verification budgets and CIs."""
import argparse
import json
from pathlib import Path
from math import comb
import random
import statistics
from .stage10_scp import (METHODS,BUDGETED,SCHEDULED,ATTACKS,ALIGNMENTS,TICKS,BUDGET,MAX_GAP,N)

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
    if len(files)<3:raise AssertionError("Require >=3 independent runner shards")
    data=[]
    for f in files:
        if not f.with_name("traces.json").exists():
            raise AssertionError("Missing unabridged HTTP/2 observation trace")
        mf=json.loads(f.with_name("manifest.json").read_text())
        if (mf.get("native_open5gs_NF_compromised") is not False or
            mf.get("native_open5gs_SCP_compromised") is not False or
            mf.get("producer_origin_key_never_exposed_to_lab_scp") is not True):
            raise AssertionError("Missing honest research attack boundary")
        ts=json.loads(f.with_name("traces.json").read_text())
        if len(ts)!=8 or not all(x.get("tampered_txids") for x in ts):
            raise AssertionError("Missing evidence for actual proxy modifications")
        data.extend(json.loads(f.read_text()))
    seeds=sorted({x["seed"] for x in data})
    if len(seeds)!=len(files):raise AssertionError("Duplicate independent runner seed")
    grouped={}
    for item in data:
        key=(item["seed"],item["episode"])
        row=grouped.setdefault(key,{})
        if item["method"] in row:
            raise AssertionError("Duplicate detector record")
        row[item["method"]]=item
    if len(grouped)!=len(seeds)*8:
        raise AssertionError("Incomplete 8 episodes per independent runner")
    for seed in seeds:
        gs=[r["cu_fixed"] for (s,_),r in grouped.items() if s==seed]
        for attack in ATTACKS:
            for align in ALIGNMENTS:
                if sum(g["attack"]==attack and g["alignment"]==align for g in gs)!=2:
                    raise AssertionError("Unbalanced attack/zone relationship design")
    for r in grouped.values():
        if set(r)!=set(METHODS):raise AssertionError("Missing scientific baseline")
        if {r[k]["control_checks"] for k in BUDGETED}!={TICKS*BUDGET}:
            raise AssertionError("Unequal active checks across CU and strong plain controls")
        if r["trusted_both_ends"]["control_checks"]!=TICKS*N:
            raise AssertionError("Two-sided full-visibility baseline incomplete")
        if r["passive_consumer"]["control_checks"] or r["nrf_only"]["control_checks"]:
            raise AssertionError("Passive comparator issued active checks")
        if any(r[k]["max_check_gap_ticks"]>MAX_GAP
               for k in ("cu_local","cu_hier")):
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
                                    ("trusted_plain","cu_hier"),
                                    ("trusted_both_ends","cu_hier"),
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
    return dict(
        n_runners=len(seeds),seeds=seeds,proxy_attack_episodes=len(grouped),
        detector_rows=len(data),by_group=by,paired=pairs,
        actual_native_NSSF_attack=False,actual_native_SCP_attack=False,
        signed_receipt_producer_is_research_lab=True,
        same_budget_methods=list(BUDGETED),
        independent_trust_needed=True),data

def markdown(s):
    lines=["# Stage 10 — LAB SCP selective alteration: origin-bound transaction KIE","",
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
        for m in ("cu_fixed","cu_local","cu_hier","trusted_plain","trusted_both_ends"):
            x=s["by_group"][a][m]
            lines.append(f"- {m}: recall {x['detected']}/{x['n']}, "
                         f"mean penalized detection {x['horizon_penalized_mean_s']:.3f} s")
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
      "- Synthetic risk-alignment is deliberately correlated or anti-correlated "
      "with faults in paired strata; not derived from an operator dataset.",
      "- Non-detections receive observed attack duration as a penalty; this "
      "is NOT a proper survival/censoring estimator.",
      "- Only four independent CI runners: percentile cluster bootstrap does "
      "not prove general statistical significance. Consult exact sign p.",
      "- Real compromise of native SCP, inside-NF attacks, collusion, key "
      "exfiltration and 3GPP-standardized end-to-end provenance are untested.",
      ""]
    return "\n".join(lines)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--input",default="stage10_batches")
    p.add_argument("--output",default="stage10_report")
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
