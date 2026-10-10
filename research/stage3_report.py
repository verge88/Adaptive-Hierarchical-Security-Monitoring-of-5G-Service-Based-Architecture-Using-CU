"""Prespecified stage-3 analysis; collusion is a separate negative control."""
import argparse
import json
from pathlib import Path
import statistics
from .experiment import paired_ci
from .stage3_experiment import POLICIES, POSITIVE_KINDS, TRAIN, TICKS, BUDGET

def assemble(paths):
    rows, core, seen = [], [], set()
    for path in paths:
        dat = json.loads(path.read_text())
        nf = path.with_name("nrf.json")
        if not nf.exists():
            raise AssertionError("Missing real NRF evidence: " + str(path))
        core.append(json.loads(nf.read_text()))
        for row in dat:
            k = (row["seed"], row["policy"])
            if k in seen:
                raise AssertionError("Duplicate seed/policy " + str(k))
            seen.add(k)
            rows.append(row)
    seeds = sorted({r["seed"] for r in rows})
    if len(seeds) < 2 or len(rows) != len(seeds) * len(POLICIES):
        raise AssertionError("Missing full matched trial set")
    for s in seeds:
        group = [r for r in rows if r["seed"] == s]
        if set(r["policy"] for r in group) != set(POLICIES):
            raise AssertionError("Incomplete seed " + str(s))
        if set(r["probes"] for r in group) != {(TICKS-TRAIN)*BUDGET}:
            raise AssertionError("Unequal CU budget")
    return rows, core

def summarize(rows, core):
    grouped = {p: sorted((r for r in rows if r["policy"] == p),
                         key=lambda r: r["seed"]) for p in POLICIES}
    table = {}
    for p, samples in grouped.items():
        pos = [e for r in samples for e in r["events"] if e["kind"] in POSITIVE_KINDS]
        neg = [e for r in samples for e in r["events"] if e["kind"] == "collusion"]
        clean = sum(r["clean_checks"] for r in samples)
        table[p] = dict(
            pooled_recall=sum(e["detected"] for e in pos)/len(pos),
            mean_censored_delay_logical_s=statistics.mean(
                r["mean_censored_delay_s"] for r in samples),
            false_alarms=sum(r["false_alarms"] for r in samples),
            false_alarms_per_1000_checks=1000*sum(r["false_alarms"] for r in samples)/max(clean,1),
            cu_checks_per_seed=statistics.mean(r["probes"] for r in samples),
            cu_http2_bytes_per_seed=statistics.mean(r["cu_h2_wire_bytes"] for r in samples),
            cu_rtt_wall_ms=statistics.mean(r["cu_rtt_mean_ms"] for r in samples),
            negative_control_detected=sum(e["detected"] for e in neg),
            negative_control_total=len(neg),
            attacks_by_kind={k: {
                "recall": sum(e["detected"] for e in pos if e["kind"] == k) /
                          sum(e["kind"] == k for e in pos),
                "mean_censored_delay_logical_s": statistics.mean(
                    e["censored_delay_logical_s"] for e in pos if e["kind"] == k)}
                for k in POSITIVE_KINDS})
    aligned = {p: {r["seed"]: r for r in rows if r["policy"] == p} for p in POLICIES}
    paired = {}
    for base in ("local_adaptive", "fixed", "random"):
        diffs = [aligned[base][seed]["mean_censored_delay_s"] -
                 aligned["zone_adaptive"][seed]["mean_censored_delay_s"]
                 for seed in sorted(aligned[base])]
        paired[base + "_minus_zone"] = dict(
            mean_logical_s=statistics.mean(diffs),
            ci95_logical_s=paired_ci(diffs, seed=39201, n_boot=4000),
            wins=sum(v > 0 for v in diffs),
            losses=sum(v < 0 for v in diffs),
            ties=sum(v == 0 for v in diffs))
    return dict(scope="Real Open5GS NRF discovery; CU in research-owned HTTP2 sidecars",
                n_seeds=len(aligned["fixed"]), seeds=sorted(aligned["fixed"]),
                nrf_samples=sum(n["samples"] for n in core),
                nrf_wall_rtt_median_of_medians_ms=statistics.median(
                    n["median_wall_rtt_ms"] for n in core),
                policies=table, comparisons=paired)

def report(s):
    lines = [
        "# Stage 3: blinded HTTP/2 CU overlay experiment with real Open5GS NRF",
        "", "Native Open5GS NRF/AUSF/NSSF register and respond to HTTP/2 service "
        "discovery. CU is implemented ONLY in research sidecars (not native Open5GS NF).",
        f"Seeds={s['n_seeds']}; native NRF probes={s['nrf_samples']}; "
        f"median NRF HTTP/2 wall RTT={s['nrf_wall_rtt_median_of_medians_ms']:.2f} ms.",
        "", "Primary: zonal adaptive versus **local adaptive (spatial ablation)**, "
        "mean censored attack-event delay in accelerated LOGICAL seconds. "
        "Colluding SCP scenario is a negative control outside the primary effect.",
        "", "| Scheduler | Event recall | Censored delay (logical s) | "
        "False alarms/1000 checks | CU checks/seed | HTTP/2 CU bytes/seed | "
        "Collusion alerts |", "|---|---:|---:|---:|---:|---:|---:|"]
    for p, t in s["policies"].items():
        lines.append(f"| {p} | {t['pooled_recall']:.3f} | "
                     f"{t['mean_censored_delay_logical_s']:.2f} | "
                     f"{t['false_alarms_per_1000_checks']:.2f} | "
                     f"{t['cu_checks_per_seed']:.0f} | "
                     f"{t['cu_http2_bytes_per_seed']:.0f} | "
                     f"{t['negative_control_detected']}/{t['negative_control_total']} |")
    lines += ["", "## Paired bootstrap comparisons", ""]
    for p, t in s["comparisons"].items():
        lo, hi = t["ci95_logical_s"]
        status = ("consistent positive" if lo > 0 else
                  "consistent negative" if hi < 0 else "inconclusive (CI crosses zero)")
        lines.append(f"- {p}: {t['mean_logical_s']:+.2f} logical s, "
                     f"95% CI [{lo:+.2f}, {hi:+.2f}]; {status}; "
                     f"wins/losses/ties {t['wins']}/{t['losses']}/{t['ties']}.")
    lines += [
        "", "## Methodological boundaries", "",
        "- Distinct attacker kinds: slower signed false reporting, stealthy signed "
        "false reporting, intermittent mimicry, and collusion with observer.",
        "- Attack labels enter injection and scoring only. Schedulers only see "
        "HTTP/2 latency and prior CU schedule, NEVER attack labels.",
        "- Common-mode benign latency surges are injected; local-only scheduler "
        "is the zonal-feature ablation, a stronger baseline than fixed-only.",
        "- Each policy uses exactly two CU probes each tick after training. "
        "Equal probe counts do NOT imply exactly equal on-wire bytes.",
        "- Both HTTP/2 RTT and Open5GS NRF discovery RTT are REAL wall times. "
        "Attack detection delays are ACCELERATED LOGICAL seconds, not network latency.",
        "- Colluding observer falsifies both CU-compatible proxy counts and NF "
        "signed reports; the method cannot reliably detect it without a third "
        "independent source.",
        "- No real NF binary compromise, modified native NRF heartbeat, UE/RAN, "
        "mTLS, OAuth2, or production 5G core validation is claimed.",
        "- Seed bootstrap CI covers synthetic scenario variation; results cannot "
        "prove scientific priority, production accuracy or generalization.", ""]
    return "\n".join(lines)

def main():
    a = argparse.ArgumentParser()
    a.add_argument("--input", default="stage3_batches")
    a.add_argument("--output", default="stage3_aggregate")
    ns = a.parse_args()
    paths = sorted(Path(ns.input).rglob("runs.json"))
    if not paths:
        raise SystemExit("No stage3 CI shard files")
    rows, core = assemble(paths)
    summary = summarize(rows, core)
    out = Path(ns.output)
    out.mkdir(parents=True, exist_ok=True)
    (out/"raw_runs.json").write_text(json.dumps(rows, indent=2))
    (out/"summary.json").write_text(json.dumps(summary, indent=2))
    (out/"REPORT.md").write_text(report(summary))
    print(report(summary))
if __name__ == "__main__":
    main()
