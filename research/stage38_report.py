"""Stage 38 multi-NF held-out audit."""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.959963984540054):
    if n <= 0:
        return [0.0, 0.0]
    p = k / n
    den = 1 + z*z/n
    center = (p + z*z/(2*n)) / den
    half = z * math.sqrt(p*(1-p)/n + z*z/(4*n*n)) / den
    return [max(0.0, center-half), min(1.0, center+half)]


def load_by_seed(root: Path, filename: str):
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text())
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(f"duplicate {filename} seed={seed}")
        out[seed] = doc
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="stage38_report")
    p.add_argument("--seed-start", type=int, default=18001)
    p.add_argument("--seed-end", type=int, default=18256)
    args = p.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    signed = load_by_seed(root, "signed_verdict.json")
    evidence = load_by_seed(root, "evidence.json")
    expected = set(range(args.seed_start, args.seed_end + 1))
    if any(set(group) != expected for group in (labels, signed, evidence)):
        raise AssertionError("Stage38 requires complete preregistered seed range")

    total = rel = legacy = 0
    clean = clean_alerts = 0
    transition_clean = transition_clean_alerts = 0
    soak = soak_alerts = 0
    unique_plans = set()
    topology_runs = Counter()
    attack_counts = []
    compound_entries = 0
    by_family = defaultdict(lambda: [0,0,0])
    by_type = defaultdict(lambda: [0,0,0])
    by_slot = defaultdict(lambda: [0,0,0])
    by_topology = defaultdict(lambda: [0,0,0])
    by_density = defaultdict(lambda: [0,0,0])
    by_variant = defaultdict(lambda: [0,0,0])
    by_simultaneous = defaultdict(lambda: [0,0,0])

    for seed in sorted(expected):
        lab = labels[seed]
        ver = signed[seed]["verdict"]
        ev = evidence[seed]
        if ev["multi_nf_scope"]["nf_types"] != ["NSSF", "AUSF", "BSF", "UDM"]:
            raise AssertionError("NF scope mismatch")
        if ev["multi_nf_scope"]["instances"] != 8:
            raise AssertionError("instance scope mismatch")
        if ev["multi_nf_scope"]["independent_witness_channel"] is not True:
            raise AssertionError("missing witness channel")
        if ev["multi_nf_scope"]["witness_uses_nrf_discovery"] is not False:
            raise AssertionError("witness depends on NRF discovery")

        entries = lab["attack_entries"]
        events = {int(e["index"]): e for e in lab["lifecycle_events"]}
        attack_ticks = {int(e["tick"]) for e in entries}
        alerts = {int(a["tick"]): a for a in ver["alerts"]}
        unique_plans.add(lab["private_plan_sha256"])
        topology = int(lab["topology_template_id"])
        topology_runs[topology] += 1
        attack_counts.append(len(entries))

        for entry in entries:
            tick = int(entry["tick"])
            nf_type = entry["target_nf_type"]
            alert = alerts[tick]
            r = bool(alert["relational_alert_by_nf_type"][nf_type])
            l = bool(alert["legacy_alert_by_nf_type"][nf_type])
            total += 1
            rel += int(r)
            legacy += int(l)
            if int(entry["simultaneous_count"]) > 1:
                compound_entries += 1
            density = events[int(entry["event_index"])]["density_bin"]
            groups = (
                (by_family, entry["kind"]),
                (by_type, nf_type),
                (by_slot, entry["target_slot"]),
                (by_topology, str(topology)),
                (by_density, density),
                (by_variant, str(entry["variant"])),
                (by_simultaneous, str(entry["simultaneous_count"])),
            )
            for target, key in groups:
                target[key][0] += 1
                target[key][1] += int(r)
                target[key][2] += int(l)

        for tick, alert in alerts.items():
            if tick in attack_ticks:
                continue
            r = bool(alert["relational_alert"])
            clean += 1
            clean_alerts += int(r)
            phase = alert["phase"]
            if str(phase).startswith("transition_"):
                transition_clean += 1
                transition_clean_alerts += int(r)
            elif phase == "clean_soak":
                soak += 1
                soak_alerts += int(r)

    def groups(src):
        return {
            key: {
                "total": v[0],
                "relational_detected": v[1],
                "relational_recall": v[1]/v[0] if v[0] else 0,
                "relational_wilson95": wilson(v[1], v[0]),
                "legacy_detected": v[2],
                "legacy_recall": v[2]/v[0] if v[0] else 0,
            }
            for key, v in sorted(src.items())
        }

    summary = {
        "runs": len(expected),
        "seed_range": [args.seed_start, args.seed_end],
        "nf_types": ["NSSF", "AUSF", "BSF", "UDM"],
        "nf_instance_slots": 8,
        "unique_private_plan_hashes": len(unique_plans),
        "topology_template_run_counts": dict(sorted(topology_runs.items())),
        "attack_count_per_run": {
            "min": min(attack_counts),
            "max": max(attack_counts),
            "mean": sum(attack_counts)/len(attack_counts),
        },
        "compound_attack_entries": compound_entries,
        "attacks": {
            "total": total,
            "relational_detected": rel,
            "relational_recall": rel/total,
            "relational_wilson95": wilson(rel, total),
            "legacy_detected": legacy,
            "legacy_recall": legacy/total,
        },
        "transition_clean": {
            "ticks": transition_clean,
            "false_alerts": transition_clean_alerts,
            "false_alert_rate": transition_clean_alerts/max(1, transition_clean),
            "wilson95": wilson(transition_clean_alerts, transition_clean),
        },
        "clean_soak": {
            "ticks": soak,
            "false_alerts": soak_alerts,
            "false_alert_rate": soak_alerts/max(1, soak),
            "wilson95": wilson(soak_alerts, soak),
        },
        "all_clean": {
            "ticks": clean,
            "false_alerts": clean_alerts,
            "false_alert_rate": clean_alerts/max(1, clean),
            "wilson95": wilson(clean_alerts, clean),
        },
        "by_family": groups(by_family),
        "by_nf_type": groups(by_type),
        "by_target_slot": groups(by_slot),
        "by_topology_template": groups(by_topology),
        "by_density": groups(by_density),
        "by_variant": groups(by_variant),
        "by_simultaneous_count": groups(by_simultaneous),
    }

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf8"
    )

    a = summary["attacks"]
    lines = [
        "# Stage 38 — multi-NF validation with independent NF-side witness",
        "",
        f"Runs: **{summary['runs']}**; NF types: **{len(summary['nf_types'])}**; "
        f"real NF slots: **{summary['nf_instance_slots']}**; unique private plans: "
        f"**{summary['unique_private_plan_hashes']}**.",
        f"Attack entries: **{a['total']}**; relational recall: "
        f"**{a['relational_recall']:.4f}** ({a['relational_detected']}/{a['total']}), "
        f"Wilson 95% [{a['relational_wilson95'][0]:.4f}, "
        f"{a['relational_wilson95'][1]:.4f}].",
        f"Legacy per-type count/status recall: **{a['legacy_recall']:.4f}** "
        f"({a['legacy_detected']}/{a['total']}).",
        f"Transition clean false alerts: **{transition_clean_alerts}/{transition_clean}**.",
        f"Clean-soak false alerts: **{soak_alerts}/{soak}**.",
        f"All clean false alerts: **{clean_alerts}/{clean}**.",
        f"Attack entries participating in simultaneous cross-NF ticks: "
        f"**{compound_entries}**.",
        "",
        "## By NF type",
        "",
        "| NF type | Total | Relational | Legacy |",
        "|---|---:|---:|---:|",
    ]
    for name, row in summary["by_nf_type"].items():
        lines.append(
            f"| {name} | {row['total']} | "
            f"{row['relational_detected']}/{row['total']} | "
            f"{row['legacy_detected']}/{row['total']} |"
        )
    lines += [
        "", "## By attack family", "",
        "| Family | Total | Relational | Legacy |",
        "|---|---:|---:|---:|",
    ]
    for name, row in summary["by_family"].items():
        lines.append(
            f"| {name} | {row['total']} | "
            f"{row['relational_detected']}/{row['total']} | "
            f"{row['legacy_detected']}/{row['total']} |"
        )
    (out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
