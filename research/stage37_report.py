"""Stage 37 randomized-topology held-out audit."""
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
    half = z * math.sqrt((p*(1-p)/n) + z*z/(4*n*n)) / den
    return [max(0.0, center-half), min(1.0, center+half)]


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(f"duplicate {filename} seed={seed}")
        out[seed] = doc
    return out


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="stage37_report")
    p.add_argument("--seed-start", type=int, default=17001)
    p.add_argument("--seed-end", type=int, default=17512)
    args = p.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    signed = load_by_seed(root, "signed_verdict.json")
    evidence = load_by_seed(root, "evidence.json")
    expected = set(range(args.seed_start, args.seed_end + 1))
    if any(set(group) != expected for group in (labels, signed, evidence)):
        raise AssertionError("Stage37 requires complete preregistered seed range")

    total_attack = rel_detected = legacy_detected = 0
    clean_total = clean_rel_alerts = 0
    transition_clean = transition_clean_alerts = 0
    soak_total = soak_alerts = 0
    by_family = defaultdict(lambda: [0,0,0])
    by_template = defaultdict(lambda: [0,0,0])
    by_density = defaultdict(lambda: [0,0,0])
    by_target = defaultdict(lambda: [0,0,0])
    by_variant = defaultdict(lambda: [0,0,0])
    topology_runs = Counter()
    attack_counts = []
    unique_plan_hashes = set()

    for seed in sorted(expected):
        lab = labels[seed]
        ver = signed[seed]["verdict"]
        alerts = {int(row["tick"]): row for row in ver["alerts"]}
        attacks = {int(row["tick"]): row for row in lab["transition_attack_entries"]}
        events = {int(row["index"]): row for row in lab["lifecycle_events"]}
        topology_runs[int(lab["topology_template_id"])] += 1
        unique_plan_hashes.add(lab["private_plan_sha256"])
        attack_counts.append(len(attacks))

        for tick, alert in alerts.items():
            is_attack = tick in attacks
            rel = bool(alert["relational_alert"])
            leg = bool(alert["legacy_count_status_alert"])
            if is_attack:
                entry = attacks[tick]
                event = events[int(entry["event_index"])]
                total_attack += 1
                rel_detected += int(rel)
                legacy_detected += int(leg)
                groups = (
                    (by_family, entry["kind"]),
                    (by_template, str(lab["topology_template_id"])),
                    (by_density, event["density_bin"]),
                    (by_target, entry["target_slot"]),
                    (by_variant, str(entry["variant"])),
                )
                for target, key in groups:
                    target[key][0] += 1
                    target[key][1] += int(rel)
                    target[key][2] += int(leg)
            else:
                clean_total += 1
                clean_rel_alerts += int(rel)
                phase = str(alert["phase"])
                if phase.startswith("transition_"):
                    transition_clean += 1
                    transition_clean_alerts += int(rel)
                elif phase == "clean_soak":
                    soak_total += 1
                    soak_alerts += int(rel)

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
        "unique_private_plan_hashes": len(unique_plan_hashes),
        "topology_template_run_counts": dict(sorted(topology_runs.items())),
        "attack_count_per_run": {
            "min": min(attack_counts),
            "max": max(attack_counts),
            "mean": sum(attack_counts)/len(attack_counts),
        },
        "attacks": {
            "total": total_attack,
            "relational_detected": rel_detected,
            "relational_recall": rel_detected/total_attack,
            "relational_wilson95": wilson(rel_detected, total_attack),
            "legacy_detected": legacy_detected,
            "legacy_recall": legacy_detected/total_attack,
        },
        "transition_clean": {
            "ticks": transition_clean,
            "false_alerts": transition_clean_alerts,
            "false_alert_rate": transition_clean_alerts/max(1, transition_clean),
            "wilson95": wilson(transition_clean_alerts, transition_clean),
        },
        "clean_soak": {
            "ticks": soak_total,
            "false_alerts": soak_alerts,
            "false_alert_rate": soak_alerts/max(1, soak_total),
            "wilson95": wilson(soak_alerts, soak_total),
        },
        "all_clean": {
            "ticks": clean_total,
            "false_alerts": clean_rel_alerts,
            "false_alert_rate": clean_rel_alerts/max(1, clean_total),
            "wilson95": wilson(clean_rel_alerts, clean_total),
        },
        "by_family": groups(by_family),
        "by_topology_template": groups(by_template),
        "by_density": groups(by_density),
        "by_target_slot": groups(by_target),
        "by_variant": groups(by_variant),
    }

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out/"summary.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf8")

    a=summary["attacks"]
    lines=[
        "# Stage 37 — randomized topology and attack-variation validation",
        "",
        f"Runs: **{summary['runs']}**; unique private plans: **{summary['unique_private_plan_hashes']}**.",
        f"Attack episodes: **{a['total']}**; relational recall: **{a['relational_recall']:.4f}** "
        f"({a['relational_detected']}/{a['total']}), Wilson 95% "
        f"[{a['relational_wilson95'][0]:.4f}, {a['relational_wilson95'][1]:.4f}].",
        f"Legacy count/status recall: **{a['legacy_recall']:.4f}** "
        f"({a['legacy_detected']}/{a['total']}).",
        f"Transition clean false alerts: **{transition_clean_alerts}/{transition_clean}**.",
        f"Clean-soak false alerts: **{soak_alerts}/{soak_total}**.",
        f"All clean false alerts: **{clean_rel_alerts}/{clean_total}**.",
        "",
        "## Topology template coverage",
        "",
        json.dumps(summary["topology_template_run_counts"], ensure_ascii=False),
        "",
        "## By attack family",
        "",
        "| Family | Total | Relational | Legacy |",
        "|---|---:|---:|---:|",
    ]
    for name,row in summary["by_family"].items():
        lines.append(
            f"| {name} | {row['total']} | "
            f"{row['relational_detected']}/{row['total']} | "
            f"{row['legacy_detected']}/{row['total']} |"
        )
    lines += ["", "## By density", "", "| Density | Total | Relational | Legacy |",
              "|---|---:|---:|---:|"]
    for name,row in summary["by_density"].items():
        lines.append(
            f"| {name} | {row['total']} | "
            f"{row['relational_detected']}/{row['total']} | "
            f"{row['legacy_detected']}/{row['total']} |"
        )
    lines += ["", "## By target slot", "", "| Slot | Total | Relational | Legacy |",
              "|---|---:|---:|---:|"]
    for name,row in summary["by_target_slot"].items():
        lines.append(
            f"| {name} | {row['total']} | "
            f"{row['relational_detected']}/{row['total']} | "
            f"{row['legacy_detected']}/{row['total']} |"
        )
    (out/"REPORT.md").write_text("\n".join(lines)+"\n", encoding="utf8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
