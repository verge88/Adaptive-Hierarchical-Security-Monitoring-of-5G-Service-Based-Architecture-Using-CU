"""Stage 21 unified frozen ablation report.

Dedicated untouched block: 64 independent Open5GS runners, seeds 8701..8764.
All detector components are frozen before this block. The report compares
single-channel, cumulative, and leave-one-channel-out variants on identical
episodes within every runner.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8701, 8765))
BOOTSTRAPS = 50000

VARIANTS = (
    "directional_only",
    "directional_plus_sparse",
    "structural_only",
    "semantic_only",
    "directional_plus_structural",
    "full_without_semantic",
    "full_without_structural",
    "full_without_sparse",
    "full",
)

LABELS = {
    "directional_only": "Directional only",
    "directional_plus_sparse": "Directional + sparse memory",
    "structural_only": "Structural only",
    "semantic_only": "Semantic only",
    "directional_plus_structural": "Directional + structural",
    "full_without_semantic": "Full minus semantic (Stage 20)",
    "full_without_structural": "Full minus structural",
    "full_without_sparse": "Full minus sparse memory",
    "full": "Full Stage 21",
}

COMPARISONS = {
    "sparse_increment_over_directional": (
        "directional_plus_sparse",
        "directional_only",
    ),
    "structural_increment_over_directional": (
        "directional_plus_structural",
        "directional_only",
    ),
    "structural_increment_over_stage19": (
        "full_without_semantic",
        "directional_plus_sparse",
    ),
    "semantic_increment_over_stage20": (
        "full",
        "full_without_semantic",
    ),
    "leave_sparse_out_loss": (
        "full",
        "full_without_sparse",
    ),
    "leave_structural_out_loss": (
        "full",
        "full_without_structural",
    ),
    "leave_semantic_out_loss": (
        "full",
        "full_without_semantic",
    ),
}


def cluster_ci(values, seed, n_boot=BOOTSTRAPS):
    rng = random.Random(seed)
    n = len(values)
    draws = sorted(
        statistics.mean(
            values[rng.randrange(n)] for _ in range(n)
        )
        for _ in range(n_boot)
    )
    return [
        draws[int(0.025 * (n_boot - 1))],
        draws[int(0.975 * (n_boot - 1))],
    ]


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(
                f"Duplicate {filename} for seed {seed}"
            )
        out[seed] = doc
    return out


def evaluate_seed(labels: dict, alarms: dict, provenance: dict):
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Ablation artifact seed mismatch")
    if (
        not provenance["all_native_scp_upstream_http_200"]
        or provenance["min_native_nssf_profiles_seen_upstream"] < 2
        or provenance["native_open5gs_scp_binary_modified"]
        or provenance["stage18_fixed_sparse_schedule_reused"]
    ):
        raise AssertionError(
            f"Ablation provenance failed for seed {seed}"
        )

    episodes = labels["episodes"]
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    primary = [
        e for e in episodes if not e.get("boundary", False)
    ]
    boundary = [
        e for e in episodes if e.get("boundary", False)
    ]
    episode_ticks = {
        tick
        for e in episodes
        for tick in range(
            int(e["start_tick"]), int(e["end_tick"])
        )
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks

    rows = {
        int(row["tick"]): row
        for row in alarms["ticks"]
    }
    if set(rows) != set(range(total)):
        raise AssertionError(
            f"Incomplete ablation alarm stream seed={seed}"
        )

    variants = {}
    for variant in VARIANTS:
        alert_ticks = {
            tick for tick, row in rows.items()
            if bool(row[variant])
        }
        event_rows = []
        for event_id, episode in enumerate(primary):
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(
                t for t in alert_ticks if start <= t < end
            )
            event_rows.append(
                {
                    "event_id": event_id,
                    "kind": episode["kind"],
                    "detected": bool(inside),
                    "delay_ticks": (
                        inside[0] - start
                        if inside else end - start
                    ),
                }
            )

        boundary_rows = []
        for episode in boundary:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = [
                t for t in alert_ticks if start <= t < end
            ]
            boundary_rows.append(
                {
                    "kind": episode["kind"],
                    "detected": bool(inside),
                }
            )

        kinds = sorted({e["kind"] for e in event_rows})
        per_kind = {
            kind: {
                "event_recall": statistics.mean(
                    e["detected"]
                    for e in event_rows
                    if e["kind"] == kind
                ),
                "mean_horizon_penalized_delay_ticks": statistics.mean(
                    e["delay_ticks"]
                    for e in event_rows
                    if e["kind"] == kind
                ),
            }
            for kind in kinds
        }
        boundary_kinds = sorted(
            {e["kind"] for e in boundary_rows}
        )
        boundary_recall = {
            kind: statistics.mean(
                e["detected"]
                for e in boundary_rows
                if e["kind"] == kind
            )
            for kind in boundary_kinds
        }

        false_alarms = len(alert_ticks & clean_ticks)
        variants[variant] = {
            "event_recall": statistics.mean(
                e["detected"] for e in event_rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                e["delay_ticks"] for e in event_rows
            ),
            "false_alarms": false_alarms,
            "clean_ticks": len(clean_ticks),
            "false_alarms_per_1000": (
                1000 * false_alarms / max(1, len(clean_ticks))
            ),
            "per_kind": per_kind,
            "boundary_recall": boundary_recall,
            "events": event_rows,
        }

    return {
        "seed": seed,
        "structural_enabled": alarms["calibration"][
            "structural_channel_enabled"
        ],
        "semantic_enabled": alarms["calibration"][
            "semantic_channel_enabled"
        ],
        "semantic_selected_path_count": alarms["calibration"][
            "semantic_selected_path_count"
        ],
        "variants": variants,
    }


def paired_effect(rows, challenger, comparator, seed_base):
    recall = [
        row["variants"][challenger]["event_recall"]
        - row["variants"][comparator]["event_recall"]
        for row in rows
    ]
    delay = [
        row["variants"][challenger][
            "mean_horizon_penalized_delay_ticks"
        ]
        - row["variants"][comparator][
            "mean_horizon_penalized_delay_ticks"
        ]
        for row in rows
    ]
    fa = [
        row["variants"][challenger]["false_alarms_per_1000"]
        - row["variants"][comparator]["false_alarms_per_1000"]
        for row in rows
    ]

    rescued = 0
    lost = 0
    total_events = 0
    per_kind_rescued = {}
    for row in rows:
        a = row["variants"][challenger]["events"]
        b = row["variants"][comparator]["events"]
        if len(a) != len(b):
            raise AssertionError("Paired event count mismatch")
        for ae, be in zip(a, b):
            if ae["event_id"] != be["event_id"] or ae["kind"] != be["kind"]:
                raise AssertionError("Paired event identity mismatch")
            total_events += 1
            if ae["detected"] and not be["detected"]:
                rescued += 1
                per_kind_rescued[ae["kind"]] = (
                    per_kind_rescued.get(ae["kind"], 0) + 1
                )
            if be["detected"] and not ae["detected"]:
                lost += 1

    return {
        "challenger": challenger,
        "comparator": comparator,
        "recall_difference": statistics.mean(recall),
        "recall_difference_ci95": cluster_ci(
            recall, seed_base
        ),
        "delay_difference_ticks": statistics.mean(delay),
        "delay_difference_ci95_ticks": cluster_ci(
            delay, seed_base + 1
        ),
        "false_alarm_difference_per_1000": statistics.mean(fa),
        "false_alarm_difference_ci95_per_1000": cluster_ci(
            fa, seed_base + 2
        ),
        "rescued_events": rescued,
        "lost_events": lost,
        "total_primary_events": total_events,
        "rescued_events_per_kind": per_kind_rescued,
    }


def summarize(rows):
    kinds = sorted(
        rows[0]["variants"]["full"]["per_kind"]
    )
    boundary_kinds = sorted(
        rows[0]["variants"]["full"]["boundary_recall"]
    )
    summary = {
        "independent_runners": len(rows),
        "seeds": [r["seed"] for r in rows],
        "total_primary_events": (
            len(rows)
            * len(rows[0]["variants"]["full"]["events"])
        ),
        "structural_enabled_fraction": statistics.mean(
            r["structural_enabled"] for r in rows
        ),
        "semantic_enabled_fraction": statistics.mean(
            r["semantic_enabled"] for r in rows
        ),
        "mean_semantic_selected_path_count": statistics.mean(
            r["semantic_selected_path_count"] for r in rows
        ),
        "variants": {},
        "effects": {},
    }

    for variant in VARIANTS:
        total_fa = sum(
            r["variants"][variant]["false_alarms"]
            for r in rows
        )
        total_clean = sum(
            r["variants"][variant]["clean_ticks"]
            for r in rows
        )
        summary["variants"][variant] = {
            "event_recall": statistics.mean(
                r["variants"][variant]["event_recall"]
                for r in rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                r["variants"][variant][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for r in rows
            ),
            "false_alarms_total": total_fa,
            "clean_ticks_total": total_clean,
            "false_alarms_per_1000": (
                1000 * total_fa / max(1, total_clean)
            ),
            "per_kind": {
                kind: {
                    "event_recall": statistics.mean(
                        r["variants"][variant]["per_kind"][
                            kind
                        ]["event_recall"]
                        for r in rows
                    ),
                    "mean_horizon_penalized_delay_ticks": statistics.mean(
                        r["variants"][variant]["per_kind"][
                            kind
                        ][
                            "mean_horizon_penalized_delay_ticks"
                        ]
                        for r in rows
                    ),
                }
                for kind in kinds
            },
            "boundary_recall": {
                kind: statistics.mean(
                    r["variants"][variant]["boundary_recall"][
                        kind
                    ]
                    for r in rows
                )
                for kind in boundary_kinds
            },
        }

    for index, (name, pair) in enumerate(COMPARISONS.items()):
        summary["effects"][name] = paired_effect(
            rows, pair[0], pair[1], 41000 + index * 10
        )
    return summary


def markdown(s):
    lines = [
        "# Stage 21 — unified frozen ablation on new Open5GS block",
        "",
        (
            f"Independent runners: **{s['independent_runners']}**, "
            f"seeds **{s['seeds'][0]}..{s['seeds'][-1]}**; "
            f"primary episodes: **{s['total_primary_events']}**."
        ),
        (
            "All components were frozen before capture. Every ablation "
            "variant is evaluated on exactly the same episodes within each runner."
        ),
        (
            f"Structural channel enabled: "
            f"**{s['structural_enabled_fraction']:.3f}**; "
            f"semantic channel enabled: "
            f"**{s['semantic_enabled_fraction']:.3f}**; "
            f"mean selected semantic paths: "
            f"**{s['mean_semantic_selected_path_count']:.2f}**."
        ),
        "",
        "| Variant | Recall | Penalized delay | FA total | Clean ticks | FA/1000 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    order = [
        "directional_only",
        "directional_plus_sparse",
        "structural_only",
        "semantic_only",
        "directional_plus_structural",
        "full_without_semantic",
        "full_without_structural",
        "full_without_sparse",
        "full",
    ]
    for key in order:
        v = s["variants"][key]
        lines.append(
            f"| {LABELS[key]} | {v['event_recall']:.3f} | "
            f"{v['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{v['false_alarms_total']} | "
            f"{v['clean_ticks_total']} | "
            f"{v['false_alarms_per_1000']:.4f} |"
        )

    lines += [
        "",
        "## Paired component effects",
        "",
        "| Effect | Recall delta | 95% CI | Delay delta | 95% CI | Rescued | Lost |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    effect_labels = {
        "sparse_increment_over_directional": (
            "Add sparse memory to directional"
        ),
        "structural_increment_over_directional": (
            "Add structural to directional"
        ),
        "structural_increment_over_stage19": (
            "Add structural to directional+sparse"
        ),
        "semantic_increment_over_stage20": (
            "Add semantic to Stage 20"
        ),
        "leave_sparse_out_loss": (
            "Full vs full without sparse"
        ),
        "leave_structural_out_loss": (
            "Full vs full without structural"
        ),
        "leave_semantic_out_loss": (
            "Full vs full without semantic"
        ),
    }
    for name in COMPARISONS:
        e = s["effects"][name]
        lines.append(
            f"| {effect_labels[name]} | "
            f"{e['recall_difference']:+.3f} | "
            f"[{e['recall_difference_ci95'][0]:+.3f}, "
            f"{e['recall_difference_ci95'][1]:+.3f}] | "
            f"{e['delay_difference_ticks']:+.2f} | "
            f"[{e['delay_difference_ci95_ticks'][0]:+.2f}, "
            f"{e['delay_difference_ci95_ticks'][1]:+.2f}] | "
            f"{e['rescued_events']} | {e['lost_events']} |"
        )

    lines += [
        "",
        "## Per-family recall",
        "",
        "| Family | Directional | + sparse | Structural | Semantic | "
        "Stage20 | Full Stage21 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for kind in sorted(
        s["variants"]["full"]["per_kind"]
    ):
        lines.append(
            f"| {kind} | "
            f"{s['variants']['directional_only']['per_kind'][kind]['event_recall']:.3f} | "
            f"{s['variants']['directional_plus_sparse']['per_kind'][kind]['event_recall']:.3f} | "
            f"{s['variants']['structural_only']['per_kind'][kind]['event_recall']:.3f} | "
            f"{s['variants']['semantic_only']['per_kind'][kind]['event_recall']:.3f} | "
            f"{s['variants']['full_without_semantic']['per_kind'][kind]['event_recall']:.3f} | "
            f"{s['variants']['full']['per_kind'][kind]['event_recall']:.3f} |"
        )

    lines += [
        "",
        "## Leave-one-channel-out interpretation",
        "",
    ]
    for name in (
        "leave_sparse_out_loss",
        "leave_structural_out_loss",
        "leave_semantic_out_loss",
    ):
        e = s["effects"][name]
        lines.append(
            f"- **{effect_labels[name]}**: recall advantage "
            f"{e['recall_difference']:+.3f}; "
            f"{e['rescued_events']} primary events recovered by the full system."
        )

    lines += [
        "",
        "## Predeclared relational boundary",
        "",
    ]
    for kind, value in s["variants"]["full"][
        "boundary_recall"
    ].items():
        lines.append(
            f"- {kind}: full Stage21 recall **{value:.3f}**."
        )
    lines += [
        "",
        "Seeds 8701..8764 are evaluation-only after this audit and "
        "must not be used for detector retuning.",
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--output", default="stage21_ablation_report"
    )
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "ablation_alarms.json")
    provenance = load_by_seed(root, "provenance.json")
    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
        or set(provenance) != expected
    ):
        raise AssertionError(
            "Ablation requires all 64 preregistered runners"
        )

    rows = [
        evaluate_seed(
            labels[seed], alarms[seed], provenance[seed]
        )
        for seed in EXPECTED_SEEDS
    ]
    summary = summarize(rows)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf8"
    )
    md = markdown(summary)
    (output / "REPORT.md").write_text(md, encoding="utf8")
    print(md)


if __name__ == "__main__":
    main()
