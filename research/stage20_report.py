"""Stage 20 blind live structural-integrity audit."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8301, 8307))
METHOD_KEYS = {
    "page_hinkley": "page_hinkley_alert",
    "stage17_directional": "stage17_directional_alert",
    "stage19_sparse_directional": (
        "stage19_sparse_directional_alert"
    ),
    "stage20_combined": "stage20_combined_alert",
}


def paired_ci(values, *, seed, n_boot=5000):
    rng = random.Random(seed)
    n = len(values)
    draws = sorted(
        statistics.mean(
            values[rng.randrange(n)]
            for _ in range(n)
        )
        for _ in range(n_boot)
    )
    return [
        draws[int(0.025 * (n_boot - 1))],
        draws[int(0.975 * (n_boot - 1))],
    ]


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    output = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in output:
            raise AssertionError(
                f"Duplicate {filename} for seed {seed}"
            )
        output[seed] = doc
    return output


def evaluate_seed(labels: dict, alarms: dict, provenance: dict):
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage20 artifact seed mismatch")

    if (
        not provenance["all_native_scp_upstream_http_200"]
        or provenance[
            "min_native_nssf_profiles_seen_upstream"
        ] < 2
        or provenance["native_open5gs_scp_binary_modified"]
    ):
        raise AssertionError(
            "Stage20 provenance does not prove native SCP route"
        )

    episodes = labels["episodes"]
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    attack_ticks = {
        tick
        for episode in episodes
        for tick in range(
            episode["start_tick"],
            episode["end_tick"],
        )
    }
    clean_ticks = set(range(warmup, total)) - attack_ticks

    tick_rows = {
        int(row["tick"]): row
        for row in alarms["ticks"]
    }
    if set(tick_rows) != set(range(total)):
        raise AssertionError("Incomplete Stage20 alarm stream")

    methods = {}
    for method, key in METHOD_KEYS.items():
        alert_ticks = {
            tick
            for tick, row in tick_rows.items()
            if row[key]
        }
        false_alarms = len(alert_ticks & clean_ticks)
        events = []

        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(
                tick
                for tick in alert_ticks
                if start <= tick < end
            )
            detected = bool(inside)
            delay = (
                inside[0] - start
                if detected
                else end - start
            )
            events.append(
                {
                    "kind": episode["kind"],
                    "detected": detected,
                    "delay_ticks": delay,
                }
            )

        per_kind = {}
        for kind in sorted({item["kind"] for item in events}):
            selected = [
                item
                for item in events
                if item["kind"] == kind
            ]
            per_kind[kind] = {
                "event_recall": statistics.mean(
                    item["detected"]
                    for item in selected
                ),
                "mean_horizon_penalized_delay_ticks": (
                    statistics.mean(
                        item["delay_ticks"]
                        for item in selected
                    )
                ),
            }

        methods[method] = {
            "event_recall": statistics.mean(
                item["detected"] for item in events
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                item["delay_ticks"] for item in events
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * false_alarms / max(1, len(clean_ticks))
            ),
            "per_kind": per_kind,
        }

    return {
        "seed": seed,
        "structural_channel_enabled": alarms[
            "calibration"
        ]["structural_channel_enabled"],
        "structural_exact_fraction": alarms[
            "calibration"
        ]["structural_exact_fraction"],
        "methods": methods,
    }


def summarize(seed_rows):
    summary = {
        "independent_live_runners": len(seed_rows),
        "seeds": [row["seed"] for row in seed_rows],
        "structural_channel_enabled_fraction": statistics.mean(
            row["structural_channel_enabled"]
            for row in seed_rows
        ),
        "mean_structural_warmup_exact_fraction": statistics.mean(
            row["structural_exact_fraction"]
            for row in seed_rows
        ),
        "methods": {},
    }

    kinds = sorted(
        seed_rows[0]["methods"]["stage20_combined"][
            "per_kind"
        ]
    )
    for method in METHOD_KEYS:
        summary["methods"][method] = {
            "event_recall": statistics.mean(
                row["methods"][method]["event_recall"]
                for row in seed_rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["methods"][method][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in seed_rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["methods"][method][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in seed_rows
            ),
            "per_kind": {
                kind: {
                    "event_recall": statistics.mean(
                        row["methods"][method]["per_kind"][
                            kind
                        ]["event_recall"]
                        for row in seed_rows
                    )
                }
                for kind in kinds
            },
        }

    def effect(challenger, comparator, seed_base):
        recall = [
            row["methods"][challenger]["event_recall"]
            - row["methods"][comparator]["event_recall"]
            for row in seed_rows
        ]
        delay = [
            row["methods"][challenger][
                "mean_horizon_penalized_delay_ticks"
            ]
            - row["methods"][comparator][
                "mean_horizon_penalized_delay_ticks"
            ]
            for row in seed_rows
        ]
        fa = [
            row["methods"][challenger][
                "false_alarms_per_1000_clean_ticks"
            ]
            - row["methods"][comparator][
                "false_alarms_per_1000_clean_ticks"
            ]
            for row in seed_rows
        ]
        return {
            "event_recall_difference": statistics.mean(recall),
            "event_recall_difference_ci95": paired_ci(
                recall, seed=seed_base
            ),
            "delay_difference_ticks": statistics.mean(delay),
            "delay_difference_ci95_ticks": paired_ci(
                delay, seed=seed_base + 1
            ),
            "false_alarm_difference_per_1000": statistics.mean(fa),
            "false_alarm_difference_ci95_per_1000": paired_ci(
                fa, seed=seed_base + 2
            ),
        }

    summary["stage20_minus_stage19"] = effect(
        "stage20_combined",
        "stage19_sparse_directional",
        20020,
    )
    summary["stage20_minus_page_hinkley"] = effect(
        "stage20_combined",
        "page_hinkley",
        20030,
    )
    return summary


def markdown(summary):
    methods = summary["methods"]
    ph = methods["page_hinkley"]
    s17 = methods["stage17_directional"]
    s19 = methods["stage19_sparse_directional"]
    s20 = methods["stage20_combined"]
    effect = summary["stage20_minus_stage19"]

    lines = [
        "# Stage 20 — blind structural-integrity live validation",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            f"Structural channel enabled on "
            f"**{summary['structural_channel_enabled_fraction']:.3f}** "
            "of runners from label-free warm-up agreement."
        ),
        "",
        "| Detector | Event recall | Penalized delay (ticks) | "
        "FA / 1000 clean ticks |",
        "|---|---:|---:|---:|",
        (
            f"| Page-Hinkley | {ph['event_recall']:.3f} | "
            f"{ph['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{ph['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            f"| Stage-17 directional | {s17['event_recall']:.3f} | "
            f"{s17['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{s17['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            f"| Stage-19 sparse directional | {s19['event_recall']:.3f} | "
            f"{s19['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{s19['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            f"| **Stage-20 combined structural** | "
            f"**{s20['event_recall']:.3f}** | "
            f"**{s20['mean_horizon_penalized_delay_ticks']:.2f}** | "
            f"{s20['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        "",
        "## Stage 20 minus Stage 19",
        "",
        (
            f"- Event recall: **{effect['event_recall_difference']:+.3f}**, "
            "95% runner-cluster bootstrap CI "
            f"[{effect['event_recall_difference_ci95'][0]:+.3f}, "
            f"{effect['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        (
            f"- Penalized delay: **{effect['delay_difference_ticks']:+.2f} ticks**, "
            "95% CI "
            f"[{effect['delay_difference_ci95_ticks'][0]:+.2f}, "
            f"{effect['delay_difference_ci95_ticks'][1]:+.2f}]."
        ),
        (
            f"- False alarms / 1000: "
            f"**{effect['false_alarm_difference_per_1000']:+.3f}**, "
            "95% CI "
            f"[{effect['false_alarm_difference_ci95_per_1000'][0]:+.3f}, "
            f"{effect['false_alarm_difference_ci95_per_1000'][1]:+.3f}]."
        ),
        "",
        "## Per-family recall",
        "",
        "| Family | Page-Hinkley | Stage-17 | Stage-19 | Stage-20 |",
        "|---|---:|---:|---:|---:|",
    ]
    for kind in sorted(s20["per_kind"]):
        lines.append(
            f"| {kind} | "
            f"{ph['per_kind'][kind]['event_recall']:.3f} | "
            f"{s17['per_kind'][kind]['event_recall']:.3f} | "
            f"{s19['per_kind'][kind]['event_recall']:.3f} | "
            f"{s20['per_kind'][kind]['event_recall']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Scope",
            "",
            (
                "The structural fingerprint stores JSON path/type tokens and "
                "multiplicities only; scalar values are excluded. All Stage-20 "
                "parameters were frozen before seeds 8301..8306 were captured, "
                "and previous live artifacts were not used for tuning."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--output",
        default="stage20_report",
    )
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    provenance = load_by_seed(root, "provenance.json")
    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
        or set(provenance) != expected
    ):
        raise AssertionError(
            "Stage20 requires all six preregistered live runners"
        )

    rows = [
        evaluate_seed(
            labels[seed],
            alarms[seed],
            provenance[seed],
        )
        for seed in EXPECTED_SEEDS
    ]
    summary = summarize(rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2),
        encoding="utf8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    print(report)


if __name__ == "__main__":
    main()
