"""Stage 18 blind live Open5GS/SCP audit.

This is the only Stage-18 component that joins private labels with detector
alarms. It runs after the blind detector jobs have completed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8101, 8107))
METHODS = (
    "page_hinkley",
    "directional_e_process",
)


def paired_ci(values, *, seed=18018, n_boot=5000):
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


def _load_by_seed(root: Path, filename: str) -> dict[int, dict]:
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


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage18 seed mismatch across artifacts")

    if (
        provenance["native_scp_upstream_calls"] <= 0
        or not provenance["all_native_scp_upstream_http_200"]
        or provenance[
            "min_native_nssf_profiles_seen_upstream"
        ] < 2
        or provenance["native_open5gs_scp_binary_modified"]
    ):
        raise AssertionError(
            "Stage18 provenance does not prove genuine unmodified SCP route"
        )

    episodes = labels["episodes"]
    attack_ticks = {
        tick
        for episode in episodes
        for tick in range(
            episode["start_tick"],
            episode["end_tick"],
        )
    }
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])

    tick_rows = {
        int(row["tick"]): row
        for row in alarms["ticks"]
    }
    if set(tick_rows) != set(range(total)):
        raise AssertionError("Stage18 alarm stream is incomplete")

    per_method = {}
    for method in METHODS:
        key = (
            "directional_alert"
            if method == "directional_e_process"
            else "page_hinkley_alert"
        )
        alert_ticks = {
            tick
            for tick, row in tick_rows.items()
            if row[key]
        }

        clean_ticks = set(range(warmup, total)) - attack_ticks
        false_alarms = len(alert_ticks & clean_ticks)

        event_rows = []
        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(
                tick
                for tick in alert_ticks
                if start <= tick < end
            )
            detected = bool(inside)
            duration = end - start
            delay = (
                inside[0] - start
                if detected
                else duration
            )
            event_rows.append(
                {
                    "episode": episode["episode"],
                    "kind": episode["kind"],
                    "direction": episode["direction"],
                    "detected": detected,
                    "delay_ticks": delay,
                    "duration_ticks": duration,
                    "mutation_ticks": len(
                        episode["mutation_ticks"]
                    ),
                }
            )

        per_kind = {}
        kinds = sorted(
            {row["kind"] for row in event_rows}
        )
        for kind in kinds:
            selected = [
                row
                for row in event_rows
                if row["kind"] == kind
            ]
            per_kind[kind] = {
                "events": len(selected),
                "event_recall": statistics.mean(
                    row["detected"] for row in selected
                ),
                "mean_horizon_penalized_delay_ticks": (
                    statistics.mean(
                        row["delay_ticks"]
                        for row in selected
                    )
                ),
            }

        per_method[method] = {
            "events": len(event_rows),
            "event_recall": statistics.mean(
                row["detected"] for row in event_rows
            ),
            "mean_horizon_penalized_delay_ticks": (
                statistics.mean(
                    row["delay_ticks"]
                    for row in event_rows
                )
            ),
            "false_alarms": false_alarms,
            "clean_monitor_ticks": len(clean_ticks),
            "false_alarms_per_1000_clean_ticks": (
                1000 * false_alarms / max(1, len(clean_ticks))
            ),
            "per_kind": per_kind,
        }

    return {
        "seed": seed,
        "native_scp_upstream_calls": provenance[
            "native_scp_upstream_calls"
        ],
        "methods": per_method,
    }


def summarize(seed_rows: list[dict]) -> dict:
    result = {
        "independent_live_runners": len(seed_rows),
        "seeds": [row["seed"] for row in seed_rows],
        "methods": {},
    }

    all_kinds = sorted(
        seed_rows[0]["methods"][
            "directional_e_process"
        ]["per_kind"]
    )

    for method in METHODS:
        result["methods"][method] = {
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
                    ),
                    "mean_horizon_penalized_delay_ticks": (
                        statistics.mean(
                            row["methods"][method]["per_kind"][
                                kind
                            ][
                                "mean_horizon_penalized_delay_ticks"
                            ]
                            for row in seed_rows
                        )
                    ),
                }
                for kind in all_kinds
            },
        }

    directional = "directional_e_process"
    page = "page_hinkley"

    recall_diff = [
        row["methods"][directional]["event_recall"]
        - row["methods"][page]["event_recall"]
        for row in seed_rows
    ]
    delay_diff = [
        row["methods"][directional][
            "mean_horizon_penalized_delay_ticks"
        ]
        - row["methods"][page][
            "mean_horizon_penalized_delay_ticks"
        ]
        for row in seed_rows
    ]
    false_diff = [
        row["methods"][directional][
            "false_alarms_per_1000_clean_ticks"
        ]
        - row["methods"][page][
            "false_alarms_per_1000_clean_ticks"
        ]
        for row in seed_rows
    ]

    result["paired_seed_effect_directional_minus_page_hinkley"] = {
        "event_recall_difference": statistics.mean(
            recall_diff
        ),
        "event_recall_difference_ci95": paired_ci(
            recall_diff, seed=18019
        ),
        "delay_difference_ticks": statistics.mean(
            delay_diff
        ),
        "delay_difference_ci95_ticks": paired_ci(
            delay_diff, seed=18020
        ),
        "false_alarm_difference_per_1000": statistics.mean(
            false_diff
        ),
        "false_alarm_difference_ci95_per_1000": paired_ci(
            false_diff, seed=18021
        ),
    }
    return result


def markdown(summary: dict) -> str:
    page = summary["methods"]["page_hinkley"]
    directional = summary["methods"][
        "directional_e_process"
    ]
    effect = summary[
        "paired_seed_effect_directional_minus_page_hinkley"
    ]

    lines = [
        "# Stage 18 — blind native Open5GS SCP live validation",
        "",
        (
            f"Independent hosted Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            "Every consumer transaction traversed a genuine unmodified "
            "Open5GS v2.7.6 SCP to the genuine NRF before the research "
            "post-SCP gateway could alter the consumer-facing copy."
        ),
        (
            "Detector jobs received only telemetry artifacts; private fault "
            "labels were uploaded separately and joined only by this audit."
        ),
        "",
        "| Detector | Event recall | Horizon-penalized delay (ticks) | "
        "False alarms / 1000 clean ticks |",
        "|---|---:|---:|---:|",
        (
            "| Page-Hinkley (Stage17 frozen) | "
            f"{page['event_recall']:.3f} | "
            f"{page['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{page['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        (
            "| Directional e-process (Stage17 frozen) | "
            f"{directional['event_recall']:.3f} | "
            f"{directional['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{directional['false_alarms_per_1000_clean_ticks']:.3f} |"
        ),
        "",
        "## Paired runner-level effect: directional minus Page-Hinkley",
        "",
        (
            f"- Event recall: **{effect['event_recall_difference']:+.3f}**, "
            "95% runner-cluster bootstrap CI "
            f"[{effect['event_recall_difference_ci95'][0]:+.3f}, "
            f"{effect['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        (
            f"- Horizon-penalized delay: "
            f"**{effect['delay_difference_ticks']:+.2f} ticks**, "
            "95% CI "
            f"[{effect['delay_difference_ci95_ticks'][0]:+.2f}, "
            f"{effect['delay_difference_ci95_ticks'][1]:+.2f}]."
        ),
        (
            f"- False alarms / 1000 clean ticks: "
            f"**{effect['false_alarm_difference_per_1000']:+.3f}**, "
            "95% CI "
            f"[{effect['false_alarm_difference_ci95_per_1000'][0]:+.3f}, "
            f"{effect['false_alarm_difference_ci95_per_1000'][1]:+.3f}]."
        ),
        "",
        "## Per-fault-family recall",
        "",
        "| Family | Page-Hinkley | Directional e-process |",
        "|---|---:|---:|",
    ]

    for kind in sorted(page["per_kind"]):
        lines.append(
            f"| {kind} | "
            f"{page['per_kind'][kind]['event_recall']:.3f} | "
            f"{directional['per_kind'][kind]['event_recall']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Scope",
            "",
            (
                "This validates the frozen sequential integrity mechanism on "
                "real HTTP/2 traffic through native Open5GS SCP/NRF. The "
                "fault is still injected by research code after the native "
                "SCP, so this is not evidence of a compromised Open5GS SCP "
                "binary, production mTLS behavior, or native NF attestation."
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
        default="stage18_report",
    )
    args = parser.parse_args()

    root = Path(args.input)
    labels = _load_by_seed(root, "private_labels.json")
    alarms = _load_by_seed(root, "alarms.json")
    provenance = _load_by_seed(root, "provenance.json")

    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
        or set(provenance) != expected
    ):
        raise AssertionError(
            "Stage18 requires all six preregistered independent runners"
        )

    seed_rows = [
        evaluate_seed(
            labels[seed],
            alarms[seed],
            provenance[seed],
        )
        for seed in EXPECTED_SEEDS
    ]
    summary = summarize(seed_rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(seed_rows, indent=2),
        encoding="utf8",
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(
        report,
        encoding="utf8",
    )
    print(report)


if __name__ == "__main__":
    main()
