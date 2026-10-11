"""Stage-19 untouched synthetic final evaluation.

This module is deliberately parameter-free.  It evaluates the frozen Stage-19
Tri-Path ensemble and two development-tuned comparators on exactly seeds
10001..10200.

A miss receives the full episode length as horizon-penalized delay.  This is a
penalty metric, not survival-analysis censoring.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics

from .stage19_develop import clean_tick_set
from .stage19_frozen import (
    FINAL_SEEDS,
    FINAL_START_SEED,
    TriPathDirectionalEvidenceEnsemble,
    frozen_page_hinkley_detector,
    frozen_single_detector,
)
from .stage19_simulation import (
    ALL_KINDS,
    PERSISTENT_KINDS,
    SPARSE_KINDS,
    WARMUP_TICKS,
    SparseIntegrityWorld,
)

METHODS = (
    "tri_path_directional",
    "single_scale_directional",
    "page_hinkley",
)


def paired_ci(
    values: list[float],
    *,
    seed: int,
    n_boot: int = 5000,
) -> list[float]:
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


def run_detector(world: SparseIntegrityWorld, method: str) -> dict:
    calibration = world.values[:WARMUP_TICKS]
    if method == "tri_path_directional":
        detector = TriPathDirectionalEvidenceEnsemble(
            calibration
        )
    elif method == "single_scale_directional":
        detector = frozen_single_detector(calibration)
    elif method == "page_hinkley":
        detector = frozen_page_hinkley_detector(
            calibration
        )
    else:
        raise ValueError(method)

    alerts = set()
    channel_alarm_counts = {
        "sparse": 0,
        "single": 0,
        "consecutive": 0,
    }
    for tick in range(WARMUP_TICKS, world.total_ticks):
        alarm, state = detector.observe(
            world.values[tick]
        )
        if alarm:
            alerts.add(tick)
        if method == "tri_path_directional":
            channel_alarm_counts["sparse"] += int(
                state["sparse_alarm"]
            )
            channel_alarm_counts["single"] += int(
                state["single_alarm"]
            )
            channel_alarm_counts["consecutive"] += int(
                state["consecutive_alarm"]
            )

    clean = clean_tick_set(world)
    false_alarms = len(alerts & clean)

    events = []
    for episode in world.episodes:
        inside = sorted(
            tick
            for tick in alerts
            if episode.start_tick <= tick < episode.end_tick
        )
        detected = bool(inside)
        duration = episode.end_tick - episode.start_tick
        delay = (
            inside[0] - episode.start_tick
            if detected
            else duration
        )
        events.append(
            {
                "episode": episode.episode,
                "kind": episode.kind,
                "sparse": episode.sparse,
                "detected": detected,
                "delay_ticks": delay,
            }
        )

    sparse_events = [
        event for event in events if event["sparse"]
    ]
    persistent_events = [
        event for event in events if not event["sparse"]
    ]

    per_kind = {}
    for kind in ALL_KINDS:
        selected = [
            event for event in events if event["kind"] == kind
        ]
        per_kind[kind] = {
            "event_recall": statistics.mean(
                event["detected"] for event in selected
            ),
            "mean_horizon_penalized_delay_ticks": (
                statistics.mean(
                    event["delay_ticks"]
                    for event in selected
                )
            ),
        }

    return {
        "seed": world.seed,
        "method": method,
        "event_recall": statistics.mean(
            event["detected"] for event in events
        ),
        "sparse_event_recall": statistics.mean(
            event["detected"] for event in sparse_events
        ),
        "persistent_event_recall": statistics.mean(
            event["detected"]
            for event in persistent_events
        ),
        "horizon_penalized_delay_ticks": statistics.mean(
            event["delay_ticks"] for event in events
        ),
        "sparse_horizon_penalized_delay_ticks": (
            statistics.mean(
                event["delay_ticks"]
                for event in sparse_events
            )
        ),
        "persistent_horizon_penalized_delay_ticks": (
            statistics.mean(
                event["delay_ticks"]
                for event in persistent_events
            )
        ),
        "false_alarms": false_alarms,
        "clean_monitor_ticks": len(clean),
        "false_alarms_per_1000_clean_ticks": (
            1000 * false_alarms / max(1, len(clean))
        ),
        "channel_alarm_counts": channel_alarm_counts,
        "per_kind": per_kind,
    }


def run(seeds) -> list[dict]:
    rows = []
    for seed in seeds:
        world = SparseIntegrityWorld(seed)
        for method in METHODS:
            rows.append(run_detector(world, method))
    return rows


def summarize_method(rows: list[dict]) -> dict:
    numeric = (
        "event_recall",
        "sparse_event_recall",
        "persistent_event_recall",
        "horizon_penalized_delay_ticks",
        "sparse_horizon_penalized_delay_ticks",
        "persistent_horizon_penalized_delay_ticks",
        "false_alarms_per_1000_clean_ticks",
    )
    result = {
        key: statistics.mean(row[key] for row in rows)
        for key in numeric
    }
    result["per_kind"] = {
        kind: {
            "event_recall": statistics.mean(
                row["per_kind"][kind]["event_recall"]
                for row in rows
            ),
            "mean_horizon_penalized_delay_ticks": (
                statistics.mean(
                    row["per_kind"][kind][
                        "mean_horizon_penalized_delay_ticks"
                    ]
                    for row in rows
                )
            ),
        }
        for kind in ALL_KINDS
    }
    if rows[0]["method"] == "tri_path_directional":
        result["mean_channel_alarms_per_world"] = {
            channel: statistics.mean(
                row["channel_alarm_counts"][channel]
                for row in rows
            )
            for channel in ("sparse", "single", "consecutive")
        }
    return result


def paired_effect(
    rows: list[dict],
    comparator: str,
    *,
    seed_offset: int,
) -> dict:
    tri = {
        row["seed"]: row
        for row in rows
        if row["method"] == "tri_path_directional"
    }
    base = {
        row["seed"]: row
        for row in rows
        if row["method"] == comparator
    }
    common = sorted(set(tri) & set(base))
    keys = (
        "event_recall",
        "sparse_event_recall",
        "persistent_event_recall",
        "horizon_penalized_delay_ticks",
        "sparse_horizon_penalized_delay_ticks",
        "false_alarms_per_1000_clean_ticks",
    )
    result = {
        "comparator": comparator,
        "n_seeds": len(common),
    }
    for index, key in enumerate(keys):
        values = [
            tri[seed][key] - base[seed][key]
            for seed in common
        ]
        result[f"{key}_difference"] = statistics.mean(
            values
        )
        result[f"{key}_difference_ci95"] = paired_ci(
            values,
            seed=19019 + seed_offset + index,
        )
    return result


def summarize(rows: list[dict]) -> dict:
    output = {
        "protocol": {
            "development_block": [9001, 9040],
            "historical_stage18_live_evaluation": [8101, 8106],
            "untouched_synthetic_final_block": [10001, 10200],
            "parameters_frozen_before_final": True,
            "false_alarm_ceiling_per_1000": 0.50,
            "development_persistent_recall_floor": 0.90,
        },
        "methods": {},
    }
    for method in METHODS:
        output["methods"][method] = summarize_method(
            [
                row
                for row in rows
                if row["method"] == method
            ]
        )
    output["paired_effects"] = {
        "tri_minus_single": paired_effect(
            rows,
            "single_scale_directional",
            seed_offset=100,
        ),
        "tri_minus_page_hinkley": paired_effect(
            rows,
            "page_hinkley",
            seed_offset=200,
        ),
    }
    return output


def markdown(summary: dict) -> str:
    tri = summary["methods"]["tri_path_directional"]
    single = summary["methods"]["single_scale_directional"]
    page = summary["methods"]["page_hinkley"]
    effect = summary["paired_effects"]["tri_minus_single"]

    lines = [
        "# Stage 19 — untouched sparse-rich synthetic final",
        "",
        (
            "Final block: **200 previously unopened worlds, seeds "
            "10001..10200**.  All detector parameters were frozen from "
            "development seeds 9001..9040 before this run."
        ),
        "",
        "| Detector | Overall recall | Sparse recall | Persistent recall | "
        "Delay (ticks) | Sparse delay | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name, item in (
        ("Tri-Path directional", tri),
        ("Single-scale directional", single),
        ("Page-Hinkley", page),
    ):
        lines.append(
            f"| {name} | "
            f"{item['event_recall']:.3f} | "
            f"{item['sparse_event_recall']:.3f} | "
            f"{item['persistent_event_recall']:.3f} | "
            f"{item['horizon_penalized_delay_ticks']:.2f} | "
            f"{item['sparse_horizon_penalized_delay_ticks']:.2f} | "
            f"{item['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Primary paired effect: Tri-Path minus tuned single-scale",
            "",
        ]
    )
    metric_labels = (
        ("event_recall", "Overall recall"),
        ("sparse_event_recall", "Sparse recall"),
        ("persistent_event_recall", "Persistent recall"),
        ("horizon_penalized_delay_ticks", "Horizon-penalized delay"),
        (
            "sparse_horizon_penalized_delay_ticks",
            "Sparse horizon-penalized delay",
        ),
        (
            "false_alarms_per_1000_clean_ticks",
            "False alarms / 1000 clean ticks",
        ),
    )
    for key, label in metric_labels:
        value = effect[f"{key}_difference"]
        ci = effect[f"{key}_difference_ci95"]
        suffix = " ticks" if "delay" in key else ""
        lines.append(
            f"- {label}: **{value:+.3f}{suffix}**, "
            f"95% paired seed-bootstrap CI "
            f"[{ci[0]:+.3f}, {ci[1]:+.3f}]{suffix}."
        )

    lines.extend(
        [
            "",
            "## Per-family recall",
            "",
            "| Family | Tri-Path | Single-scale | Page-Hinkley |",
            "|---|---:|---:|---:|",
        ]
    )
    for kind in ALL_KINDS:
        lines.append(
            f"| {kind} | "
            f"{tri['per_kind'][kind]['event_recall']:.3f} | "
            f"{single['per_kind'][kind]['event_recall']:.3f} | "
            f"{page['per_kind'][kind]['event_recall']:.3f} |"
        )

    lines.extend(
        [
            "",
            "## Guardrails",
            "",
            (
                "No threshold, channel, window or fallback selection is "
                "performed on seeds 10001..10200."
            ),
            (
                "False alarms are measured only outside labelled attack "
                "episode windows, matching the preregistered development "
                "metric.  Interior clean gaps of sparse episodes therefore "
                "do not count as clean-monitor false alarms."
            ),
            (
                "This final remains synthetic.  A fresh live Open5GS block "
                "is only justified if the frozen detector remains useful "
                "here without violating the false-alarm ceiling."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def flatten(row: dict) -> dict:
    return {
        key: value
        for key, value in row.items()
        if key not in ("per_kind", "channel_alarm_counts")
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--start-seed",
        type=int,
        default=FINAL_START_SEED,
    )
    parser.add_argument(
        "--seeds",
        type=int,
        default=FINAL_SEEDS,
    )
    parser.add_argument(
        "--output",
        default="stage19_final_results",
    )
    args = parser.parse_args()

    if (
        args.start_seed != FINAL_START_SEED
        or args.seeds != FINAL_SEEDS
    ):
        raise SystemExit(
            "Stage19 final protocol is frozen to seeds "
            "10001..10200 (200 worlds)"
        )

    rows = run(
        range(
            args.start_seed,
            args.start_seed + args.seeds,
        )
    )
    summary = summarize(rows)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "runs.json").write_text(
        json.dumps(rows, indent=2),
        encoding="utf8",
    )
    (root / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )

    flat = [flatten(row) for row in rows]
    with (root / "runs.csv").open(
        "w",
        newline="",
        encoding="utf8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(flat[0]),
        )
        writer.writeheader()
        writer.writerows(flat)

    report = markdown(summary)
    (root / "REPORT.md").write_text(
        report,
        encoding="utf8",
    )
    print(report)


if __name__ == "__main__":
    main()
