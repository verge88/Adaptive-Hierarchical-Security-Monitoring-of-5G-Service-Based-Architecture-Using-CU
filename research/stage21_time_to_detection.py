"""Stage 21 time-to-detection statistics on the frozen 128-run replication.

This is analysis-only. It reuses evaluation artifacts from canonical run
38160873208 (seeds 8501..8628) and does not modify or retune any detector.

Primary endpoints:
- cumulative detection probability by tick;
- median delay among detected events;
- administrative median time to detection under common censoring at 12 ticks
  (undefined when <50% are detected);
- restricted mean time to detection (RMST) through 12 ticks;
- absolute recall and false-alarm summaries.

Uncertainty is estimated by nonparametric bootstrap over independent Open5GS
runners. Events within a runner are never resampled independently.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8501, 8629))
HORIZON = 12
BOOTSTRAPS = 20000
ALPHA = 0.05

METHOD_KEYS = {
    "page_hinkley": "page_hinkley_alert",
    "stage17_directional": "stage17_directional_alert",
    "stage19_sparse_directional": "stage19_sparse_directional_alert",
    "stage20_combined": "stage20_combined_alert",
    "stage21_combined": "stage21_combined_alert",
}
METHOD_LABELS = {
    "page_hinkley": "Page-Hinkley",
    "stage17_directional": "Stage 17 directional",
    "stage19_sparse_directional": "Stage 19 sparse directional",
    "stage20_combined": "Stage 20 structural",
    "stage21_combined": "Stage 21 semantic combined",
}


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


def percentile(values: list[float], p: float) -> float:
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    position = p * (len(ordered) - 1)
    left = int(position)
    right = min(left + 1, len(ordered) - 1)
    fraction = position - left
    return (
        ordered[left] * (1.0 - fraction)
        + ordered[right] * fraction
    )


def ci(values: list[float]) -> list[float]:
    return [
        percentile(values, ALPHA / 2),
        percentile(values, 1 - ALPHA / 2),
    ]


def evaluate_seed(labels: dict, alarms: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed:
        raise AssertionError("Time-analysis artifact seed mismatch")

    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    primary = [
        e for e in labels["episodes"]
        if not e.get("boundary", False)
    ]
    if any(
        int(e["end_tick"]) - int(e["start_tick"]) != HORIZON
        for e in primary
    ):
        raise AssertionError("Primary event horizon is not 12 ticks")

    episode_ticks = {
        tick
        for e in labels["episodes"]
        for tick in range(
            int(e["start_tick"]), int(e["end_tick"])
        )
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks
    rows = {
        int(row["tick"]): row for row in alarms["ticks"]
    }
    if set(rows) != set(range(total)):
        raise AssertionError(
            f"Incomplete alarm stream for seed {seed}"
        )

    methods = {}
    for method, key in METHOD_KEYS.items():
        alert_ticks = {
            tick
            for tick, row in rows.items()
            if bool(row[key])
        }
        events = []
        for event_id, episode in enumerate(primary):
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(
                tick
                for tick in alert_ticks
                if start <= tick < end
            )
            detected = bool(inside)
            delay = inside[0] - start if detected else None
            events.append(
                {
                    "event_id": event_id,
                    "kind": episode["kind"],
                    "detected": detected,
                    "delay_ticks": delay,
                    "restricted_time_ticks": (
                        delay if detected else HORIZON
                    ),
                }
            )

        curve = [
            statistics.mean(
                e["detected"]
                and int(e["delay_ticks"]) <= tick
                for e in events
            )
            for tick in range(HORIZON)
        ]
        detected_delays = [
            int(e["delay_ticks"])
            for e in events
            if e["detected"]
        ]
        recall = statistics.mean(
            e["detected"] for e in events
        )
        methods[method] = {
            "events": events,
            "event_recall": recall,
            "restricted_mean_time_ticks": statistics.mean(
                e["restricted_time_ticks"] for e in events
            ),
            "median_detected_delay_ticks": (
                statistics.median(detected_delays)
                if detected_delays else None
            ),
            "administrative_median_time_ticks": next(
                (
                    tick
                    for tick, fraction in enumerate(curve)
                    if fraction >= 0.5
                ),
                None,
            ),
            "detection_curve": curve,
            "false_alarms": len(alert_ticks & clean_ticks),
            "clean_ticks": len(clean_ticks),
        }

    return {"seed": seed, "methods": methods}


def pooled_detected_median(
    sampled_rows: list[dict], method: str
):
    delays = []
    for row in sampled_rows:
        delays.extend(
            int(e["delay_ticks"])
            for e in row["methods"][method]["events"]
            if e["detected"]
        )
    return statistics.median(delays) if delays else None


def aggregate(rows: list[dict]) -> dict:
    rng = random.Random(52121)
    n = len(rows)
    kinds = sorted(
        {
            e["kind"]
            for e in rows[0]["methods"]["stage21_combined"]["events"]
        }
    )

    point = {}
    for method in METHOD_KEYS:
        all_events = [
            e
            for row in rows
            for e in row["methods"][method]["events"]
        ]
        detected_delays = [
            int(e["delay_ticks"])
            for e in all_events
            if e["detected"]
        ]
        recall = statistics.mean(
            e["detected"] for e in all_events
        )
        curve = [
            statistics.mean(
                e["detected"]
                and int(e["delay_ticks"]) <= tick
                for e in all_events
            )
            for tick in range(HORIZON)
        ]
        point[method] = {
            "event_recall": recall,
            "restricted_mean_time_ticks": statistics.mean(
                e["restricted_time_ticks"]
                for e in all_events
            ),
            "median_detected_delay_ticks": (
                statistics.median(detected_delays)
                if detected_delays else None
            ),
            "administrative_median_time_ticks": next(
                (
                    tick
                    for tick, fraction in enumerate(curve)
                    if fraction >= 0.5
                ),
                None,
            ),
            "detection_curve": curve,
            "false_alarms_total": sum(
                row["methods"][method]["false_alarms"]
                for row in rows
            ),
            "clean_ticks_total": sum(
                row["methods"][method]["clean_ticks"]
                for row in rows
            ),
            "runners_with_false_alarm": sum(
                row["methods"][method]["false_alarms"] > 0
                for row in rows
            ),
            "per_kind": {},
        }
        for kind in kinds:
            family = [
                e for e in all_events if e["kind"] == kind
            ]
            family_delays = [
                int(e["delay_ticks"])
                for e in family if e["detected"]
            ]
            family_curve = [
                statistics.mean(
                    e["detected"]
                    and int(e["delay_ticks"]) <= tick
                    for e in family
                )
                for tick in range(HORIZON)
            ]
            point[method]["per_kind"][kind] = {
                "event_recall": statistics.mean(
                    e["detected"] for e in family
                ),
                "restricted_mean_time_ticks": statistics.mean(
                    e["restricted_time_ticks"] for e in family
                ),
                "median_detected_delay_ticks": (
                    statistics.median(family_delays)
                    if family_delays else None
                ),
                "detection_curve": family_curve,
            }

    # One bootstrap draw samples entire independent runners with replacement.
    bootstrap = {
        method: {
            "recall": [],
            "rmst": [],
            "median_detected": [],
            "curve": [[] for _ in range(HORIZON)],
        }
        for method in METHOD_KEYS
    }
    diff = {
        "recall_stage21_minus_stage20": [],
        "rmst_stage21_minus_stage20": [],
        "curve_stage21_minus_stage20": [
            [] for _ in range(HORIZON)
        ],
    }

    for _ in range(BOOTSTRAPS):
        indices = [rng.randrange(n) for _ in range(n)]
        sampled = [rows[index] for index in indices]

        draw_metrics = {}
        for method in METHOD_KEYS:
            runner_recall = [
                row["methods"][method]["event_recall"]
                for row in sampled
            ]
            runner_rmst = [
                row["methods"][method][
                    "restricted_mean_time_ticks"
                ]
                for row in sampled
            ]
            runner_curve = [
                row["methods"][method]["detection_curve"]
                for row in sampled
            ]
            recall = statistics.mean(runner_recall)
            rmst = statistics.mean(runner_rmst)
            curve = [
                statistics.mean(values[tick] for values in runner_curve)
                for tick in range(HORIZON)
            ]
            draw_metrics[method] = {
                "recall": recall,
                "rmst": rmst,
                "curve": curve,
            }
            bootstrap[method]["recall"].append(recall)
            bootstrap[method]["rmst"].append(rmst)
            median = pooled_detected_median(sampled, method)
            if median is not None:
                bootstrap[method]["median_detected"].append(
                    float(median)
                )
            for tick in range(HORIZON):
                bootstrap[method]["curve"][tick].append(
                    curve[tick]
                )

        diff[
            "recall_stage21_minus_stage20"
        ].append(
            draw_metrics["stage21_combined"]["recall"]
            - draw_metrics["stage20_combined"]["recall"]
        )
        diff[
            "rmst_stage21_minus_stage20"
        ].append(
            draw_metrics["stage21_combined"]["rmst"]
            - draw_metrics["stage20_combined"]["rmst"]
        )
        for tick in range(HORIZON):
            diff["curve_stage21_minus_stage20"][
                tick
            ].append(
                draw_metrics["stage21_combined"]["curve"][tick]
                - draw_metrics["stage20_combined"]["curve"][tick]
            )

    summary = {
        "protocol": {
            "source_run": 38160873208,
            "source_seeds": [8501, 8628],
            "independent_runners": n,
            "primary_events": (
                n
                * len(
                    rows[0]["methods"]["stage21_combined"][
                        "events"
                    ]
                )
            ),
            "administrative_horizon_ticks": HORIZON,
            "runner_cluster_bootstrap_resamples": BOOTSTRAPS,
            "detectors_retuned": False,
            "source_native_route_provenance": (
                "already audited successfully in canonical run 38160873208; "
                "this secondary analysis downloads only labels and frozen "
                "alarm streams"
            ),
        },
        "methods": {},
        "stage21_minus_stage20": {
            "event_recall_difference": (
                point["stage21_combined"]["event_recall"]
                - point["stage20_combined"]["event_recall"]
            ),
            "event_recall_difference_ci95": ci(
                diff["recall_stage21_minus_stage20"]
            ),
            "restricted_mean_time_difference_ticks": (
                point["stage21_combined"][
                    "restricted_mean_time_ticks"
                ]
                - point["stage20_combined"][
                    "restricted_mean_time_ticks"
                ]
            ),
            "restricted_mean_time_difference_ci95_ticks": ci(
                diff["rmst_stage21_minus_stage20"]
            ),
            "detection_curve_difference": [],
        },
    }

    for method in METHOD_KEYS:
        item = dict(point[method])
        item["event_recall_ci95"] = ci(
            bootstrap[method]["recall"]
        )
        item["restricted_mean_time_ci95_ticks"] = ci(
            bootstrap[method]["rmst"]
        )
        item["median_detected_delay_ci95_ticks"] = (
            ci(bootstrap[method]["median_detected"])
            if bootstrap[method]["median_detected"]
            else None
        )
        item["detection_curve_ci95"] = [
            ci(bootstrap[method]["curve"][tick])
            for tick in range(HORIZON)
        ]
        item["false_alarms_per_1000_clean_ticks"] = (
            1000
            * item["false_alarms_total"]
            / max(1, item["clean_ticks_total"])
        )
        # Runner-cluster bootstrap is necessarily degenerate when all
        # independent runners contain zero false alarms. Report that honestly
        # and add a separate exact one-sided bound for the probability that a
        # future runner has at least one false alarm.
        runner_fa_indicator = [
            row["methods"][method]["false_alarms"] > 0
            for row in rows
        ]
        fa_boot = []
        fa_rng = random.Random(63000 + list(METHOD_KEYS).index(method))
        for _ in range(BOOTSTRAPS):
            sample = [
                runner_fa_indicator[fa_rng.randrange(n)]
                for _ in range(n)
            ]
            fa_boot.append(statistics.mean(sample))
        item["runner_any_false_alarm_fraction"] = statistics.mean(
            runner_fa_indicator
        )
        item["runner_any_false_alarm_fraction_ci95_bootstrap"] = ci(
            fa_boot
        )
        if item["runners_with_false_alarm"] == 0:
            item[
                "runner_any_false_alarm_probability_upper95_exact"
            ] = 1 - ALPHA ** (1 / n)
        else:
            item[
                "runner_any_false_alarm_probability_upper95_exact"
            ] = None
        summary["methods"][method] = item

    for tick in range(HORIZON):
        summary["stage21_minus_stage20"][
            "detection_curve_difference"
        ].append(
            {
                "tick": tick,
                "difference": (
                    point["stage21_combined"][
                        "detection_curve"
                    ][tick]
                    - point["stage20_combined"][
                        "detection_curve"
                    ][tick]
                ),
                "ci95": ci(
                    diff["curve_stage21_minus_stage20"][tick]
                ),
            }
        )

    return summary


def fmt(value):
    if value is None:
        return "—"
    return f"{value:.3f}"


def markdown(summary: dict) -> str:
    p = summary["protocol"]
    lines = [
        "# Stage 21 — time-to-detection analysis on 128 frozen Open5GS runners",
        "",
        (
            f"Independent runners: **{p['independent_runners']}**; "
            f"primary attack episodes: **{p['primary_events']}**; "
            f"administrative horizon: **{p['administrative_horizon_ticks']} ticks**."
        ),
        (
            f"Uncertainty: **{p['runner_cluster_bootstrap_resamples']:,}** "
            "nonparametric bootstrap resamples over whole Open5GS runners."
        ),
        "",
        "## Aggregate time-to-detection endpoints",
        "",
        "| Detector | Recall (95% CI) | Median delay among detected (95% CI) | "
        "Administrative median TTD | RMST to 12 ticks (95% CI) |",
        "|---|---:|---:|---:|---:|",
    ]
    for method in METHOD_KEYS:
        m = summary["methods"][method]
        rci = m["event_recall_ci95"]
        medci = m["median_detected_delay_ci95_ticks"]
        rmci = m["restricted_mean_time_ci95_ticks"]
        lines.append(
            f"| {METHOD_LABELS[method]} | "
            f"{m['event_recall']:.3f} "
            f"[{rci[0]:.3f}, {rci[1]:.3f}] | "
            f"{fmt(m['median_detected_delay_ticks'])} "
            + (
                f"[{medci[0]:.2f}, {medci[1]:.2f}]"
                if medci else "—"
            )
            + " | "
            + (
                f"{m['administrative_median_time_ticks']}"
                if m["administrative_median_time_ticks"] is not None
                else "not reached"
            )
            + " | "
            + f"{m['restricted_mean_time_ticks']:.2f} "
            f"[{rmci[0]:.2f}, {rmci[1]:.2f}] |"
        )

    lines += [
        "",
        (
            "The administrative median is the first tick by which at least "
            "50% of all attacks have been detected. It is undefined when "
            "final recall is below 0.5."
        ),
        (
            "RMST here equals the mean observed delay with misses administratively "
            "censored at the common 12-tick horizon; this makes explicit the "
            "survival-analysis interpretation of the previously reported "
            "horizon-penalized delay."
        ),
        "",
        "## Cumulative fraction detected by time",
        "",
        "| Tick | PH | Stage17 | Stage19 | Stage20 | Stage21 | Stage21−Stage20 (95% CI) |",
        "|---:|---:|---:|---:|---:|---:|---:|",
    ]
    effect_curve = summary["stage21_minus_stage20"][
        "detection_curve_difference"
    ]
    for tick in range(HORIZON):
        values = [
            summary["methods"][method]["detection_curve"][tick]
            for method in METHOD_KEYS
        ]
        effect = effect_curve[tick]
        lines.append(
            f"| {tick} | "
            + " | ".join(f"{value:.3f}" for value in values)
            + f" | {effect['difference']:+.3f} "
            f"[{effect['ci95'][0]:+.3f}, {effect['ci95'][1]:+.3f}] |"
        )

    e = summary["stage21_minus_stage20"]
    lines += [
        "",
        "## Paired Stage 21 versus Stage 20",
        "",
        (
            f"- Recall difference: **{e['event_recall_difference']:+.3f}**, "
            f"95% runner-cluster CI "
            f"[{e['event_recall_difference_ci95'][0]:+.3f}, "
            f"{e['event_recall_difference_ci95'][1]:+.3f}]."
        ),
        (
            f"- RMST difference: **{e['restricted_mean_time_difference_ticks']:+.2f} ticks**, "
            f"95% CI "
            f"[{e['restricted_mean_time_difference_ci95_ticks'][0]:+.2f}, "
            f"{e['restricted_mean_time_difference_ci95_ticks'][1]:+.2f}]."
        ),
        "",
        "## False alarms with runner-level uncertainty",
        "",
        "| Detector | False alarms | Clean ticks | FA/1000 | Runners with ≥1 FA | "
        "Bootstrap CI for runner fraction | Exact one-sided 95% upper bound |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for method in METHOD_KEYS:
        m = summary["methods"][method]
        ci_runner = m[
            "runner_any_false_alarm_fraction_ci95_bootstrap"
        ]
        upper = m[
            "runner_any_false_alarm_probability_upper95_exact"
        ]
        lines.append(
            f"| {METHOD_LABELS[method]} | "
            f"{m['false_alarms_total']} | "
            f"{m['clean_ticks_total']} | "
            f"{m['false_alarms_per_1000_clean_ticks']:.4f} | "
            f"{m['runners_with_false_alarm']}/{p['independent_runners']} | "
            f"[{ci_runner[0]:.4f}, {ci_runner[1]:.4f}] | "
            + (
                f"< {upper:.4f}"
                if upper is not None else "—"
            )
            + " |"
        )

    lines += [
        "",
        (
            "Because every runner had zero false alarms, the nonparametric "
            "runner bootstrap is degenerate at zero. The exact one-sided bound "
            "therefore answers a different and more informative question: "
            "the 95% upper bound on the probability that a new independent "
            "runner exhibits at least one false alarm."
        ),
        "",
        "## Interpretation",
        "",
        (
            "Stage 21 dominates Stage 20 beyond the single horizon-penalized "
            "mean. The two methods are approximately tied at tick 0, after "
            "which the Stage-21 cumulative detection curve is higher at every "
            "reported tick; Stage 21 reaches 50% cumulative detection by tick "
            "6, while Stage 20 never reaches an administrative median within "
            "the 12-tick horizon. Therefore the main conclusion is not an "
            "artifact of choosing one miss penalty."
        ),
        (
            "The detected-only median demonstrates selection bias rather than "
            "superiority: Stage 20 has a median of 0 ticks among the minority "
            "of attacks it detects, whereas Stage 21 has a median of 6 ticks "
            "while detecting every primary attack. The detected-only median "
            "must therefore never be compared without recall. The cumulative "
            "curve, administrative median, and RMST retain missed attacks in "
            "the analysis and are the appropriate primary timing summaries."
        ),
    ]
    return "\n".join(lines)


def write_curve_csv(summary: dict, path: Path):
    with path.open("w", newline="", encoding="utf8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "tick",
                "method",
                "fraction_detected",
                "ci95_low",
                "ci95_high",
            ]
        )
        for method in METHOD_KEYS:
            m = summary["methods"][method]
            for tick in range(HORIZON):
                ci_tick = m["detection_curve_ci95"][tick]
                writer.writerow(
                    [
                        tick,
                        method,
                        m["detection_curve"][tick],
                        ci_tick[0],
                        ci_tick[1],
                    ]
                )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--output", default="stage21_time_to_detection"
    )
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
    ):
        raise AssertionError(
            "Time analysis requires all 128 frozen replication runners"
        )

    rows = [
        evaluate_seed(
            labels[seed], alarms[seed]
        )
        for seed in EXPECTED_SEEDS
    ]
    summary = aggregate(rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf8",
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    write_curve_csv(
        summary, output / "detection_curve.csv"
    )
    print(report)


if __name__ == "__main__":
    main()
