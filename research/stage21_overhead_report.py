"""Aggregate Stage-21 clean monitoring-overhead benchmark.

Expected block: 64 independent Open5GS runners, seeds 8801..8864.
The report uses runner-level statistics and nonparametric bootstrap over whole
runners. It separates network/request amplification from local computation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(8801, 8865))
BOOTSTRAPS = 20000


def percentile(values, p):
    values = sorted(values)
    position = p * (len(values) - 1)
    left = int(position)
    right = min(left + 1, len(values) - 1)
    fraction = position - left
    return (
        values[left] * (1 - fraction)
        + values[right] * fraction
    )


def bootstrap_ci(values, *, statistic, seed):
    rng = random.Random(seed)
    n = len(values)
    draws = []
    for _ in range(BOOTSTRAPS):
        sample = [
            values[rng.randrange(n)] for _ in range(n)
        ]
        draws.append(statistic(sample))
    return [
        percentile(draws, 0.025),
        percentile(draws, 0.975),
    ]


def median_ci(values, seed):
    return bootstrap_ci(
        values,
        statistic=statistics.median,
        seed=seed,
    )


def mean_ci(values, seed):
    return bootstrap_ci(
        values,
        statistic=statistics.mean,
        seed=seed,
    )


def load(root: Path):
    docs = {}
    for path in root.rglob("overhead.json"):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in docs:
            raise AssertionError(
                f"duplicate overhead result seed={seed}"
            )
        docs[seed] = doc
    expected = set(EXPECTED_SEEDS)
    if set(docs) != expected:
        raise AssertionError(
            f"Expected all 64 overhead runners; "
            f"missing={sorted(expected-set(docs))}"
        )
    return [docs[seed] for seed in EXPECTED_SEEDS]


def summary_metric(
    rows, getter, *, center="median", seed=1
):
    values = [float(getter(row)) for row in rows]
    if center == "median":
        point = statistics.median(values)
        interval = median_ci(values, seed)
    elif center == "mean":
        point = statistics.mean(values)
        interval = mean_ci(values, seed)
    else:
        raise ValueError(center)
    return {
        "center": center,
        "value": point,
        "ci95": interval,
        "min": min(values),
        "max": max(values),
    }


def summarize(rows):
    for row in rows:
        if (
            not row["clean_fault_free"]
            or not row["native_open5gs_scp_nrf"]
            or row["native_open5gs_binaries_modified"]
            or row["research_fault_gateway_included"]
            or row["request_count_amplification"] != 2.0
        ):
            raise AssertionError(
                f"Invalid overhead provenance seed={row['seed']}"
            )
        if row["detector_microbenchmark"][
            "alerts_on_clean_batch"
        ] != 0:
            raise AssertionError(
                f"Clean detector alarm seed={row['seed']}"
            )

    metrics = {}
    specifications = [
        (
            "baseline_request_median_ms",
            lambda r: r["baseline"]["median_elapsed_ms"],
            "median",
        ),
        (
            "monitored_cycle_median_ms",
            lambda r: r["monitored_cycle"][
                "median_elapsed_ms"
            ],
            "median",
        ),
        (
            "paired_extra_median_ms",
            lambda r: r["paired_overhead"][
                "median_extra_elapsed_ms"
            ],
            "median",
        ),
        (
            "paired_latency_ratio",
            lambda r: r["paired_overhead"][
                "median_latency_ratio"
            ],
            "median",
        ),
        (
            "wire_byte_ratio",
            lambda r: r["paired_overhead"][
                "median_wire_ratio"
            ],
            "median",
        ),
        (
            "live_pair_feature_ms",
            lambda r: r["monitored_cycle"][
                "median_feature_ms"
            ],
            "median",
        ),
        (
            "feature_micro_ms_per_response",
            lambda r: r["feature_microbenchmark"][
                "mean_ms_per_response"
            ],
            "median",
        ),
        (
            "feature_micro_responses_per_second",
            lambda r: r["feature_microbenchmark"][
                "responses_per_second"
            ],
            "median",
        ),
        (
            "detector_ms_per_tick",
            lambda r: r["detector_microbenchmark"][
                "mean_ms_per_tick"
            ],
            "median",
        ),
        (
            "detector_tick_updates_per_second",
            lambda r: r["detector_microbenchmark"][
                "tick_updates_per_second"
            ],
            "median",
        ),
        (
            "feature_peak_traced_bytes",
            lambda r: r["feature_microbenchmark"][
                "single_call_peak_traced_bytes"
            ],
            "median",
        ),
        (
            "detector_batch_peak_traced_bytes",
            lambda r: r["detector_microbenchmark"][
                "single_batch_peak_traced_bytes"
            ],
            "median",
        ),
        (
            "local_telemetry_bytes_per_pair",
            lambda r: r["monitored_cycle"][
                "median_local_telemetry_bytes"
            ],
            "median",
        ),
        (
            "raw_body_bytes_per_pair",
            lambda r: r["monitored_cycle"][
                "median_response_body_bytes"
            ],
            "median",
        ),
    ]
    for index, (name, getter, center) in enumerate(
        specifications
    ):
        metrics[name] = summary_metric(
            rows,
            getter,
            center=center,
            seed=61000 + index,
        )

    telemetry_ratios = [
        (
            r["monitored_cycle"]["median_local_telemetry_bytes"]
            / max(
                1,
                r["monitored_cycle"][
                    "median_response_body_bytes"
                ],
            )
        )
        for r in rows
    ]
    metrics["local_telemetry_to_raw_body_ratio"] = {
        "center": "median",
        "value": statistics.median(telemetry_ratios),
        "ci95": median_ci(telemetry_ratios, 61200),
        "min": min(telemetry_ratios),
        "max": max(telemetry_ratios),
    }

    selected_paths = [
        r["detector_microbenchmark"][
            "semantic_selected_path_count"
        ]
        for r in rows
    ]

    return {
        "protocol": {
            "independent_open5gs_runners": len(rows),
            "seeds": [rows[0]["seed"], rows[-1]["seed"]],
            "measured_cycles_per_runner": rows[0][
                "measured_cycles"
            ],
            "total_baseline_cycles": sum(
                r["measured_cycles"] for r in rows
            ),
            "total_monitored_cycles": sum(
                r["measured_cycles"] for r in rows
            ),
            "total_native_scp_nrf_requests_measured": sum(
                r["measured_cycles"]
                * (
                    r["native_requests_per_baseline_cycle"]
                    + r["native_requests_per_monitored_cycle"]
                )
                for r in rows
            ),
            "runner_cluster_bootstrap_resamples": BOOTSTRAPS,
            "request_count_amplification": 2.0,
            "fault_gateway_included": False,
            "production_mtls_oauth_sepp_modeled": False,
            "detector_retuned": False,
        },
        "metrics": metrics,
        "semantic_channel_enabled_fraction": statistics.mean(
            r["detector_microbenchmark"][
                "semantic_channel_enabled"
            ]
            for r in rows
        ),
        "median_semantic_selected_path_count": statistics.median(
            selected_paths
        ),
    }


def fmetric(m, digits=3):
    return (
        f"{m['value']:.{digits}f} "
        f"[{m['ci95'][0]:.{digits}f}, "
        f"{m['ci95'][1]:.{digits}f}]"
    )


def markdown(s):
    p = s["protocol"]
    m = s["metrics"]
    lines = [
        "# Stage 21 — clean monitoring overhead on 64 Open5GS runners",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{p['independent_open5gs_runners']}**; "
            f"seeds **{p['seeds'][0]}..{p['seeds'][1]}**."
        ),
        (
            f"Measured per runner: "
            f"**{p['measured_cycles_per_runner']} baseline + "
            f"{p['measured_cycles_per_runner']} monitored cycles**; "
            f"total measured native SCP→NRF requests: "
            f"**{p['total_native_scp_nrf_requests_measured']:,}**."
        ),
        (
            f"Uncertainty: **{p['runner_cluster_bootstrap_resamples']:,}** "
            "bootstrap resamples over whole runners."
        ),
        "",
        "## Native path and paired monitoring cycle",
        "",
        "| Quantity | Runner-median estimate, 95% cluster CI |",
        "|---|---:|",
        (
            "| Native SCP→NRF single-request latency, ms | "
            + fmetric(m["baseline_request_median_ms"])
            + " |"
        ),
        (
            "| Sequential paired monitoring-cycle latency, ms | "
            + fmetric(m["monitored_cycle_median_ms"])
            + " |"
        ),
        (
            "| Incremental paired-cycle latency, ms | "
            + fmetric(m["paired_extra_median_ms"])
            + " |"
        ),
        (
            "| Latency ratio, monitored / baseline | "
            + fmetric(m["paired_latency_ratio"])
            + " |"
        ),
        (
            "| HTTP/2 wire-byte ratio, monitored / baseline | "
            + fmetric(m["wire_byte_ratio"])
            + " |"
        ),
        "",
        (
            "The request-count amplification is **exactly 2.0× by design**: "
            "one consumer-side observation plus one independent nearby "
            "reference request replace a single unmonitored request."
        ),
        (
            "This is a per-monitored-transaction amplification, not a claim "
            "that total production 5G traffic doubles. The total network "
            "impact depends on what fraction of transactions are sampled."
        ),
        "",
        "## Local feature and detector cost",
        "",
        "| Quantity | Runner-median estimate, 95% cluster CI |",
        "|---|---:|",
        (
            "| Feature extraction for one clean paired observation, ms | "
            + fmetric(m["live_pair_feature_ms"], 4)
            + " |"
        ),
        (
            "| Feature microbenchmark per response, ms | "
            + fmetric(m["feature_micro_ms_per_response"], 4)
            + " |"
        ),
        (
            "| Feature extraction responses/s | "
            + fmetric(
                m["feature_micro_responses_per_second"], 1
            )
            + " |"
        ),
        (
            "| Frozen Stage-21 detector per tick, ms | "
            + fmetric(m["detector_ms_per_tick"], 5)
            + " |"
        ),
        (
            "| Frozen Stage-21 detector tick updates/s | "
            + fmetric(
                m["detector_tick_updates_per_second"], 1
            )
            + " |"
        ),
        (
            "| Feature extraction peak traced memory, bytes | "
            + fmetric(m["feature_peak_traced_bytes"], 0)
            + " |"
        ),
        (
            "| 80-tick detector batch peak traced memory, bytes | "
            + fmetric(
                m["detector_batch_peak_traced_bytes"], 0
            )
            + " |"
        ),
        "",
        "## Local monitoring telemetry representation",
        "",
        "| Quantity | Runner-median estimate, 95% cluster CI |",
        "|---|---:|",
        (
            "| Raw two-response JSON body bytes | "
            + fmetric(m["raw_body_bytes_per_pair"], 0)
            + " |"
        ),
        (
            "| Serialized structural + semantic equality telemetry bytes | "
            + fmetric(m["local_telemetry_bytes_per_pair"], 0)
            + " |"
        ),
        (
            "| Local telemetry / raw response-body ratio | "
            + fmetric(
                m["local_telemetry_to_raw_body_ratio"], 2
            )
            + " |"
        ),
        "",
        (
            "The local telemetry ratio describes the current research "
            "serialization, which uses full hexadecimal SHA-256 equality "
            "tokens. These bytes are **not injected into native SBI messages** "
            "and therefore must not be reported as 5G wire overhead."
        ),
        "",
        "## Interpretation",
        "",
        (
            "The dominant operational cost of the current design is expected "
            "to be the second independent SCP→NRF request, not the sequential "
            "detector arithmetic. Local feature extraction and detector update "
            "costs are reported separately so that networking and computation "
            "are not conflated."
        ),
        (
            "The benchmark intentionally excludes the research-only fault "
            "gateway. It therefore estimates monitoring overhead rather than "
            "fault-injection harness overhead."
        ),
        (
            "These measurements are laboratory h2c results on GitHub-hosted "
            "runners. They do not include production mutual TLS, delegated "
            "authorization, SEPP processing, persistent HTTP/2 connection "
            "reuse, realistic concurrent load, or operator traffic. They "
            "should not be presented as a production capacity guarantee."
        ),
    ]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--output", default="stage21_overhead_report"
    )
    args = parser.parse_args()

    rows = load(Path(args.input))
    result = summarize(rows)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    report = markdown(result)
    (output / "REPORT.md").write_text(
        report, encoding="utf8"
    )
    print(report)


if __name__ == "__main__":
    main()
