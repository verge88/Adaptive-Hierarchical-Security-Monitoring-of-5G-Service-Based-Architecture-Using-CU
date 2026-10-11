"""Stage 21 clean Open5GS monitoring-overhead benchmark.

This benchmark measures three distinct costs without changing detector logic:

1. Native request cost:
   one genuine Open5GS SCP -> NRF discovery transaction.

2. Paired-observation monitoring-cycle cost:
   two independent genuine SCP -> NRF requests plus local canonical,
   structural and semantic feature extraction. The research-only post-SCP fault
   gateway is intentionally excluded from this benchmark.

3. Frozen detector CPU cost:
   Stage-21 detection over already extracted label-free telemetry.

The benchmark is clean (no injected faults) and uses new evaluation-only
Open5GS runners. It is NOT a production throughput benchmark and does not
model mTLS/OAuth/SEPP overhead.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import random
import statistics
import time
import tracemalloc

from .h2_wire import encode
from .stage14_native_scp import (
    NATIVE_SCP,
    NRF_PATH,
    await_scp_ready,
    discovered_nssf_ids,
    h2_exchange,
)
from .stage5_native import wait_core
from .stage20_structure import (
    serialize_counter,
    structural_counter,
)
from .stage21_live_detect import detect as stage21_detect
from .stage21_semantic import (
    semantic_projection,
    serialize_projection,
)

WARMUP_CYCLES = 12
MEASURED_CYCLES = 80
FEATURE_BENCH_ITERS = 1000
DETECTOR_BENCH_BATCHES = 50


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("percentile requires values")
    position = p * (len(ordered) - 1)
    left = int(position)
    right = min(left + 1, len(ordered) - 1)
    fraction = position - left
    return ordered[left] * (1 - fraction) + ordered[right] * fraction


def feature_view(obj: dict) -> dict:
    structure = serialize_counter(structural_counter(obj))
    semantic = serialize_projection(semantic_projection(obj))
    canonical = encode(obj)
    return {
        "canonical_bytes": len(canonical),
        "structure": structure,
        "semantic": semantic,
    }


def telemetry_pair_bytes(left: dict, right: dict) -> int:
    payload = {
        "trusted_structure": left["structure"],
        "consumer_structure": right["structure"],
        "trusted_semantic": left["semantic"],
        "consumer_semantic": right["semantic"],
    }
    return len(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf8")
    )


async def native_request():
    response = await h2_exchange(
        NATIVE_SCP,
        NRF_PATH,
        target="http://nrf:80",
        timeout=4,
    )
    ids = discovered_nssf_ids(response)
    obj = json.loads(response.body)
    return response, ids, obj


async def baseline_once() -> dict:
    started = time.perf_counter()
    response, ids, obj = await native_request()
    elapsed_ms = (time.perf_counter() - started) * 1000
    return {
        "elapsed_ms": elapsed_ms,
        "wire_bytes": response.h2_bytes,
        "response_body_bytes": len(response.body),
        "nssf_profiles": len(ids),
        "obj": obj,
    }


async def monitored_once() -> dict:
    started = time.perf_counter()

    trusted_response, trusted_ids, trusted_obj = await native_request()
    consumer_response, consumer_ids, consumer_obj = await native_request()

    if trusted_ids != consumer_ids:
        raise AssertionError(
            "Clean paired monitoring observed different NSSF identity sets"
        )

    feature_started = time.perf_counter()
    trusted = feature_view(trusted_obj)
    consumer = feature_view(consumer_obj)
    feature_ms = (time.perf_counter() - feature_started) * 1000

    elapsed_ms = (time.perf_counter() - started) * 1000
    local_telemetry_bytes = telemetry_pair_bytes(
        trusted, consumer
    )

    row = {
        "trusted_status": trusted_response.status,
        "consumer_status": consumer_response.status,
        "trusted_canonical_bytes": trusted["canonical_bytes"],
        "consumer_canonical_bytes": consumer["canonical_bytes"],
        "trusted_structure": trusted["structure"],
        "consumer_structure": consumer["structure"],
        "trusted_semantic": trusted["semantic"],
        "consumer_semantic": consumer["semantic"],
    }

    return {
        "elapsed_ms": elapsed_ms,
        "feature_ms": feature_ms,
        "wire_bytes": (
            trusted_response.h2_bytes
            + consumer_response.h2_bytes
        ),
        "response_body_bytes": (
            len(trusted_response.body)
            + len(consumer_response.body)
        ),
        "local_telemetry_bytes": local_telemetry_bytes,
        "nssf_profiles": len(trusted_ids),
        "row": row,
        "representative_obj": trusted_obj,
    }


def microbenchmark_features(obj: dict) -> dict:
    # Warm interpreter caches before measurement.
    for _ in range(25):
        feature_view(obj)

    started = time.perf_counter()
    for _ in range(FEATURE_BENCH_ITERS):
        feature_view(obj)
    elapsed = time.perf_counter() - started

    tracemalloc.start()
    feature_view(obj)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "iterations": FEATURE_BENCH_ITERS,
        "mean_ms_per_response": (
            elapsed * 1000 / FEATURE_BENCH_ITERS
        ),
        "responses_per_second": (
            FEATURE_BENCH_ITERS / elapsed
        ),
        "single_call_peak_traced_bytes": peak,
    }


def benchmark_detector(rows: list[dict], seed: int) -> dict:
    if len(rows) <= 30:
        raise AssertionError(
            "Detector benchmark requires >30 telemetry rows"
        )
    telemetry = []
    for tick, row in enumerate(rows):
        item = dict(row)
        item["tick"] = tick
        item["seed"] = seed
        telemetry.append(item)

    # Warm Python caches and validate the frozen detector on clean data.
    warm = stage21_detect(telemetry)
    if any(
        row["stage21_combined_alert"]
        for row in warm["ticks"]
    ):
        raise AssertionError(
            "Clean overhead telemetry unexpectedly triggered Stage21"
        )

    started = time.perf_counter()
    for _ in range(DETECTOR_BENCH_BATCHES):
        stage21_detect(telemetry)
    elapsed = time.perf_counter() - started
    total_ticks = DETECTOR_BENCH_BATCHES * len(telemetry)

    tracemalloc.start()
    result = stage21_detect(telemetry)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "batches": DETECTOR_BENCH_BATCHES,
        "ticks_per_batch": len(telemetry),
        "total_tick_updates": total_ticks,
        "mean_ms_per_tick": elapsed * 1000 / total_ticks,
        "tick_updates_per_second": total_ticks / elapsed,
        "single_batch_peak_traced_bytes": peak,
        "semantic_selected_path_count": result[
            "calibration"
        ]["semantic_selected_path_count"],
        "semantic_channel_enabled": result[
            "calibration"
        ]["semantic_channel_enabled"],
        "alerts_on_clean_batch": sum(
            row["stage21_combined_alert"]
            for row in result["ticks"]
        ),
    }


async def run(seed: int) -> dict:
    await wait_core(
        "http://127.0.0.1:7777",
        require_registered=True,
        timeout=75,
    )
    await await_scp_ready()

    rng = random.Random(seed * 620021 + 17)

    for _ in range(WARMUP_CYCLES):
        if rng.randrange(2):
            await baseline_once()
            await monitored_once()
        else:
            await monitored_once()
            await baseline_once()

    baseline_rows = []
    monitored_rows = []

    for cycle in range(MEASURED_CYCLES):
        baseline_first = rng.randrange(2) == 0
        if baseline_first:
            baseline = await baseline_once()
            monitored = await monitored_once()
        else:
            monitored = await monitored_once()
            baseline = await baseline_once()

        baseline_rows.append(
            {
                "cycle": cycle,
                "baseline_first": baseline_first,
                **{
                    key: baseline[key]
                    for key in (
                        "elapsed_ms",
                        "wire_bytes",
                        "response_body_bytes",
                        "nssf_profiles",
                    )
                },
            }
        )
        monitored_rows.append(
            {
                "cycle": cycle,
                "baseline_first": baseline_first,
                **{
                    key: monitored[key]
                    for key in (
                        "elapsed_ms",
                        "feature_ms",
                        "wire_bytes",
                        "response_body_bytes",
                        "local_telemetry_bytes",
                        "nssf_profiles",
                    )
                },
                "row": monitored["row"],
            }
        )

    if (
        min(row["nssf_profiles"] for row in baseline_rows) < 2
        or min(row["nssf_profiles"] for row in monitored_rows) < 2
    ):
        raise AssertionError(
            "Native NRF registration pool was not preserved"
        )

    paired_extra = [
        monitored["elapsed_ms"] - baseline["elapsed_ms"]
        for baseline, monitored in zip(
            baseline_rows, monitored_rows
        )
    ]
    latency_ratio = [
        monitored["elapsed_ms"]
        / max(1e-9, baseline["elapsed_ms"])
        for baseline, monitored in zip(
            baseline_rows, monitored_rows
        )
    ]
    wire_ratio = [
        monitored["wire_bytes"]
        / max(1, baseline["wire_bytes"])
        for baseline, monitored in zip(
            baseline_rows, monitored_rows
        )
    ]

    representative = monitored_rows[
        MEASURED_CYCLES // 2
    ]
    representative_obj = (
        await native_request()
    )[2]

    feature_bench = microbenchmark_features(
        representative_obj
    )
    detector_bench = benchmark_detector(
        [row["row"] for row in monitored_rows],
        seed,
    )

    return {
        "stage": 21,
        "benchmark": "monitoring_overhead",
        "seed": seed,
        "clean_fault_free": True,
        "native_open5gs_scp_nrf": True,
        "native_open5gs_binaries_modified": False,
        "research_fault_gateway_included": False,
        "production_mtls_oauth_sepp_modeled": False,
        "warmup_cycles": WARMUP_CYCLES,
        "measured_cycles": MEASURED_CYCLES,
        "native_requests_per_baseline_cycle": 1,
        "native_requests_per_monitored_cycle": 2,
        "request_count_amplification": 2.0,
        "baseline": {
            "median_elapsed_ms": statistics.median(
                row["elapsed_ms"] for row in baseline_rows
            ),
            "mean_elapsed_ms": statistics.mean(
                row["elapsed_ms"] for row in baseline_rows
            ),
            "p95_elapsed_ms": percentile(
                [row["elapsed_ms"] for row in baseline_rows],
                0.95,
            ),
            "median_wire_bytes": statistics.median(
                row["wire_bytes"] for row in baseline_rows
            ),
            "median_response_body_bytes": statistics.median(
                row["response_body_bytes"]
                for row in baseline_rows
            ),
        },
        "monitored_cycle": {
            "median_elapsed_ms": statistics.median(
                row["elapsed_ms"] for row in monitored_rows
            ),
            "mean_elapsed_ms": statistics.mean(
                row["elapsed_ms"] for row in monitored_rows
            ),
            "p95_elapsed_ms": percentile(
                [row["elapsed_ms"] for row in monitored_rows],
                0.95,
            ),
            "median_feature_ms": statistics.median(
                row["feature_ms"] for row in monitored_rows
            ),
            "median_wire_bytes": statistics.median(
                row["wire_bytes"] for row in monitored_rows
            ),
            "median_response_body_bytes": statistics.median(
                row["response_body_bytes"]
                for row in monitored_rows
            ),
            "median_local_telemetry_bytes": statistics.median(
                row["local_telemetry_bytes"]
                for row in monitored_rows
            ),
        },
        "paired_overhead": {
            "median_extra_elapsed_ms": statistics.median(
                paired_extra
            ),
            "mean_extra_elapsed_ms": statistics.mean(
                paired_extra
            ),
            "p95_extra_elapsed_ms": percentile(
                paired_extra, 0.95
            ),
            "median_latency_ratio": statistics.median(
                latency_ratio
            ),
            "mean_latency_ratio": statistics.mean(
                latency_ratio
            ),
            "median_wire_ratio": statistics.median(
                wire_ratio
            ),
        },
        "feature_microbenchmark": feature_bench,
        "detector_microbenchmark": detector_bench,
        "baseline_samples": [
            {
                key: value
                for key, value in row.items()
                if key != "obj"
            }
            for row in baseline_rows
        ],
        "monitored_samples": [
            {
                key: value
                for key, value in row.items()
                if key != "row"
            }
            for row in monitored_rows
        ],
    }


async def main_async(args):
    result = await run(args.seed)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "overhead.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(
        "STAGE21_OVERHEAD_OK "
        f"seed={args.seed} "
        f"baseline_med_ms={result['baseline']['median_elapsed_ms']:.3f} "
        f"monitored_med_ms={result['monitored_cycle']['median_elapsed_ms']:.3f} "
        f"ratio={result['paired_overhead']['median_latency_ratio']:.3f} "
        f"detector_ms_tick={result['detector_microbenchmark']['mean_ms_per_tick']:.6f}",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument(
        "--output", default="stage21_overhead"
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
