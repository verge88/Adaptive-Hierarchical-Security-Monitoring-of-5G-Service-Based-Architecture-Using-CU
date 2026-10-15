"""Stage 35 held-out audit.

Scores transition-window relational attacks, legitimate-transition false alarms,
long clean soak, external freshness/authentication controls, and full-path
latency/availability.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

from .stage28_report import wilson_interval

EXPECTED_SEEDS = tuple(range(13001, 13017))


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(f"duplicate {filename} seed={seed}")
        out[seed] = doc
    return out


def percentile(values: list[float], q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty percentile input")
    pos = (len(ordered) - 1) * q
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return ordered[low] * (1 - frac) + ordered[high] * frac


def cluster_bootstrap(values: list[float], seed: int = 350035, n: int = 10000):
    rng = random.Random(seed)
    m = len(values)
    draws = sorted(
        statistics.mean(values[rng.randrange(m)] for _ in range(m))
        for _ in range(n)
    )
    return [
        draws[int(0.025 * (n - 1))],
        draws[int(0.975 * (n - 1))],
    ]


def score(labels: dict, signed: dict, evidence: dict) -> dict:
    seed = int(labels["seed"])
    if int(signed["seed"]) != seed or int(evidence["seed"]) != seed:
        raise AssertionError("Stage35 seed mismatch")
    if int(labels["stage"]) != 35 or int(evidence["stage"]) != 35:
        raise AssertionError("Stage35 stage mismatch")

    required = (
        labels["labels_join_posthoc_only"]
        and evidence["github_created_telemetry_rows"] is False
        and evidence["collector_sent_telemetry_directly_to_verifier"] is True
        and evidence["unauthenticated_request_rejected"] is True
        and evidence["cross_instance_replay_rejected"] is True
        and evidence["collector_signature_verified_by_github"] is True
        and evidence["verifier_signature_verified_by_github"] is True
        and evidence["collector_package_tamper_rejected_by_github"] is True
        and evidence["verifier_verdict_tamper_rejected_by_github"] is True
    )
    if not required:
        raise AssertionError("Stage35 trust/control audit failed")

    verdict = signed["verdict"]
    rows = {int(row["tick"]): row for row in verdict["alerts"]}
    attack_entries = labels["transition_attack_entries"]
    attack_ticks = {int(row["tick"]) for row in attack_entries}
    total_ticks = int(labels["total_ticks"])
    if set(rows) != set(range(total_ticks)):
        raise AssertionError("Stage35 incomplete verdict tick stream")

    rel_detected = sum(
        int(bool(rows[int(entry["tick"])]["relational_alert"]))
        for entry in attack_entries
    )
    legacy_detected = sum(
        int(bool(rows[int(entry["tick"])]["legacy_count_status_alert"]))
        for entry in attack_entries
    )

    transition_ticks = set()
    for start, end in labels["transition_windows"].values():
        transition_ticks.update(range(int(start), int(end) + 1))
    transition_clean = transition_ticks - attack_ticks
    soak_ticks = {
        tick for tick, row in rows.items() if row["phase"] == "clean_soak"
    }
    other_clean = set(rows) - attack_ticks
    rel_alerts = {
        tick for tick, row in rows.items() if row["relational_alert"]
    }
    legacy_alerts = {
        tick for tick, row in rows.items() if row["legacy_count_status_alert"]
    }

    family = {}
    phase = {}
    for entry in attack_entries:
        tick = int(entry["tick"])
        for group, key in (
            (family, str(entry["kind"])),
            (phase, str(entry["phase"])),
        ):
            group.setdefault(key, {"total": 0, "relational": 0, "legacy": 0})
            group[key]["total"] += 1
            group[key]["relational"] += int(rows[tick]["relational_alert"])
            group[key]["legacy"] += int(rows[tick]["legacy_count_status_alert"])

    return {
        "seed": seed,
        "attack_total": len(attack_entries),
        "relational_detected": rel_detected,
        "legacy_detected": legacy_detected,
        "relational_recall": rel_detected / len(attack_entries),
        "legacy_recall": legacy_detected / len(attack_entries),
        "transition_clean_tick_count": len(transition_clean),
        "transition_relational_false_alarms": len(rel_alerts & transition_clean),
        "transition_legacy_false_alarms": len(legacy_alerts & transition_clean),
        "soak_tick_count": len(soak_ticks),
        "soak_relational_false_alarms": len(rel_alerts & soak_ticks),
        "soak_legacy_false_alarms": len(legacy_alerts & soak_ticks),
        "all_clean_tick_count": len(other_clean),
        "all_clean_relational_false_alarms": len(rel_alerts & other_clean),
        "all_clean_legacy_false_alarms": len(legacy_alerts & other_clean),
        "family": family,
        "phase": phase,
        "verifier_latency_ms": float(
            evidence["authenticated_verifier_latency_ms"]
        ),
        "orchestration_round_trip_ms": float(
            evidence["orchestration_round_trip_ms"]
        ),
        "cross_instance_replay_latency_ms": float(
            evidence["cross_instance_replay_latency_ms"]
        ),
        "unauthenticated_latency_ms": float(
            evidence["unauthenticated_request_latency_ms"]
        ),
        "collector_sequence": int(evidence["collector_sequence"]),
        "policy_sha256": evidence["policy_sha256"],
        "collector_public_key_sha256": evidence[
            "collector_public_key_sha256"
        ],
        "verifier_service_revision": verdict["verifier_service_revision"],
        "verifier_public_key_sha256": verdict[
            "verifier_public_key_sha256"
        ],
        "anchor_service_revision": verdict[
            "freshness_anchor_service_revision"
        ],
    }


def aggregate_group(rows: list[dict], field: str) -> dict:
    merged = {}
    for row in rows:
        for key, values in row[field].items():
            target = merged.setdefault(
                key, {"total": 0, "relational": 0, "legacy": 0}
            )
            for name in ("total", "relational", "legacy"):
                target[name] += int(values[name])
    for values in merged.values():
        values["relational_recall"] = (
            values["relational"] / values["total"]
        )
        values["legacy_recall"] = values["legacy"] / values["total"]
        values["relational_wilson95"] = wilson_interval(
            values["relational"], values["total"]
        )
    return dict(sorted(merged.items()))


def summarize(rows: list[dict], benchmark: dict) -> dict:
    policies = {row["policy_sha256"] for row in rows}
    collector_keys = {row["collector_public_key_sha256"] for row in rows}
    verifier_keys = {row["verifier_public_key_sha256"] for row in rows}
    verifier_revs = {row["verifier_service_revision"] for row in rows}
    anchor_revs = {row["anchor_service_revision"] for row in rows}
    if any(
        len(values) != 1
        for values in (
            policies,
            collector_keys,
            verifier_keys,
            verifier_revs,
            anchor_revs,
        )
    ):
        raise AssertionError("Stage35 service/trust identity changed")

    total = sum(row["attack_total"] for row in rows)
    rel = sum(row["relational_detected"] for row in rows)
    legacy = sum(row["legacy_detected"] for row in rows)

    transition_clean = sum(row["transition_clean_tick_count"] for row in rows)
    transition_rel_fa = sum(
        row["transition_relational_false_alarms"] for row in rows
    )
    soak = sum(row["soak_tick_count"] for row in rows)
    soak_rel_fa = sum(row["soak_relational_false_alarms"] for row in rows)
    all_clean = sum(row["all_clean_tick_count"] for row in rows)
    all_clean_rel_fa = sum(
        row["all_clean_relational_false_alarms"] for row in rows
    )

    gains = [
        row["relational_recall"] - row["legacy_recall"] for row in rows
    ]
    verifier_latencies = [row["verifier_latency_ms"] for row in rows]

    return {
        "independent_external_runs": len(rows),
        "seeds": [row["seed"] for row in rows],
        "transition_attack_episodes": total,
        "relational": {
            "detected": rel,
            "recall": rel / total,
            "wilson95": wilson_interval(rel, total),
        },
        "legacy_count_status": {
            "detected": legacy,
            "recall": legacy / total,
            "wilson95": wilson_interval(legacy, total),
        },
        "paired_recall_gain": {
            "runner_mean": statistics.mean(gains),
            "runner_cluster_bootstrap_ci95": cluster_bootstrap(gains),
        },
        "transition_clean": {
            "false_alarms": transition_rel_fa,
            "ticks": transition_clean,
            "fa_per_1000": 1000 * transition_rel_fa / max(1, transition_clean),
            "wilson95": wilson_interval(
                transition_rel_fa, transition_clean
            ),
        },
        "long_clean_soak": {
            "false_alarms": soak_rel_fa,
            "ticks": soak,
            "fa_per_1000": 1000 * soak_rel_fa / max(1, soak),
            "wilson95": wilson_interval(soak_rel_fa, soak),
        },
        "all_clean": {
            "false_alarms": all_clean_rel_fa,
            "ticks": all_clean,
            "fa_per_1000": 1000 * all_clean_rel_fa / max(1, all_clean),
        },
        "authentication_negative_control_rejected_runs": len(rows),
        "cross_instance_replay_rejected_runs": len(rows),
        "by_family": aggregate_group(rows, "family"),
        "by_phase": aggregate_group(rows, "phase"),
        "run_verifier_latency_ms": {
            "p50": percentile(verifier_latencies, 0.50),
            "p95": percentile(verifier_latencies, 0.95),
            "p99": percentile(verifier_latencies, 0.99),
            "max": max(verifier_latencies),
        },
        "full_path_benchmark": benchmark,
        "policy_sha256": next(iter(policies)),
        "collector_public_key_sha256": next(iter(collector_keys)),
        "verifier_public_key_sha256": next(iter(verifier_keys)),
        "verifier_service_revision": next(iter(verifier_revs)),
        "anchor_service_revision": next(iter(anchor_revs)),
    }


def markdown(summary: dict) -> str:
    rel = summary["relational"]
    leg = summary["legacy_count_status"]
    gain = summary["paired_recall_gain"]
    transition = summary["transition_clean"]
    soak = summary["long_clean_soak"]
    bench = summary["full_path_benchmark"]

    lines = [
        "# Stage 35 — transition-race, external freshness and availability",
        "",
        (
            f"Independent external Open5GS runs: "
            f"**{summary['independent_external_runs']}**; transition-window "
            f"attack episodes: **{summary['transition_attack_episodes']}**."
        ),
        "",
        "| Detector | Recall | Wilson 95% |",
        "|---|---:|---:|",
        (
            f"| Legacy phase-aware count/status | {leg['recall']:.3f} "
            f"({leg['detected']}/{summary['transition_attack_episodes']}) | "
            f"[{leg['wilson95'][0]:.3f}, {leg['wilson95'][1]:.3f}] |"
        ),
        (
            f"| Transition-aware relational verifier | {rel['recall']:.3f} "
            f"({rel['detected']}/{summary['transition_attack_episodes']}) | "
            f"[{rel['wilson95'][0]:.3f}, {rel['wilson95'][1]:.3f}] |"
        ),
        "",
        (
            f"Paired runner-level recall gain: "
            f"**{gain['runner_mean']:+.3f}**, 95% runner-cluster bootstrap "
            f"[{gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
            f"{gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
        ),
        (
            f"Clean legitimate-transition false alarms: "
            f"**{transition['false_alarms']}/{transition['ticks']}**, "
            f"{transition['fa_per_1000']:.3f}/1000, Wilson 95% "
            f"[{transition['wilson95'][0]:.3f}, "
            f"{transition['wilson95'][1]:.3f}]."
        ),
        (
            f"Long clean soak false alarms: "
            f"**{soak['false_alarms']}/{soak['ticks']}**, "
            f"{soak['fa_per_1000']:.3f}/1000, Wilson 95% "
            f"[{soak['wilson95'][0]:.3f}, {soak['wilson95'][1]:.3f}]."
        ),
        (
            "Unauthenticated collector requests rejected: "
            f"**{summary['authentication_negative_control_rejected_runs']}/"
            f"{summary['independent_external_runs']}**."
        ),
        (
            "Cross-verifier-instance replays rejected by external freshness "
            f"anchor: **{summary['cross_instance_replay_rejected_runs']}/"
            f"{summary['independent_external_runs']}**."
        ),
        "",
        "## Full verifier + freshness-anchor benchmark",
        "",
        (
            f"Availability: **{bench['successes']}/{bench['iterations']} = "
            f"{bench['availability']:.3f}**."
        ),
        (
            f"Latency p50/p95/p99: **{bench['latency_ms']['p50']:.2f} / "
            f"{bench['latency_ms']['p95']:.2f} / "
            f"{bench['latency_ms']['p99']:.2f} ms**; max "
            f"**{bench['latency_ms']['max']:.2f} ms**."
        ),
        (
            f"Sequential full-path throughput: "
            f"**{bench['sequential_throughput_requests_per_second']:.2f} "
            "requests/s**."
        ),
        "",
        "## Attack family",
        "",
        "| Family | Legacy | Relational | Relational Wilson 95% |",
        "|---|---:|---:|---:|",
    ]
    for name, row in summary["by_family"].items():
        ci = row["relational_wilson95"]
        lines.append(
            f"| {name} | {row['legacy_recall']:.3f} "
            f"({row['legacy']}/{row['total']}) | "
            f"{row['relational_recall']:.3f} "
            f"({row['relational']}/{row['total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Transition phase",
            "",
            "| Phase | Legacy | Relational | Relational Wilson 95% |",
            "|---|---:|---:|---:|",
        ]
    )
    for name, row in summary["by_phase"].items():
        ci = row["relational_wilson95"]
        lines.append(
            f"| {name} | {row['legacy_recall']:.3f} "
            f"({row['legacy']}/{row['total']}) | "
            f"{row['relational_recall']:.3f} "
            f"({row['relational']}/{row['total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Trust and remaining boundary",
            "",
            (
                "The collector sends signed telemetry directly to authenticated "
                "verifier A; GitHub does not carry telemetry into the decision "
                "path. Verifier freshness is claimed through a third external "
                "anchor process, and replay to verifier B tests that freshness "
                "does not reside only in verifier A memory."
            ),
            (
                "The freshness anchor is free-tier process-memory state, not a "
                "crash-durable database or hardware monotonic counter. Its own "
                "restart resets replay state. The collector, both verifier "
                "instances, and anchor also remain under one Render control "
                "plane."
            ),
            (
                "Transition endpoint references are clean old/new Open5GS "
                "states captured by the trusted external collector. This tests "
                "old/new convergence discrimination but is not independent "
                "hardware measurement of physical-network truth."
            ),
            "",
            f"Policy SHA-256: {summary['policy_sha256']}.",
            (
                "Collector public-key SHA-256: "
                f"{summary['collector_public_key_sha256']}."
            ),
            (
                "Verifier public-key SHA-256: "
                f"{summary['verifier_public_key_sha256']}."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--benchmark", required=True)
    parser.add_argument("--output", default="stage35_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    signed = load_by_seed(root, "signed_verdict.json")
    evidence = load_by_seed(root, "evidence.json")
    expected = set(EXPECTED_SEEDS)
    if any(set(group) != expected for group in (labels, signed, evidence)):
        raise AssertionError("Stage35 requires all 16 preregistered runs")

    rows = [
        score(labels[seed], signed[seed], evidence[seed])
        for seed in EXPECTED_SEEDS
    ]
    benchmark = json.loads(Path(args.benchmark).read_text(encoding="utf8"))
    summary = summarize(rows, benchmark)

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf8"
    )
    report = markdown(summary)
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
