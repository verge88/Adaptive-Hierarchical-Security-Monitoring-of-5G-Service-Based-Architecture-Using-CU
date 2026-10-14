"""Stage 34 held-out audit for relational invariant-preserving attacks."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

from .stage28_report import wilson_interval

EXPECTED_SEEDS = tuple(range(12001, 12033))


def load_by_seed(root: Path, filename: str) -> dict[int, dict]:
    out = {}
    for path in root.rglob(filename):
        doc = json.loads(path.read_text(encoding="utf8"))
        seed = int(doc["seed"])
        if seed in out:
            raise AssertionError(f"duplicate {filename} seed {seed}")
        out[seed] = doc
    return out


def cluster_bootstrap(values: list[float], *, seed: int, n: int = 10000):
    rng = random.Random(seed)
    size = len(values)
    draws = sorted(
        statistics.mean(values[rng.randrange(size)] for _ in range(size))
        for _ in range(n)
    )
    return [
        draws[int(0.025 * (n - 1))],
        draws[int(0.975 * (n - 1))],
    ]


def score(labels: dict, verdict_doc: dict, evidence: dict) -> dict:
    seed = int(labels["seed"])
    if int(verdict_doc["seed"]) != seed or int(evidence["seed"]) != seed:
        raise AssertionError("Stage34 seed mismatch")
    if int(labels["stage"]) != 34 or int(evidence["stage"]) != 34:
        raise AssertionError("Stage34 stage mismatch")

    required = (
        labels["count_preserving_by_design"]
        and labels["labels_join_posthoc_only"]
        and evidence["collector_signature_verified"]
        and evidence["collector_tamper_rejected"]
        and evidence["verifier_signature_verified"]
        and evidence["verifier_tamper_rejected"]
        and evidence["verifier_replay_rejected"]
        and evidence["telemetry_origin"] == "external_open5gs_testbed"
        and evidence["github_created_telemetry_rows"] is False
    )
    if not required:
        raise AssertionError("Stage34 trust/blinding audit failed")

    verdict = verdict_doc["verdict"]
    rows = {int(row["tick"]): row for row in verdict["alerts"]}
    total_ticks = int(labels["total_ticks"])
    if set(rows) != set(range(total_ticks)):
        raise AssertionError("Stage34 verdict tick stream incomplete")

    episodes = labels["episodes"]
    attack_ticks = {
        tick
        for ep in episodes
        for tick in range(int(ep["start_tick"]), int(ep["end_tick"]))
    }
    mutation_ticks = {
        int(tick)
        for ep in episodes
        for tick in ep["mutation_ticks"]
    }
    clean_ticks = set(range(total_ticks)) - attack_ticks

    episode_results = []
    for ep in episodes:
        start = int(ep["start_tick"])
        end = int(ep["end_tick"])
        rel = [
            t for t in range(start, end)
            if bool(rows[t]["relational_alert"])
        ]
        legacy = [
            t for t in range(start, end)
            if bool(rows[t]["legacy_count_status_alert"])
        ]
        episode_results.append(
            {
                "episode": int(ep["episode"]),
                "kind": ep["kind"],
                "duration_bin": ep["duration_bin"],
                "density_bin": ep["density_bin"],
                "relational_detected": bool(rel),
                "legacy_detected": bool(legacy),
                "relational_delay": rel[0] - start if rel else end - start,
                "legacy_delay": legacy[0] - start if legacy else end - start,
            }
        )

    relational_alert_ticks = {
        tick for tick, row in rows.items() if row["relational_alert"]
    }
    legacy_alert_ticks = {
        tick
        for tick, row in rows.items()
        if row["legacy_count_status_alert"]
    }

    return {
        "seed": seed,
        "episode_total": len(episodes),
        "relational_detected": sum(
            int(row["relational_detected"]) for row in episode_results
        ),
        "legacy_detected": sum(
            int(row["legacy_detected"]) for row in episode_results
        ),
        "relational_recall": statistics.mean(
            row["relational_detected"] for row in episode_results
        ),
        "legacy_recall": statistics.mean(
            row["legacy_detected"] for row in episode_results
        ),
        "relational_mean_delay": statistics.mean(
            row["relational_delay"] for row in episode_results
        ),
        "legacy_mean_delay": statistics.mean(
            row["legacy_delay"] for row in episode_results
        ),
        "relational_mutation_tick_coverage": (
            len(relational_alert_ticks & mutation_ticks)
            / max(1, len(mutation_ticks))
        ),
        "legacy_mutation_tick_coverage": (
            len(legacy_alert_ticks & mutation_ticks)
            / max(1, len(mutation_ticks))
        ),
        "relational_false_alarm_count": len(
            relational_alert_ticks & clean_ticks
        ),
        "legacy_false_alarm_count": len(legacy_alert_ticks & clean_ticks),
        "clean_tick_count": len(clean_ticks),
        "mutation_tick_count": len(mutation_ticks),
        "episode_results": episode_results,
        "collector_sequence": int(verdict["collector_sequence"]),
        "policy_sha256": evidence["policy_sha256"],
        "collector_public_key_sha256": evidence[
            "collector_public_key_sha256"
        ],
        "verifier_public_key_sha256": evidence[
            "verifier_public_key_sha256"
        ],
        "collector_service_revision": evidence[
            "collector_service_revision"
        ],
        "verifier_service_revision": evidence[
            "verifier_service_revision"
        ],
        "native_nrf_source_sha256": evidence[
            "native_nrf_source_sha256"
        ],
    }


def stratified(rows: list[dict], field: str) -> dict:
    groups: dict[str, dict[str, list[bool]]] = {}
    for row in rows:
        for ep in row["episode_results"]:
            key = str(ep[field])
            groups.setdefault(key, {"relational": [], "legacy": []})
            groups[key]["relational"].append(
                bool(ep["relational_detected"])
            )
            groups[key]["legacy"].append(bool(ep["legacy_detected"]))

    out = {}
    for key, values in sorted(groups.items()):
        n = len(values["relational"])
        rel = sum(values["relational"])
        leg = sum(values["legacy"])
        out[key] = {
            "total": n,
            "relational_detected": rel,
            "relational_recall": rel / n,
            "relational_wilson95": wilson_interval(rel, n),
            "legacy_detected": leg,
            "legacy_recall": leg / n,
        }
    return out


def summarize(rows: list[dict]) -> dict:
    policies = {r["policy_sha256"] for r in rows}
    collector_keys = {r["collector_public_key_sha256"] for r in rows}
    verifier_keys = {r["verifier_public_key_sha256"] for r in rows}
    collector_revs = {r["collector_service_revision"] for r in rows}
    verifier_revs = {r["verifier_service_revision"] for r in rows}
    nrf_sources = {r["native_nrf_source_sha256"] for r in rows}

    if any(
        len(values) != 1
        for values in (
            policies,
            collector_keys,
            verifier_keys,
            collector_revs,
            verifier_revs,
            nrf_sources,
        )
    ):
        raise AssertionError("Stage34 trust/code identity changed across runners")

    total = sum(r["episode_total"] for r in rows)
    relational_detected = sum(r["relational_detected"] for r in rows)
    legacy_detected = sum(r["legacy_detected"] for r in rows)
    clean_ticks = sum(r["clean_tick_count"] for r in rows)
    rel_fa = sum(r["relational_false_alarm_count"] for r in rows)
    leg_fa = sum(r["legacy_false_alarm_count"] for r in rows)
    mutation_ticks = sum(r["mutation_tick_count"] for r in rows)

    gains = [r["relational_recall"] - r["legacy_recall"] for r in rows]
    sequences = [r["collector_sequence"] for r in rows]
    if len(set(sequences)) != len(sequences):
        raise AssertionError("collector sequence values are not unique")

    return {
        "independent_external_runs": len(rows),
        "seeds": [r["seed"] for r in rows],
        "total_attack_episodes": total,
        "relational": {
            "detected": relational_detected,
            "recall": relational_detected / total,
            "wilson95": wilson_interval(relational_detected, total),
            "mean_delay_ticks": statistics.mean(
                r["relational_mean_delay"] for r in rows
            ),
            "mutation_tick_coverage": (
                sum(
                    r["relational_mutation_tick_coverage"]
                    * r["mutation_tick_count"]
                    for r in rows
                )
                / mutation_ticks
            ),
            "false_alarm_count": rel_fa,
            "clean_tick_count": clean_ticks,
            "false_alarms_per_1000": 1000 * rel_fa / max(1, clean_ticks),
        },
        "legacy_count_status": {
            "detected": legacy_detected,
            "recall": legacy_detected / total,
            "wilson95": wilson_interval(legacy_detected, total),
            "mean_delay_ticks": statistics.mean(
                r["legacy_mean_delay"] for r in rows
            ),
            "mutation_tick_coverage": (
                sum(
                    r["legacy_mutation_tick_coverage"]
                    * r["mutation_tick_count"]
                    for r in rows
                )
                / mutation_ticks
            ),
            "false_alarm_count": leg_fa,
            "clean_tick_count": clean_ticks,
            "false_alarms_per_1000": 1000 * leg_fa / max(1, clean_ticks),
        },
        "paired_recall_gain": {
            "runner_mean": statistics.mean(gains),
            "runner_cluster_bootstrap_ci95": cluster_bootstrap(
                gains, seed=340034
            ),
        },
        "by_attack_family": stratified(rows, "kind"),
        "by_duration": stratified(rows, "duration_bin"),
        "by_density": stratified(rows, "density_bin"),
        "policy_sha256": next(iter(policies)),
        "collector_public_key_sha256": next(iter(collector_keys)),
        "verifier_public_key_sha256": next(iter(verifier_keys)),
        "collector_service_revision": next(iter(collector_revs)),
        "verifier_service_revision": next(iter(verifier_revs)),
        "native_nrf_source_sha256": next(iter(nrf_sources)),
        "collector_sequence_min": min(sequences),
        "collector_sequence_max": max(sequences),
        "replay_rejected_runs": len(rows),
        "tamper_rejected_runs": len(rows),
    }


def markdown(s: dict) -> str:
    rel = s["relational"]
    leg = s["legacy_count_status"]
    gain = s["paired_recall_gain"]
    lines = [
        "# Stage 34 — external relational collector experiment",
        "",
        (
            f"Independent external Open5GS runs: "
            f"**{s['independent_external_runs']}**; "
            f"count-preserving attack episodes: "
            f"**{s['total_attack_episodes']}**."
        ),
        "",
        "| Detector | Event recall | Wilson 95% | Mutation coverage | Mean delay | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|---:|",
        (
            f"| Legacy count/status invariant | "
            f"{leg['recall']:.3f} "
            f"({leg['detected']}/{s['total_attack_episodes']}) | "
            f"[{leg['wilson95'][0]:.3f}, {leg['wilson95'][1]:.3f}] | "
            f"{leg['mutation_tick_coverage']:.3f} | "
            f"{leg['mean_delay_ticks']:.2f} | "
            f"{leg['false_alarms_per_1000']:.3f} |"
        ),
        (
            f"| Identity-bound relational verifier | "
            f"{rel['recall']:.3f} "
            f"({rel['detected']}/{s['total_attack_episodes']}) | "
            f"[{rel['wilson95'][0]:.3f}, {rel['wilson95'][1]:.3f}] | "
            f"{rel['mutation_tick_coverage']:.3f} | "
            f"{rel['mean_delay_ticks']:.2f} | "
            f"{rel['false_alarms_per_1000']:.3f} |"
        ),
        "",
        (
            "Paired runner-level recall gain: "
            f"**{gain['runner_mean']:+.3f}**, 95% runner-cluster bootstrap "
            f"[{gain['runner_cluster_bootstrap_ci95'][0]:+.3f}, "
            f"{gain['runner_cluster_bootstrap_ci95'][1]:+.3f}]."
        ),
        (
            f"Signed collector/verifier tamper checks passed on "
            f"**{s['tamper_rejected_runs']}/{s['independent_external_runs']}** "
            f"runs; verifier replay checks rejected "
            f"**{s['replay_rejected_runs']}/{s['independent_external_runs']}** "
            "replays."
        ),
        "",
        "## Attack-family stratification",
        "",
        "| Family | Legacy | Relational | Relational Wilson 95% |",
        "|---|---:|---:|---:|",
    ]
    for name, row in s["by_attack_family"].items():
        ci = row["relational_wilson95"]
        lines.append(
            f"| {name} | {row['legacy_recall']:.3f} "
            f"({row['legacy_detected']}/{row['total']}) | "
            f"{row['relational_recall']:.3f} "
            f"({row['relational_detected']}/{row['total']}) | "
            f"[{ci[0]:.3f}, {ci[1]:.3f}] |"
        )

    lines.extend(
        [
            "",
            "## Trust boundary",
            "",
            (
                "Open5GS NRF/SCP/NSSF execution and telemetry collection "
                "occurred inside the external collector service. GitHub "
                "Actions did not construct the telemetry rows; it transported "
                "an ECDSA-signed collector package to the separate relational "
                "verifier."
            ),
            (
                "The relational verifier never received private attack labels. "
                "It verified the collector signature, enforced a unique nonce "
                "and monotonic collector sequence in the verifier process, "
                "compared identity-bound profiles against the clean external "
                "baseline, and returned its own signed verdict."
            ),
            (
                "This is software-separated external collection and decision, "
                "not hardware remote attestation. A compromise of the Render "
                "control plane or both external services remains outside the "
                "validated model."
            ),
            "",
            f"Policy SHA-256: {s['policy_sha256']}.",
            f"Collector public-key SHA-256: {s['collector_public_key_sha256']}.",
            f"Verifier public-key SHA-256: {s['verifier_public_key_sha256']}.",
            f"Native NRF source SHA-256: {s['native_nrf_source_sha256']}.",
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage34_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    verdicts = load_by_seed(root, "relational_verdict.json")
    evidence = load_by_seed(root, "external_evidence.json")

    expected = set(EXPECTED_SEEDS)
    if any(set(group) != expected for group in (labels, verdicts, evidence)):
        raise AssertionError("Stage34 requires all 32 preregistered runs")

    rows = [
        score(labels[seed], verdicts[seed], evidence[seed])
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
    report = markdown(summary)
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
