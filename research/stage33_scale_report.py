"""Stage 33 large-scale replication audit.

This module reuses the frozen Stage-33 scoring implementation and changes only
the preregistered fresh seed block and expected runner count.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage33_report import load_by_seed, score_seed, summarize, markdown

EXPECTED_SEEDS = tuple(range(11001, 11257))
EXPECTED_RUNNERS = 256


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage33_scale_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    verdicts = load_by_seed(root, "external_verdict.json")
    provenance = load_by_seed(root, "provenance.json")

    expected = set(EXPECTED_SEEDS)
    if any(set(group) != expected for group in (labels, verdicts, provenance)):
        missing = {
            "labels": sorted(expected - set(labels)),
            "verdicts": sorted(expected - set(verdicts)),
            "provenance": sorted(expected - set(provenance)),
        }
        raise AssertionError(
            "Stage33 scale replication requires all 256 preregistered "
            f"runners; missing={missing}"
        )

    rows = [
        score_seed(labels[seed], verdicts[seed], provenance[seed])
        for seed in EXPECTED_SEEDS
    ]
    summary = summarize(rows)
    if summary["independent_live_runners"] != EXPECTED_RUNNERS:
        raise AssertionError("Stage33 scale runner count mismatch")

    summary["replication"] = {
        "name": "stage33-scale-256-run-replication",
        "runner_count": EXPECTED_RUNNERS,
        "seed_start": EXPECTED_SEEDS[0],
        "seed_end": EXPECTED_SEEDS[-1],
        "detector_changed": False,
        "attack_generator_changed": False,
        "external_verifier_policy_changed": False,
        "external_verifier_decision_rule_changed": False,
    }

    report = markdown(summary)
    report = report.replace(
        "# Stage 33 — final independent external-verifier iteration",
        "# Stage 33 — 256-run independent external-verifier replication",
        1,
    )
    report += (
        "\n## Replication lock\n\n"
        "This replication used 256 fresh Open5GS runners "
        "(seeds 11001..11256). The Stage-28 randomized attack generator, "
        "Stage-29 invariant semantics, Stage-30 legitimate-transition "
        "schedule, Stage-33 policy, external decision rule, and external "
        "service identity were frozen before this block. Only the number of "
        "fresh independent runners was increased.\n"
    )

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "seed_results.json").write_text(
        json.dumps(rows, indent=2), encoding="utf8"
    )
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf8"
    )
    (output / "REPORT.md").write_text(report, encoding="utf8")
    print(report)


if __name__ == "__main__":
    main()
