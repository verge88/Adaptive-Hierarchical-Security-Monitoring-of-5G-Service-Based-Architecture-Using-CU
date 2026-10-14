"""Stage 29 blind detector with one preregistered attested-invariant channel.

Stage-28 exploratory analysis showed that all 15 combined false negatives were
low-amplitude single-profile/state changes; 13/15 were short, 10/15 were status
substitutions, and every miss had multiplicity one. The frozen Stage-21 stack
was therefore not retuned.

Instead Stage 29 adds a logically distinct channel that is valid only when the
reference is cryptographically verified: a single-sample mismatch in the
signed discrete NSSF invariants is itself evidence. The held-out Stage-29
labels are unavailable to this module.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .stage27_live_detect import detect as frozen_stage21_detect


def attested_invariant_mismatch(row: dict) -> bool:
    if not bool(row.get("stage29_attestation_verified_reference", False)):
        return False

    count_mismatch = (
        int(row["trusted_nssf_profiles"])
        != int(row["consumer_nssf_profiles"])
    )
    semantic_mismatch = (
        row["trusted_semantic"] != row["consumer_semantic"]
    )
    return count_mismatch or semantic_mismatch


def decorate(rows: list[dict], frozen_ticks: list[dict]) -> list[dict]:
    if len(rows) != len(frozen_ticks):
        raise AssertionError("Stage29 detector stream length mismatch")

    output = []
    for source, tick in zip(rows, frozen_ticks):
        if int(source["tick"]) != int(tick["tick"]):
            raise AssertionError("Stage29 detector tick mismatch")
        enriched = dict(tick)
        invariant = attested_invariant_mismatch(source)
        enriched["stage29_attested_invariant_alert"] = invariant
        enriched["stage29_augmented_alert"] = (
            bool(enriched["stage21_combined_alert"]) or invariant
        )
        output.append(enriched)
    return output


def detect(
    attested_rows: list[dict],
    compromised_rows: list[dict],
) -> dict:
    result = frozen_stage21_detect(attested_rows, compromised_rows)

    result["external_reference"]["ticks"] = decorate(
        attested_rows,
        result["external_reference"]["ticks"],
    )
    result["common_path_control"]["ticks"] = decorate(
        compromised_rows,
        result["common_path_control"]["ticks"],
    )
    result["protocol"].update(
        {
            "detector_retuned_for_stage29": False,
            "stage29_private_schedule_received": False,
            "stage29_rule_selected_from_stage28_design_set": True,
            "stage29_rule": (
                "verified_attestation AND "
                "(NSSF_count_mismatch OR semantic_projection_mismatch)"
            ),
            "stage29_rule_has_numeric_threshold": False,
            "stage29_evaluation_role": "fresh held-out randomized runners",
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--attested-telemetry", required=True)
    parser.add_argument("--compromised-pair-telemetry", required=True)
    parser.add_argument("--output", default="stage29_detector")
    args = parser.parse_args()

    attested = json.loads(
        Path(args.attested_telemetry).read_text(encoding="utf8")
    )
    compromised = json.loads(
        Path(args.compromised_pair_telemetry).read_text(encoding="utf8")
    )
    result = detect(attested, compromised)

    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "alarms.json").write_text(
        json.dumps(result, indent=2), encoding="utf8"
    )

    ext = result["external_reference"]["ticks"]
    pair = result["common_path_control"]["ticks"]
    print(
        "STAGE29_BLIND_DETECT_OK "
        f"seed={result['seed']} "
        f"legacy={sum(bool(r['stage21_combined_alert']) for r in ext)} "
        f"invariant={sum(bool(r['stage29_attested_invariant_alert']) for r in ext)} "
        f"augmented={sum(bool(r['stage29_augmented_alert']) for r in ext)} "
        f"pair_augmented={sum(bool(r['stage29_augmented_alert']) for r in pair)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
