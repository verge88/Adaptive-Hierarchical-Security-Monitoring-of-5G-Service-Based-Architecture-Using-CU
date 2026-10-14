"""Stage 27 post-hoc audit: common-source failure and signed recovery."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import statistics

EXPECTED_SEEDS = tuple(range(9401, 9409))
CHANNEL_KEYS = {
    "directional": "stage17_directional_alert",
    "sparse": "stage19_sparse_directional_alert",
    "structural": "stage20_structural_alert",
    "semantic": "stage21_semantic_alert",
    "combined": "stage21_combined_alert",
}


def paired_ci(values, *, seed, n_boot=5000):
    rng = random.Random(seed)
    n = len(values)
    draws = sorted(
        statistics.mean(values[rng.randrange(n)] for _ in range(n))
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
            raise AssertionError(f"Duplicate {filename} for seed {seed}")
        output[seed] = doc
    return output


def score(labels: dict, detector: dict) -> dict:
    warmup = int(labels["warmup_ticks"])
    total = int(labels["total_ticks"])
    episodes = labels["episodes"]
    episode_ticks = {
        tick
        for episode in episodes
        for tick in range(
            int(episode["start_tick"]),
            int(episode["end_tick"]),
        )
    }
    clean_ticks = set(range(warmup, total)) - episode_ticks
    rows = {int(row["tick"]): row for row in detector["ticks"]}
    if set(rows) != set(range(total)):
        raise AssertionError("Incomplete Stage27 alarm stream")

    output = {}
    for channel, key in CHANNEL_KEYS.items():
        alerts = {
            tick
            for tick, row in rows.items()
            if bool(row.get(key, False))
        }
        event_rows = []
        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(t for t in alerts if start <= t < end)
            event_rows.append(
                {
                    "detected": bool(inside),
                    "delay_ticks": (
                        inside[0] - start if inside else end - start
                    ),
                }
            )
        output[channel] = {
            "event_recall": statistics.mean(
                row["detected"] for row in event_rows
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["delay_ticks"] for row in event_rows
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * len(alerts & clean_ticks)
                / max(1, len(clean_ticks))
            ),
        }
    return output


def evaluate_seed(
    labels: dict,
    alarms: dict,
    capture_prov: dict,
    attest_prov: dict,
) -> dict:
    seed = int(labels["seed"])
    docs = (alarms, capture_prov, attest_prov)
    if any(int(doc["seed"]) != seed for doc in docs):
        raise AssertionError("Stage27 artifact seed mismatch")
    if int(labels["stage"]) != 27 or int(capture_prov["stage"]) != 27:
        raise AssertionError("Stage27 stage marker mismatch")
    if labels["native_nrf_inprocess_log_marker_count"] != 72:
        raise AssertionError("Stage27 requires 72 native NRF mutations")

    required = (
        capture_prov["open5gs_source_ref"] == "v2.7.6"
        and capture_prov["all_common_source_rows_equal"]
        and not capture_prov["signed_attestation_available_to_capture_job"]
        and attest_prov["attestation_signature_verified"]
        and attest_prov["attestation_algorithm"] == "Ed25519"
        and not attest_prov["authority_private_key_available_to_verifier"]
        and not attest_prov["authority_private_key_uploaded"]
        and attest_prov["pairwise_common_source_equal_in_raw_input"]
        and attest_prov["manifest_expected_nssf_count"] == 2
        and attest_prov["manifest_expected_registered_count"] == 2
    )
    if not required:
        raise AssertionError("Stage27 trust-domain audit failed")

    return {
        "seed": seed,
        "native_nrf_binary_sha256": capture_prov[
            "native_nrf_binary_sha256"
        ],
        "instrumented_nrf_source_sha256": capture_prov[
            "instrumented_nrf_source_sha256"
        ],
        "manifest_sha256": attest_prov["manifest_sha256"],
        "public_key_sha256": attest_prov["public_key_sha256"],
        "attested_reference": score(
            labels, alarms["external_reference"]
        ),
        "compromised_pair": score(
            labels, alarms["common_path_control"]
        ),
    }


def summarize(rows: list[dict]) -> dict:
    manifests = {row["manifest_sha256"] for row in rows}
    public_keys = {row["public_key_sha256"] for row in rows}
    nrf_sources = {
        row["instrumented_nrf_source_sha256"] for row in rows
    }
    if len(manifests) != 1 or len(public_keys) != 1:
        raise AssertionError(
            "Stage27 runners did not share one authority attestation"
        )
    if len(nrf_sources) != 1:
        raise AssertionError("Stage27 runners used different NRF source")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "episodes_per_runner": 6,
        "native_nrf_mutations_per_runner": 72,
        "manifest_sha256": next(iter(manifests)),
        "authority_public_key_sha256": next(iter(public_keys)),
        "instrumented_nrf_source_sha256": next(iter(nrf_sources)),
        "attested_reference": {},
        "compromised_pair": {},
    }

    for channel in CHANNEL_KEYS:
        att = [
            row["attested_reference"][channel]["event_recall"]
            for row in rows
        ]
        pair = [
            row["compromised_pair"][channel]["event_recall"]
            for row in rows
        ]
        summary["attested_reference"][channel] = {
            "event_recall": statistics.mean(att),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["attested_reference"][channel][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["attested_reference"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }
        summary["compromised_pair"][channel] = {
            "event_recall": statistics.mean(pair),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                row["compromised_pair"][channel][
                    "mean_horizon_penalized_delay_ticks"
                ]
                for row in rows
            ),
            "false_alarms_per_1000_clean_ticks": statistics.mean(
                row["compromised_pair"][channel][
                    "false_alarms_per_1000_clean_ticks"
                ]
                for row in rows
            ),
        }

    gains = [
        row["attested_reference"]["combined"]["event_recall"]
        - row["compromised_pair"]["combined"]["event_recall"]
        for row in rows
    ]
    summary["attestation_recovery_gain"] = {
        "combined_event_recall_difference": statistics.mean(gains),
        "combined_event_recall_difference_ci95": paired_ci(
            gains, seed=270027
        ),
    }
    return summary


def markdown(summary: dict) -> str:
    att = summary["attested_reference"]
    pair = summary["compromised_pair"]
    gain = summary["attestation_recovery_gain"]
    lines = [
        "# Stage 27 — common-source compromise with software-rooted attestation",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            f"Episodes: **{summary['episodes_per_runner']} per runner**; "
            f"native NRF in-process mutations: "
            f"**{summary['native_nrf_mutations_per_runner']} per runner**."
        ),
        "",
        "| Frozen channel | Signed attestation recall | Colluding NRF+witness recall | Penalized delay (attested) | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|",
    ]
    for channel in (
        "directional", "sparse", "structural", "semantic", "combined"
    ):
        lines.append(
            f"| {channel} | "
            f"{att[channel]['event_recall']:.3f} | "
            f"{pair[channel]['event_recall']:.3f} | "
            f"{att[channel]['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{att[channel]['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    lines.extend(
        [
            "",
            (
                "Combined recall recovery from the independent signed "
                f"attestation domain: "
                f"**{gain['combined_event_recall_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{gain['combined_event_recall_difference_ci95'][0]:+.3f}, "
                f"{gain['combined_event_recall_difference_ci95'][1]:+.3f}]."
            ),
            "",
            "## Attestation provenance",
            "",
            (
                f"Canonical signed manifest SHA-256: "
                f"{summary['manifest_sha256']}."
            ),
            (
                f"Ephemeral authority public-key SHA-256: "
                f"{summary['authority_public_key_sha256']}."
            ),
            (
                "Instrumented native NRF source SHA-256: "
                f"{summary['instrumented_nrf_source_sha256']}."
            ),
            "",
            "## Interpretation boundary",
            "",
            (
                "The ordinary pairwise observer is intentionally defeated: "
                "the compromised NF-side witness reports the same false NSSF "
                "cardinality as the compromised native NRF. The third branch "
                "uses a canonical manifest signed by an ephemeral Ed25519 key "
                "in a separate GitHub Actions authority job. The private key is "
                "not uploaded and is unavailable to capture, verifier and "
                "blind-detector jobs."
            ),
            (
                "This is a software-rooted trust-domain experiment. It proves "
                "recovery from the modeled NRF+witness common-source failure "
                "under GitHub Actions job isolation and signed-artifact "
                "verification. It is not TPM/TEE remote attestation and does "
                "not protect against compromise of the GitHub Actions control "
                "plane or the authority job itself."
            ),
            "",
        ]
    )
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", default="stage27_report")
    args = parser.parse_args()

    root = Path(args.input)
    labels = load_by_seed(root, "private_labels.json")
    alarms = load_by_seed(root, "alarms.json")
    capture = load_by_seed(root, "provenance.json")
    attest = load_by_seed(root, "attestation_provenance.json")

    expected = set(EXPECTED_SEEDS)
    if any(
        set(group) != expected
        for group in (labels, alarms, capture, attest)
    ):
        raise AssertionError(
            "Stage27 requires all eight preregistered runners"
        )

    rows = [
        evaluate_seed(
            labels[seed],
            alarms[seed],
            capture[seed],
            attest[seed],
        )
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
