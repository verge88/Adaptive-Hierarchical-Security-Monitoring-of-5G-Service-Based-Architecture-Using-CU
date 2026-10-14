"""Stage 27 post-hoc audit: coordinated false state vs signed third domain."""
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
        if "seed" not in doc:
            continue
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
        raise AssertionError("Incomplete Stage27 detector stream")

    result = {}
    for channel, key in CHANNEL_KEYS.items():
        alerts = {
            tick for tick, row in rows.items() if bool(row.get(key, False))
        }
        events = []
        for episode in episodes:
            start = int(episode["start_tick"])
            end = int(episode["end_tick"])
            inside = sorted(t for t in alerts if start <= t < end)
            events.append(
                {
                    "detected": bool(inside),
                    "delay_ticks": inside[0] - start if inside else end - start,
                }
            )

        result[channel] = {
            "event_recall": statistics.mean(
                event["detected"] for event in events
            ),
            "mean_horizon_penalized_delay_ticks": statistics.mean(
                event["delay_ticks"] for event in events
            ),
            "false_alarms_per_1000_clean_ticks": (
                1000 * len(alerts & clean_ticks) / max(1, len(clean_ticks))
            ),
        }
    return result


def evaluate_seed(labels: dict, alarms: dict, provenance: dict) -> dict:
    seed = int(labels["seed"])
    if int(alarms["seed"]) != seed or int(provenance["seed"]) != seed:
        raise AssertionError("Stage27 artifact seed mismatch")
    if int(labels["stage"]) != 27 or int(provenance["stage"]) != 27:
        raise AssertionError("Stage27 stage marker mismatch")

    protocol = alarms["protocol"]
    required = (
        labels["coordinated_false_state"]
        and provenance["nrf_false_state_generated_in_native_process"]
        and provenance["nf_witness_false_state_generated_separately"]
        and not provenance["nf_witness_false_state_copies_consumer_response"]
        and provenance["coordinated_pair_exact_fraction"] == 1.0
        and not provenance["attestation_manifest_received_by_capture_job"]
        and not provenance["attestation_private_key_received_by_capture_job"]
        and protocol["attestation_signature_verified"]
        and not protocol["attestation_private_key_received"]
        and not protocol["private_labels_received"]
        and not protocol["detector_retuned_for_stage27"]
    )
    if not required:
        raise AssertionError("Stage27 trust-domain/provenance audit failed")

    return {
        "seed": seed,
        "native_nrf_binary_sha256": provenance[
            "native_nrf_binary_sha256"
        ],
        "instrumented_nrf_source_sha256": provenance[
            "instrumented_nrf_source_sha256"
        ],
        "manifest_sha256": protocol["manifest_sha256"],
        "public_key_sha256": protocol["public_key_sha256"],
        "attested_reference": score(
            labels, alarms["attested_reference"]
        ),
        "compromised_pair": score(
            labels, alarms["compromised_pair"]
        ),
    }


def summarize(rows: list[dict]) -> dict:
    manifest_hashes = {row["manifest_sha256"] for row in rows}
    public_keys = {row["public_key_sha256"] for row in rows}
    nrf_sources = {row["instrumented_nrf_source_sha256"] for row in rows}
    nrf_binaries = {row["native_nrf_binary_sha256"] for row in rows}
    if len(manifest_hashes) != 1 or len(public_keys) != 1:
        raise AssertionError(
            "Stage27 runners did not use one common signed authority bundle"
        )
    if len(nrf_sources) != 1:
        raise AssertionError("Stage27 runners used different NRF source")

    summary = {
        "independent_live_runners": len(rows),
        "seeds": [row["seed"] for row in rows],
        "episodes_per_runner": 6,
        "native_nrf_mutations_per_runner": 72,
        "manifest_sha256": next(iter(manifest_hashes)),
        "public_key_sha256": next(iter(public_keys)),
        "native_nrf_binary_sha256_values": sorted(nrf_binaries),
        "instrumented_nrf_source_sha256": next(iter(nrf_sources)),
        "attested_reference": {},
        "compromised_pair": {},
    }

    for channel in CHANNEL_KEYS:
        att = [row["attested_reference"][channel]["event_recall"] for row in rows]
        pair = [row["compromised_pair"][channel]["event_recall"] for row in rows]
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
    summary["third_domain_gain"] = {
        "combined_event_recall_difference": statistics.mean(gains),
        "combined_event_recall_difference_ci95": paired_ci(
            gains, seed=270027
        ),
    }
    return summary


def markdown(summary: dict) -> str:
    att = summary["attested_reference"]
    pair = summary["compromised_pair"]
    gain = summary["third_domain_gain"]

    lines = [
        "# Stage 27 — software-attested third trust domain",
        "",
        (
            f"Independent Open5GS runners: "
            f"**{summary['independent_live_runners']}**; "
            f"seeds {summary['seeds'][0]}..{summary['seeds'][-1]}."
        ),
        (
            f"Episodes: **{summary['episodes_per_runner']} per runner**; "
            f"native NRF mutations: "
            f"**{summary['native_nrf_mutations_per_runner']} per runner**."
        ),
        "",
        "| Frozen channel | Signed third-domain recall | Compromised NRF + witness recall | Penalized delay | FA / 1000 clean |",
        "|---|---:|---:|---:|---:|",
    ]
    for channel in (
        "directional", "sparse", "structural", "semantic", "combined"
    ):
        lines.append(
            f"| {channel} | {att[channel]['event_recall']:.3f} | "
            f"{pair[channel]['event_recall']:.3f} | "
            f"{att[channel]['mean_horizon_penalized_delay_ticks']:.2f} | "
            f"{att[channel]['false_alarms_per_1000_clean_ticks']:.3f} |"
        )

    lines.extend(
        [
            "",
            (
                "Combined recall gain from introducing the signed third "
                f"trust domain: **{gain['combined_event_recall_difference']:+.3f}**, "
                "95% runner-cluster bootstrap CI "
                f"[{gain['combined_event_recall_difference_ci95'][0]:+.3f}, "
                f"{gain['combined_event_recall_difference_ci95'][1]:+.3f}]."
            ),
            "",
            "## Cryptographic provenance",
            "",
            (
                "Signed manifest SHA-256: "
                f"{summary['manifest_sha256']}."
            ),
            (
                "Ed25519 public key SHA-256: "
                f"{summary['public_key_sha256']}."
            ),
            (
                "Instrumented native NRF source SHA-256: "
                f"{summary['instrumented_nrf_source_sha256']}."
            ),
            (
                "Native NRF binary SHA-256 values: "
                f"{summary['native_nrf_binary_sha256_values']}."
            ),
            "",
            "## Interpretation boundary",
            "",
            (
                "The ordinary pair is intentionally information-theoretically "
                "blind: the compromised NRF and the independently generated "
                "compromised NF-witness layer expose exactly the same false "
                "three-NSSF state. Detection is restored only when the blind "
                "job verifies an Ed25519-signed two-NSSF deployment-state "
                "contract produced in a separate GitHub Actions authority job."
            ),
            (
                "This is software-rooted attestation. It demonstrates a third "
                "cryptographically separated workflow trust domain, but it is "
                "not TPM/TEE proof of the live NF runtime. Hardware-rooted "
                "runtime attestation remains a stronger future trust level."
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
    provenance = load_by_seed(root, "provenance.json")

    expected = set(EXPECTED_SEEDS)
    if (
        set(labels) != expected
        or set(alarms) != expected
        or set(provenance) != expected
    ):
        raise AssertionError("Stage27 requires all eight preregistered runners")

    rows = [
        evaluate_seed(labels[seed], alarms[seed], provenance[seed])
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
