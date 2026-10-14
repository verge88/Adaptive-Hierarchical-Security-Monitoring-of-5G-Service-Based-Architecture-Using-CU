"""Stage31 GitHub-anchored authority-bundle tests."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from research.stage30_attestation import project
from research.stage30_authority import build_epoch_manifests
from research.stage31_attestation import load_github_verification
from research.stage31_live_detect import detect


def synthetic_raw() -> list[dict]:
    rows = []
    for tick in range(70):
        if tick < 30:
            count = registered = 2
            epoch = 0
        elif tick < 40:
            count = registered = 1
            epoch = 1
        elif tick < 45:
            count = registered = 2
            epoch = 2
        else:
            count = registered = 2
            epoch = 3

        if tick == 55:
            count = registered = 3

        rows.append(
            {
                "seed": 99801,
                "tick": tick,
                "witness_first": tick % 2 == 0,
                "baseline_epoch": epoch,
                "consumer_nssf_count": count,
                "consumer_registered_count": registered,
                "compromised_witness_nssf_count": count,
                "compromised_witness_registered_count": registered,
                "common_source_equal": True,
            }
        )
    return rows


class Stage31Tests(unittest.TestCase):
    def test_github_verification_marker_requires_success_and_tamper_rejection(self):
        good = {
            "github_artifact_attestation_verified": True,
            "tampered_bundle_rejected": True,
            "repository": "owner/repo",
            "source_digest": "abc123",
            "signer_workflow": "owner/repo/.github/workflows/stage31.yml",
            "authority_bundle_sha256": "a" * 64,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "marker.json"
            path.write_text(json.dumps(good), encoding="utf8")
            self.assertEqual(
                load_github_verification(path)["repository"],
                "owner/repo",
            )

            bad = dict(good)
            bad["tampered_bundle_rejected"] = False
            path.write_text(json.dumps(bad), encoding="utf8")
            with self.assertRaises(ValueError):
                load_github_verification(path)

    def test_stage31_detector_remains_stage29_rule(self):
        manifests = build_epoch_manifests(Path("."))
        attested, compromised = project(synthetic_raw(), manifests)
        result = detect(attested, compromised)

        self.assertTrue(
            result["external_reference"]["ticks"][55][
                "stage29_augmented_alert"
            ]
        )
        self.assertFalse(
            any(
                row["stage29_augmented_alert"]
                for row in result["common_path_control"]["ticks"]
            )
        )
        self.assertFalse(
            result["protocol"]["detector_retuned_for_stage31"]
        )
        self.assertTrue(
            result["protocol"]["stage30_freshness_protocol_frozen_for_stage31"]
        )

    def test_legitimate_transition_ticks_remain_clean(self):
        manifests = build_epoch_manifests(Path("."))
        raw = synthetic_raw()
        raw[55]["consumer_nssf_count"] = 2
        raw[55]["consumer_registered_count"] = 2
        raw[55]["compromised_witness_nssf_count"] = 2
        raw[55]["compromised_witness_registered_count"] = 2

        attested, compromised = project(raw, manifests)
        result = detect(attested, compromised)
        ext = result["external_reference"]["ticks"]
        for tick in range(30, 50):
            self.assertFalse(ext[tick]["stage29_augmented_alert"])

    def test_authority_chain_is_same_stage30_design(self):
        manifests = build_epoch_manifests(Path("."))
        self.assertEqual([m["epoch"] for m in manifests], [0, 1, 2, 3])
        self.assertEqual(
            [m["expected_nssf_count"] for m in manifests],
            [2, 1, 2, 2],
        )


if __name__ == "__main__":
    unittest.main()
