"""Stage33 external-verifier invariants."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from research.stage33_external_verifier import (
    project_from_policy,
    validate_policy,
    verify_request_and_detect,
)
from research.stage33_policy_bundle import (
    build_policy,
    canonical_bytes,
)
from research.stage33_verify_verdict import verify_response


def synthetic_raw() -> list[dict]:
    rows = []
    for tick in range(70):
        if tick < 30:
            count = registered = 2
        elif tick < 40:
            count = registered = 1
        else:
            count = registered = 2
        if tick == 55:
            count = registered = 3
        rows.append(
            {
                "seed": 99901,
                "tick": tick,
                "witness_first": tick % 2 == 0,
                "consumer_nssf_count": count,
                "consumer_registered_count": registered,
                "compromised_witness_nssf_count": count,
                "compromised_witness_registered_count": registered,
                "common_source_equal": True,
            }
        )
    return rows


class Stage33Tests(unittest.TestCase):
    def test_policy_measurements_match_external_verifier(self):
        policy = build_policy(Path("."))
        validate_policy(policy, Path("."))
        self.assertEqual(policy["stage"], 33)
        self.assertIn(
            "research/stage33_external_verifier.py",
            policy["measurements_sha256"],
        )

    def test_external_projection_uses_signed_epochs_not_capture_epoch_marker(self):
        policy = build_policy(Path("."))
        rows = synthetic_raw()
        rows[30]["baseline_epoch"] = 999
        attested, compromised = project_from_policy(rows, policy)
        self.assertEqual(attested[30]["trusted_nssf_profiles"], 1)
        self.assertEqual(attested[40]["trusted_nssf_profiles"], 2)
        self.assertEqual(
            attested[30]["stage33_external_policy_epoch"],
            1,
        )
        self.assertEqual(
            compromised[30]["stage33_external_policy_epoch"],
            1,
        )

    def test_external_service_computes_and_signs_detector_verdict(self):
        policy = build_policy(Path("."))
        raw_rows = synthetic_raw()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            policy_path = root / "policy.json"
            kms_private = root / "kms-private.pem"
            kms_public = root / "kms-public.pem"
            kms_signature = root / "kms-signature.der"
            receipt_path = root / "receipt.json"
            verdict_private = root / "verdict-private.pem"
            response_path = root / "response.json"
            raw_path = root / "raw.json"

            policy_path.write_bytes(canonical_bytes(policy))
            raw_path.write_text(
                json.dumps(raw_rows, indent=2),
                encoding="utf8",
            )

            subprocess.run(
                [
                    "openssl",
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    str(kms_private),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(kms_private),
                    "-pubout",
                    "-out",
                    str(kms_public),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl",
                    "dgst",
                    "-sha256",
                    "-sign",
                    str(kms_private),
                    "-out",
                    str(kms_signature),
                    str(policy_path),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl",
                    "genpkey",
                    "-algorithm",
                    "ED25519",
                    "-out",
                    str(verdict_private),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            digest = hashlib.sha256(
                policy_path.read_bytes()
            ).hexdigest()
            key_arn = (
                "arn:aws:kms:eu-north-1:111122223333:key/stage33-test"
            )
            receipt = {
                "stage": 32,
                "digest_sha256": digest,
                "approved_digest": digest,
                "approval_source": "external_ssm_allowlist",
                "kms_key_arn": key_arn,
                "signing_algorithm": "ECDSA_SHA_256",
                "signature_base64": base64.b64encode(
                    kms_signature.read_bytes()
                ).decode("ascii"),
            }
            receipt_path.write_text(
                json.dumps(receipt),
                encoding="utf8",
            )
            kms_public_hash = hashlib.sha256(
                kms_public.read_bytes()
            ).hexdigest()

            request = {
                "raw_telemetry": raw_rows,
                "policy_json_base64": base64.b64encode(
                    policy_path.read_bytes()
                ).decode("ascii"),
                "kms_receipt_json_base64": base64.b64encode(
                    receipt_path.read_bytes()
                ).decode("ascii"),
                "kms_public_key_pem_base64": base64.b64encode(
                    kms_public.read_bytes()
                ).decode("ascii"),
            }
            response = verify_request_and_detect(
                request,
                repo_root=Path("."),
                expected_kms_key_arn=key_arn,
                expected_kms_public_key_sha256=kms_public_hash,
                expected_policy_sha256=digest,
                verdict_private_key_pem=verdict_private.read_bytes(),
            )
            response_path.write_text(
                json.dumps(response, indent=2),
                encoding="utf8",
            )

            verified = verify_response(
                response_path=response_path,
                raw_telemetry_path=raw_path,
                expected_verifier_public_key_sha256=response[
                    "verifier_public_key_sha256"
                ],
                expected_policy_sha256=digest,
            )
            ticks = verified["detector"]["external_reference"]["ticks"]
            self.assertTrue(
                ticks[55]["stage29_augmented_alert"]
            )
            self.assertFalse(
                any(
                    row["stage29_augmented_alert"]
                    for row in verified["detector"][
                        "common_path_control"
                    ]["ticks"]
                )
            )

    def test_private_attack_labels_are_rejected(self):
        policy = build_policy(Path("."))
        rows = synthetic_raw()
        rows[0]["mutation_ticks"] = [55]
        with self.assertRaises(ValueError):
            # Validation happens before any external-root material is decoded.
            verify_request_and_detect(
                {
                    "raw_telemetry": rows,
                },
                repo_root=Path("."),
                expected_kms_key_arn="unused",
                expected_kms_public_key_sha256="unused",
                expected_policy_sha256="unused",
                verdict_private_key_pem=b"unused",
            )


if __name__ == "__main__":
    unittest.main()
