"""Stage33 independent external-verifier tests."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from research.stage33_policy import build_policy, canonical_bytes
from research.stage33_external_client import verify_signature


def load_service_module(policy_sha256: str):
    key = ec.generate_private_key(ec.SECP256R1())
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")
    os.environ["STAGE33_PRIVATE_KEY_PEM"] = private_pem
    os.environ["STAGE33_APPROVED_POLICY_SHA256"] = policy_sha256
    os.environ["STAGE33_SERVICE_REVISION"] = "unit-test"
    spec = importlib.util.spec_from_file_location(
        "stage33_render_verifier_test",
        "stage33/render_verifier.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def synthetic_rows():
    rows = []
    for tick in range(70):
        if 30 <= tick < 40:
            count = registered = 1
            epoch = 1
        elif 40 <= tick < 45:
            count = registered = 2
            epoch = 2
        elif tick >= 45:
            count = registered = 2
            epoch = 3
        else:
            count = registered = 2
            epoch = 0

        if tick == 55:
            count = registered = 3

        rows.append({
            "seed": 19901,
            "tick": tick,
            "baseline_epoch": epoch,
            "consumer_nssf_count": count,
            "consumer_registered_count": registered,
            "compromised_witness_nssf_count": count,
            "compromised_witness_registered_count": registered,
            "common_source_equal": True,
        })
    return rows


class Stage33Tests(unittest.TestCase):
    def test_policy_is_deterministic(self):
        a = canonical_bytes(build_policy(Path(".")))
        b = canonical_bytes(build_policy(Path(".")))
        self.assertEqual(a, b)
        self.assertIn(b"Render web service with auto-deploy disabled", a)

    def test_external_service_detects_attack_and_keeps_transition_clean(self):
        policy_raw = canonical_bytes(build_policy(Path(".")))
        policy_sha = hashlib.sha256(policy_raw).hexdigest()
        module = load_service_module(policy_sha)

        request = {
            "stage": 33,
            "policy_sha256": policy_sha,
            "request_nonce": "0123456789abcdef0123456789abcdef",
            "raw_telemetry": synthetic_rows(),
        }
        response = module.verify_request(request)
        verdict = response["verdict"]

        self.assertEqual(verdict["legitimate_transition_alert_rows"], 0)
        self.assertEqual(verdict["colluding_pair_alert_rows"], 0)
        self.assertTrue(verdict["alerts"][55]["external_invariant_alert"])
        self.assertFalse(verdict["alerts"][30]["external_invariant_alert"])
        self.assertFalse(verdict["alerts"][40]["external_invariant_alert"])
        self.assertFalse(verdict["alerts"][45]["external_invariant_alert"])

        verify_signature(
            module.PUBLIC_KEY_PEM,
            verdict,
            response["signature_base64"],
        )

    def test_policy_mismatch_is_rejected(self):
        policy_raw = canonical_bytes(build_policy(Path(".")))
        policy_sha = hashlib.sha256(policy_raw).hexdigest()
        module = load_service_module(policy_sha)

        request = {
            "stage": 33,
            "policy_sha256": "0" * 64,
            "request_nonce": "0123456789abcdef0123456789abcdef",
            "raw_telemetry": synthetic_rows(),
        }
        with self.assertRaises(PermissionError):
            module.verify_request(request)

    def test_tampered_signed_verdict_fails(self):
        policy_raw = canonical_bytes(build_policy(Path(".")))
        policy_sha = hashlib.sha256(policy_raw).hexdigest()
        module = load_service_module(policy_sha)

        request = {
            "stage": 33,
            "policy_sha256": policy_sha,
            "request_nonce": "0123456789abcdef0123456789abcdef",
            "raw_telemetry": synthetic_rows(),
        }
        response = module.verify_request(request)
        verdict = response["verdict"]

        tampered = json.loads(json.dumps(verdict))
        tampered["external_alert_rows"] += 1
        with self.assertRaises(InvalidSignature):
            verify_signature(
                module.PUBLIC_KEY_PEM,
                tampered,
                response["signature_base64"],
            )


if __name__ == "__main__":
    unittest.main()
