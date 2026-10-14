"""Stage34 relational and trust-boundary tests."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from research.stage34_policy import build_policy, canonical_bytes


def private_pem(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def public_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class Stage34Tests(unittest.TestCase):
    def test_policy_is_deterministic_and_count_preserving_families_locked(self):
        a = canonical_bytes(build_policy(Path(".")))
        b = canonical_bytes(build_policy(Path(".")))
        self.assertEqual(a, b)
        text = a.decode("utf8")
        for kind in (
            "identity_swap",
            "identity_replacement",
            "endpoint_substitution",
            "service_injection",
        ):
            self.assertIn(kind, text)
        self.assertIn("preserve NSSF profile count", text)

    def test_native_hook_contains_only_relational_count_preserving_families(self):
        text = Path("live/stage34-nnrf-handler.c").read_text(encoding="utf8")
        for kind in (
            "identity_swap",
            "identity_replacement",
            "endpoint_substitution",
            "service_injection",
        ):
            self.assertIn(kind, text)
        self.assertIn("STAGE34_NATIVE_NRF_RELATIONAL_MUTATION", text)
        self.assertNotIn("phantom_registered", text)
        self.assertNotIn("status_substitution", text)

    def test_relational_projection_sees_state_preserving_mutations(self):
        collector_key = ec.generate_private_key(ec.SECP256R1())
        os.environ["STAGE34_POLICY_SHA256"] = "1" * 64
        os.environ["STAGE34_COLLECTOR_REVISION"] = "unit-test"
        os.environ["STAGE34_COLLECTOR_PRIVATE_KEY_PEM"] = private_pem(
            collector_key
        )
        collector = load_module(
            "stage34/external_testbed/collector_service.py",
            "stage34_collector_test",
        )

        baseline_obj = {
            "nfInstances": [
                {
                    "nfInstanceId": "a",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.1"],
                },
                {
                    "nfInstanceId": "b",
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "ipv4Addresses": ["10.0.0.2"],
                },
            ]
        }
        baseline = collector.relational_projection(baseline_obj)
        self.assertEqual(collector.count_projection(baseline), (2, 2))

        identity = json.loads(json.dumps(baseline_obj))
        identity["nfInstances"][0]["nfInstanceId"] = "phantom"
        identity_projection = collector.relational_projection(identity)
        self.assertEqual(collector.count_projection(identity_projection), (2, 2))
        self.assertNotEqual(
            collector.canonical_bytes(baseline),
            collector.canonical_bytes(identity_projection),
        )

        endpoint = json.loads(json.dumps(baseline_obj))
        endpoint["nfInstances"][0]["ipv4Addresses"] = ["203.0.113.7"]
        endpoint_projection = collector.relational_projection(endpoint)
        self.assertEqual(collector.count_projection(endpoint_projection), (2, 2))
        self.assertNotEqual(
            collector.canonical_bytes(baseline),
            collector.canonical_bytes(endpoint_projection),
        )

        service = json.loads(json.dumps(baseline_obj))
        service["nfInstances"][0]["nfServices"] = [
            {
                "serviceInstanceId": "x",
                "serviceName": "nnssf-nsselection",
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "versions": [
                    {
                        "apiVersionInUri": "v1",
                        "apiFullVersion": "34.0.0-lab",
                    }
                ],
            }
        ]
        service_projection = collector.relational_projection(service)
        self.assertEqual(collector.count_projection(service_projection), (2, 2))
        self.assertNotEqual(
            collector.canonical_bytes(baseline),
            collector.canonical_bytes(service_projection),
        )

    def test_external_verifier_detects_relation_while_legacy_counts_stay_clean(self):
        collector_key = ec.generate_private_key(ec.SECP256R1())
        verifier_key = ec.generate_private_key(ec.SECP256R1())
        policy = "2" * 64
        collector_pub = public_pem(collector_key)

        os.environ["STAGE34_POLICY_SHA256"] = policy
        os.environ["STAGE34_COLLECTOR_PUBLIC_KEY_PEM"] = collector_pub.decode(
            "ascii"
        )
        os.environ["STAGE34_COLLECTOR_PUBLIC_KEY_SHA256"] = hashlib.sha256(
            collector_pub
        ).hexdigest()
        os.environ["STAGE34_VERIFIER_PRIVATE_KEY_PEM"] = private_pem(
            verifier_key
        )
        os.environ["STAGE34_VERIFIER_REVISION"] = "unit-test"
        verifier = load_module(
            "stage34/relational_verifier_service.py",
            "stage34_verifier_test",
        )

        baseline = {
            "profiles": {
                "a": {
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "fqdn": None,
                    "ipv4Addresses": ["10.0.0.1"],
                    "nfServices": [],
                },
                "b": {
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "fqdn": None,
                    "ipv4Addresses": ["10.0.0.2"],
                    "nfServices": [],
                },
            },
            "duplicateIds": [],
        }
        mutated = json.loads(json.dumps(baseline))
        mutated["profiles"]["a"]["ipv4Addresses"] = ["203.0.113.8"]

        package = {
            "stage": 34,
            "schema": "stage34-external-relational-telemetry-v1",
            "seed": 99999,
            "challenge_nonce": "abcdef0123456789abcdef0123456789",
            "collector_sequence": 1,
            "collector_service_revision": "unit-test",
            "collector_public_key_sha256": hashlib.sha256(
                collector_pub
            ).hexdigest(),
            "policy_sha256": policy,
            "open5gs_ref": "v2.7.6",
            "consumer_path": "test",
            "baseline": {
                "projection": baseline,
                "count": 2,
                "registered": 2,
            },
            "observations": [
                {
                    "tick": 0,
                    "projection": mutated,
                    "legacy_nssf_count": 2,
                    "legacy_registered_count": 2,
                    "raw_response_sha256": "0" * 64,
                }
            ],
            "native_nrf_source_sha256": "3" * 64,
            "attack_labels_in_package": False,
        }
        signature = collector_key.sign(
            verifier.canonical_bytes(package),
            ec.ECDSA(hashes.SHA256()),
        )
        encoded = base64.b64encode(signature).decode("ascii")

        result = verifier.verify_package(package, encoded)
        verdict = result["verdict"]
        self.assertEqual(verdict["legacy_count_status_alert_rows"], 0)
        self.assertEqual(verdict["relational_alert_rows"], 1)
        self.assertTrue(verdict["alerts"][0]["relational_alert"])

        with self.assertRaises(ValueError):
            verifier.verify_package(package, encoded)


if __name__ == "__main__":
    unittest.main()
