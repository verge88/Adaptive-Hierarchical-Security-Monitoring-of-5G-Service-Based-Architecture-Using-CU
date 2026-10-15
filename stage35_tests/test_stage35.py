"""Stage35 unit tests."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import unittest

from research.stage35_policy import build_policy, canonical_bytes


def load_module(path: str, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class Stage35Tests(unittest.TestCase):
    def test_policy_is_deterministic_and_preregisters_transition_attacks(self):
        a = canonical_bytes(build_policy(Path(".")))
        b = canonical_bytes(build_policy(Path(".")))
        self.assertEqual(a, b)
        text = a.decode("utf8")
        self.assertIn("nssf2 graceful stop", text)
        self.assertIn("nssf2 start", text)
        self.assertIn("nssf1 restart", text)
        self.assertIn("cross_instance_replay_test", text)
        self.assertIn("clean_soak_ticks_per_run", text)

    def test_anchor_rejects_replay_and_sequence_rollback(self):
        os.environ["STAGE35_ANCHOR_TOKEN"] = "anchor-test-token"
        os.environ["STAGE35_POLICY_SHA256"] = "a" * 64
        os.environ["STAGE35_ANCHOR_REVISION"] = "unit-test"
        anchor = load_module(
            "stage35/state_anchor_service.py", "stage35_anchor_test"
        )

        first = {
            "stage": 35,
            "policy_sha256": "a" * 64,
            "challenge_nonce": "0123456789abcdef0123456789abcdef",
            "collector_sequence": 1,
            "collector_package_sha256": "b" * 64,
        }
        status, result = anchor.claim(first)
        self.assertEqual(status, 200)
        self.assertTrue(result["accepted"])

        status, _ = anchor.claim(first)
        self.assertEqual(status, 409)

        rollback = dict(first)
        rollback["challenge_nonce"] = "fedcba9876543210fedcba9876543210"
        rollback["collector_sequence"] = 1
        status, _ = anchor.claim(rollback)
        self.assertEqual(status, 409)

    def test_verifier_transition_reference_rule_detects_relation_change(self):
        # Only import pure rule helpers; verifier startup env is populated with
        # synthetic keys/tokens.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        collector = ec.generate_private_key(ec.SECP256R1())
        verifier = ec.generate_private_key(ec.SECP256R1())
        collector_pub = collector.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verifier_private = verifier.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        os.environ["STAGE35_POLICY_SHA256"] = "c" * 64
        os.environ["STAGE35_VERIFIER_REVISION"] = "unit-test"
        os.environ["STAGE35_VERIFIER_INSTANCE"] = "test"
        os.environ["STAGE35_COLLECTOR_TO_VERIFIER_TOKEN"] = "collector-token"
        os.environ["STAGE35_ANCHOR_TOKEN"] = "anchor-token"
        os.environ["STAGE35_ANCHOR_ENDPOINT"] = "http://127.0.0.1:9"
        os.environ["STAGE35_COLLECTOR_PUBLIC_KEY_PEM"] = collector_pub.decode()
        os.environ["STAGE35_COLLECTOR_PUBLIC_KEY_SHA256"] = hashlib.sha256(
            collector_pub
        ).hexdigest()
        os.environ["STAGE35_VERIFIER_PRIVATE_KEY_PEM"] = verifier_private.decode()

        module = load_module(
            "stage35/transition_verifier_service.py",
            "stage35_verifier_test",
        )
        old = {
            "profiles": {
                "a": {
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "fqdn": None,
                    "ipv4Addresses": ["127.0.0.12"],
                    "nfServices": [],
                },
                "b": {
                    "nfType": "NSSF",
                    "nfStatus": "REGISTERED",
                    "fqdn": None,
                    "ipv4Addresses": ["127.0.0.13"],
                    "nfServices": [],
                },
            },
            "duplicateIds": [],
        }
        new = {
            "profiles": {
                "a": old["profiles"]["a"],
            },
            "duplicateIds": [],
        }
        mutated = json.loads(json.dumps(old))
        mutated["profiles"]["a"]["ipv4Addresses"] = ["203.0.113.9"]

        self.assertTrue(module.projection_equal(old, old))
        self.assertTrue(module.projection_equal(new, new))
        self.assertFalse(module.projection_equal(mutated, old))
        self.assertFalse(module.projection_equal(mutated, new))
        self.assertEqual(module.state_counts(old), (2, 2))
        self.assertEqual(module.state_counts(new), (1, 1))

    def test_collector_contains_direct_auth_and_long_soak(self):
        text = Path(
            "stage35/external_testbed/collector_service.py"
        ).read_text(encoding="utf8")
        self.assertIn("STAGE35_COLLECTOR_TO_VERIFIER_TOKEN", text)
        self.assertIn("cross-instance replay", text.lower())
        self.assertIn("SOAK_TICKS = 300", text)
        for phase in (
            "stop_transition",
            "start_transition",
            "restart_transition",
        ):
            self.assertIn(phase, text)


if __name__ == "__main__":
    unittest.main()
