"""Stage32 external-root invariants."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from research.stage32_external_verify import verify_receipt
from research.stage32_policy_bundle import build_policy, canonical_bytes


class Stage32Tests(unittest.TestCase):
    def test_policy_is_deterministic_and_excludes_run_identity(self):
        first = build_policy(Path("."))
        second = build_policy(Path("."))
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        text = canonical_bytes(first).decode("utf8")
        self.assertNotIn("github_run_id", text)
        self.assertNotIn("GITHUB_SHA", text)
        self.assertIn("aws_kms_asymmetric_nonexportable_key", text)

    def test_external_signature_verifies_and_tamper_fails(self):
        policy = build_policy(Path("."))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private = root / "private.pem"
            public = root / "public.pem"
            policy_path = root / "policy.json"
            signature = root / "signature.der"
            receipt = root / "receipt.json"

            policy_path.write_bytes(canonical_bytes(policy))
            subprocess.run(
                [
                    "openssl", "ecparam", "-name", "prime256v1",
                    "-genkey", "-noout", "-out", str(private),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl", "pkey", "-in", str(private),
                    "-pubout", "-out", str(public),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            subprocess.run(
                [
                    "openssl", "dgst", "-sha256",
                    "-sign", str(private),
                    "-out", str(signature),
                    str(policy_path),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            digest = hashlib.sha256(policy_path.read_bytes()).hexdigest()
            public_hash = hashlib.sha256(public.read_bytes()).hexdigest()
            key_arn = "arn:aws:kms:eu-north-1:111122223333:key/test"
            receipt.write_text(
                json.dumps(
                    {
                        "stage": 32,
                        "digest_sha256": digest,
                        "approved_digest": digest,
                        "approval_source": "external_ssm_allowlist",
                        "kms_key_arn": key_arn,
                        "signing_algorithm": "ECDSA_SHA_256",
                        "signature_base64": base64.b64encode(
                            signature.read_bytes()
                        ).decode("ascii"),
                    }
                ),
                encoding="utf8",
            )

            result = verify_receipt(
                policy_path=policy_path,
                receipt_path=receipt,
                public_key_pem=public,
                expected_key_arn=key_arn,
                expected_public_key_sha256=public_hash,
            )
            self.assertTrue(result["external_signature_verified"])

            tampered = bytearray(policy_path.read_bytes())
            tampered[-1] ^= 1
            policy_path.write_bytes(tampered)
            with self.assertRaises(ValueError):
                verify_receipt(
                    policy_path=policy_path,
                    receipt_path=receipt,
                    public_key_pem=public,
                    expected_key_arn=key_arn,
                    expected_public_key_sha256=public_hash,
                )

    def test_aws_stack_denies_github_digest_mutation_by_omission(self):
        text = Path(
            "stage32/aws/stage32-external-root.yaml"
        ).read_text(encoding="utf8")
        self.assertIn("kms:Sign", text)
        self.assertIn("kms:GetPublicKey", text)
        self.assertIn("lambda:InvokeFunction", text)
        self.assertNotIn("ssm:PutParameter", text)
        self.assertIn("approved-policy-sha256", text)
        self.assertIn("ECC_NIST_P256", text)

    def test_signer_checks_external_approved_digest_before_kms_sign(self):
        text = Path(
            "stage32/aws/stage32-external-root.yaml"
        ).read_text(encoding="utf8")
        check_pos = text.index("if digest != approved:")
        sign_pos = text.index("response = kms.sign(")
        self.assertLess(check_pos, sign_pos)


if __name__ == "__main__":
    unittest.main()
