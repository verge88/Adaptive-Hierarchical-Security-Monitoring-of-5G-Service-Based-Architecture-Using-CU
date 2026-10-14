"""Stage 32 external KMS/HSM signature verifier.

This verifier accepts a policy only if:
- the locally computed SHA-256 matches the externally approved digest;
- the receipt names the exact expected AWS KMS key ARN;
- the signature verifies under the public key returned for that KMS key;
- the public-key SHA-256 matches an independently configured expected value.

No signing secret is present in GitHub Actions.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from .stage32_policy_bundle import SIGNING_ALGORITHM


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_ecdsa_sha256(
    policy_path: Path,
    signature: bytes,
    public_key_pem: Path,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        signature_path = Path(tmp) / "signature.der"
        signature_path.write_bytes(signature)
        proc = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_pem),
                "-signature",
                str(signature_path),
                str(policy_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError(
                "Stage32 external KMS signature verification failed: "
                + proc.stderr[-800:]
            )


def verify_receipt(
    *,
    policy_path: Path,
    receipt_path: Path,
    public_key_pem: Path,
    expected_key_arn: str,
    expected_public_key_sha256: str,
) -> dict:
    receipt = json.loads(receipt_path.read_text(encoding="utf8"))
    digest = sha256_file(policy_path)

    if receipt.get("stage") != 32:
        raise ValueError("Stage32 receipt stage mismatch")
    if receipt.get("signing_algorithm") != SIGNING_ALGORITHM:
        raise ValueError("Stage32 signing algorithm mismatch")
    if receipt.get("kms_key_arn") != expected_key_arn:
        raise ValueError("Stage32 KMS key ARN mismatch")
    if receipt.get("digest_sha256") != digest:
        raise ValueError("Stage32 receipt digest mismatch")
    if receipt.get("approved_digest") != digest:
        raise ValueError("Stage32 external approval digest mismatch")
    if receipt.get("approval_source") != "external_ssm_allowlist":
        raise ValueError("Stage32 external approval source mismatch")

    public_key_hash = sha256_file(public_key_pem)
    if public_key_hash != expected_public_key_sha256:
        raise ValueError("Stage32 externally pinned public-key hash mismatch")

    try:
        signature = base64.b64decode(
            receipt["signature_base64"], validate=True
        )
    except Exception as ex:
        raise ValueError("Invalid Stage32 base64 signature") from ex

    verify_ecdsa_sha256(
        policy_path,
        signature,
        public_key_pem,
    )

    return {
        "stage": 32,
        "external_signature_verified": True,
        "digest_sha256": digest,
        "kms_key_arn": expected_key_arn,
        "public_key_sha256": public_key_hash,
        "signing_algorithm": SIGNING_ALGORITHM,
        "approval_source": receipt["approval_source"],
        "signer_function_arn": receipt.get("signer_function_arn", ""),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--expected-key-arn", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--output", default="stage32_external_verification.json")
    args = parser.parse_args()

    result = verify_receipt(
        policy_path=Path(args.policy),
        receipt_path=Path(args.receipt),
        public_key_pem=Path(args.public_key),
        expected_key_arn=args.expected_key_arn,
        expected_public_key_sha256=args.expected_public_key_sha256,
    )
    Path(args.output).write_text(
        json.dumps(result, indent=2),
        encoding="utf8",
    )
    print(
        "STAGE32_EXTERNAL_ROOT_VERIFY_OK "
        f"digest={result['digest_sha256']} "
        f"key={result['kms_key_arn']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
