"""Verify a Stage-33 externally computed signed verdict.

The final statistical audit may run on GitHub, but it never recomputes detector
alarms. It verifies the externally emitted signature, checks a pinned verifier
public-key fingerprint, checks the request telemetry digest and then exposes the
external detector result for post-hoc label joining.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from .stage33_policy_bundle import canonical_bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_ed25519(
    payload: bytes,
    signature: bytes,
    public_key_pem: bytes,
) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        payload_path = root / "payload.json"
        signature_path = root / "signature.bin"
        public_path = root / "public.pem"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        public_path.write_bytes(public_key_pem)
        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(public_path),
                "-in",
                str(payload_path),
                "-sigfile",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError(
                "Stage33 external verdict signature verification failed: "
                + proc.stderr[-800:]
            )


def verify_response(
    *,
    response_path: Path,
    raw_telemetry_path: Path,
    expected_verifier_public_key_sha256: str,
    expected_policy_sha256: str,
) -> dict:
    response = json.loads(response_path.read_text(encoding="utf8"))
    verdict_bytes = base64.b64decode(
        response["verdict_canonical_base64"],
        validate=True,
    )
    signature = base64.b64decode(
        response["verdict_signature_base64"],
        validate=True,
    )
    public_key = base64.b64decode(
        response["verifier_public_key_pem_base64"],
        validate=True,
    )

    public_hash = sha256_bytes(public_key)
    if public_hash != expected_verifier_public_key_sha256:
        raise ValueError("Stage33 external verifier public-key hash mismatch")
    if response.get("verifier_public_key_sha256") != public_hash:
        raise ValueError("Stage33 response public-key hash mismatch")

    verify_ed25519(verdict_bytes, signature, public_key)

    verdict = json.loads(verdict_bytes)
    if canonical_bytes(verdict) != verdict_bytes:
        raise ValueError("Stage33 external verdict is not canonical JSON")
    if int(verdict.get("stage", -1)) != 33:
        raise ValueError("Stage33 verdict stage mismatch")
    if verdict.get("external_execution") is not True:
        raise ValueError("Stage33 verdict lacks external-execution marker")
    if verdict.get("private_labels_received") is not False:
        raise ValueError("Stage33 external verifier received private labels")
    if verdict.get("policy_sha256") != expected_policy_sha256:
        raise ValueError("Stage33 verdict policy digest mismatch")

    raw_rows = json.loads(
        raw_telemetry_path.read_text(encoding="utf8")
    )
    expected_request_digest = sha256_bytes(
        canonical_bytes({"raw_telemetry": raw_rows})
    )
    if verdict.get("request_telemetry_sha256") != expected_request_digest:
        raise ValueError("Stage33 verdict does not bind the submitted telemetry")

    detector = verdict.get("detector")
    if not isinstance(detector, dict):
        raise ValueError("Stage33 verdict lacks detector result")

    return {
        "verdict": verdict,
        "detector": detector,
        "verifier_public_key_sha256": public_hash,
        "verdict_sha256": sha256_bytes(verdict_bytes),
        "request_telemetry_sha256": expected_request_digest,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--response", required=True)
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument(
        "--expected-verifier-public-key-sha256",
        required=True,
    )
    parser.add_argument("--expected-policy-sha256", required=True)
    parser.add_argument("--output", default="stage33_verified")
    args = parser.parse_args()

    result = verify_response(
        response_path=Path(args.response),
        raw_telemetry_path=Path(args.raw_telemetry),
        expected_verifier_public_key_sha256=(
            args.expected_verifier_public_key_sha256
        ),
        expected_policy_sha256=args.expected_policy_sha256,
    )

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "alarms.json").write_text(
        json.dumps(result["detector"], indent=2),
        encoding="utf8",
    )
    provenance = {
        "stage": 33,
        "seed": int(result["verdict"]["seed"]),
        "external_verdict_signature_verified": True,
        "external_execution": True,
        "private_labels_received_by_external_verifier": False,
        "verifier_public_key_sha256": result[
            "verifier_public_key_sha256"
        ],
        "verdict_sha256": result["verdict_sha256"],
        "request_telemetry_sha256": result[
            "request_telemetry_sha256"
        ],
        "policy_sha256": result["verdict"]["policy_sha256"],
        "external_root_key_arn": result["verdict"][
            "external_root_key_arn"
        ],
        "external_root_public_key_sha256": result["verdict"][
            "external_root_public_key_sha256"
        ],
    }
    (output / "external_verdict_provenance.json").write_text(
        json.dumps(provenance, indent=2),
        encoding="utf8",
    )

    print(
        "STAGE33_EXTERNAL_VERDICT_VERIFY_OK "
        f"seed={provenance['seed']} "
        f"verdict={provenance['verdict_sha256']}",
        flush=True,
    )


if __name__ == "__main__":
    main()
