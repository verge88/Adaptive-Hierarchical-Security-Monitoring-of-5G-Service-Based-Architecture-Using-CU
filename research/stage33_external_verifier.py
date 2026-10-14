"""Stage 33 externally executed verifier and detector service.

This module is designed to run outside GitHub Actions. It receives only
label-free raw telemetry plus the externally KMS-signed Stage-33 policy
materials, verifies the external root, checks local code measurements, projects
the trusted baseline directly from the signed policy epochs, runs the frozen
Stage-29 detector, and returns a signed canonical verdict.

The service never receives private attack labels or the realized randomized
attack schedule.
"""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from .stage27_attestation import row_from_states
from .stage29_live_detect import detect as frozen_stage29_detect
from .stage32_external_verify import verify_receipt
from .stage33_policy_bundle import SCHEMA, canonical_bytes


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def validate_policy(policy: dict, repo_root: Path) -> None:
    if int(policy.get("stage", -1)) != 33:
        raise ValueError("Stage33 policy stage mismatch")
    if policy.get("schema") != SCHEMA:
        raise ValueError("Stage33 policy schema mismatch")
    if policy.get("open5gs_ref") != "v2.7.6":
        raise ValueError("Stage33 Open5GS version mismatch")

    epochs = policy.get("epochs")
    if not isinstance(epochs, list) or not epochs:
        raise ValueError("Stage33 policy lacks epochs")

    previous_until = -1
    for expected_epoch, epoch in enumerate(epochs):
        if int(epoch["epoch"]) != expected_epoch:
            raise ValueError("Stage33 epoch sequence is not contiguous")
        start = int(epoch["valid_from_tick"])
        end = int(epoch["valid_until_tick"])
        if start != previous_until + 1:
            raise ValueError("Stage33 epoch validity is not contiguous")
        if end < start:
            raise ValueError("Stage33 epoch interval is inverted")
        previous_until = end

    measurements = policy.get("measurements_sha256")
    if not isinstance(measurements, dict) or not measurements:
        raise ValueError("Stage33 policy lacks code measurements")
    for relative, expected in sorted(measurements.items()):
        path = repo_root / relative
        if not path.is_file():
            raise FileNotFoundError(path)
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(
                f"Stage33 local measurement mismatch for {relative}: "
                f"{actual} != {expected}"
            )


def baseline_for_tick(policy: dict, tick: int) -> tuple[int, int, int]:
    matches = [
        epoch
        for epoch in policy["epochs"]
        if int(epoch["valid_from_tick"])
        <= tick
        <= int(epoch["valid_until_tick"])
    ]
    if len(matches) != 1:
        raise ValueError(
            f"Stage33 tick {tick} has {len(matches)} baseline epochs"
        )
    epoch = matches[0]
    return (
        int(epoch["epoch"]),
        int(epoch["expected_nssf_count"]),
        int(epoch["expected_registered_count"]),
    )


def project_from_policy(
    raw_rows: list[dict],
    policy: dict,
) -> tuple[list[dict], list[dict]]:
    attested = []
    compromised = []

    for raw in raw_rows:
        tick = int(raw["tick"])
        epoch, trusted_count, trusted_registered = baseline_for_tick(
            policy, tick
        )

        trusted = row_from_states(
            raw,
            trusted_count,
            trusted_registered,
            scope="stage33_external_verified_policy_baseline",
        )
        trusted["stage29_attestation_verified_reference"] = True
        trusted["stage33_external_policy_epoch"] = epoch

        pair = row_from_states(
            raw,
            int(raw["compromised_witness_nssf_count"]),
            int(raw["compromised_witness_registered_count"]),
            scope="colluding_nrf_and_nf_side_witness",
        )
        pair["stage29_attestation_verified_reference"] = False
        pair["stage33_external_policy_epoch"] = epoch

        attested.append(trusted)
        compromised.append(pair)

    return attested, compromised


def sign_ed25519(payload: bytes, private_key_pem: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        payload_path = root / "payload.json"
        private_path = root / "private.pem"
        signature_path = root / "signature.bin"
        payload_path.write_bytes(payload)
        private_path.write_bytes(private_key_pem)
        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_path),
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError(
                "Stage33 verdict signing failed: " + proc.stderr[-800:]
            )
        return signature_path.read_bytes()


def derive_public_key(private_key_pem: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        private_path = root / "private.pem"
        public_path = root / "public.pem"
        private_path.write_bytes(private_key_pem)
        proc = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_path),
                "-pubout",
                "-out",
                str(public_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            raise ValueError(
                "Stage33 public-key derivation failed: "
                + proc.stderr[-800:]
            )
        return public_path.read_bytes()


def decode_b64_field(request: dict, name: str) -> bytes:
    value = request.get(name)
    if not isinstance(value, str) or not value:
        raise ValueError(f"Stage33 request lacks {name}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as ex:
        raise ValueError(f"Invalid base64 field {name}") from ex


def verify_request_and_detect(
    request: dict,
    *,
    repo_root: Path,
    expected_kms_key_arn: str,
    expected_kms_public_key_sha256: str,
    expected_policy_sha256: str,
    verdict_private_key_pem: bytes,
) -> dict:
    raw_rows = request.get("raw_telemetry")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("Stage33 request lacks label-free raw telemetry")
    if any(
        "private_labels" in row or "mutation_ticks" in row
        for row in raw_rows
        if isinstance(row, dict)
    ):
        raise ValueError("Stage33 request contains private attack labels")

    policy_bytes = decode_b64_field(request, "policy_json_base64")
    receipt_bytes = decode_b64_field(request, "kms_receipt_json_base64")
    kms_public_key = decode_b64_field(
        request, "kms_public_key_pem_base64"
    )

    policy_digest = sha256_bytes(policy_bytes)
    if policy_digest != expected_policy_sha256:
        raise ValueError(
            "Stage33 policy digest differs from externally pinned value"
        )

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        policy_path = root / "policy.json"
        receipt_path = root / "receipt.json"
        public_path = root / "kms-public.pem"
        policy_path.write_bytes(policy_bytes)
        receipt_path.write_bytes(receipt_bytes)
        public_path.write_bytes(kms_public_key)

        external = verify_receipt(
            policy_path=policy_path,
            receipt_path=receipt_path,
            public_key_pem=public_path,
            expected_key_arn=expected_kms_key_arn,
            expected_public_key_sha256=expected_kms_public_key_sha256,
        )

    policy = json.loads(policy_bytes)
    if canonical_bytes(policy) != policy_bytes:
        raise ValueError("Stage33 policy is not canonical JSON")
    validate_policy(policy, repo_root)

    seed = int(raw_rows[0]["seed"])
    if any(int(row["seed"]) != seed for row in raw_rows):
        raise ValueError("Stage33 mixed-seed request")

    attested, compromised = project_from_policy(raw_rows, policy)
    detector = frozen_stage29_detect(attested, compromised)

    request_digest = sha256_bytes(
        canonical_bytes({"raw_telemetry": raw_rows})
    )
    verdict = {
        "stage": 33,
        "seed": seed,
        "external_execution": True,
        "private_labels_received": False,
        "policy_sha256": policy_digest,
        "external_root_key_arn": external["kms_key_arn"],
        "external_root_public_key_sha256": external[
            "public_key_sha256"
        ],
        "request_telemetry_sha256": request_digest,
        "detector": detector,
    }

    verdict_bytes = canonical_bytes(verdict)
    signature = sign_ed25519(
        verdict_bytes,
        verdict_private_key_pem,
    )
    public_key = derive_public_key(verdict_private_key_pem)

    return {
        "verdict": verdict,
        "verdict_canonical_base64": base64.b64encode(
            verdict_bytes
        ).decode("ascii"),
        "verdict_signature_base64": base64.b64encode(
            signature
        ).decode("ascii"),
        "verifier_public_key_pem_base64": base64.b64encode(
            public_key
        ).decode("ascii"),
        "verifier_public_key_sha256": sha256_bytes(public_key),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "Stage33ExternalVerifier/1.0"

    def _send(self, status: int, body: dict) -> None:
        payload = json.dumps(
            body,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(
                200,
                {
                    "stage": 33,
                    "status": "ok",
                    "external_execution": True,
                },
            )
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/verify":
            self._send(404, {"error": "not found"})
            return
        try:
            expected_token = os.environ.get("STAGE33_API_TOKEN", "")
            if expected_token:
                supplied = self.headers.get("Authorization", "")
                if supplied != "Bearer " + expected_token:
                    self._send(401, {"error": "unauthorized"})
                    return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 8_000_000:
                raise ValueError("Invalid Stage33 request size")
            request = json.loads(self.rfile.read(length))
            result = verify_request_and_detect(
                request,
                repo_root=Path(
                    os.environ.get("STAGE33_REPO_ROOT", ".")
                ),
                expected_kms_key_arn=os.environ[
                    "STAGE33_EXPECTED_KMS_KEY_ARN"
                ],
                expected_kms_public_key_sha256=os.environ[
                    "STAGE33_EXPECTED_KMS_PUBLIC_KEY_SHA256"
                ],
                expected_policy_sha256=os.environ[
                    "STAGE33_EXPECTED_POLICY_SHA256"
                ],
                verdict_private_key_pem=base64.b64decode(
                    os.environ[
                        "STAGE33_VERDICT_PRIVATE_KEY_PEM_B64"
                    ],
                    validate=True,
                ),
            )
            self._send(200, result)
        except Exception as ex:
            self._send(
                400,
                {
                    "stage": 33,
                    "error": type(ex).__name__,
                    "message": str(ex),
                },
            )

    def log_message(self, format: str, *args: Any) -> None:
        print(
            "STAGE33_HTTP "
            + format % args,
            flush=True,
        )


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(
        f"STAGE33_EXTERNAL_VERIFIER_LISTENING {host}:{port}",
        flush=True,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
