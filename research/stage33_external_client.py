"""Stage 33 client for the independent external verifier."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=20) as response:
        return json.loads(response.read())


def post_json(url: str, doc: dict) -> dict:
    raw = canonical_bytes(doc)
    request = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def verify_signature(public_pem: bytes, verdict: dict, signature_b64: str) -> None:
    key = serialization.load_pem_public_key(public_pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Stage33 public key is not EC")
    signature = base64.b64decode(signature_b64, validate=True)
    key.verify(signature, canonical_bytes(verdict), ec.ECDSA(hashes.SHA256()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--expected-public-key-sha256", required=True)
    parser.add_argument("--policy-sha256-file", required=True)
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--output", default="stage33_external")
    args = parser.parse_args()

    endpoint = args.endpoint.rstrip("/")
    policy_sha256 = Path(args.policy_sha256_file).read_text(
        encoding="ascii"
    ).strip().lower()
    rows = json.loads(Path(args.raw_telemetry).read_text(encoding="utf8"))
    if not rows:
        raise ValueError("empty Stage33 raw telemetry")
    seed = int(rows[0]["seed"])

    health = fetch_json(endpoint + "/health")
    if int(health.get("stage", -1)) != 33 or health.get("status") != "ok":
        raise ValueError("Stage33 external verifier health check failed")
    if health.get("approved_policy_sha256") != policy_sha256:
        raise ValueError("Stage33 service approved policy differs from run policy")

    public_doc = fetch_json(endpoint + "/public-key")
    public_pem = public_doc["public_key_pem"].encode("ascii")
    public_hash = hashlib.sha256(public_pem).hexdigest()
    if public_hash != args.expected_public_key_sha256:
        raise ValueError("Stage33 public-key fingerprint mismatch")
    if public_doc.get("public_key_sha256") != public_hash:
        raise ValueError("Stage33 service public-key self-report mismatch")
    if health.get("public_key_sha256") != public_hash:
        raise ValueError("Stage33 service health public-key mismatch")

    request_doc = {
        "stage": 33,
        "policy_sha256": policy_sha256,
        "request_nonce": secrets.token_hex(24),
        "raw_telemetry": rows,
    }
    expected_request_sha = hashlib.sha256(
        canonical_bytes(request_doc)
    ).hexdigest()

    response = post_json(endpoint + "/verify", request_doc)
    verdict = response["verdict"]
    signature_b64 = response["signature_base64"]

    verify_signature(public_pem, verdict, signature_b64)

    if verdict.get("request_sha256") != expected_request_sha:
        raise ValueError("Stage33 signed verdict is not bound to request")
    if int(verdict.get("seed", -1)) != seed:
        raise ValueError("Stage33 signed verdict seed mismatch")
    if verdict.get("policy_sha256") != policy_sha256:
        raise ValueError("Stage33 signed verdict policy mismatch")
    if verdict.get("public_key_sha256") != public_hash:
        raise ValueError("Stage33 signed verdict key mismatch")
    if int(verdict.get("legitimate_transition_alert_rows", -1)) != 0:
        raise ValueError("Stage33 external verifier observed transition mismatch")
    if int(verdict.get("colluding_pair_alert_rows", -1)) != 0:
        raise ValueError("Stage33 external verifier broke negative control")

    tampered = json.loads(json.dumps(verdict))
    tampered["external_alert_rows"] = int(tampered["external_alert_rows"]) + 1
    tamper_rejected = False
    try:
        verify_signature(public_pem, tampered, signature_b64)
    except InvalidSignature:
        tamper_rejected = True
    if not tamper_rejected:
        raise AssertionError("Tampered Stage33 verdict unexpectedly verified")

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    final = {
        "stage": 33,
        "seed": seed,
        "external_verifier_url": endpoint,
        "external_service_revision": verdict.get("service_revision", ""),
        "policy_sha256": policy_sha256,
        "public_key_sha256": public_hash,
        "signature_verified": True,
        "tampered_verdict_rejected": True,
        "request_sha256": expected_request_sha,
        "verdict": verdict,
        "signature_base64": signature_b64,
    }
    (output / "external_verdict.json").write_text(
        json.dumps(final, indent=2),
        encoding="utf8",
    )
    (output / "external_public_key.pem").write_bytes(public_pem)

    print(
        "STAGE33_EXTERNAL_VERDICT_OK "
        f"seed={seed} alerts={verdict['external_alert_rows']} "
        f"revision={verdict.get('service_revision','')}",
        flush=True,
    )


if __name__ == "__main__":
    main()
