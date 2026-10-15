"""Stage 37 GitHub-side audit client.

GitHub orchestrates only. The collector executes Open5GS and sends telemetry
directly to verifier A. This client validates the returned signatures and stores
verdict/evidence separately from private labels.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import time
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_bytes(doc) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def get_json(url: str, timeout: float = 20) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def post_json(url: str, doc: dict, timeout: float = 300):
    request = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return (
                response.status,
                json.loads(response.read()),
                (time.perf_counter() - started) * 1000,
            )
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return (
            ex.code,
            json.loads(body) if body else {},
            (time.perf_counter() - started) * 1000,
        )


def load_key(doc: dict, expected_hash: str):
    pem = doc["public_key_pem"].encode("ascii")
    actual = hashlib.sha256(pem).hexdigest()
    if actual != expected_hash:
        raise ValueError(f"public-key hash mismatch {actual} != {expected_hash}")
    if doc.get("public_key_sha256") != actual:
        raise ValueError("service public-key self-report mismatch")
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected EC public key")
    return key, pem


def verify(key, doc: dict, signature_b64: str) -> None:
    key.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(doc),
        ec.ECDSA(hashes.SHA256()),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--collector-endpoint", required=True)
    parser.add_argument("--verifier-a-endpoint", required=True)
    parser.add_argument("--policy-sha256-file", required=True)
    parser.add_argument("--expected-collector-key-sha256", required=True)
    parser.add_argument("--expected-verifier-key-sha256", required=True)
    parser.add_argument("--output", default="stage37_evidence")
    parser.add_argument("--labels-output", default="stage37_labels")
    args = parser.parse_args()

    collector = args.collector_endpoint.rstrip("/")
    verifier_a = args.verifier_a_endpoint.rstrip("/")
    policy_sha = Path(args.policy_sha256_file).read_text(
        encoding="ascii"
    ).strip().lower()

    collector_health = get_json(collector + "/health")
    if collector_health.get("policy_sha256") != policy_sha:
        raise ValueError("collector policy mismatch")
    if collector_health.get("direct_verifier_transport") is not True:
        raise ValueError("collector is not direct-to-verifier mode")

    collector_key_doc = get_json(collector + "/public-key")
    collector_key, collector_pem = load_key(
        collector_key_doc, args.expected_collector_key_sha256
    )
    verifier_key_doc = get_json(verifier_a + "/public-key")
    verifier_key, verifier_pem = load_key(
        verifier_key_doc, args.expected_verifier_key_sha256
    )

    nonce = secrets.token_hex(32)
    status, result, orchestration_ms = post_json(
        collector + "/run",
        {
            "stage": 37,
            "seed": args.seed,
            "challenge_nonce": nonce,
            "policy_sha256": policy_sha,
        },
        timeout=420,
    )
    if status != 200:
        raise RuntimeError(f"collector run failed HTTP {status}: {result}")

    package = result["telemetry_package"]
    collector_signature = result["collector_signature_base64"]
    verifier_result = result["verifier_result"]
    verdict = verifier_result["verdict"]
    verifier_signature = verifier_result["signature_base64"]
    labels = result["private_labels"]
    evidence = dict(result["evidence"])

    verify(collector_key, package, collector_signature)
    verify(verifier_key, verdict, verifier_signature)

    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    if result["collector_package_sha256"] != package_sha:
        raise ValueError("collector package digest mismatch")
    if verdict["collector_package_sha256"] != package_sha:
        raise ValueError("verdict is not bound to collector package")
    if package["challenge_nonce"] != nonce or verdict["challenge_nonce"] != nonce:
        raise ValueError("challenge nonce binding mismatch")
    if int(package["seed"]) != args.seed or int(verdict["seed"]) != args.seed:
        raise ValueError("seed binding mismatch")
    if package["attack_labels_in_package"] is not False:
        raise ValueError("verifier package contains private labels")
    if verdict["attack_labels_received"] is not False:
        raise ValueError("verifier received private labels")

    tampered_package = json.loads(json.dumps(package))
    tampered_package["seed"] += 1
    package_tamper_rejected = False
    try:
        verify(collector_key, tampered_package, collector_signature)
    except InvalidSignature:
        package_tamper_rejected = True
    if not package_tamper_rejected:
        raise AssertionError("tampered collector package verified")

    tampered_verdict = json.loads(json.dumps(verdict))
    tampered_verdict["relational_alert_rows"] += 1
    verdict_tamper_rejected = False
    try:
        verify(verifier_key, tampered_verdict, verifier_signature)
    except InvalidSignature:
        verdict_tamper_rejected = True
    if not verdict_tamper_rejected:
        raise AssertionError("tampered verifier verdict verified")

    evidence.update(
        {
            "orchestration_round_trip_ms": orchestration_ms,
            "collector_signature_verified_by_github": True,
            "verifier_signature_verified_by_github": True,
            "collector_package_tamper_rejected_by_github": True,
            "verifier_verdict_tamper_rejected_by_github": True,
            "collector_package_sha256": package_sha,
        }
    )

    output = Path(args.output)
    labels_output = Path(args.labels_output)
    output.mkdir(parents=True, exist_ok=True)
    labels_output.mkdir(parents=True, exist_ok=True)

    (output / "telemetry_package.json").write_text(
        json.dumps(package, indent=2), encoding="utf8"
    )
    (output / "signed_verdict.json").write_text(
        json.dumps(
            {
                "stage": 35,
                "seed": args.seed,
                "verdict": verdict,
                "signature_base64": verifier_signature,
            },
            indent=2,
        ),
        encoding="utf8",
    )
    (output / "evidence.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf8"
    )
    (output / "collector_public_key.pem").write_bytes(collector_pem)
    (output / "verifier_public_key.pem").write_bytes(verifier_pem)
    (labels_output / "private_labels.json").write_text(
        json.dumps(labels, indent=2), encoding="utf8"
    )

    print(
        "STAGE35_RUN_OK "
        f"seed={args.seed} relational_alert_rows="
        f"{verdict['relational_alert_rows']} "
        f"legacy_alert_rows={verdict['legacy_count_status_alert_rows']} "
        f"verifier_ms={evidence['authenticated_verifier_latency_ms']:.2f}",
        flush=True,
    )


if __name__ == "__main__":
    main()
