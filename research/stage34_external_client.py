"""Stage 34 client for external signed collector and relational verifier."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import secrets
import urllib.error
import urllib.request

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(
        doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf8")


def get_json(url: str, timeout: float = 30) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read())


def post_json(url: str, doc: dict, timeout: float = 180) -> tuple[int, dict]:
    request = urllib.request.Request(
        url,
        data=canonical_bytes(doc),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as ex:
        body = ex.read()
        return ex.code, json.loads(body) if body else {}


def load_ec_public_key(pem: bytes) -> ec.EllipticCurvePublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("expected EC public key")
    return key


def verify_signature(
    public_key: ec.EllipticCurvePublicKey,
    doc: dict,
    signature_b64: str,
) -> None:
    public_key.verify(
        base64.b64decode(signature_b64, validate=True),
        canonical_bytes(doc),
        ec.ECDSA(hashes.SHA256()),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--collector-endpoint", required=True)
    parser.add_argument("--verifier-endpoint", required=True)
    parser.add_argument("--policy-sha256-file", required=True)
    parser.add_argument("--expected-collector-key-sha256", required=True)
    parser.add_argument("--expected-verifier-key-sha256", required=True)
    parser.add_argument("--output", default="stage34_external")
    parser.add_argument("--labels-output", default="stage34_private_labels")
    args = parser.parse_args()

    collector = args.collector_endpoint.rstrip("/")
    verifier = args.verifier_endpoint.rstrip("/")
    policy_sha = Path(args.policy_sha256_file).read_text(
        encoding="ascii"
    ).strip().lower()

    collector_health = get_json(collector + "/health")
    verifier_health = get_json(verifier + "/health")
    if collector_health.get("policy_sha256") != policy_sha:
        raise ValueError("collector policy mismatch")
    if verifier_health.get("policy_sha256") != policy_sha:
        raise ValueError("verifier policy mismatch")
    if collector_health.get("telemetry_origin") != "external_open5gs_testbed":
        raise ValueError("collector is not external-testbed origin")

    collector_key_doc = get_json(collector + "/public-key")
    collector_pem = collector_key_doc["public_key_pem"].encode("ascii")
    collector_hash = hashlib.sha256(collector_pem).hexdigest()
    if collector_hash != args.expected_collector_key_sha256:
        raise ValueError("collector key fingerprint mismatch")
    if collector_key_doc.get("public_key_sha256") != collector_hash:
        raise ValueError("collector self-reported key mismatch")
    collector_key = load_ec_public_key(collector_pem)

    verifier_key_doc = get_json(verifier + "/public-key")
    verifier_pem = verifier_key_doc["public_key_pem"].encode("ascii")
    verifier_hash = hashlib.sha256(verifier_pem).hexdigest()
    if verifier_hash != args.expected_verifier_key_sha256:
        raise ValueError("verifier key fingerprint mismatch")
    if verifier_key_doc.get("public_key_sha256") != verifier_hash:
        raise ValueError("verifier self-reported key mismatch")
    verifier_key = load_ec_public_key(verifier_pem)

    challenge_nonce = secrets.token_hex(32)
    status, collector_result = post_json(
        collector + "/run",
        {
            "stage": 34,
            "seed": args.seed,
            "challenge_nonce": challenge_nonce,
            "policy_sha256": policy_sha,
        },
        timeout=240,
    )
    if status != 200:
        raise RuntimeError(
            f"collector run failed HTTP {status}: {collector_result}"
        )

    package = collector_result["telemetry_package"]
    collector_signature = collector_result["collector_signature_base64"]
    private_labels = collector_result["private_labels"]

    verify_signature(collector_key, package, collector_signature)
    if int(package["seed"]) != args.seed:
        raise ValueError("collector package seed mismatch")
    if package["challenge_nonce"] != challenge_nonce:
        raise ValueError("collector challenge binding mismatch")
    if package["policy_sha256"] != policy_sha:
        raise ValueError("collector package policy mismatch")
    if private_labels["challenge_nonce"] != challenge_nonce:
        raise ValueError("private labels challenge mismatch")

    tampered_package = json.loads(json.dumps(package))
    tampered_package["seed"] = args.seed + 1
    collector_tamper_rejected = False
    try:
        verify_signature(collector_key, tampered_package, collector_signature)
    except InvalidSignature:
        collector_tamper_rejected = True
    if not collector_tamper_rejected:
        raise AssertionError("tampered collector package unexpectedly verified")

    verify_request = {
        "telemetry_package": package,
        "collector_signature_base64": collector_signature,
    }
    vstatus, verifier_result = post_json(
        verifier + "/verify", verify_request, timeout=60
    )
    if vstatus != 200:
        raise RuntimeError(
            f"relational verifier failed HTTP {vstatus}: {verifier_result}"
        )

    verdict = verifier_result["verdict"]
    verifier_signature = verifier_result["signature_base64"]
    verify_signature(verifier_key, verdict, verifier_signature)

    package_sha = hashlib.sha256(canonical_bytes(package)).hexdigest()
    if verdict.get("collector_package_sha256") != package_sha:
        raise ValueError("verdict is not bound to collector package")
    if verdict.get("challenge_nonce") != challenge_nonce:
        raise ValueError("verdict challenge mismatch")
    if int(verdict.get("seed", -1)) != args.seed:
        raise ValueError("verdict seed mismatch")
    if verdict.get("attack_labels_received") is not False:
        raise ValueError("verifier received private labels")

    tampered_verdict = json.loads(json.dumps(verdict))
    tampered_verdict["relational_alert_rows"] = (
        int(tampered_verdict["relational_alert_rows"]) + 1
    )
    verifier_tamper_rejected = False
    try:
        verify_signature(verifier_key, tampered_verdict, verifier_signature)
    except InvalidSignature:
        verifier_tamper_rejected = True
    if not verifier_tamper_rejected:
        raise AssertionError("tampered relational verdict unexpectedly verified")

    replay_status, replay_doc = post_json(
        verifier + "/verify", verify_request, timeout=60
    )
    replay_rejected = replay_status in (400, 409, 422)
    if not replay_rejected:
        raise AssertionError(
            f"verifier replay was not rejected: {replay_status} {replay_doc}"
        )

    output = Path(args.output)
    labels_output = Path(args.labels_output)
    output.mkdir(parents=True, exist_ok=True)
    labels_output.mkdir(parents=True, exist_ok=True)

    evidence = {
        "stage": 34,
        "seed": args.seed,
        "policy_sha256": policy_sha,
        "challenge_nonce": challenge_nonce,
        "collector_endpoint": collector,
        "verifier_endpoint": verifier,
        "collector_public_key_sha256": collector_hash,
        "verifier_public_key_sha256": verifier_hash,
        "collector_signature_verified": True,
        "collector_tamper_rejected": True,
        "verifier_signature_verified": True,
        "verifier_tamper_rejected": True,
        "verifier_replay_rejected": True,
        "collector_package_sha256": package_sha,
        "collector_service_revision": package[
            "collector_service_revision"
        ],
        "verifier_service_revision": verdict[
            "verifier_service_revision"
        ],
        "native_nrf_source_sha256": package[
            "native_nrf_source_sha256"
        ],
        "telemetry_origin": "external_open5gs_testbed",
        "github_created_telemetry_rows": False,
    }
    (output / "external_evidence.json").write_text(
        json.dumps(evidence, indent=2), encoding="utf8"
    )
    (output / "telemetry_package.json").write_text(
        json.dumps(package, indent=2), encoding="utf8"
    )
    (output / "relational_verdict.json").write_text(
        json.dumps(
            {
                "stage": 34,
                "seed": args.seed,
                "verdict": verdict,
                "signature_base64": verifier_signature,
            },
            indent=2,
        ),
        encoding="utf8",
    )
    (labels_output / "private_labels.json").write_text(
        json.dumps(private_labels, indent=2), encoding="utf8"
    )

    print(
        "STAGE34_EXTERNAL_RELATIONAL_OK "
        f"seed={args.seed} legacy_alert_rows="
        f"{verdict['legacy_count_status_alert_rows']} "
        f"relational_alert_rows={verdict['relational_alert_rows']} "
        "replay_rejected=1",
        flush=True,
    )


if __name__ == "__main__":
    main()
