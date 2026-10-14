"""Submit label-free telemetry to the Stage-33 external verifier."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
import urllib.request


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--api-token", required=True)
    parser.add_argument("--raw-telemetry", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--kms-receipt", required=True)
    parser.add_argument("--kms-public-key", required=True)
    parser.add_argument("--output", default="stage33_external_response.json")
    args = parser.parse_args()

    raw_rows = json.loads(
        Path(args.raw_telemetry).read_text(encoding="utf8")
    )
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("Stage33 raw telemetry is empty")
    if any(
        "mutation_ticks" in row or "private_labels" in row
        for row in raw_rows
        if isinstance(row, dict)
    ):
        raise ValueError("Stage33 submitter found private labels in request")

    request_body = {
        "raw_telemetry": raw_rows,
        "policy_json_base64": b64(Path(args.policy)),
        "kms_receipt_json_base64": b64(Path(args.kms_receipt)),
        "kms_public_key_pem_base64": b64(Path(args.kms_public_key)),
    }
    body = json.dumps(
        request_body,
        separators=(",", ":"),
    ).encode("utf8")

    target = args.url.rstrip("/") + "/verify"
    request = urllib.request.Request(
        target,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + args.api_token,
        },
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        payload = response.read()
        if response.status != 200:
            raise RuntimeError(
                f"Stage33 external verifier HTTP {response.status}"
            )

    doc = json.loads(payload)
    Path(args.output).write_text(
        json.dumps(doc, indent=2),
        encoding="utf8",
    )
    print(
        "STAGE33_EXTERNAL_SUBMIT_OK "
        f"output={args.output}",
        flush=True,
    )


if __name__ == "__main__":
    main()
