"""Stage35 benchmark client for the full collector->verifier->anchor path."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import urllib.request


def canonical_bytes(doc: dict) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector-endpoint", required=True)
    parser.add_argument("--policy-sha256-file", required=True)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--output", default="stage35_benchmark.json")
    args = parser.parse_args()

    policy = Path(args.policy_sha256_file).read_text().strip()
    request = urllib.request.Request(
        args.collector_endpoint.rstrip("/") + "/benchmark",
        data=canonical_bytes(
            {
                "policy_sha256": policy,
                "iterations": args.iterations,
            }
        ),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=600) as response:
        doc = json.loads(response.read())
    if int(doc.get("iterations", 0)) != args.iterations:
        raise ValueError("benchmark iteration mismatch")
    Path(args.output).write_text(json.dumps(doc, indent=2), encoding="utf8")
    print(
        "STAGE35_BENCHMARK_OK "
        f"successes={doc['successes']}/{doc['iterations']} "
        f"p95={doc['latency_ms']['p95']:.2f}ms",
        flush=True,
    )


if __name__ == "__main__":
    main()
