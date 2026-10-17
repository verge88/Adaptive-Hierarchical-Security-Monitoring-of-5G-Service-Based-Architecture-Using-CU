from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

MUTATION_TYPES=("NSSF","AUSF","BSF","UDM","AMF","SMF","PCF","SCP","NRF")
ARTICLE_KINDS=(
    "identity_replacement",
    "endpoint_substitution",
    "service_injection",
    "fqdn_substitution",
    "nf_type_substitution",
    "compound_identity_service",
)
BOUNDARY_KINDS=("duplicate_profile",)


def cases():
    rows=[]
    for typ in MUTATION_TYPES:
        for kind in ARTICLE_KINDS:
            for variant in range(1,5):
                rows.append((typ,kind,variant,True))
        for kind in BOUNDARY_KINDS:
            rows.append((typ,kind,1,False))
    return rows


def atomic_write(path,doc):
    tmp=path.with_suffix(path.suffix+".tmp")
    tmp.write_text(json.dumps(doc,sort_keys=True)+"\n",encoding="utf-8")
    tmp.replace(path)


def wait_for_ack(path,sequence,timeout):
    deadline=time.monotonic()+timeout
    last=None
    while time.monotonic()<deadline:
        if path.exists():
            try:
                doc=json.loads(path.read_text(encoding="utf-8"))
                last=doc
                if int(doc.get("sequence",-1))==sequence:
                    return doc
            except Exception as exc:
                last={"error":f"{type(exc).__name__}: {exc}"}
        time.sleep(0.002)
    raise RuntimeError(
        f"timeout waiting for attack ack sequence={sequence}; last={last}"
    )


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--control-dir",type=Path,required=True)
    ap.add_argument("--timeout-seconds",type=float,default=180.0)
    args=ap.parse_args()
    args.control_dir.mkdir(parents=True,exist_ok=True)
    command=args.control_dir/"command.json"
    ack=args.control_dir/"ack.json"
    command.unlink(missing_ok=True)
    ack.unlink(missing_ok=True)

    results=[]
    for sequence,(typ,kind,variant,article_family) in enumerate(cases(),1):
        ack.unlink(missing_ok=True)
        onset_ns=time.monotonic_ns()
        doc={
            "schema":"stage39-external-attack-trigger-v1",
            "sequence":sequence,
            "target_nf_type":typ,
            "kind":kind,
            "variant":variant,
            "article_family":article_family,
            "onset_monotonic_ns":onset_ns,
        }
        atomic_write(command,doc)
        reply=wait_for_ack(ack,sequence,args.timeout_seconds)
        results.append({
            **doc,
            "ack_detection_monotonic_ns":
                int(reply.get("detection_monotonic_ns",0)),
            "ack_detected":bool(reply.get("detected")),
        })
        command.unlink(missing_ok=True)

    if not all(row["ack_detected"] for row in results):
        raise SystemExit("one or more externally triggered mutations missed")
    latencies=[
        (row["ack_detection_monotonic_ns"]-row["onset_monotonic_ns"])/1_000_000
        for row in results
    ]
    if any(value<0 for value in latencies):
        raise SystemExit("negative external onset latency")
    summary={
        "schema":"stage39-external-attack-driver-report-v1",
        "cases":len(results),
        "all_acknowledged":True,
        "min_ms":min(latencies),
        "max_ms":max(latencies),
    }
    atomic_write(args.control_dir/"driver_report.json",summary)
    print(json.dumps(summary,indent=2))


if __name__=="__main__":
    main()
