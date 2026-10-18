from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run(cmd):
    subprocess.run(cmd,check=True)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--policy",type=Path,required=True)
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--duration-seconds",type=float,required=True)
    ap.add_argument("--batch-events",type=int,default=1500)
    ap.add_argument("--key-hex",required=True)
    args=ap.parse_args()
    args.output.mkdir(parents=True,exist_ok=True)

    start=time.monotonic()
    deadline=start+max(1.0,args.duration_seconds)
    batches=0
    events_total=0
    fp_total=0
    fn_total=0
    operation_totals={"restart":0,"stop":0,"start":0}
    batch_summaries=[]

    while time.monotonic()<deadline:
        batches+=1
        seed=secrets.token_hex(16)
        with tempfile.TemporaryDirectory() as td:
            td=Path(td)
            events=td/"events.jsonl"
            labels=td/"labels.jsonl"
            eval_out=td/"eval"
            run([
                sys.executable,
                str(Path(__file__).with_name(
                    "stage39_external_scenarios.py"
                )),
                "--policy",str(args.policy),
                "--events",str(events),
                "--labels",str(labels),
                "--key-hex",args.key_hex,
                "--seed",seed,
                "--count",str(args.batch_events),
                "--attack-rate","0",
            ])
            run([
                sys.executable,
                str(Path(__file__).with_name(
                    "stage39_orchestration_eval.py"
                )),
                "--policy",str(args.policy),
                "--events",str(events),
                "--labels",str(labels),
                "--key-hex",args.key_hex,
                "--output",str(eval_out),
            ])
            report=json.loads(
                (eval_out/"stage39_orchestration_report.json")
                .read_text(encoding="utf-8")
            )
            generator=json.loads(
                events.with_suffix(".summary.json")
                .read_text(encoding="utf-8")
            )
            relational=report["baselines"][
                "relational_signed_event"
            ]
            fp_total+=int(relational["FP"])
            fn_total+=int(relational["FN"])
            events_total+=int(report["events"])
            for name,value in generator["operations"].items():
                operation_totals[name]+=int(value)
            batch_summaries.append({
                "batch":batches,
                "events":int(report["events"]),
                "relational_fp":int(relational["FP"]),
                "relational_fn":int(relational["FN"]),
                "seed_sha256":hashlib.sha256(
                    seed.encode()
                ).hexdigest(),
            })

    elapsed=time.monotonic()-start
    if fp_total or fn_total:
        raise SystemExit(
            f"benign churn produced FP={fp_total} FN={fn_total}"
        )
    report={
        "stage":39,
        "kind":"wall-clock benign signed lifecycle churn",
        "requested_seconds":args.duration_seconds,
        "elapsed_seconds":elapsed,
        "batches":batches,
        "events":events_total,
        "operations":operation_totals,
        "relational_false_alerts":fp_total,
        "relational_false_negatives":fn_total,
        "external_generator_process_per_batch":True,
        "signed_orchestrator_events":True,
        "future_post_reference_used":False,
        "batch_summaries":batch_summaries,
    }
    (args.output/"stage39_churn_report.json").write_text(
        json.dumps(report,indent=2)+"\n",
        encoding="utf-8",
    )
    (args.output/"stage39_churn_report.md").write_text(
        "# Stage39 benign lifecycle churn\n\n"
        f"- Requested / elapsed: {args.duration_seconds:.0f} / "
        f"{elapsed:.1f} s\n"
        f"- Signed lifecycle events: {events_total}\n"
        f"- Operations: {operation_totals}\n"
        f"- Relational false alerts: {fp_total}\n"
        f"- External generator process per batch: true\n",
        encoding="utf-8",
    )
    print(json.dumps(report,indent=2))


if __name__=="__main__":
    main()
