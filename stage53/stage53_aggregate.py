#!/usr/bin/env python3
import argparse,json,statistics
from pathlib import Path

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--root",required=True)
    ap.add_argument("--expected-workers",type=int,required=True)
    ap.add_argument("--expected-total",type=int,required=True)
    ap.add_argument("--out",required=True)
    a=ap.parse_args()
    root=Path(a.root)
    results=[];hashes=[];metas=[]
    for p in sorted(root.rglob("result.json")):
        d=json.loads(p.read_text())
        results.append(d)
        hp=p.parent/"uuid_hashes.txt"
        if not hp.exists():
            raise SystemExit(f"missing {hp}")
        hashes.extend(x.strip() for x in hp.read_text().splitlines() if x.strip())
        mp=p.parent/"runner_meta.json"
        if mp.exists():
            metas.append(json.loads(mp.read_text()))
    if len(results)!=a.expected_workers:
        raise SystemExit(f"workers {len(results)} != {a.expected_workers}")

    total=sum(x["requested_nf"] for x in results)
    live=sum(x["live_processes"] for x in results)
    nfm=sum(x["nrf_individually_verified_profiles"] for x in results)
    witnesses=sum(x["witness_records"] for x in results)
    sbi=sum(x["direct_sbi_reachable"] for x in results)
    binary_hashes=sorted(set(x["binary_sha256"] for x in results))
    unique_uuid_hashes=len(set(hashes))
    runner_names=sorted(set(str(x.get("runner_name")) for x in metas))
    hostnames=sorted(set(str(x.get("hostname")) for x in metas))
    machine_ids=sorted(set(str(x.get("machine_id_sha256")) for x in metas))
    boot_ids=sorted(set(str(x.get("boot_id_sha256")) for x in metas))
    overlap_start=max(x["ready_unix"] for x in results)
    overlap_stop=min(x["stop_unix"] for x in results)
    simultaneous_overlap_seconds=max(0.0,overlap_stop-overlap_start)

    report={
      "schema":"stage53-multiworker-aggregate-v2",
      "workers":len(results),
      "expected_workers":a.expected_workers,
      "requested_nf_total":total,
      "live_processes_total":live,
      "witness_records_total":witnesses,
      "nrf_individually_verified_profiles_total":nfm,
      "direct_sbi_reachable_total":sbi,
      "uuid_hash_records":len(hashes),
      "globally_unique_uuid_hashes":unique_uuid_hashes,
      "binary_sha256_values":binary_hashes,
      "runner_meta_records":len(metas),
      "unique_runner_names":len(runner_names),
      "unique_hostnames":len(hostnames),
      "unique_machine_id_hashes":len(machine_ids),
      "unique_boot_id_hashes":len(boot_ids),
      "registration_convergence_seconds_max":max(x["registration_convergence_seconds"] for x in results),
      "registration_convergence_seconds_median":statistics.median(x["registration_convergence_seconds"] for x in results),
      "cgroup_memory_current_after_hold_total":sum(x.get("cgroup_memory_current_after_hold") or 0 for x in results),
      "rss_kib_total_sum":sum(x.get("rss_kib_total") or 0 for x in results),
      "simultaneous_overlap_seconds":simultaneous_overlap_seconds,
      "bulk_discovery_success_workers":sum(bool(x.get("bulk_discovery_ok")) for x in results),
      "all_worker_checks_passed":all(x.get("all_checks_passed") is True for x in results),
    }
    checks={
      "worker_count":len(results)==a.expected_workers,
      "total_requested":total==a.expected_total,
      "all_live":live==a.expected_total,
      "all_witnessed":witnesses==a.expected_total,
      "all_nfm_verified":nfm==a.expected_total,
      "all_sbi_reachable":sbi==a.expected_total,
      "all_uuid_hashes_unique":len(hashes)==a.expected_total and unique_uuid_hashes==a.expected_total,
      "one_binary_build_hash":len(binary_hashes)==1,
      "all_worker_checks_passed":report["all_worker_checks_passed"],
      "runner_meta_complete":len(metas)==a.expected_workers,
      "positive_simultaneous_overlap":simultaneous_overlap_seconds>=5.0,
    }
    report["checks"]=checks
    report["all_checks_passed"]=all(checks.values())
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    md=out.with_suffix(".md")
    md.write_text("# Stage53 multi-worker aggregate\n\n"+
        "\n".join(f"- {k}: {v}" for k,v in report.items() if k!="checks")+
        "\n- checks: "+json.dumps(checks,sort_keys=True)+"\n")
    print(json.dumps(report,indent=2,sort_keys=True))
    if not report["all_checks_passed"]:
        raise SystemExit("aggregate checks failed")

if __name__=="__main__":
    main()
