"""Stage14 scientific audit: NATIVE SCP availability and SBI routing ONLY.

No security detection effects are estimated: no malicious response alterations
are introduced. A pass allows Stage15 design, not Stage14 attack superiority.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import statistics

from .stage14_native_scp import NATIVE_PROBES,NRF_PATH,NSSF_PATH

SEEDS=(5401,5402,5403,5404)
KINDS=("NRF","NSSF","NSSF2")
PHASES=("before","after_restart")


def analyze(root):
    inputs=sorted(Path(root).rglob("observations.json"))
    if len(inputs)!=len(SEEDS):
        raise AssertionError("Not all four independent hosted runners supplied native traces")
    rows=[]
    per_seed={}
    for f in inputs:
        doc=json.loads(f.read_text())
        seed=doc["seed"]
        if seed not in SEEDS or seed in per_seed:
            raise AssertionError("Non-preregistered or duplicate runner seed")
        if any(doc.get(x) is not y for x,y in [
            ("real_open5gs_scp_binary",True),
            ("real_open5gs_nrf_and_nssf_sbi",True),
            ("native_NF_binaries_modified",False),
            ("research_proxy_used",False),
            ("selective_payload_corruption_performed",False)]):
            raise AssertionError("Incorrect provenance; cannot call research proxy native")
        negative=doc["causal_scp_stop_control"]
        if (negative.get("native_direct_NRF_status")!=200
            or not negative.get("proxy_refused_after_native_scp_stop")
            or "unexpected_routed_HTTP_status" in negative):
            raise AssertionError("No causal native SCP stop/direct NF control")
        if doc["nrf_registry_before"]!=doc["nrf_registry_after_scp_restart"]:
            raise AssertionError("Native NRF registration drift")
        pairs=doc["direct_proxy_pairs"]
        if len(pairs)!=2*NATIVE_PROBES*len(KINDS):
            raise AssertionError("Missing exact direct-vs-native-SCP trial pairs")
        for kind in KINDS:
            for phase in PHASES:
                relevant=[r for r in pairs if r["kind"]==kind and r["phase"]==phase]
                if len(relevant)!=NATIVE_PROBES:
                    raise AssertionError("Native path×phase stratum unbalanced")
                if any(not r["identical_HTTP_status"] for r in relevant):
                    raise AssertionError("Native SCP did not reproduce real NF status")
                if kind=="NRF":
                    if (any(r["same_NRF_nf_instance_ids"] is not True
                            or r["native_direct"]["status"]!=200 for r in relevant)):
                        raise AssertionError("NRF discovery through SCP failed")
                else:
                    if (any(r["native_direct"]["status"] not in (400,404,405,422)
                            for r in relevant)):
                        raise AssertionError("NSSF native read-only error probe not comparable")
                if any(r["native_direct"]["wire_bytes"]<=0
                       or r["forwarded_via_native_scp"]["wire_bytes"]<=0
                       for r in relevant):
                    raise AssertionError("Not genuinely framed HTTP2")
        rows.extend(dict(seed=seed,**pair) for pair in pairs)
        per_seed[seed]=doc["descriptive_timing"]
    if tuple(sorted(per_seed))!=SEEDS:
        raise AssertionError("Missing preregistered seed")
    stats={}
    for kind in KINDS:
        observations=[x for x in rows if x["kind"]==kind]
        paired=[x["forwarded_via_native_scp"]["elapsed_ms"]-
                x["native_direct"]["elapsed_ms"] for x in observations]
        # Pair-by-pair descriptive data (do not claim security detection or
        # statistical superiority with just four independent hosted runners).
        runner_median={str(seed):statistics.median(
            x["forwarded_via_native_scp"]["elapsed_ms"]-
            x["native_direct"]["elapsed_ms"] for x in observations
            if x["seed"]==seed) for seed in SEEDS}
        stats[kind]=dict(
            paired_samples=len(paired),
            median_native_SCP_extra_wall_ms=statistics.median(paired),
            mean_native_SCP_extra_wall_ms=statistics.mean(paired),
            per_runner_paired_median_ms=runner_median,
            min_native_SCP_extra_wall_ms=min(paired),
            max_native_SCP_extra_wall_ms=max(paired))
    summary=dict(stage=14,status="native_scp_forwarding_confirmed",
       scope="UNMODIFIED native Open5GS SCP/NRF/NSSF, HTTP2 h2c infrastructure feasibility, not attack study",
       independent_runners=len(SEEDS),seeds=list(SEEDS),
       native_direct_vs_scp_request_pairs=len(rows),
       verified_nrf_discovery_via_scp=sum(x["kind"]=="NRF" for x in rows),
       read_only_native_nssf_responses_via_scp=sum(x["kind"].startswith("NSSF") for x in rows),
       negative_causal_scp_stop_controls=len(SEEDS),
       attack_episodes=0,
       signed_KIE_produced_by_native_NF=False,
       malicious_native_SCP_tampering_tested=False,
       genuine_producer_integrity_proof_available=False,
       dynamic_SBA_selection_success_tested=False,
       median_latency_descriptive=stats,
       scientific_boundary="Status matching and SCP kill switch support forwarding; no 3GPP mTLS/SEPP, NRF authentication, native integrity attestations, NF consumer transaction origin, or attack detection effects assessed")
    return summary,rows


def markdown(s):
    lines=[
        "# Stage 14 — Real Open5GS SCP forwarding and causal dependency",
        "",
        f"**Native transport gate:** {s['independent_runners']} independent containerized "
        f"Open5GS runners all proved genuine SCP forwarding to genuine native "
        f"NRF/NSSF over HTTP/2 (h2c). "
        f"{s['native_direct_vs_scp_request_pairs']} paired direct-vs-SCP trials.",
        f"Real NRF discovery matching NSSF instance IDs: "
        f"{s['verified_nrf_discovery_via_scp']} pairs.",
        f"Read-only native NSSF handler status matched via SCP: "
        f"{s['read_only_native_nssf_responses_via_scp']} pairs.",
        f"Causal stop controls: {s['negative_causal_scp_stop_controls']} / "
        f"{s['independent_runners']}. In all cases DIRECT native NRF/NSSF "
        "remained alive while HTTP2 route via stopped native SCP failed; "
        "route was restored after starting the native SCP.",
        "",
        "| Native producer | Paired trials | Median extra wall time via SCP (ms) | Per-runner paired medians (ms) |",
        "|---|---:|---:|---|"]
    for kind,r in s["median_latency_descriptive"].items():
        medians=", ".join(f"{seed}: {t:+.2f}" for seed,t in r["per_runner_paired_median_ms"].items())
        lines.append(f"| {kind} | {r['paired_samples']} | "
                     f"{r['median_native_SCP_extra_wall_ms']:+.2f} | {medians} |")
    lines+=["","## Critical constraints and no overclaim",
        "- This is an INFRASTRUCTURE validation, **0 attacks** and no KIE "
        "effect estimate. It must not be compared directly with Stages 12/13 "
        "as an improved detector.",
        "- Real Open5GS NRF/NSSF produce the original HTTP2 messages and a "
        "real Open5GS SCP forwards them, but the CONSUMER is an EXTERNAL "
        "research HTTP2 client, not an AMF producing real UE authentication/"
        "slice-selection procedures.",
        "- NSSF GET without required parameters intentionally returns a native "
        "4xx status. This proves liveness/forwarding, NOT a successful "
        "Nnssf_NSSelection semantic request.",
        "- No tampered native payload, no native NF or SCP compromise, no "
        "producer-origin HMAC from native NF, no native receiver-side "
        "signature verification, no 3GPP SBA TLS/mTLS in this lab.",
        "- Descriptive wall-clock latency varies across hosted GitHub runners; "
        "no population-level confidence interval or scientific novelty asserted.",
        "- Stage15 requires real Nnssf valid request/response semantics and "
        "separately grounded origin proof, plus strong trusted-plain and "
        "two-sided endpoint controls at equal visibility/budgets.",
        ""]
    return "\n".join(lines)


def main():
    a=argparse.ArgumentParser()
    a.add_argument("--input",default="stage14_batches")
    a.add_argument("--output",default="stage14_report")
    x=a.parse_args()
    summary,rows=analyze(x.input)
    dest=Path(x.output)
    dest.mkdir(parents=True,exist_ok=True)
    (dest/"summary.json").write_text(json.dumps(summary,indent=2))
    (dest/"raw_pairs.json").write_text(json.dumps(rows,indent=2))
    (dest/"REPORT.md").write_text(markdown(summary))
    print(markdown(summary))


if __name__=="__main__":
    main()
