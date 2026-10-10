"""Stage 12 large-N replication of the pre-registered Stage 11 lab SCP protocol.

12 independent CI runners × 6 repetitions of each 2 attacks × 4 telemetry
regimes = 576 separate LAB proxy corruption episodes (not 576 attack *types*).
Keep Stage 11 experiment/detector implementation unchanged to avoid tuning
against its disappointing 32-case pilot outcome.

Open5GS NRF and native NSSFs are REAL and healthy; the injected fault is ONLY
in a separate research producer + research HTTP/2 SCP. This experiment does
not compromise real Open5GS NF software or native 3GPP SBI transactions.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import random

from .stage11_hedged import (
    ATTACKS,ALIGNMENTS,METHODS,BUDGETED,SCHEDULED,
    BUDGET,TICKS,MAX_GAP,N,episode,wait_core
)

RUNNERS=12
REPEATS_PER_CELL=6
CELLS_PER_RUNNER=len(ATTACKS)*len(ALIGNMENTS)
EPISODES_PER_RUNNER=CELLS_PER_RUNNER*REPEATS_PER_CELL
EXPECTED_EPISODES=RUNNERS*EPISODES_PER_RUNNER
SEED_START=3601


def factorial(seed):
    """Stratified independently shuffled episodes without algorithmic retraining."""
    if not SEED_START<=seed<SEED_START+RUNNERS:
        raise ValueError("Runner seed outside pre-registered independent set")
    rng=random.Random(seed*3319+991)
    cases=[(attack,regime,rep) for attack in ATTACKS for regime in ALIGNMENTS
           for rep in range(REPEATS_PER_CELL)]
    rng.shuffle(cases)
    cases_with_targets=[]
    for ix,(attack,regime,rep) in enumerate(cases):
        # Same allocation logic used in stage11:
        # risk regime is EXTERNAL and fixed prior to attack. No fault label
        # or discovered anomaly is passed into the CU scheduler.
        stressed=rng.randrange(2)
        zone=(1-stressed if regime=="misleading" else
              rng.randrange(2) if regime=="neutral" else stressed)
        target=2*zone+rng.randrange(2)
        cases_with_targets.append(dict(case=ix,attack=attack,regime=regime,
                                       repetition=rep,stress_zone=stressed,
                                       target_context=target))
    return cases_with_targets


async def run(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    cases=factorial(args.seed)
    data=[]
    traces=[]
    for k,config in enumerate(cases):
        print(f"Stage12 seed={args.seed} event={k+1}/{len(cases)} "
              f"{config['attack']} risk={config['regime']} "
              f"rep={config['repetition']}",flush=True)
        rows,trace=await episode(
            args.seed,k,config["attack"],config["regime"],
            config["target_context"],config["stress_zone"],args.nrf_url)
        if len(rows)!=len(METHODS) or not trace["tampered_txids"]:
            raise AssertionError("Real proxy corruption or strong baseline missing")
        data.extend(rows)
        traces.append(dict(**trace,repetition=config["repetition"]))
        if args.checkpoint_every and (k+1)%args.checkpoint_every==0:
            print(f"Completed {k+1}/{len(cases)} laboratory selective faults",
                  flush=True)
    root=Path(args.output)
    root.mkdir(parents=True,exist_ok=True)
    (root/"events.json").write_text(json.dumps(data,indent=2))
    (root/"traces.json").write_text(json.dumps(traces,indent=2))
    (root/"manifest.json").write_text(json.dumps(dict(
        research_stage=12,protocol_frozen_from_stage=11,
        provenance="laboratory research HTTP/2 producer + research SCP; real NRF/NSSF healthy",
        native_open5gs_NF_compromised=False,native_open5gs_SCP_compromised=False,
        producer_origin_key_never_exposed_to_lab_scp=True,
        genuine_native_NSSF_SBI_corrupted=False,
        number_of_distinct_attack_modes=len(ATTACKS),
        attack_modes=list(ATTACKS),risk_regimes=list(ALIGNMENTS),
        independent_runner_seed=args.seed,
        predefined_seeds=list(range(SEED_START,SEED_START+RUNNERS)),
        repetitions_per_attack_risk_cell=REPEATS_PER_CELL,
        attacks_per_runner=len(cases),predefined_total_attacks=EXPECTED_EPISODES,
        total_detector_rows=len(data),
        equal_budget_active_methods=list(BUDGETED),
        active_CU_checks_per_episode=BUDGET*TICKS,
        full_two_ends_checks_per_episode=N*TICKS,
        source_reused="research.stage11_hedged.episode",
        no_training_on_stage11_outcomes=True),indent=2))
    print(f"STAGE12 COMPLETED seed={args.seed}; attacks={len(cases)}; "
          f"detector_rows={len(data)}; retained_tampering_traces={len(traces)}",
          flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,required=True)
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    p.add_argument("--output",default="stage12_shard")
    p.add_argument("--checkpoint-every",type=int,default=8)
    args=p.parse_args()
    asyncio.run(run(args))


if __name__=="__main__":
    main()
