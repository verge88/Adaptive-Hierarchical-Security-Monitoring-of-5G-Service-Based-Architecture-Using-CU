"""Stage 13: genuinely separate calibration and held-out attack episodes.

Risk confidence is updated ONLY from CU authenticated producer-origin
mismatches in training episodes; attack labels/contexts are NEVER passed
from injector or evaluator to the policy. Posterior is FROZEN before
the separate held-out evaluation attack episodes begin.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import random

from .stage13_confidence import (ATTACKS,ALIGNMENTS,METHODS,BUDGETED,N,
                                  TICKS,BUDGET,TrustedRiskCalibrator,
                                  episode,wait_core)

RUNNERS=12
SEED_START=4801
CAL_REPS=2
EVAL_REPS=3
CAL_EVENTS=len(ATTACKS)*len(ALIGNMENTS)*CAL_REPS
EVAL_EVENTS=len(ATTACKS)*len(ALIGNMENTS)*EVAL_REPS
TRAINING_TOTAL=RUNNERS*CAL_EVENTS
TEST_TOTAL=RUNNERS*EVAL_EVENTS


def create_cases(seed,phase):
    if seed not in range(SEED_START,SEED_START+RUNNERS):
        raise ValueError("Seed outside 12 independent preregistered CI runners")
    if phase not in ("calibration","heldout"):
        raise ValueError("Unexpected run phase")
    reps=CAL_REPS if phase=="calibration" else EVAL_REPS
    rng=random.Random(seed*129211+(19 if phase=="calibration" else 57071))
    cases=[(a,r,j) for a in ATTACKS for r in ALIGNMENTS for j in range(reps)]
    rng.shuffle(cases)
    descriptors=[]
    for idx,(attack,regime,repetition) in enumerate(cases):
        stressed=rng.randrange(2)
        target_zone=(1-stressed if regime=="misleading" else
                     rng.randrange(2) if regime=="neutral" else stressed)
        target=2*target_zone+rng.randrange(2)
        descriptors.append(dict(episode_id=idx if phase=="calibration"
                                      else CAL_EVENTS+idx,
                                phase=phase,attack=attack,regime=regime,
                                repetition=repetition,stress_zone=stressed,
                                target_context=target))
    return descriptors


async def execute(args):
    await wait_core(args.nrf_url,require_registered=True,timeout=75)
    model=TrustedRiskCalibrator()
    root=Path(args.output)
    root.mkdir(parents=True,exist_ok=True)
    payloads={}
    # Do not use a "training" copy of the evaluation data: both phases
    # instantiate fresh LAB producers/SCPs and have distinct transaction IDs.
    for phase in ("calibration","heldout"):
        cases=create_cases(args.seed,phase)
        # Eligibility for TEST is fixed once, before first evaluation attack;
        # calibration never gets a privileged ground-truth target label.
        trust_risk=model.choose_risk() if phase=="heldout" else False
        rows=[]
        traces=[]
        for i,c in enumerate(cases):
            print(f"STAGE13 seed={args.seed} {phase} "
                  f"{i+1}/{len(cases)} type={c['attack']} "
                  f"signal={c['regime']} guard_risk={trust_risk}",flush=True)
            observed,trace=await episode(
                args.seed,c["episode_id"],c["attack"],c["regime"],
                c["target_context"],c["stress_zone"],args.nrf_url,
                trust_risk=trust_risk,calibration=phase=="calibration")
            if not trace["tampered_txids"] or len(observed)!=len(METHODS):
                raise AssertionError("LAB SCP actual corruption not confirmed")
            traces.append(trace)
            rows.extend(observed)
            if phase=="calibration":
                # The ONLY policy feedback comes from authenticated proof of
                # original producer response mismatch; target_context from
                # the injector and hidden labels are not used here.
                evidence=trace["verified_feedback"]
                if len(evidence)>1:
                    raise AssertionError("Multiple calibration labels per incident")
                for item in evidence:
                    if item["proof"]!="producer_hmac_and_independent_cu_hmac":
                        raise AssertionError("Unauthenticated feedback")
                    model.observe_verified_mismatch(
                        item["verified_producer_context"],
                        item["observed_high_zone"])
            elif trace["verified_feedback"]:
                raise AssertionError("Holdout phase must not train the policy")
        payloads[phase]=dict(rows=rows,traces=traces,guard_risk=trust_risk)
        if phase=="calibration":
            print(f"STAGE13 FROZEN policy evidence {json.dumps(model.snapshot())}",
                  flush=True)
    (root/"events.json").write_text(json.dumps(payloads["heldout"]["rows"],indent=2))
    (root/"traces.json").write_text(json.dumps(payloads["heldout"]["traces"],indent=2))
    (root/"calibration_events.json").write_text(
        json.dumps(payloads["calibration"]["rows"],indent=2))
    (root/"calibration_traces.json").write_text(
        json.dumps(payloads["calibration"]["traces"],indent=2))
    (root/"manifest.json").write_text(json.dumps(dict(
        research_stage=13,
        threat_model="lab dynamic producer and lab SCP response tampering only",
        real_open5gs_nrf_and_nssf_healthy=True,
        native_open5gs_NF_compromised=False,
        native_open5gs_SCP_compromised=False,
        source_hmac_from_research_producer_only=True,
        risk_learning_sources="first CU-verified positive original-tx mismatch in calibration episode",
        calibration_ground_truth_leaked_to_policy=False,
        calibration_condition_balanced=True,
        distinct_training_and_test_episodes=True,
        holdout_online_weight_updates=False,
        heldout_weights_frozen=True,
        seed=args.seed,pre_registered_seeds=list(range(SEED_START,SEED_START+RUNNERS)),
        train_episodes=CAL_EVENTS,heldout_episodes=EVAL_EVENTS,
        train_rows=len(payloads["calibration"]["rows"]),
        heldout_rows=len(payloads["heldout"]["rows"]),
        active_checks_per_episode=TICKS*BUDGET,
        full_two_end_checks_per_episode=TICKS*N,
        verified_calibration_posterior=model.snapshot(),
        chosen_heldout_guard_policy=(
            "risk_hierarchical" if payloads["heldout"]["guard_risk"]
            else "safe_fixed_fallback")
    ,indent=2))
    print(f"STAGE13 DONE seed={args.seed} calibration={CAL_EVENTS} "
          f"HELDOUT={EVAL_EVENTS}; frozen_guard={model.choose_risk()}",
          flush=True)


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--seed",type=int,required=True)
    p.add_argument("--output",default="stage13_shard")
    p.add_argument("--nrf-url",default="http://127.0.0.1:7777")
    a=p.parse_args()
    asyncio.run(execute(a))


if __name__=="__main__":
    main()
