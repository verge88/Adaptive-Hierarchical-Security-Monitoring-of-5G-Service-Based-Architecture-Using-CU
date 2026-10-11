# Stage 16 — OOD attack sweep and strong sequential baselines

Stage 16 is a robustness audit of the Stage-15 hierarchical e-CUSUM.  The
Stage-15 detector is imported unchanged; this stage does not retune it after
seeing the new attack distribution.

## Research question

Does the Stage-15 detector still outperform stronger comparison detectors when:

- attack amplitudes are no longer fixed constants;
- attacks can over-report or under-report;
- temporal attack shapes differ from the training simulator;
- benign counter noise becomes more heteroscedastic after warm-up;
- clean reconciliation outliers are more frequent and heavier-tailed;
- maintenance, burst and seasonal dynamics shift?

The primary comparison is event recall and detection delay under a fixed
false-alarm budget and exactly the same CU schedule.

## OOD simulator

research/stage16_simulation.py introduces four primary attack families:

- micro_step — previously unseen low-amplitude persistent corruption;
- reverse_step — under-reporting instead of the old one-direction model;
- slow_nonlinear_ramp — a convex, nearly full-window ramp;
- sparse_bursts — short corruption bursts embedded in mostly small deviations.

Each amplitude is sampled continuously for every event.  Three instances of
each primary family are generated per world.

A fifth class, observer_silent_semantic, changes passive behavior but creates
no trusted-counter discrepancy.  It deliberately violates the independent
integrity-observer assumption.  It is reported as a boundary test and excluded
from the primary aggregate score.

Clean traffic also shifts relative to Stage 15: different seasonal periods,
nonlinear load drift, increasing counter variance, randomized maintenance
strength/duration, randomized local bursts, and a higher clean outlier rate.

## Strong comparison detectors

All classic baselines use the same warm-up data and the same hierarchical
passive/integrity features as the frozen e-CUSUM.  They differ only in their
decision recurrence:

- calibrated_static — one-shot calibrated surprise threshold;
- ewma — exponentially weighted moving sequential surprise;
- cusum — classical positive Page-style CUSUM;
- page_hinkley — running-mean Page-Hinkley change statistic.

This avoids an unfair comparison where only the new detector receives better
features.

## Reproducible tuning protocol

Unlike Stage 15, the baseline tuning procedure is executable and preserved.

research/stage16_tune.py:

1. uses only seeds 4001..4024;
2. exhaustively evaluates the declared parameter grids;
3. retains configurations with mean false alarms <= 0.50 per 1000 clean
   checks;
4. maximizes primary event recall;
5. breaks ties by lower horizon-penalized delay and then lower false alarms;
6. selects a single baseline champion using the same tuning-only rule.

The full grid results and selected configurations are written to
stage16_tuning.json.  The frozen Stage-15 hierarchical e-CUSUM is not included
in tuning.

## Evaluation block

The OOD evaluation uses seeds 5001..5200.  These seeds are disjoint from the
tuning block.

Every detector receives:

- exactly the same generated trace for a seed;
- exactly four CU checks every five seconds;
- the same round-robin fixed schedule;
- the same warm-up interval;
- no attack label, onset time, target NF, or attack family.

Attack labels are used only by the evaluator.

## Metrics

Primary metrics:

- event recall across the four integrity-visible OOD families;
- mean horizon-penalized delay in seconds;
- mean normalized delay;
- false alarms per 1000 clean CU checks.

A missed attack receives that attack's own duration as its delay penalty.
This is intentionally called horizon-penalized delay; it is not survival
analysis or a censored-likelihood estimator.

Per-family recall is also reported so an aggregate win cannot hide failure on
one attack shape.

The observer-silent semantic class is reported separately as a threat-model
boundary result.

## Reproduce

~~~bash
python -m unittest discover -s stage16_tests -v

python -m research.stage16_tune \
  --start-seed 4001 \
  --seeds 24 \
  --output stage16_tuning.json

python -m research.stage16_experiment \
  --tuning stage16_tuning.json \
  --start-seed 5001 \
  --seeds 200 \
  --output stage16_results
~~~

The GitHub Actions workflow .github/workflows/stage16-ood.yml performs the same
sequence and publishes both the complete tuning surface and raw evaluation
results.

## Interpretation

A positive Stage-16 result is stronger evidence than Stage 15 because detector
parameters are frozen while both attack and nuisance distributions move and
the comparison includes tuned sequential alternatives.

It still remains a synthetic experiment.  The next step after this benchmark
is a blind fault-injection experiment on the repository's Open5GS/SCP path,
preferably with attack scheduling and labels generated outside the detector
process.
