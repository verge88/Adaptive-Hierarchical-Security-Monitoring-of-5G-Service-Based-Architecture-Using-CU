# Stage 19 — multiscale directional e-memory for sparse attacks

Stage 18 validated the Stage-17 directional e-process on real native Open5GS
SCP/NRF traffic for persistent signed tampering, but both the directional
detector and Page-Hinkley had 0.000 recall on sparse live mutations.

Stage 19 targets that weakness without tuning on any Stage-18 live artifact.

## New detector

The candidate detector maintains multiple one-sided log-e accumulators per
direction, each with a different forgetting factor.  Fast memories react to
persistent shifts; slow memories preserve repeated same-direction evidence
across several clean observations.

Scale states are combined with **log-mean-exp**, not a raw maximum.  The
log(K) averaging penalty prevents adding more time scales from being a free
multiple-testing advantage.

## Fresh development world

The development simulator generates signed integrity streams with:

- persistent positive and negative episodes;
- isolated sparse positive and negative pulse trains;
- clustered sparse positive and negative pulse trains;
- autocorrelated clean noise;
- slow signed drift;
- increasing variance after warm-up;
- rare symmetric heavy clean outliers.

No Stage-18 telemetry, alarm, label or seed is read by the tuner.

## Data separation

- Stage-18 live evaluation: **8101..8106**, permanently evaluation-only.
- Stage-19 development: **9001..9040**.
- Stage-19 predeclared untouched synthetic final: **10001..10200**.
- A new live Open5GS block will be declared only after the detector parameters
  are frozen from development and synthetic final evaluation.

## Comparator fairness

Three families are tuned on exactly the same development worlds:

1. multiscale directional e-memory;
2. single-scale directional e-memory;
3. scalar Page-Hinkley.

Thus Stage 19 must beat a **retuned single-scale directional detector**, not
merely the old Stage-17 thresholds.

## Selection rule

For every family:

1. false alarms <= 0.50 / 1000 clean ticks;
2. persistent-event recall >= 0.90;
3. maximize sparse-event recall;
4. maximize overall recall;
5. minimize horizon-penalized delay;
6. minimize false alarms.

After development, selected parameters are frozen before the untouched
synthetic block can be executed.


## Development record before the final block

All iterations below used only development seeds **9001..9040**.  The synthetic
final block 10001..10200 and the Stage-18 live artifacts were not read.

Several plausible designs were rejected before the final ensemble was frozen:

- leaky multiscale directional e-memory recovered persistent recall but produced
  about 4.95 false alarms / 1000 clean ticks;
- raw rolling sparse e-scan reached about 0.96 sparse recall but produced about
  45 false alarms / 1000;
- a fixed robust-MAD amplitude gate reduced that to about 3.65 / 1000, still
  outside the preregistered ceiling;
- adaptive robust standardization brought false alarms to 0.391 / 1000 and
  sparse recall to 0.900, but persistent recall fell to 0.488;
- adding a sustained channel, raw directional OR fusion, and other direct
  combinations improved pieces of the tradeoff but did not satisfy both the
  <=0.50 false-alarm ceiling and the >=0.90 persistent-recall floor;
- a three-channel OR achieved sparse recall 0.903 and persistent recall 0.941,
  but its false alarms were 0.911 / 1000 and it was therefore rejected.

The final development step did not introduce a new signal.  It allocated the
existing false-alarm budget across Pareto representatives of three previously
developed channels.  Only 16 combinations were evaluated.

### Frozen Stage-19 ensemble

The selected **Tri-Path Directional Evidence Ensemble** achieved on development:

- overall event recall: **0.806**
- sparse event recall: **0.741**
- persistent event recall: **0.938**
- horizon-penalized delay: **9.77 ticks**
- false alarms: **0.391 / 1000 clean ticks**

It is the first Stage-19 configuration satisfying both preregistered gates.

The three frozen channels are:

**Adaptive robust sparse scan**

- windows = 16, 32, 64 ticks
- one-sided tail gate p = 0.07
- robust magnitude gate = 4.5 z
- minimum hits = 2
- summed log-e threshold = 2.8
- center alpha = 0.03
- scale alpha = 0.02
- clipped baseline update = 3.0 z

**Single-scale directional e-process**

- decay = 0.90
- reference = 0.12
- threshold = 7.0
- one-sided gate p = 0.04

**Adaptive consecutive confirmation**

- window = 4 ticks
- required hits = 3
- robust magnitude gate = 2.6 z
- one-sided gate p = 0.15
- center alpha = 0.03
- scale alpha = 0.02
- clipped baseline update = 3.0 z

The final detector alarms when any of these independently stateful channels
alarms.  A channel resets only on its own alarm, matching the development
evaluation.

The strong Stage-19 Page-Hinkley comparator is also frozen from the same
development block at delta=0.30, threshold=5.0, absolute-tail gate p=0.08 and
mean alpha=0.20.

## Untouched synthetic final gate

Only after the configuration above was committed and protected by exact-value
tests is the final workflow allowed to execute **exactly seeds 10001..10200**.
The final script exits for any alternative seed range and contains no
hyperparameter search or fallback selection.

A final failure will be retained as a failure.  Live Stage-19 Open5GS testing
is justified only after this untouched synthetic result is inspected.
