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


## Untouched synthetic final result

The frozen final workflow ran once on **200 previously unopened worlds,
seeds 10001..10200**, in GitHub Actions run **38141214150**.  Eighteen Stage-19
tests passed before the final block executed.

| Detector | Overall recall | Sparse recall | Persistent recall | Delay (ticks) | Sparse delay | FA / 1000 clean |
|---|---:|---:|---:|---:|---:|---:|
| **Tri-Path directional** | **0.795** | **0.728** | **0.928** | **10.07** | **11.62** | **1.354** |
| Single-scale directional | 0.287 | 0.006 | 0.848 | 17.14 | 17.95 | 0.625 |
| Page-Hinkley | 0.203 | 0.046 | 0.515 | 15.30 | 17.56 | **0.469** |

Paired Tri-Path minus tuned single-scale effects:

- overall recall: **+0.508**, 95% paired seed-bootstrap CI
  **[+0.488, +0.527]**;
- sparse recall: **+0.722**, CI **[+0.693, +0.749]**;
- persistent recall: **+0.081**, CI **[+0.065, +0.098]**;
- horizon-penalized delay: **-7.075 ticks**, CI
  **[-7.367, -6.771]**;
- sparse horizon-penalized delay: **-6.333 ticks**, CI
  **[-6.634, -6.037]**;
- false alarms / 1000 clean ticks: **+0.729**, CI
  **[+0.469, +1.016]**.

Per-family Tri-Path recall was:

- persistent positive: 0.905
- persistent negative: 0.951
- isolated sparse positive: 0.777
- isolated sparse negative: 0.782
- clustered sparse positive: 0.699
- clustered sparse negative: 0.654

### Final decision

Stage 19 is a **partial scientific success but a failed final gate**.

The architectural goal of recovering sparse detection generalized strongly to
untouched data, and persistent detection also improved.  However the
preregistered false-alarm ceiling was <=0.50 / 1000 clean ticks, while the
frozen Tri-Path detector produced **1.354 / 1000**.

Therefore:

- seeds 10001..10200 are now evaluation data and will not be used for tuning;
- the Tri-Path thresholds will not be adjusted against this final block;
- no Stage-19 live Open5GS experiment is launched;
- the next stage must address **false-alarm robustness under environment
  variation**, while preserving the sparse-recall gain.

The raw final artifact is `stage19-untouched-synthetic-final`, artifact
**11702831649**.
