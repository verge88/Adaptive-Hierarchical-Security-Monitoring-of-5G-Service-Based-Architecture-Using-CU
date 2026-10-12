# Stage 21 — time-to-detection statistics on the frozen 128-run replication

This analysis implements the final-paper timing analysis without changing any
detector.

Source evaluation block:

- canonical replication run: **38160873208**
- source evaluation SHA: **22d4207b326c768c920b57f8e954f4d8d8c06998**
- independent Open5GS runners: **128**
- seeds: **8501..8628**
- primary attack episodes: **1,536**
- common administrative episode horizon: **12 ticks**
- detector retuning after capture: **none**

The timing analysis itself was executed in:

- GitHub Actions run: **38165599584**
- analysis SHA: **1ee19a419613875159036f9fcc01c2021f2a58e2**
- result artifact: **stage21-time-to-detection-128-run-report**
- artifact ID: **11711972041**
- artifact SHA-256:
  **904096cadb153e4760e22cc6009351e80ed4a1cda2347b2c8306ccc10d10132c**

The analysis uses **20,000 nonparametric bootstrap resamples over whole
independent Open5GS runners**. Events within one runner are never treated as
independent bootstrap units.

## Why this analysis was added

Earlier reports used a horizon-penalized mean delay: a missed 12-tick episode
was assigned a delay of 12 ticks.

Under a common administrative horizon, that quantity is exactly the empirical
**restricted mean time to detection (RMST)** through 12 ticks. Therefore RMST
does not constitute an independent replacement metric; it provides the correct
time-to-event interpretation of the existing mean.

To test whether the conclusion depends on the miss penalty, this analysis also
reports:

1. cumulative fraction of attacks detected by each tick;
2. event recall with runner-cluster confidence intervals;
3. median delay among detected attacks;
4. administrative median time to detection: the first tick at which at least
   50% of *all* attacks have been detected;
5. RMST through 12 ticks;
6. runner-level uncertainty for false alarms.

## Aggregate endpoints

| Detector | Recall, 95% CI | Median delay among detected, 95% CI | Administrative median TTD | RMST to 12 ticks, 95% CI |
|---|---:|---:|---:|---:|
| Page-Hinkley | 0.164 [0.158, 0.171] | 3 [3, 4] | not reached | 10.69 [10.64, 10.74] |
| Stage 17 directional | 0.167 [0.167, 0.167] | 8 [8, 8] | not reached | 11.33 [11.33, 11.33] |
| Stage 19 sparse directional | 0.167 [0.167, 0.167] | 1 [1, 1] | not reached | 10.17 [10.17, 10.17] |
| Stage 20 structural | 0.285 [0.276, 0.294] | 0 [0, 0] | not reached | 9.58 [9.53, 9.62] |
| **Stage 21 semantic combined** | **1.000 [1.000, 1.000]** | **6 [6, 6]** | **6** | **5.74 [5.64, 5.84]** |

The detected-only median must not be read as an unconditional speed metric.
Stage 20 has a median delay of zero only among the minority of attacks it
detects. Stage 21 has a median of six while detecting every primary attack.
This is a direct demonstration of selection bias.

Only Stage 21 reaches an administrative median within the episode horizon:
at least 50% of all attacks have been detected by tick **6**.

## Cumulative fraction detected

| Tick | Page-Hinkley | Stage 17 | Stage 19 | Stage 20 | Stage 21 | Stage21 − Stage20, 95% CI |
|---:|---:|---:|---:|---:|---:|---:|
| 0 | 0.000 | 0.000 | 0.000 | 0.167 | 0.167 | +0.001 [+0.000, +0.002] |
| 1 | 0.000 | 0.000 | 0.167 | 0.167 | 0.173 | +0.006 [+0.002, +0.010] |
| 2 | 0.000 | 0.000 | 0.167 | 0.167 | 0.191 | +0.025 [+0.018, +0.033] |
| 3 | 0.091 | 0.000 | 0.167 | 0.169 | 0.246 | +0.077 [+0.065, +0.090] |
| 4 | 0.130 | 0.000 | 0.167 | 0.171 | 0.322 | +0.150 [+0.133, +0.168] |
| 5 | 0.143 | 0.000 | 0.167 | 0.179 | 0.428 | +0.249 [+0.228, +0.271] |
| 6 | 0.144 | 0.000 | 0.167 | 0.186 | 0.526 | +0.340 [+0.319, +0.361] |
| 7 | 0.158 | 0.000 | 0.167 | 0.201 | 0.652 | +0.452 [+0.432, +0.471] |
| 8 | 0.159 | 0.167 | 0.167 | 0.225 | 0.764 | +0.538 [+0.518, +0.558] |
| 9 | 0.159 | 0.167 | 0.167 | 0.245 | 0.857 | +0.612 [+0.594, +0.630] |
| 10 | 0.161 | 0.167 | 0.167 | 0.263 | 0.937 | +0.674 [+0.659, +0.688] |
| 11 | 0.164 | 0.167 | 0.167 | 0.285 | 1.000 | +0.715 [+0.706, +0.724] |

Stage 20 and Stage 21 are approximately tied at the first tick. From tick 1
onward, Stage 21 has the higher cumulative detection fraction at every reported
time point, and the gap grows throughout the episode.

## Paired Stage 21 versus Stage 20

- final event-recall difference: **+0.715**
- 95% runner-cluster bootstrap CI:
  **[+0.706, +0.724]**
- restricted mean time-to-detection difference:
  **-3.84 ticks**
- 95% runner-cluster bootstrap CI:
  **[-3.94, -3.74]**

The time-to-detection conclusion is therefore not dependent on a single
arbitrary penalty for a missed event. The cumulative detection process itself
separates Stage 21 from Stage 20 over nearly the entire episode.

## False-alarm uncertainty

All compared detectors produced:

- observed false alarms: **0**
- total clean live ticks: **10,752**
- observed false-alarm rate: **0.0000 / 1000 clean ticks**
- runners with at least one false alarm: **0 / 128**

A nonparametric runner bootstrap is necessarily degenerate at zero when every
observed runner has zero false alarms. Reporting a bootstrap interval of
[0, 0] alone would overstate what has been learned.

Therefore the analysis additionally reports an exact one-sided binomial bound
for the runner-level event "at least one false alarm in a new independent
runner":

- 95% upper bound: **0.0231**

This is intentionally a runner-level bound. It is not converted into a
per-tick production false-alarm guarantee because ticks within one Open5GS run
are dependent.

## Recommended paper interpretation

The final article should state the timing result approximately as follows:

> On 128 independent Open5GS runs, Stage 21 reached 50% cumulative detection by
> tick 6 and 100% by tick 11, whereas Stage 20 never reached 50% detection
> within the 12-tick episode. The restricted mean time to detection decreased
> from 9.58 to 5.74 ticks (paired difference -3.84 ticks, 95% runner-cluster
> bootstrap CI [-3.94, -3.74]). The cumulative Stage-21 detection fraction was
> greater than Stage 20 from tick 1 onward. Thus the improvement is not an
> artifact of one particular penalty assigned to missed events.

The detected-only median should be reported as a secondary descriptive
quantity, together with the warning that it is conditioned on successful
detection and can favor low-recall methods.

## Reuse restriction

The analysis does not change the status of seeds **8501..8628**. They remain
evaluation-only and must never be used for detector tuning or feature redesign.
