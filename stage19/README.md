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
