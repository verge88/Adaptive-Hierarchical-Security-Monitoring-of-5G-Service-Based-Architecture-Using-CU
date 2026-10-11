# Stage 20 — environment-robust competitive directional evidence

Stage 19 recovered sparse-event sensitivity on untouched synthetic data but
failed its final false-alarm gate: 1.354 false alarms / 1000 clean ticks versus
the preregistered ceiling of 0.50.

Stage 20 treats that as a distribution-robustness failure.  Stage-19 final
seeds 10001..10200 are now evaluation-only and are not used here.

## New principle: competitive evidence

Previous directional detectors accumulated positive and negative evidence in
independent states.  Under heavy symmetric clean noise, both sides could build
nuisance evidence at different times.

Stage 20 makes the directional channels compete:

- positive evidence is reduced by negative evidence;
- negative evidence is reduced by positive evidence;
- a persistent one-direction attack reinforces one side;
- sign-symmetric benign extremes tend to cancel.

Two candidate channels are developed:

1. a multi-window competitive sparse scan;
2. a competitive leaky directional e-process.

Both use clipped online robust location/scale adaptation.

## Environment-randomized development

Development seeds **11001..11060** are balanced across five nuisance modes:

- nominal;
- high drift;
- high outlier rate/amplitude;
- variance shift;
- biased autocorrelated regime.

Within each mode, AR persistence, noise scale, drift periods/amplitudes,
outlier parameters, variance jumps and regime offsets are randomized.

Attack amplitudes, sparse pulse locations and episode order are also randomized.

## Data separation

- Stage-18 live evaluation: 8101..8106 — forbidden for development.
- Stage-19 untouched final: 10001..10200 — forbidden for development.
- Stage-20 development: **11001..11060**.
- Stage-20 predeclared untouched final: **12001..12200**.

## Distributionally robust selection

A candidate ensemble must satisfy on development:

- mean false alarms <= **0.40 / 1000 clean ticks**;
- false alarms <= **0.50 / 1000 in every environment mode**;
- persistent event recall >= **0.85**.

Within those constraints selection prioritizes worst-mode sparse recall, then
mean sparse/persistent/overall recall and delay.

This is intentionally stricter than the Stage-19 mean-only development gate.
No Stage-20 final evaluation is enabled until a configuration passes these
requirements.
