# Stage 33 — 256-run final replication

This branch repeats the final Stage-33 experiment at a substantially larger
scale without changing the detector, attack generator, external verifier
decision rule, legitimate-transition schedule, or approved policy.

## Preregistered block

- independent live Open5GS runners: **256**;
- fresh runner identifiers: **11001..11256**;
- randomized attack episodes per runner: **12**;
- total attack episodes: **3072**;
- private randomized schedules: one fresh plan per runner;
- labels remain separate until every external signed verdict has completed.

The capture matrix and external-decision matrix each use 256 jobs. This stays
below the GitHub Actions matrix expansion ceiling while matching the largest
earlier Open5GS runner block used in this research line.

## Frozen elements

The following are unchanged from the successful Stage-33 final experiment:

- Open5GS v2.7.6 laboratory topology;
- Stage-28 native-NRF randomized fault generator;
- Stage-29 discrete attested-invariant semantics;
- Stage-30 legitimate deregistration/registration/restart interval;
- external verifier endpoint and decision implementation;
- approved Stage-33 policy digest;
- common-source colluding NRF+witness negative control;
- signed external verdict and tamper check.

Only the number and seed identifiers of fresh runners are changed.

## Metrics

The final audit reports pooled recall and Wilson 95% interval, mutation-tick
coverage, horizon-penalized delay, clean false alarms, legitimate-transition
false alarms, common-source negative-control alerts, and stratification by
attack family, duration, and density.

An observed value of recall 1.000 is still reported as a finite-sample result
with a non-degenerate Wilson lower confidence bound rather than as a claim of a
population probability exactly equal to one.
