# Stage 20 — Structural integrity fingerprints

Stage 19 raised blind live recall to 0.750 and solved `padding_sparse`, but
`metadata_strip_sparse` remained completely undetected. Its byte-size change
was too small for the frozen 2% sparse accounting quorum.

Stage 20 changes the **feature**, not the Stage-19 threshold.

## Structural signal

Each trusted and consumer JSON response is converted into a value-independent
multiset of typed paths:

- object / array container paths;
- field-presence paths;
- scalar type paths;
- multiplicity of repeated array-item structure.

Scalar values are excluded. Normal value churn therefore does not change the
fingerprint, while field deletion/addition and profile multiplicity corruption
do.

The detector computes missing and extra structural-token counts between an
independent genuine-SCP/NRF reference response and the consumer-visible copy.

## Structural sequential rule

A structural channel is enabled only when warm-up trusted/consumer structure is
sufficiently stable.

The selected frozen rule is:

- warm-up exact structural agreement fraction >= **0.98**;
- finite directional window = **12 ticks**;
- quorum = **4 same-direction structural mismatches**;
- minimum mismatch = **1 token**;
- immediate large-mismatch threshold = **8 tokens**.

The final Stage-20 alarm is:

> Stage-19 stability-gated byte detector OR Stage-20 structural detector.

This preserves all previously validated persistent and byte-sparse behavior
while adding a semantic-structure channel.

## Development discipline

No Stage-18 or Stage-19 live artifact was used for Stage-20 tuning.

The first Stage-20 search passed stable development but failed the predeclared
unstable-schema stress false-alarm gate. The failed stress block
**20001..20080** was then treated as inspected and never reused for selection.

A new conservative mixed-regime protocol was declared:

- stable tuning: **21001..21040**
- unstable-schema tuning: **21101..21140**
- stable validation: **22001..22120**
- fresh unstable-schema stress: **23001..23080**

A candidate was eligible only if it produced **zero false alarms on both
tuning regimes**.

Selected configuration on stable tuning:

- recall: **0.769**
- minimum family recall: **0.575**
- false alarms: **0.000 / 1000**

On unstable tuning:

- false alarms: **0.000 / 1000**
- structural channel enabled fraction: **0.500**

Fresh stable validation:

- recall: **0.814**
- sparse field-add recall: **0.642**
- sparse field-delete recall: **0.647**
- persistent array duplicate/drop recall: **0.983 / 0.983**
- false alarms: **0.000 / 1000**

Fresh unstable-schema stress:

- false alarms: **0.347 / 1000**, below the 0.50 ceiling;
- structural channel enabled fraction: **0.475**.

Only after those results were obtained were the parameters frozen.

## Untouched blind Open5GS block

New live seeds: **8301..8306**.

GitHub Actions run: **38145970135**.

The workflow used the same blind separation as Stages 18–19:

1. six independent runners started genuine Open5GS v2.7.6
   NRF/NSSF/AUSF/SCP containers;
2. capture generated value-free structural telemetry and PRIVATE labels as
   separate artifacts;
3. six detector jobs downloaded telemetry only and explicitly checked that no
   private-label file was present;
4. labels were joined only by the final audit job.

All static tests, six live captures, six blind detector jobs, and the final
audit completed successfully.

## Final live result

| Detector | Event recall | Horizon-penalized delay (ticks) | FA / 1000 clean ticks |
|---|---:|---:|---:|
| Page-Hinkley | 0.347 | 9.58 | 0.000 |
| Stage-17 directional | 0.500 | 10.00 | 0.000 |
| Stage-19 sparse directional | 0.750 | 4.50 | 0.000 |
| **Stage-20 combined structural** | **1.000** | **3.50** | **0.000** |

Stage 20 minus Stage 19:

- event recall: **+0.250**
- 95% runner-cluster bootstrap CI: **[+0.250, +0.250]**
- horizon-penalized delay: **-1.00 tick**
- 95% CI: **[-1.00, -1.00]**
- false-alarm difference: **0.000**

The structural channel enabled itself on **all six** untouched live runners
using only label-free warm-up agreement.

### Per-family live recall

| Fault family | Page-Hinkley | Stage 17 | Stage 19 | Stage 20 |
|---|---:|---:|---:|---:|
| profile_drop | 0.778 | 1.000 | 1.000 | **1.000** |
| profile_duplicate | 0.611 | 1.000 | 1.000 | **1.000** |
| padding_sparse | 0.000 | 0.000 | 1.000 | **1.000** |
| metadata_strip_sparse | 0.000 | 0.000 | 0.000 | **1.000** |

Stage 20 therefore closes the last known blind live fault family in this
laboratory suite without adding a clean false alarm.

## Scope and next gate

This remains a controlled post-SCP research fault environment over lab h2c.
The result does not prove:

- compromise detection inside a production Open5GS SCP binary;
- robustness under production mTLS/OAuth/SEPP;
- resilience to an adaptive attacker that knows the fingerprint definition;
- correctness under arbitrary legitimate schema evolution.

The next useful gate is no longer another threshold tweak. It should introduce
**schema evolution and adaptive structural evasion**: legitimate NRF response
shape changes, attacker-preserved field counts, key substitution, nested value
semantics, and possibly cryptographic producer-side structural attestations.
