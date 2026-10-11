# Stage 21 — stable semantic integrity on native Open5GS SCP/NRF

Stage 20 closed the known structural sparse-deletion failure, but its JSON
fingerprint deliberately excluded scalar values. Stage 21 tests the resulting
evasion class: consumer-visible responses whose JSON path/type structure is
unchanged while semantically important scalar values are altered.

The final Stage-21 detector was frozen **before** live seeds 8401..8408 were
captured. Those seeds are now evaluation-only and must never be used for
retuning.

## Research question

Can a separate semantic-value channel detect structure-preserving tampering
without reacting to ordinary dynamic value churn or transient nearby-reference
races?

The Stage-21 channel is additive:

> Stage-21 alarm = frozen Stage-20 combined alarm OR stable semantic alarm.

Nothing in the Stage-17, Stage-19 or Stage-20 detector is retuned.

## Semantic representation

research/stage21_semantic.py maps every scalar JSON leaf to a normalized typed
path and a deterministic SHA-256 value token. Array indices are normalized to
[], so values at a repeated path are represented as a multiset.

Raw scalar values are not placed in detector telemetry. The digest is used only
as an equality token. **No privacy claim is made**: low-entropy values may be
dictionary-testable.

Warm-up selects only paths that satisfy both:

- trusted/consumer paired agreement >= the configured fraction;
- temporal stability of the trusted path >= the configured fraction.

Thus volatile paths such as counters/timestamps are excluded rather than
requiring attack-specific allowlists.

## Repeated semantic-signature quorum

The first Stage-21 prototype accumulated any mismatch on a stable path. That was
not sufficiently conservative under legitimate reference races.

The final design instead computes an equality signature for the complete
stable-path transition:

(path, trusted value multiset, consumer value multiset).

Only repetitions of the **same semantic mismatch signature** share quorum
memory. Different transient identities or different values do not accumulate
together. After an alarm the semantic channel remains in recovery until a
configured number of exact paired matches have been observed, preventing
residual attack pulses from spilling into a clean gap.

This is a finite-memory empirical detector. It is not claimed to be an exact
anytime-valid e-process.

## Development discipline and negative results

Historical blocks are forbidden:

- Stage 17 final: 7001..7200
- Stage 18 live: 8101..8106
- Stage 19 live: 8201..8206
- Stage 20 live: 8301..8306
- inspected Stage-20 synthetic blocks through 23080

Two Stage-21 attempts were also retained as negative evidence.

### Attempt 1 — generic path-mismatch quorum

Blocks 24001..24140 were used for tuning. No candidate achieved the required
zero false alarms on both stable and race tuning regimes. These blocks were
retired.

### Attempt 2 — post-alarm recovery

Fresh tuning blocks 27001..27140 produced a tuning-feasible configuration, but
the untouched race stress 29001..29080 exceeded the predeclared 0.50 false
alarms / 1000 ceiling. Blocks 27001..29080 were then retired.

### Final signature-aware development

Fresh blocks:

- stable tuning: 30001..30040
- race tuning: 30101..30140
- stable validation: 31001..31120
- race stress: 32001..32080

Selection required **zero false alarms on both tuning regimes** before recall or
delay were considered.

Frozen configuration:

- paired agreement threshold = **0.98**
- temporal stability threshold = **0.90**
- semantic window = **16 ticks**
- identical-signature quorum = **3 hits**
- minimum mismatched stable paths = **1**
- immediate large semantic mismatch = **3 paths**
- post-alarm exact-match recovery = **2 ticks**

GitHub Actions development run: **38159390075**.
Development artifact: stage21-semantic-development, artifact ID
**11709668915**.

### Final development results

Stable validation 31001..31120:

- primary event recall: **0.9944**
- minimum family recall: **0.9833**
- mean horizon-penalized delay: **5.67 ticks**
- false alarms: **0.000 / 1000**
- semantic channel enabled fraction: **1.000**

Race stress 32001..32080:

- primary event recall: **0.9188**
- minimum family recall: **0.7000**
- mean horizon-penalized delay: **6.46 ticks**
- false alarms: **0.000 / 1000**
- semantic channel enabled fraction: **1.000**

The predeclared cross_profile_identity_swap boundary remained at recall 0,
because swapping identities between two profiles preserves the normalized
per-path value multiset.

## New live generator

Stage 21 does **not** reuse the Stage-18 fixed sparse tick set.

research/stage21_gateway.py creates a new private schedule independently for
every runner:

- episode order is randomized per seed;
- every sparse episode gets 3, 4, or 5 randomly selected mutation ticks in its
  12-tick window;
- mutation field details are stored only with private labels;
- all consumer requests first traverse the genuine native Open5GS SCP -> NRF
  route;
- native SCP and NRF binaries remain unmodified.

Primary live families:

1. identity_value_sparse — changes nfInstanceId value only;
2. status_value_sparse — changes nfStatus value only;
3. number_value_sparse — changes a numeric profile value only;
4. scheme_value_sparse — changes a service scheme string only;
5. structural_leaf_delete_sparse — structural comparator family;
6. profile_drop_persistent — persistent profile-level comparator.

Predeclared boundary:

- boundary_cross_profile_identity_swap — swaps two profile identities while
  preserving the normalized value multiset.

## Blind live protocol

Live seeds: **8401..8408**.

Canonical GitHub Actions run: **38159711749**.

The live run executed at head SHA:

88af1e62c85fe734caa7ce827776ba8b95d0dd50

The workflow enforced:

1. eight independent Open5GS v2.7.6 NRF/NSSF/AUSF/SCP capture runners;
2. telemetry and private labels uploaded as separate artifacts;
3. blind detector jobs downloaded telemetry only and failed if any private
   label file was present;
4. labels were joined only after all blind detector jobs completed;
5. runner-level paired bootstrap effects were computed post-hoc.

All static tests, eight captures, eight blind detector jobs and the final audit
completed successfully.

Final report artifact:

- stage21-blind-semantic-open5gs-report
- artifact ID **11709213677**
- retained for 90 days from the canonical run

## Final live result

| Detector | Primary event recall | Penalized delay (ticks) | FA / 1000 clean ticks |
|---|---:|---:|---:|
| Page-Hinkley | 0.177 | 10.61 | 0.000 |
| Stage-17 directional | 0.167 | 11.33 | 0.000 |
| Stage-19 sparse directional | 0.167 | 10.17 | 0.000 |
| Stage-20 structural combined | 0.312 | 9.47 | 0.000 |
| **Stage-21 semantic combined** | **1.000** | **5.34** | **0.000** |

Stage 21 minus Stage 20, paired by runner:

- event recall: **+0.688**
- 95% runner-cluster bootstrap CI: **[+0.667, +0.708]**
- horizon-penalized delay: **-4.12 ticks**
- 95% CI: **[-4.41, -3.77]**
- false-alarm difference: **0.000 / 1000**
- 95% CI: **[0.000, 0.000]**

The semantic channel enabled itself on **all eight** runners and selected a mean
of **23.0 stable scalar paths** from label-free warm-up telemetry.

### Per-family primary live recall

| Family | Page-Hinkley | Stage 17 | Stage 19 | Stage 20 | Stage 21 |
|---|---:|---:|---:|---:|---:|
| identity_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| number_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| scheme_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| status_value_sparse | 0.125 | 0.000 | 0.000 | 0.000 | **1.000** |
| structural_leaf_delete_sparse | 0.000 | 0.000 | 0.000 | 0.875 | **1.000** |
| profile_drop_persistent | 0.938 | 1.000 | 1.000 | 1.000 | **1.000** |

Boundary result:

- boundary_cross_profile_identity_swap: Stage-21 recall **0.000**

## Interpretation

The Stage-20 result was not sufficient evidence against an adaptive attacker:
structure-preserving value substitutions were a direct blind spot. Stage 21
closes that declared class in the current laboratory suite by adding a feature
channel rather than lowering an existing threshold.

The causal interpretation is therefore strong inside the stated experiment:

- byte accounting does not reliably see small value substitutions;
- path/type structure cannot see value-only substitutions by construction;
- repeated stable semantic equality signatures directly expose them;
- the new channel adds no observed clean live false alarms in this block.

However, Stage 21 also exposes the next boundary: normalized path multisets lose
**relational semantics**. A cross-profile swap can preserve all per-path value
multisets while changing which identity belongs to which profile.

## Scope and limitations

This remains a controlled post-SCP research fault environment over lab HTTP/2
without production mTLS/OAuth/SEPP behavior. The experiment does not prove:

- compromise detection inside the native Open5GS SCP binary;
- robustness to an attacker controlling both consumer and trusted reference;
- privacy of deterministic semantic hashes;
- detection of relational/cross-field semantic attacks;
- correctness under arbitrary production registration churn;
- production false-alarm rates.

The next detector change, if pursued, should target relational entity semantics
rather than another scalar threshold. The Stage-21 live seeds 8401..8408 must
remain untouched evaluation data.


## Large-scale frozen replication: 128 independent Open5GS runners

To strengthen the statistical basis without changing the detector, Stage 21 was
replicated on **128 new independent Open5GS runners** using seeds
**8501..8628**. The detector configuration was identical to the configuration
frozen before the first live block 8401..8408.

No seed from this replication was used for model selection, threshold tuning or
feature design. Each runner independently repeated the complete native
Open5GS SCP/NRF capture, separate telemetry/label upload, blind detection and
post-hoc audit procedure.

Canonical replication workflow:

- GitHub Actions run: **38160873208**
- evaluation head SHA: **22d4207b326c768c920b57f8e954f4d8d8c06998**
- captures completed successfully: **128 / 128**
- blind detectors completed successfully: **128 / 128**
- final audit: **success**
- final report artifact: **stage21-128-run-open5gs-replication-report**
- report artifact ID: **11711065745**

The audit used **50,000 runner-cluster bootstrap resamples** for paired
confidence intervals.

### Replication result

| Detector | Primary event recall | Penalized delay (ticks) | False alarms | Clean ticks | FA / 1000 |
|---|---:|---:|---:|---:|---:|
| Page-Hinkley | 0.164 | 10.69 | 0 | 10,752 | 0.0000 |
| Stage-17 directional | 0.167 | 11.33 | 0 | 10,752 | 0.0000 |
| Stage-19 sparse directional | 0.167 | 10.17 | 0 | 10,752 | 0.0000 |
| Stage-20 structural combined | 0.285 | 9.58 | 0 | 10,752 | 0.0000 |
| **Stage-21 semantic combined** | **1.000** | **5.74** | **0** | **10,752** | **0.0000** |

Stage 21 minus Stage 20, paired by independent runner:

- primary event recall difference: **+0.715**
- 95% runner-cluster bootstrap CI: **[+0.706, +0.724]**
- penalized delay difference: **-3.84 ticks**
- 95% CI: **[-3.94, -3.74]**
- observed false-alarm difference: **0.0000 / 1000**
- 95% runner-cluster bootstrap CI: **[0.0000, 0.0000]**

The Stage-21 semantic channel enabled on **128 / 128 runners** and selected a
mean of **23.0 stable scalar paths**.

Across six primary families and two repetitions per family per runner, the
replication contains **1,536 primary attack episodes**. Stage 21 detected all
**1,536 / 1,536** primary episodes.

### Per-family replication recall

| Family | Page-Hinkley | Stage 17 | Stage 19 | Stage 20 | Stage 21 |
|---|---:|---:|---:|---:|---:|
| identity_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| number_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| scheme_value_sparse | 0.000 | 0.000 | 0.000 | 0.000 | **1.000** |
| status_value_sparse | 0.023 | 0.000 | 0.000 | 0.000 | **1.000** |
| structural_leaf_delete_sparse | 0.035 | 0.000 | 0.000 | 0.711 | **1.000** |
| profile_drop_persistent | 0.926 | 1.000 | 1.000 | 1.000 | **1.000** |

The preregistered relational boundary again remained undetected:

- boundary_cross_profile_identity_swap: Stage-21 recall **0.000**

This larger replication substantially narrows the runner-level uncertainty
around the Stage-21 gain and shows zero observed false alarms over **10,752
clean live ticks**. This remains an empirical lab result; correlated ticks and
the controlled post-SCP environment mean the zero count must not be interpreted
as a universal production false-alarm guarantee.

Seeds **8501..8628** are now evaluation-only and are forbidden for any future
detector tuning.
