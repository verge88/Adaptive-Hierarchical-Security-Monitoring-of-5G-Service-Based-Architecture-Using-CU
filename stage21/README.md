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


## Unified frozen ablation

A dedicated untouched ablation block was executed after the 128-run replication:

- **64 independent Open5GS runners**
- seeds **8701..8764**
- **768 primary episodes**
- all Stage-17/19/20/21 components frozen before capture
- every variant evaluated on the exact same episodes
- 50,000 runner-cluster bootstrap resamples

Canonical run: **38162596406**  
Evaluation SHA: **7e1296046379d3ee9e3e5aac9b12ab7b550cfbe6**  
Final artifact ID: **11711631100**

Key result:

- directional only: recall **0.167**, delay **11.33**
- directional + sparse memory: recall **0.167**, delay **10.17**
- structural only: recall **0.277**, delay **9.59**
- semantic only: recall **1.000**, delay **5.78**
- full Stage 20 without semantic: recall **0.277**, delay **9.59**
- full Stage 21: recall **1.000**, delay **5.78**
- all variants observed **0 false alarms over 5,376 clean ticks**

Paired effects:

- structural over directional: **+0.111 recall**, 95% CI
  **[+0.098, +0.124]**, 85 rescued events
- semantic over Stage 20: **+0.723 recall**, 95% CI
  **[+0.710, +0.736]**, 555 rescued events
- sparse memory: no recall gain in this live mixture, but
  **-1.17 ticks** penalized delay versus directional-only
- removing sparse or structural channels from the full Stage-21 detector caused
  no loss on this specific Stage-21 attack mixture
- removing the semantic channel reduced recall from **1.000 to 0.277**

This does **not** establish universal redundancy of the earlier channels.
The Stage-21 live mixture is concentrated on semantic substitutions, one
structural sparse family and one persistent profile family. Earlier channels
were developed under different drift/noise/fault regimes.

Full methodology and tables: **stage21/ABLATION.md**.

Seeds **8701..8764** are now evaluation-only and forbidden for future tuning.


## Clustered time-to-detection analysis

A separate timing analysis was performed on the frozen **128-run replication**
(seeds **8501..8628**, **1,536** primary episodes) without any detector
retuning.

Canonical analysis run: **38165599584**  
Analysis SHA: **1ee19a419613875159036f9fcc01c2021f2a58e2**  
Result artifact: **stage21-time-to-detection-128-run-report**  
Artifact ID: **11711972041**

Uncertainty was estimated with **20,000 nonparametric bootstrap resamples over
whole independent Open5GS runners**.

Key endpoints:

- Stage 20 recall: **0.285 [0.276, 0.294]**
- Stage 21 recall: **1.000 [1.000, 1.000]**
- Stage 20 restricted mean time to detection: **9.58 [9.53, 9.62] ticks**
- Stage 21 restricted mean time to detection: **5.74 [5.64, 5.84] ticks**
- paired RMST difference: **-3.84 ticks**, 95% CI **[-3.94, -3.74]**
- Stage 21 reaches 50% cumulative detection by **tick 6**
- Stage 20 never reaches 50% cumulative detection within the 12-tick horizon
- by tick 11: Stage 20 cumulative detection **0.285**, Stage 21 **1.000**

The detected-only median is deliberately not used as the primary speed
comparison. Stage 20 has median delay 0 among the small subset of attacks it
detects, while Stage 21 has median delay 6 while detecting all primary attacks.
This illustrates conditioning/selection bias rather than Stage-20 superiority.

All methods had **0 observed false alarms over 10,752 clean live ticks** and
**0/128 runners** with any false alarm. Because the runner bootstrap is then
degenerate at zero, an exact one-sided runner-level bound is also reported:
the 95% upper bound on the probability that a new independent runner contains
at least one false alarm is **0.0231**. This is not interpreted as a per-tick
production guarantee.

Full methodology, cumulative detection table and paper-ready interpretation are
in **stage21/TIME_TO_DETECTION.md**.


## Monitoring overhead and scalability benchmark

A dedicated clean overhead block was executed on **64 independent Open5GS
runners** using seeds **8801..8864**. No detector parameter or feature was
changed.

Canonical run: **38169182709**  
Evaluation SHA: **c0c8f00eec06fcf2abf149fed0bb4480b3d57b82**  
Final artifact: **stage21-64-run-monitoring-overhead-report**  
Artifact ID: **11713461239**

Measured workload:

- 80 baseline + 80 monitored cycles per runner
- 5,120 baseline cycles
- 5,120 monitored cycles
- 15,360 measured genuine native SCP -> NRF requests
- 20,000 runner-cluster bootstrap resamples
- 64 / 64 benchmark runners succeeded

Key results:

- single native SCP -> NRF request: **1.570 ms**
  (95% cluster CI **[1.532, 1.596]**)
- sequential paired monitoring cycle: **4.027 ms**
  (**[3.908, 4.066]**)
- incremental monitoring-cycle latency: **+2.456 ms**
  (**[2.387, 2.478]**)
- monitored/baseline latency ratio: **2.554**
  (**[2.539, 2.565]**)
- native request-count amplification: **2.0x**
- measured HTTP/2 wire-byte amplification: **2.0x**
- feature extraction for one paired observation: **0.8459 ms**
  (**[0.8197, 0.8515]**)
- full frozen Stage-21 detector update: **0.24529 ms/tick**
  (**[0.24214, 0.24759]**)
- detector throughput: **4076.8 tick updates/s**
  (**[4038.9, 4129.8]**)

The benchmark shows that the dominant current cost is acquisition of the second
independent SCP -> NRF observation, not detector arithmetic.

The current research serialization of structural + semantic telemetry is
**11,811 bytes per clean pair**, versus **2,358 bytes** of raw response bodies,
a **5.01x local-storage ratio**. These bytes are not injected into native SBI
messages and must not be reported as 5G wire overhead.

A key limitation is explicit: because every monitored sample performs a second
reference request, Stage 21 does **not** by itself demonstrate a production-wide
traffic overhead below 1%. Overall network overhead is determined mainly by the
sampling fraction. The measured local compute and incremental h2c latency are
below 10 ms in this lab, but production mTLS/OAuth/SEPP and concurrent operator
load were not modeled.

Full methodology and paper-ready interpretation:
**stage21/OVERHEAD.md**.

Seeds **8801..8864** are now evaluation-only and forbidden for future tuning.


## Formal trust and attacker model

The Stage-21 trust boundary is now frozen explicitly in
**stage21/TRUST_MODEL.md** with a machine-readable counterpart in
**stage21/trust_model.json**.

The model distinguishes four levels:

- **L0 — evaluation integrity:** private attack labels are unavailable to the
  blind detector;
- **L1 — post-common-path branch integrity:** the actually validated live
  Open5GS model. Native NRF/SCP are trusted and unmodified; only the
  consumer-facing copy after the genuine SCP->NRF response is adversary
  controlled;
- **L2 — independent-observer node-compromise model:** the target
  master/slave monitoring concept, where a compromised reporting node is
  compared against an observation generated outside its control. This stronger
  case is conceptually supported but is **not** directly established by the
  current live Stage-21 experiment;
- **L3 — multi-point Byzantine/common-mode compromise:** attacker control of
  both observations or of infrastructure common to both. This is out of scope.

The critical claim boundary is:

> Stage 21 validates detection of observable consumer-branch integrity
> divergence after a genuine native Open5GS SCP->NRF path under a trusted
> reference assumption. It does not establish detection of a compromised native
> SCP, compromised NRF, or arbitrary colluding multi-point attacker.

The model also states explicitly that paired reconciliation is **not a truth
oracle**. If both reference and consumer observations carry the same false
state, or if an attack preserves every monitored representation, reconciliation
alone cannot prove the state false.

The preregistered cross-profile identity-swap boundary is retained as the
concrete representation-invariance example: Stage-21 recall remains **0.000**
because the current normalized per-path semantic multiset loses entity
relationships.

A static consistency audit prevents the trust document from silently drifting
away from the evaluated code architecture:

- canonical audit run: **38266079919**
- audit head SHA: **7eeef446cfcfc434bbf6a24cc122e1a38f89853b**
- result: **PASS**
- artifact: **stage21-trust-model-audit**
- artifact ID: **11755006315**
- artifact SHA-256:
  **375a75276ea0e354c0d7411aafc420e7d331290ca58991100cbaa830731db594**

The audit checks that consumer mutation occurs only after a genuine native
upstream response, the trusted reference still uses native SCP->NRF, the blind
detector imports neither the fault generator nor private labels, and the known
relational blind spot remains explicitly documented.


## Publication-facing experimental nomenclature

The scientific article no longer uses internal repository labels Stage 15..21
as the primary narrative.

A publication-ready Russian structure is now defined in
**article/EXPERIMENTAL_PROGRAM_RU.md**.

Main-text terminology:

- Experiment 1 — within-family validation of hierarchical sequential detection
- Experiment 2 — validation under distribution shift
- Experiment 3 — directional sequential discrepancy accumulation
- Experiment 4 — blind transfer validation on native Open5GS SCP->NRF
- Experiment 5 — stability-gated sparse-event memory
- Experiment 6 — value-independent structural JSON reconciliation
- Experiment 7 — semantic reconciliation of stable scalar values

The later validation work is presented by scientific function rather than new
Stage numbers:

- large-scale independent replication
- unified ablation
- time-to-detection analysis
- monitoring-overhead benchmark
- formal trust and attacker model

Internal Stage labels are retained only in the reproducibility mapping that
links article terminology to repository branches and artifacts.

An automated nomenclature guard checks that Stage 15..21 labels do not leak
into the scientific narrative before the reproducibility section.
