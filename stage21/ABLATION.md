# Stage 21 unified ablation — 64-run frozen Open5GS block

This experiment is an evaluation-only ablation of the already frozen
Stage-17, Stage-19, Stage-20 and Stage-21 components.

Dedicated untouched live block:

- 64 independent Open5GS runners;
- seeds 8701..8764;
- 12 primary episodes per runner;
- 768 primary attack episodes total;
- all detector parameters frozen before capture;
- identical telemetry and episodes used by every ablation variant;
- private labels unavailable to the blind detector jobs;
- labels joined only in the final audit;
- 50,000 runner-cluster bootstrap resamples for paired confidence intervals.

Canonical workflow run: **38162596406**

Evaluation head SHA:

**7e1296046379d3ee9e3e5aac9b12ab7b550cfbe6**

Final artifact:

- name: **stage21-unified-ablation-report**
- artifact ID: **11711631100**
- SHA-256:
  **a57dfb2c18cc0157387dff55664e2d89fa884d527e95a83644b0d176015d7ec1**

All 64 captures, all 64 blind ablation jobs and the final audit completed
successfully.

## Variants

The following frozen compositions were evaluated on the same event stream:

1. directional only — frozen Stage-17 channel;
2. directional + sparse memory — frozen Stage-19 detector;
3. structural only — frozen Stage-20 structural channel without directional
   channels;
4. semantic only — frozen Stage-21 stable semantic channel;
5. directional + structural;
6. full minus semantic — Stage-19 + structural, equivalent to the Stage-20
   combined architecture;
7. full minus structural — Stage-19 + semantic;
8. full minus sparse memory — Stage-17 + structural + semantic;
9. full Stage 21 — Stage-19 + structural + semantic.

The leave-one-channel-out comparisons replace Stage-19 by Stage-17 when sparse
memory is removed, so the base directional fast path remains present.

## Aggregate result

| Variant | Recall | Penalized delay, ticks | False alarms | Clean ticks | FA / 1000 |
|---|---:|---:|---:|---:|---:|
| Directional only | 0.167 | 11.33 | 0 | 5,376 | 0.0000 |
| Directional + sparse memory | 0.167 | 10.17 | 0 | 5,376 | 0.0000 |
| Structural only | 0.277 | 9.59 | 0 | 5,376 | 0.0000 |
| Semantic only | **1.000** | **5.78** | 0 | 5,376 | 0.0000 |
| Directional + structural | 0.277 | 9.59 | 0 | 5,376 | 0.0000 |
| Full minus semantic (Stage 20) | 0.277 | 9.59 | 0 | 5,376 | 0.0000 |
| Full minus structural | **1.000** | **5.78** | 0 | 5,376 | 0.0000 |
| Full minus sparse memory | **1.000** | **5.78** | 0 | 5,376 | 0.0000 |
| Full Stage 21 | **1.000** | **5.78** | 0 | 5,376 | 0.0000 |

Both structural and semantic calibration gates enabled on **64 / 64** runners.
The semantic channel selected a mean of **23.0 stable scalar paths**.

## Paired component effects

| Comparison | Recall delta | 95% runner-cluster CI | Delay delta, ticks | 95% CI | Rescued events | Lost events |
|---|---:|---:|---:|---:|---:|---:|
| Add sparse memory to directional | +0.000 | [+0.000, +0.000] | -1.17 | [-1.17, -1.17] | 0 | 0 |
| Add structural to directional | +0.111 | [+0.098, +0.124] | -1.75 | [-1.82, -1.68] | 85 | 0 |
| Add structural to directional+sparse | +0.111 | [+0.098, +0.124] | -0.58 | [-0.65, -0.51] | 85 | 0 |
| Add semantic to Stage 20 | **+0.723** | **[+0.710, +0.736]** | **-3.80** | **[-3.95, -3.66]** | **555** | **0** |
| Full vs full without sparse | +0.000 | [+0.000, +0.000] | +0.00 | [+0.00, +0.00] | 0 | 0 |
| Full vs full without structural | +0.000 | [+0.000, +0.000] | +0.00 | [+0.00, +0.00] | 0 | 0 |
| Full vs full without semantic | **+0.723** | **[+0.710, +0.736]** | **-3.80** | **[-3.95, -3.66]** | **555** | **0** |

Sparse memory did not increase event recall on this particular live family
mixture, but it reduced the horizon-penalized delay by 1.17 ticks relative to
the directional-only detector.

The structural channel rescued **85** events relative to the directional
channel. The semantic channel rescued **555** additional events relative to the
full Stage-20 architecture.

## Per-family recall

| Family | Directional | + sparse | Structural | Semantic | Stage 20 | Full Stage 21 |
|---|---:|---:|---:|---:|---:|---:|
| identity_value_sparse | 0.000 | 0.000 | 0.000 | **1.000** | 0.000 | **1.000** |
| number_value_sparse | 0.000 | 0.000 | 0.000 | **1.000** | 0.000 | **1.000** |
| scheme_value_sparse | 0.000 | 0.000 | 0.000 | **1.000** | 0.000 | **1.000** |
| status_value_sparse | 0.000 | 0.000 | 0.000 | **1.000** | 0.000 | **1.000** |
| structural_leaf_delete_sparse | 0.000 | 0.000 | 0.664 | **1.000** | 0.664 | **1.000** |
| profile_drop_persistent | **1.000** | **1.000** | **1.000** | **1.000** | **1.000** | **1.000** |

The preregistered relational boundary remained unchanged:

- boundary_cross_profile_identity_swap: full Stage-21 recall **0.000**.

## Interpretation

The ablation provides two distinct conclusions.

First, the historical component progression remains causally visible before the
semantic channel is introduced. On the same live data:

- Stage-17 directional evidence detects the persistent profile-drop family;
- Stage-19 sparse memory improves detection speed but does not add recall in
  this specific Stage-21 family mixture;
- Stage-20 structural evidence adds 0.111 recall and rescues 85 structural
  sparse-deletion episodes.

Second, after the Stage-21 semantic channel is added, the current live suite is
fully covered by that channel alone. Removing sparse memory or the structural
channel from the *full* detector causes no loss in recall or delay on this
specific block, whereas removing the semantic channel drops recall from 1.000
to 0.277.

This is not evidence that the previous channels are universally redundant.
The semantic projection compares stable scalar paths. Therefore it can also
detect many structural attacks whenever deleting or replacing structure changes
a selected stable scalar path. It does not cover every possible structural
change, for example changes involving only empty containers or changes confined
to paths excluded by semantic stability calibration.

Likewise, the Stage-21 live generator is intentionally concentrated on
structure-preserving semantic substitutions, one structural sparse family and
one persistent profile family. It is not the same stress distribution under
which Stage-19 sparse memory and Stage-20 structural gating were originally
developed. Their value under heavy drift, unstable semantic paths, large
accounting-only disturbances, or other out-of-distribution regimes is therefore
not negated by this ablation.

The correct article-level conclusion is:

> In the dedicated Stage-21 live attack mixture, semantic reconciliation is the
> dominant source of event-recall gain, while the structural channel provides
> measurable benefit before semantic reconciliation is introduced and sparse
> memory improves delay without increasing recall. The experiment does not
> establish universal redundancy of the earlier channels outside this mixture.

## Reuse restriction

Seeds **8701..8764** are evaluation-only after this audit and must never be used
for parameter tuning, feature selection or detector redesign.
