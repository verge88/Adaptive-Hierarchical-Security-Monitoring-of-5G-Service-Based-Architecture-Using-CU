# Stage 28 trust and statistical model

Stage 28 freezes the Stage-27 trust model and changes only the distribution of
false states.

Let `A` be the signed software authority baseline, `N_t` the compromised NRF
view, and `W_t` the colluding NF-side witness.

The common-source branch remains

    W_t = N_t

so pairwise consistency contains no truth-bearing disagreement.

The attested branch remains

    compare A with N_t.

## Randomized attack process

For each runner, twelve attack episodes are sampled from a preregistered
distribution over:

- duration class;
- mutation density;
- mutation family;
- phantom multiplicity;
- clean recovery-gap length.

The realized schedule is private until post-hoc audit.

This separates two concepts:

1. **pre-registration of the experiment distribution**, which is public;
2. **realized attack labels**, which remain hidden from the blind detector.

## Why event recall alone is insufficient

An event counts as detected if any alarm falls within its attack window. For a
finite block of long attacks this can produce recall 1.000 even when the detector
covers only a fraction of attack ticks.

Stage 28 therefore reports:

    event recall
    mutation-tick alert coverage
    attack-window alarm fraction
    horizon-penalized delay
    clean-sample false-alarm rate

and a Wilson interval for pooled event recall.

The Wilson interval is intentionally non-degenerate when all finite sampled
episodes are detected; for example, 96/96 observed successes do not imply that
the population detection probability is exactly 1.

## Remaining boundary

The Stage-28 result is conditional on the sampled attack distribution and the
software-rooted authority remaining trustworthy.

Moving beyond this point requires either:

- a larger and independently replicated stress distribution; or
- hardware/external attestation that removes the authority job from the same
  software control plane.
