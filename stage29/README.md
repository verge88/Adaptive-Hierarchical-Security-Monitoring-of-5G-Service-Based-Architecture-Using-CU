# Stage 29 — held-out validation of a verified attested-invariant channel

Stage 28 was intentionally treated as an exploratory/design set rather than as
a final performance estimate.

Its randomized block contained 96 attack episodes. The frozen Stage-21 combined
alarm missed 15. Those misses were not randomly distributed:

- 13/15 were short episodes;
- 10/15 were status substitutions;
- 9/15 were low-density;
- all 15 used multiplicity one.

That pattern indicates a sensitivity problem caused by temporal accumulation:
the generic frozen detector often does not receive enough repeated evidence
before a short low-amplitude episode ends.

Stage 29 does not retune the Stage-21 detector.

## New rule

Stage 29 adds one logically separate channel that is only valid after successful
verification of the signed Stage-27 authority manifest.

For each observation:

    attested_invariant_alert =
        verified_attestation
        AND (
            consumer_NSSF_count != signed_reference_NSSF_count
            OR consumer_semantic_projection != signed_reference_projection
        )

There is no learned threshold, window, quorum, decay coefficient, or recovery
parameter.

The final Stage-29 augmented decision is

    augmented_alert =
        frozen_stage21_combined_alert
        OR attested_invariant_alert

The original frozen alarm is retained and reported separately.

## Why this is not evaluated on Stage 28

Stage 28 identified the failure mode and is therefore a design set.

Stage 29 uses:

- fresh runner identifiers **9601..9608**;
- fresh system-random private schedules;
- the unchanged Stage-28 randomized attack distribution;
- the unchanged Stage-28 native Open5GS NRF fault injector;
- the unchanged Stage-27 software attestation authority;
- the unchanged Stage-27/28 verifier;
- blind detector jobs with no private labels or realized schedules.

Therefore, Stage-29 performance is a held-out estimate for the rule selected
after examining Stage 28.

## Scientific hypothesis

The new channel should mainly improve short, low-density, and
status-substitution episodes because a cryptographically verified discrete
invariant does not require repeated statistical accumulation.

The experiment is allowed to falsify that hypothesis. The audit reports:

- legacy combined recall;
- invariant-only recall;
- augmented recall;
- Wilson 95% intervals;
- mutation-tick alert coverage;
- delay;
- false alarms per 1000 clean ticks;
- fresh stratified recall by family, duration, and density;
- the colluding NRF+witness negative control.

No CI assertion requires recall to improve or false alarms to remain zero.

## Trust boundary

The immediate invariant rule is valid only for facts covered by a trusted,
fresh, verified attestation baseline.

In Stage 29 those facts are the two logical NSSF instances and their REGISTERED
state represented by the signed software authority manifest.

The result must not be generalized to arbitrary dynamic NF state unless a
separate baseline freshness/update protocol exists.

Stage 29 remains software-rooted attestation, not TPM/TEE remote attestation.
