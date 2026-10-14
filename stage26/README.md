# Stage 26 — persistent phantom-profile directional validation

Stage 25 established an NRF-independent reference for every frozen detector
mechanism by projecting both trusted and consumer observations onto the same
NF-side witness-supported representation. In those intermittent Stage-24 fault
families, however, the frozen directional e-process did not cross threshold.

Stage 26 tests whether that is a sensitivity/property-of-the-attack issue rather
than a remaining trust-boundary problem.

## Research question

Will the unchanged Stage-17 directional mechanism detect a sustained
NRF-generated distribution shift when the reference remains outside the NRF
trust domain?

## Native NRF fault

The Stage-26 Open5GS v2.7.6 NRF build injects one phantom NSSF profile into the
NF Discovery response inside
`src/nrf/nnrf-handler.c::nrf_nnrf_handle_nf_discover()` immediately before
the stock server-send path.

The phantom profile is not inserted into the NRF's internal registry. It exists
only in the consumer-visible Discovery response.

After a 30-sample clean warm-up, each of six cycles contains:

- 12 consecutive samples with the phantom profile present;
- four clean recovery samples.

This produces a persistent positive canonical-byte discrepancy, unlike the
three sparse pulses used in Stage 24/25.

## External witness

The trusted branch is unchanged from Stage 25. It never calls NRF Discovery.
It derives the real NSSF membership set from NSSF-local registration UUIDs and
direct NSSF SBI liveness. Both branches are projected to the same fields:

- `nfInstanceId`;
- `nfType`;
- `nfStatus`;
- `nfRegisteredAtSource`.

The injected phantom UUID is absent from the NF-side registration set and is
therefore represented as `nfRegisteredAtSource=false` on the consumer side.

## Detector discipline

No detector parameter is changed. Stage 26 reuses the frozen Stage-21 stack,
including the original directional decay, evidence reference, threshold and
one-sided gate.

The private mutation schedule and native-NRF audit log remain unavailable to
the blind detector.

A common-mode control assigns the same compromised projected state to the
trusted branch. Directional detection should disappear there.

## Claim boundary

A positive result supports the conclusion that the previously observed
zero directional recall in Stage 25 was specific to the sparse/intermittent
attack schedule rather than failure of the independent-reference design.

Stage 26 remains a controlled malicious-behaviour build, not exploitation of a
production Open5GS vulnerability.

Preregistered live seeds: **9301..9308**.
