# Stage 25 — full multichannel NRF-independent witness projection

Stage 24 proved that a false NF Discovery response produced inside the native
Open5GS NRF can be detected when semantic facts are reconstructed outside the
NRF process. Numeric and structural channels were intentionally neutralized
because a minimal NF-side witness does not reproduce every field in the full
NRF Discovery document.

Stage 25 closes that narrower gap without changing detector thresholds.

## Research question

Can all frozen Stage-21 channels receive an NRF-independent reference if both
the trusted witness and the consumer response are mapped to the same
independently attestable representation?

## Witness-supported projection

The external witness still does not call NRF Discovery. For the two live NSSF
processes it uses:

1. each NSSF process's own local Open5GS registered-state log record, including
   its NF instance UUID;
2. direct HTTP/2 liveness observation of the NSSF's own native SBI socket.

Only facts justified by those observations are retained:

- `nfInstanceId`;
- `nfType=NSSF`;
- `nfStatus=REGISTERED`.

The consumer's compromised NRF Discovery response is mapped to exactly the same
three-field NSSF projection. Fields outside this evidence boundary are discarded
rather than treated as independently known truth.

For both observations Stage 25 then derives:

- canonical JSON byte length for the directional channel;
- the same canonical discrepancy for the sparse-memory channel;
- value-free structural fingerprints;
- stable semantic value projections.

Thus the detector is unchanged. Only the representation supplied to it changes.

## Native NRF fault

Stage 25 deliberately reuses the frozen Stage-24 Open5GS v2.7.6 NRF build and
its in-process response faults:

- `status_substitution`;
- `profile_drop`.

The modification occurs inside
`src/nrf/nnrf-handler.c::nrf_nnrf_handle_nf_discover()` before the stock
response send. Internal NRF registry state is not changed.

## Calibration discipline

A Stage-25 runner is rejected unless every one of the 30 warm-up pairs matches
exactly in canonical byte length, structural projection and semantic projection.

This is important: structural and sparse gates are enabled by independently
paired clean observations rather than by copying consumer fields into the
trusted branch.

The Stage-21 detector configuration remains frozen. No Stage-25 threshold,
window, recovery rule or feature-specific parameter is tuned.

## Negative control

The common-mode control replaces all trusted projected fields with the same
consumer-visible projected state returned through the compromised NRF.

Expected behavior:

    external witness outside NRF -> discrepancy evidence exists
    common compromised view      -> pairwise evidence disappears

This control distinguishes observer independence from merely issuing a second
observation.

## Blind protocol

Preregistered live seeds: **9201..9208**.

The native NRF mutation log and private episode labels are uploaded separately.
Blind detection jobs receive only label-free projected telemetry. Labels are
joined only after all blind jobs finish.

## Claim boundary

A positive Stage-25 result supports a stronger statement than Stage 24:

> all frozen multichannel mechanisms can operate with an NRF-independent
> reference when both sides are expressed in a common representation whose
> facts are independently attestable outside the NRF process.

It does **not** establish independent truth for arbitrary NRF fields omitted
from the projection, and it does not demonstrate exploitation of a production
Open5GS vulnerability.

Files:

- `research/stage25_capture.py`
- `research/stage25_live_detect.py`
- `research/stage25_report.py`
- `stage25_tests/test_stage25.py`
- `.github/workflows/stage25-nrf-full-witness.yml`

The native NRF build remains the audited Stage-24 build.
