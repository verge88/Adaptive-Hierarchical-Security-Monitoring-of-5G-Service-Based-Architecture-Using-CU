# Stage 24 — native Open5GS NRF compromise with an external NF-side witness

Stage 23 closed the SCP-process gap by producing false service data inside
`open5gs-scpd` while the reference observation bypassed the SCP.  An analogous
NRF experiment cannot use a second request to the same NRF as truth: if the NRF
returns the same false state to both branches, pairwise consistency contains no
evidence of compromise.

Stage 24 therefore changes the reference source, not the frozen detector.

## Research question

Can the frozen Stage-21 semantic detector identify false NF Discovery data
produced inside `open5gs-nrfd` when the reference is reconstructed outside the
NRF process from independent NF-side evidence?

## Native NRF fault location

The Stage-24 image is built from Open5GS v2.7.6 source.  The pinned
`src/nrf/nnrf-handler.c` contains a research-only function called from
`nrf_nnrf_handle_nf_discover()` after the normal SearchResult response is
built and immediately before the stock server-send call.

The internal NRF registry is not changed.  Only the consumer-visible Discovery
response is modified.  The local hook is disabled during startup and is enabled
only by creating `/run/stage24/enabled` inside the disposable NRF container.
It exposes no network control interface.

After a 30-response clean warm-up, six 16-sample cycles are used.  Each cycle
contains a 12-sample monitored episode and four clean samples.  At local samples
0, 4 and 8 the NRF performs one of two alternating response faults:

- `status_substitution`: one returned `nfStatus` changes from
  `REGISTERED` to `SUSPENDED`;
- `profile_drop`: one returned NSSF profile is removed from the Discovery
  response.

There are six episodes and 18 in-process NRF mutations per runner.

## NRF-independent witness

The trusted Stage-24 witness never calls NRF Discovery.

For each of the two real Open5GS NSSF processes it uses two observations that
remain outside the NRF process:

1. the NSSF's own local Open5GS log record showing that its NF state entered
   `NF registered`, including that NF's own instance UUID;
2. a direct HTTP/2 liveness observation of that NSSF's native SBI socket.

From those observations Stage 24 reconstructs a minimal semantic shadow view
containing `nfInstanceId`, `nfType=NSSF`, and `nfStatus=REGISTERED` for the
two live NSSF instances.

The consumer view follows the normal lab path:

    consumer -> stock Open5GS SCP -> instrumented native Open5GS NRF

The trusted witness follows neither the SCP nor NRF Discovery:

    NSSF local registered-state record + direct NSSF SBI observation
                                      -> semantic shadow witness

This is deliberately narrower than a full duplicate NRF.  It independently
attests only fields justified by NF-side evidence.

## Detector discipline

Stage 24 reuses the frozen Stage-21 detector without retuning.

Only the semantic channel receives an independent NRF-external reference.
Canonical-byte and structural reference fields are deliberately set equal to
the consumer view, neutralizing those channels rather than pretending they have
independent truth.  This keeps the claim auditable:

> Stage 24 validates the frozen semantic integrity channel against native NRF
> output corruption when the monitored semantic facts can be independently
> reconstructed from NF-side evidence.

A common-mode negative control replaces the trusted semantic projection with
the same compromised-NRF consumer projection.  Pairwise detection is expected
to disappear in that control.

## Blind protocol

Live seeds are preregistered as **9101..9108**.

Telemetry contains no private mutation schedule and no native-NRF mutation log.
Blind detector jobs download only telemetry.  Private labels and the native NRF
log are uploaded separately and joined only in the final audit.

## Provenance

Every runner records:

- Open5GS source ref `v2.7.6`;
- SHA-256 of the instrumented `src/nrf/nnrf-handler.c`;
- SHA-256 of the executed `open5gs-nrfd` binary;
- confirmation that the binary contains the Stage-24 marker;
- NF-side registration UUIDs;
- the exact in-process mutation markers emitted by the native NRF.

The audit rejects the run if the native NRF markers do not exactly match the
frozen schedule.

## Claim boundary

A positive result does not demonstrate exploitation of a production NRF
vulnerability and does not prove that NF-side liveness is a complete substitute
for an NRF registry.

It does demonstrate the narrower property needed to close the current
common-source gap: false Discovery data generated inside the native NRF process
can be exposed when at least the monitored semantic facts are independently
available outside the NRF control domain.

Files:

- `live/stage24-nnrf-handler.c`
- `live/stage24-nrf.Dockerfile`
- `live/stage24-nrf-compose.yaml`
- `research/stage24_capture.py`
- `research/stage24_live_detect.py`
- `research/stage24_report.py`
- `stage24_tests/test_stage24.py`
- `.github/workflows/stage24-native-nrf.yml`
