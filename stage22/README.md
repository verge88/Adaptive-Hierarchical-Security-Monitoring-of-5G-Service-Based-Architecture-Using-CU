# Stage 22 — SCP-compromise trust-boundary validation

Stage 21 explicitly left one trust-model gap: both the trusted and consumer
observations traversed the same native Open5GS SCP -> NRF path.  Therefore
Stage 21 could not establish detection when the SCP itself was inside the
attacker's control domain.

Stage 22 changes the observation topology without retuning the detector.

## Research question

Can the frozen Stage-21 multichannel detector expose arbitrary corruption
attributed to a compromised SCP when the trusted observation is generated
outside the SCP trust domain?

The experiment compares two designs on the same attack schedule:

1. **Independent reference:** the consumer view traverses the genuine native
   Open5GS SCP -> NRF path and may be corrupted at the SCP consumer-facing
   output boundary; the trusted reference queries the native NRF directly and
   therefore bypasses the SCP.
2. **Common-path control:** both observations are assigned the same corrupted
   consumer view, representing the information-theoretic case where both
   observers remain downstream of one compromised SCP.

The detector is the frozen Stage-21 detector.  No Stage-22 threshold, semantic
feature, structural feature or sequential-state parameter is tuned.

## What is and is not compromised

Stage 22 is a controlled **effect-level component-compromise experiment**.

The native Open5GS v2.7.6 SCP and NRF binaries remain unmodified and no exploit
is attempted.  A research-only facade first obtains a genuine response through
the native SCP -> NRF route and is then allowed to corrupt the response at the
SCP output boundary.  This models the downstream integrity effect that a
compromised SCP could produce while avoiding an implementation-specific exploit
mechanism.

Accordingly, a successful result supports the following claim:

> When the reference observation is moved outside the SCP trust domain,
> arbitrary SCP-output corruption that changes a monitored representation can
> be detected by the frozen multichannel pairwise detector.

It does **not** support the stronger claim that a vulnerability in the Open5GS
SCP binary was exploited or that every internal SCP compromise is detectable.

## Fresh evaluation block

Stage-22 live seeds are preregistered as **8901..8908**.  The private schedule is
freshly randomized per runner.  The tested fault families are:

- identity value substitution;
- NF status substitution;
- service scheme substitution;
- sparse structural-leaf deletion;
- persistent profile removal.

The private labels are uploaded separately from telemetry.  Blind detector jobs
receive only telemetry.  Labels are joined only after all detector jobs finish.

## Trust-boundary interpretation

The Stage-22 topology is:

    direct native NRF -----------------------> trusted reference
            ^
            |
    native SCP -> native NRF -> fault facade -> consumer view

The fault facade represents the SCP-controlled output boundary.  The trusted
reference does not traverse that boundary.

The common-path control intentionally replaces the trusted fields with the same
consumer-visible fields.  Pairwise detection should then lose its evidence even
though the underlying consumer state is false.  This is a negative control for
the common-mode limitation documented in Stage 21.

## Reproducibility

Live workflow:

- `.github/workflows/stage22-scp-compromise.yml`

Implementation:

- `research/stage22_scp_fault.py`
- `research/stage22_capture.py`
- `research/stage22_live_detect.py`
- `research/stage22_report.py`
- `stage22_tests/test_stage22.py`

The audited report is emitted as the artifact
`stage22-scp-compromise-boundary-report`.

## Remaining gap

Stage 22 closes the Stage-21 gap only for the **SCP trust domain at the
observable response boundary**.  A compromised NRF remains a common source if
both observations derive from that same NRF.  Testing NRF compromise requires a
separate witness outside the NRF trust domain, such as an independently built
registry view or direct NF-side attestation.  That stronger experiment is not
silently inferred from Stage 22.
