# Stage 27 — common-source compromise with software-rooted attestation

Stage 26 demonstrated that all frozen detector mechanisms can detect a
persistent false-membership shift generated inside the native Open5GS NRF when
the NF-side witness remains outside the NRF trust domain.

Stage 27 deliberately removes that assumption.

## Research question

What happens if the native NRF and the NF-side witness software are compromised
at the same time and report the same false state? Can a third, cryptographically
separated software trust domain restore detection without retuning the detector?

## Common-source failure

The native Open5GS v2.7.6 NRF reuses the Stage-26 in-process fault: one phantom
NSSF profile is injected into every Discovery response for all 12 samples of
each attack episode.

The ordinary NF-side witness is then deliberately compromised at its software
output boundary. Instead of reporting the NSSF state derived from its local
sources, it returns the same NSSF cardinality and REGISTERED-state count as the
consumer-visible compromised NRF response.

Therefore, during an attack,

    ordinary_witness == compromised_NRF_view

and the pairwise detector has no discrepancy evidence.

This is the expected L3/common-source failure.

## Independent software attestation domain

A separate GitHub Actions `authority` job is the third trust domain.

It builds a canonical manifest from reviewable repository facts:

- Open5GS baseline ref: v2.7.6;
- expected logical NSSF services: nssf and nssf2;
- expected NSSF count: 2;
- expected REGISTERED count: 2;
- SHA-256 of live/nssf.yaml and live/nssf2.yaml;
- repository, commit SHA, workflow and run identity.

The authority job generates an ephemeral Ed25519 private key, signs the
canonical manifest, exports only the public key and signature, and deletes the
private key. The private key is never uploaded as an artifact.

Capture jobs never receive the signed manifest or the authority key material.

A later `attestation-project` job receives:

1. label-free raw consumer/witness telemetry;
2. the signed manifest;
3. the public key and signature.

It verifies the Ed25519 signature, validates repository/config hashes, and then
builds two detector inputs:

- **compromised pair:** trusted state comes from the colluding witness;
- **attested reference:** trusted state comes from the verified signed baseline.

Neither projection job receives attack labels.

## Common representation

Stage 27 intentionally attests only the facts supported by the authority
manifest: NSSF cardinality and REGISTERED-state cardinality.

Both states are represented as a list of anonymous logical NSSF slots. This
allows the unchanged frozen detector to derive:

- directional canonical-byte discrepancy;
- sparse directional discrepancy;
- structural multiplicity;
- semantic multiplicity.

The authority does not claim to attest runtime NF UUIDs.

## Blind protocol

Preregistered seeds: **9401..9408**.

Workflow separation is:

    static-tests
       |
       +---- authority ---- signed manifest/public key
       |
       +---- capture x8 ---- raw telemetry + PRIVATE labels
                 |
                 +---- attestation-project x8
                              |
                              +---- blind-detect x8
                                           |
                                           +---- post-hoc audit

Private labels and the native-NRF mutation log are unavailable to authority,
attestation projection, and blind detection.

## Expected falsification pattern

A successful experiment should show both sides of the boundary:

1. colluding NRF + witness pair: recall near zero;
2. signed independent attestation reference: high recall;
3. no observed clean-sample false alarms;
4. invalid or modified manifests fail signature verification.

## Claim boundary

Stage 27 is **software-rooted attestation**, not hardware remote attestation.

A positive result supports this statement:

> Pairwise consistency fails when NRF and the NF-side witness share the same
> false state, but detection can be restored by moving the trusted reference
> into a third cryptographically separated software trust domain.

It does not establish protection against compromise of the GitHub Actions
control plane, the authority job itself, or its runner. Those require a
hardware-backed or externally controlled root of trust such as TPM, TEE or a
separate attestation service.

Implementation:

- `research/stage27_authority.py`
- `research/stage27_capture.py`
- `research/stage27_attestation.py`
- `research/stage27_live_detect.py`
- `research/stage27_report.py`
- `stage27_tests/test_stage27.py`
- `.github/workflows/stage27-common-source-attestation.yml`
