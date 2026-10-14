# Stage 33 — final external-verifier experiment

Stage 32 moves signing-key custody and policy approval outside GitHub Actions.
One final decision-plane gap remains: trusted projection and detector execution
still occur on GitHub-hosted runners.

Stage 33 moves those operations into a separately administered external service.

## Final research question

Does the Stage-29 augmented detector preserve its attack/false-alarm behavior
when the trusted projection and detector decision are computed outside GitHub,
with the external service accepting only a policy approved by the Stage-32 KMS
root and emitting a signed verdict?

## External verifier

`research/stage33_external_verifier.py` runs as a small HTTP service.

It receives only:

- label-free raw telemetry;
- the canonical Stage-33 policy;
- the Stage-32 external KMS signing receipt;
- the Stage-32 KMS public key.

It does **not** receive private attack labels or the realized randomized attack
schedule.

The service then:

1. verifies the external KMS policy signature;
2. checks the externally pinned KMS key identity/fingerprint;
3. checks the exact externally approved policy digest;
4. verifies hashes of its local frozen detector dependency chain;
5. derives the legitimate baseline epoch directly from the signed policy;
6. constructs attested and colluding-pair projections;
7. runs the frozen Stage-29 detector;
8. emits a canonical verdict;
9. signs that verdict with an external-service Ed25519 key unavailable to
   GitHub Actions.

GitHub does not recompute the alarms in the final protocol.

## Held-out experiment

Fresh final runner identifiers are preregistered as:

    10001..10008

Each runner uses the frozen Stage-30 live transition protocol and the frozen
Stage-28 randomized attack generator with a fresh private random schedule.

The external verifier sees no labels.

Only after a signed external verdict has been returned and verified does the
GitHub audit job join private labels to compute recall, delay and false alarms.

## External service deployment

A generic Docker image is provided in `stage33/Dockerfile`.

A Render blueprint is provided in `stage33/render.yaml`, but the verifier may
be hosted on any separately administered container platform.

The external administrator must configure:

- `STAGE33_EXPECTED_KMS_KEY_ARN`
- `STAGE33_EXPECTED_KMS_PUBLIC_KEY_SHA256`
- `STAGE33_EXPECTED_POLICY_SHA256`
- `STAGE33_VERDICT_PRIVATE_KEY_PEM_B64`
- `STAGE33_API_TOKEN`

The verdict private key must be generated outside GitHub and must never be
stored in the repository or GitHub Actions.

## Final trust stack

    external AWS KMS approval root
        -> signed Stage-33 execution policy
        -> external verifier code measurements
        -> external trusted projection
        -> frozen Stage-29 detector
        -> externally signed verdict
        -> GitHub post-hoc signature check and label join

## Claim boundary

Stage 33 moves the **decision plane** outside GitHub.

It still does not move live Open5GS telemetry capture outside GitHub runners.
Therefore a malicious capture environment could still fabricate its input before
it reaches the independent verifier.

The final claim is consequently:

> trusted projection and detector decision were independently executed outside
> GitHub on label-free telemetry under an externally approved cryptographic
> policy.

It is not a claim that every experimental component is Byzantine-independent.
