# Stage 33 trust model

## Layer removed from GitHub

Before Stage 33, GitHub Actions still executed the final verifier/detector.

Stage 33 moves that decision into a Render service with auto-deploy disabled.

The service maintains:

    K_ext = external ECDSA private key
    D_approved = approved Stage-33 policy digest

Neither value is supplied by the GitHub workflow.

## Request binding

For request R:

    d_R = SHA256(canonical(R))

The external service computes decision V from R and signs a canonical verdict
containing d_R:

    sigma = Sign(K_ext, canonical(V))

The GitHub client verifies:

    Verify(pk_ext, V, sigma)
    SHA256(pk_ext_PEM) == pinned fingerprint
    V.request_sha256 == SHA256(R)
    V.policy_sha256 == D_approved

Thus changing the returned detector decision after it leaves the external
service invalidates the signature.

## Common-source negative control

The external service requires the consumer and compromised NF-side witness
counts to be identical. The negative-control alert remains false.

This preserves the L3/common-source result: colluding sources contain no
truth-bearing disagreement.

## Legitimate transition handling

Ticks 30..49 remain the Stage-30 legitimate transition validation interval.
The external service validates the expected signed logical epoch state and
rejects a run if that interval contains a state mismatch.

## Trusted computing base

Trusted:

- Render service/control plane;
- the Render-held private signing key;
- pinned Stage-33 service deployment;
- pinned public-key fingerprint;
- Stage-33 approved policy;
- GitHub capture telemetry as input data.

Not trusted for the decision itself:

- GitHub detector code;
- GitHub post-processing before private-label audit.

## Residual gap

The telemetry origin is not independently attested. Therefore a fully malicious
GitHub capture runner can still fabricate raw observations that the external
service will faithfully evaluate.

Stage 33 validates independent **decision execution**, not an end-to-end
hardware-attested measurement chain.
