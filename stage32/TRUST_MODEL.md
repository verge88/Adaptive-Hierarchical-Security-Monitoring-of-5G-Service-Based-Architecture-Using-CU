# Stage 32 trust model

## Security objective

Stage 32 addresses the residual Stage-31 problem that GitHub remained both the
execution environment and the identity root for the authority bundle.

The Stage-32 root is an asymmetric AWS KMS key K_ext and an independently
administered allowlist value D_approved.

For deterministic policy P:

    d = SHA256(P)

The external signer evaluates:

    d == D_approved

before requesting:

    sigma = KMS.Sign(K_ext, d)

GitHub Actions has no permission to change D_approved and cannot export K_ext.

## Acceptance conditions

The verifier accepts the external policy only when:

    SHA256(P) == receipt.digest
    receipt.digest == receipt.approved_digest
    receipt.key_arn == expected external KMS key
    SHA256(public_key_PEM) == independently recorded fingerprint
    Verify(public_key, P, sigma) == true

Only then may the lower trust layers execute.

## Layered chain

    external AWS administrative domain
        -> approved deterministic policy digest
        -> non-exportable KMS signing key
        -> Stage-32 policy signature
        -> Stage-31 GitHub bundle provenance
        -> Stage-30 epoch freshness
        -> Stage-29 attested invariant
        -> detector decision

## Compromise cases

A compromised GitHub runner that changes P cannot obtain a valid signature
unless the independently administered approval value is also changed.

A compromised GitHub runner cannot extract the KMS private key.

A compromised AWS administrator can change the allowlist or key policy and is
therefore inside the Stage-32 trusted computing base.

A fully compromised GitHub verifier can still ignore verification failures or
alter the detector result. Stage 32 does not claim otherwise.

## Stronger next boundary

Complete execution independence requires the verification and/or detector
decision to be performed outside GitHub as well. A suitable Stage 33 design is
an externally hosted verifier or confidential VM that consumes the signed
telemetry package, verifies the external root, and emits its own signed result.
