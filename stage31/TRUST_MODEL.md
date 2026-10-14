# Stage 31 trust-model extension

## Stage-30 residual gap

Stage 30 verified the chain

    Verify(pk_A, baseline_epoch, signature)

but pk_A was delivered together with the signed material.

Without another trust anchor, replacing

    (pk_A, manifests, signatures)

with

    (pk_attacker, fake_manifests, fake_signatures)

could still form an internally consistent bundle.

## Stage-31 composition

Stage 31 authenticates the entire authority bundle before it is unpacked.

Let U be the tarball containing:

    pk_A
    B_0..B_3
    sigma_0..sigma_3

GitHub Actions produces provenance P for digest H(U) using its OIDC workflow
identity.

The verifier requires:

    Verify_GitHub(P, H(U)) = true
    repository(P) = expected repository
    signer_workflow(P) = exact Stage-31 workflow
    source_digest(P) = current workflow source digest

Only then does it perform the Stage-30 checks:

    Verify(pk_A, B_e, sigma_e)
    epoch-chain continuity
    logical freshness interval
    replay rejection

## Tamper control

For U' differing from U by one bit:

    H(U') != H(U)

and therefore U' has no matching valid artifact attestation under the required
identity.

Every verifier job exercises this negative control.

## Trust boundary after Stage 31

The authority key is no longer accepted solely because it is present in the
same artifact. Trust is anchored to GitHub's attestation identity layer.

The resulting stack is:

    GitHub OIDC / attestation trust root
        -> authority bundle digest
            -> ephemeral Ed25519 authority key
                -> signed baseline epoch chain
                    -> fresh trusted NSSF invariant
                        -> Stage-29 detector

This does not provide an independent hardware root. Compromise of GitHub OIDC,
the attestation service, the authorized signer workflow or the GitHub control
plane remains outside the validated model.
