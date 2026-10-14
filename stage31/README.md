# Stage 31 — GitHub-anchored authority-bundle provenance

Stage 30 solved stale-baseline handling only inside a software-rooted trust
model. One important gap remained: the verifier received the ephemeral Ed25519
public key and the signed epoch manifests through the same workflow delivery
path. If an attacker could replace the complete bundle, signature verification
alone would not distinguish the attacker's new key from the authority key.

Stage 31 adds an externally anchored provenance layer without changing the
detector, attack distribution, or baseline-freshness protocol.

## Research question

Can the verifier reject substitution of the complete authority bundle by first
binding that bundle to an independently verifiable GitHub Actions OIDC
attestation for the exact repository, source commit and signer workflow?

## Authority bundle

The Stage-30 authority still creates:

- four signed baseline epochs;
- one ephemeral Ed25519 key pair;
- the public key;
- epoch signatures;
- the epoch-chain index.

The private Ed25519 key is deleted and is never uploaded.

All public authority material is then packed into one tarball:

    stage31_authority_bundle.tar.gz

## GitHub Artifact Attestation

Before the bundle is uploaded, the authority job uses GitHub Artifact
Attestations to create build provenance for the exact tarball digest.

The attestation is produced with:

- GitHub Actions OIDC identity;
- the current repository identity;
- the current source digest;
- the exact Stage-31 signer workflow.

The verifier does not extract the bundle immediately.

It first executes:

    gh attestation verify ...

while requiring:

- the expected repository;
- the exact signer workflow;
- the current source digest.

Only after this verification succeeds is the tarball extracted and the existing
Stage-30 Ed25519 epoch-chain verification performed.

## Tamper negative control

Every verifier job creates a bit-modified copy of the authority tarball and
submits it to the same GitHub attestation verifier.

The experiment fails if the modified bundle is accepted.

Thus Stage 31 distinguishes:

    valid signed epoch contents
    from
    authenticated provenance of the container that carries the signing key.

## Frozen experimental layers

Stage 31 does not retune or redesign the security detector.

It freezes:

- Stage-28 randomized native-NRF attack generator;
- Stage-29 one-sample attested-invariant channel;
- Stage-30 four-epoch baseline freshness protocol;
- Stage-30 live NSSF stop/start/restart sequence.

Fresh runner identifiers are **9801..9808**, each with a new system-random
private attack plan.

## Expected validation

The final audit reports:

- GitHub authority-bundle verification success;
- rejection of the modified authority bundle;
- attack recall;
- legitimate-transition false alarms;
- stale signed-epoch replay rejection;
- common-source NRF+witness negative control.

## Security boundary

This is stronger than Stage 30 because an unauthenticated replacement public key
is no longer sufficient: the complete bundle must also possess valid provenance
from the required GitHub repository, source digest and signer workflow.

It is still not a hardware-independent root of trust.

Stage 31 trusts:

- GitHub Actions OIDC issuance;
- GitHub Artifact Attestation verification and its trust root;
- the required workflow identity;
- the GitHub control plane.

An attacker who controls those services or the authorized signer workflow can
still produce a false but validly attested authority bundle.

A later hardware/external stage would move the root beyond GitHub, for example
to TPM/TEE/KMS/HSM-backed identity or an independent attestation service.
