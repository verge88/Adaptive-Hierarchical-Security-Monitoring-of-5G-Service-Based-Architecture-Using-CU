# Stage 27 trust-model extension

Stage 27 models the first case where the two ordinary observation branches are
both inside the attacker's control domain.

Let:

- `N` be the compromised native NRF;
- `W` be the compromised NF-side witness software;
- `A` be the independent software attestation authority;
- `V` be the signature-verifying projection job.

During an attack the ordinary pair is constructed so that

    W_t = N_t = false_state_t

and therefore

    for every frozen feature phi_k:
    phi_k(W_t) = phi_k(N_t).

The pairwise detector is expected to fail. This is not a detector defect; there
is no disagreement carrying information about truth.

The authority creates a canonical baseline `M` containing independently
reviewable configuration facts and signs it with an ephemeral Ed25519 private
key:

    sigma = Sign(sk_A, M)

Only `M`, `sigma` and `pk_A` leave the authority job. The private key is
deleted and is not uploaded.

The verifier first checks

    Verify(pk_A, M, sigma) = true

and rejects modified manifests. It then derives the trusted projected state
`T_A` from the signed NSSF cardinality facts.

Detection becomes

    compare T_A with N_t

rather than

    compare W_t with N_t.

## Trust levels

| Level | Assumption | Validation |
|---|---|---|
| L2-NRF | NRF false; NF witness independent | Stage 24–26 |
| L3-common-source | NRF and NF witness share same false state | Stage 27 negative branch |
| L3+software-root | third signed authority isolated by GitHub Actions job boundary | Stage 27 recovery branch |
| L4-hardware-root | authority identity/state anchored in TPM/TEE/external verifier | not implemented |

## What the signature proves

Within the Stage-27 model the signature establishes integrity of the canonical
authority manifest after creation and separates the signing capability from the
capture and detector jobs.

The manifest covers:

- repository and commit identity;
- Open5GS baseline version;
- hashes of the two NSSF configuration files;
- expected logical NSSF count;
- expected REGISTERED-state count.

It does not attest runtime UUIDs, runtime memory, kernel state, or hardware
identity.

## Remaining boundary

If an attacker compromises the authority job or the GitHub Actions control
plane, the software root can issue a false but validly signed manifest. Solving
that problem requires moving the signing/measurement root outside the workflow
runner, for example to a TPM-backed self-hosted runner, confidential VM/TEE, or
external attestation service.
