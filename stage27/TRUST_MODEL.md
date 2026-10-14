# Stage 27 trust model

Stage 27 explicitly reproduces the common-source/common-mode failure left after
Stage 26.

Let:

- `N` be the compromised native NRF;
- `W` be the compromised NF-side witness layer;
- `A` be the isolated software attestation authority;
- `P` be the common ordinal NSSF projection.

During an attack episode, both ordinary branches report the same false state:

    P(N_t) = P(W_t) = {nssf-1, nssf-2, nssf-3}

while the signed deployment contract is

    P(A) = {nssf-1, nssf-2}.

Therefore the ordinary pair satisfies

    P(N_t) = P(W_t)

and pairwise consistency alone carries no truth-bearing discrepancy.

The third-domain comparison instead satisfies

    P(A) != P(N_t),

which restores an observable integrity signal.

## Authority separation

The authority job:

- never starts the Open5GS runtime;
- never queries NRF Discovery;
- never reads NF witness runtime logs;
- signs only the predeclared deployment-state contract;
- destroys the ephemeral Ed25519 private key before artifact upload.

The capture job never receives the authority bundle. The blind detector receives
the public signed bundle but not the private key. Private attack labels remain
separate until post-hoc audit.

## Trust hierarchy after Stage 27

| Level | Assumption | Status |
|---|---|---|
| L2-SCP | SCP may lie; reference outside SCP | validated |
| L2-NRF | NRF may lie; NF-side witness outside NRF | validated |
| L3-common-mode | NRF and NF witness agree on the same false state | reproduced |
| L3-software-attested | third signed workflow domain remains outside both compromised branches | Stage 27 |
| L4-hardware-attested | runtime state rooted in TPM/TEE/confidential VM measurement | not yet validated |

The Stage-27 signing key separation is a workflow property, not a hardware
property. A repository/workflow compromise capable of modifying the authority
job itself remains outside the experiment's trusted computing base.
