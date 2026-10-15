# Stage 35 trust model

## Chain

    external Open5GS testbed
        -> collector K_C
            -> authenticated verifier A
                -> external freshness anchor
                    -> verifier K_V
                        -> GitHub post-hoc audit

A second verifier B shares only the approved policy, collector public key,
verifier signing key, service authentication credential, and freshness anchor.

## Collector authentication

Verifier requests require:

    Authorization: Bearer T_CV

where T_CV is present only in the collector and verifier service environments.

An unauthenticated request is exercised once per held-out run and must be
rejected.

## Freshness anchor

For package P:

    n = P.challenge_nonce
    s = P.collector_sequence
    d = SHA256(P)

the verifier requests an atomic anchor claim:

    Claim(n, s, d)

The anchor accepts only when:

    n has not appeared before
    s > last_sequence

Verifier A claims the package first. The same package is then sent to verifier
B. Rejection by B demonstrates verifier-process-independent replay state.

The anchor is a separate process but uses memory-only state on the free Render
tier. Therefore this experiment does not demonstrate replay protection after an
anchor restart.

## Transition reference model

Let O be the stable state before a legitimate transition and N the stable state
after it.

During the bounded convergence phase the verifier accepts:

    observed == O
    OR
    observed == N

and alerts otherwise.

Because the comparison is over the complete Stage-34 identity-bound relational
projection, count-preserving identity, endpoint, or service corruption is not
made legitimate merely because cardinality remains valid.

The old/new endpoint states are collected cleanly by the trusted external
collector with the research hook disabled. They are not TPM/TEE-backed physical
network measurements.

## Availability boundary

The security recall metric and service availability metric are distinct.

Held-out attack scoring requires a signed verifier decision. A separate
100-request full-path benchmark measures external verifier+anchor response
availability and latency.

No claim is made about high-concurrency saturation, multi-region failover, or
production carrier-grade availability.
