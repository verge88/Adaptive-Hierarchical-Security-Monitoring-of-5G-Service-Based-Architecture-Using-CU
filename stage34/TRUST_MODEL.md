# Stage 34 trust model

## Previous residual gap

Stage 33 established an external decision domain but trusted telemetry rows
created on GitHub.

It also evaluated only:

    count != expected_count
    OR
    registered_count != expected_registered_count

which cannot detect state-preserving profile corruption.

## Stage-34 trust chain

The experiment uses:

    external Open5GS testbed
        -> external collector
            -> ECDSA-signed relational telemetry
                -> separate external relational verifier
                    -> ECDSA-signed verdict
                        -> GitHub post-hoc label audit

GitHub does not originate the telemetry rows consumed by the relational
verifier.

## Collector statement

For telemetry package T:

    sigma_C = Sign(K_C, canonical(T))

T binds:

- run seed;
- fresh challenge nonce;
- collector sequence;
- policy digest;
- clean relational baseline;
- all attack-period relational observations;
- raw NRF response hashes;
- native NRF source hash.

The private attack schedule is not inside T.

## Relational state

For each NSSF identity i:

    R[i] = (
        nfType,
        nfStatus,
        fqdn,
        ipv4Addresses,
        nfServices
    )

The verifier raises an alert if:

    Keys(R_expected) != Keys(R_observed)

or if for any shared identity:

    R_expected[i] != R_observed[i]

or if a duplicate nfInstanceId is present.

This preserves identity/attribute binding.

## Legacy negative comparator

Every native Stage-34 mutation is required to keep:

    |NSSF| = 2
    REGISTERED(NSSF) = 2

The old count/status invariant is therefore expected to remain silent. A count
or REGISTERED-count deviation invalidates the run rather than improving the
relational detector's score.

## Freshness

The verifier accepts a collector package only when:

    nonce not previously seen
    sequence > last accepted collector sequence

and the collector signature is valid.

This is process-lifetime freshness. Service restart resets the in-memory replay
state; no hardware monotonic counter is claimed.

## Trusted components

Trusted for this experiment:

- external Render collector service;
- external Render relational verifier service;
- their pinned public-key fingerprints;
- Stage-34 approved policy;
- external service deployment revisions;
- Render platform/control plane.

Not trusted for telemetry creation or detector decision:

- GitHub Actions capture logic;
- GitHub-side detector logic.

## Residual limitations

The collector and verifier share one cloud provider/workspace, so provider-level
compromise can affect both domains.

No TPM/TEE measurement proves the running image hash.

The clean baseline is acquired immediately before attack realization from the
external testbed itself; it is a protected pre-attack reference, not an
independent hardware measurement of physical network truth.

The attack families cover selected identity, endpoint, and service relations,
not every NFProfile field or arbitrary semantic corruption.
