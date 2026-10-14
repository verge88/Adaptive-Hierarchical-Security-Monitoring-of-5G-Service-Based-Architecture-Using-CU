# Stage 33 final trust model

## Domains

Stage 33 separates four domains:

1. **Capture domain** — GitHub-hosted runner executing live Open5GS.
2. **External root domain** — AWS KMS plus externally administered approved
   policy digest.
3. **Decision domain** — separately hosted Stage-33 verifier.
4. **Audit domain** — GitHub post-hoc statistical label join.

## External policy

Let P be the canonical Stage-33 policy and K_ext the Stage-32 non-exportable
external KMS key.

The decision domain accepts P only if:

    SHA256(P) == externally pinned policy digest
    Verify(K_ext_public, P, signature) == true
    KMS key ARN == expected external key ARN
    KMS public-key fingerprint == expected external fingerprint

P binds:

- baseline epoch rules;
- Open5GS version;
- NSSF configuration;
- native NRF laboratory fault source;
- the complete frozen detector dependency chain;
- the Stage-33 external verifier implementation.

## Decision execution

For every raw observation t, the external verifier derives the trusted baseline
from the policy epoch covering t.

It does not trust any baseline-epoch claim supplied by capture telemetry.

The external service computes both:

    trusted external-policy baseline versus NRF consumer view

and

    colluding NF-side witness versus NRF consumer view

then runs the unchanged Stage-29 detector.

## Label separation

Private attack labels and realized mutation ticks remain absent from the external
verifier request.

The request contains only the raw label-free observation stream.

## Signed verdict

The external service emits canonical verdict V and an Ed25519 signature:

    sigma_V = Sign(K_verifier, canonical(V))

K_verifier is generated and stored outside GitHub.

The post-hoc audit verifies:

    fingerprint(K_verifier_public) == externally configured value
    Verify(K_verifier_public, V, sigma_V) == true
    telemetry_digest(V) == digest(submitted raw telemetry)

Only then may labels be joined.

## Compromise interpretation

A GitHub detector-runner compromise no longer permits changing detector logic,
because GitHub no longer executes the detector in the final protocol.

A GitHub capture compromise can still fabricate telemetry before submission.

An external verifier compromise can fabricate verdicts and is therefore inside
the Stage-33 trusted computing base.

An AWS KMS / external approval compromise can authorize a different execution
policy and is inside the root trust base.

## Scientific endpoint

Stage 33 is intended as the final iteration of this experiment series.

The remaining unresolved problem is not detector logic but end-to-end trusted
telemetry acquisition. Solving that would require moving capture or measurement
into attested hardware/TEE or another independently measured acquisition domain,
which is outside the scope of this Open5GS/GitHub Actions study.
