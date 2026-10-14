# Stage 32 — external KMS/HSM-backed root of trust

Stage 31 authenticated the authority bundle with GitHub Artifact Attestations,
but the root still depended on GitHub OIDC and the GitHub control plane.

Stage 32 moves two security-critical capabilities outside GitHub:

1. custody of the asymmetric signing private key;
2. approval of the exact policy digest that may be signed.

The concrete implementation uses an AWS KMS asymmetric `ECC_NIST_P256`
SIGN_VERIFY key plus an AWS-side approval parameter that GitHub Actions is not
allowed to modify.

## External policy

`research/stage32_policy_bundle.py` builds a deterministic canonical policy
covering:

- the Stage-30 baseline epoch sequence;
- the frozen Stage-29 detector rule;
- Open5GS v2.7.6;
- hashes of the NSSF configuration;
- hashes of the native NRF fault source;
- hashes of the frozen verifier/detector sources.

The policy deliberately excludes GitHub run IDs and commit-specific runtime
metadata so it can be reviewed and approved externally.

Its SHA-256 is the value an independent AWS administrator places into the
Stage-32 SSM approval parameter.

## External signing boundary

The CloudFormation stack in `stage32/aws/` creates:

- a non-exportable AWS KMS asymmetric signing key;
- a Lambda signer;
- an SSM parameter containing the independently approved policy digest;
- a narrow GitHub OIDC role.

The GitHub role can:

- invoke the signer;
- read the KMS public key.

It cannot:

- export the private key;
- modify the approved digest;
- call KMS Sign directly.

The Lambda signer first compares the requested digest with the SSM-approved
digest. It calls KMS Sign only on an exact match.

## Verification

The GitHub verifier independently checks:

- exact policy SHA-256;
- exact KMS key ARN;
- externally recorded public-key SHA-256;
- ECDSA-SHA256 signature;
- approval-source marker.

A bit-modified policy is then submitted to the same verifier and must fail.

After this external-root check, the existing layers remain frozen:

- Stage 31 GitHub Artifact Attestation of the dynamic authority bundle;
- Stage 30 signed epoch freshness and replay rejection;
- Stage 29 detector;
- Stage 28 randomized attack generator.

Fresh live validation is reserved for runners 9901..9908.

## Why this is materially more independent

A compromised GitHub runner can change the requested digest, but it cannot
change the AWS-side allowlist value because its IAM role has no
`ssm:PutParameter` permission.

It can request a signature only for the digest already approved from the
separately administered AWS account.

The KMS private key is non-exportable and never exists on a GitHub runner.

## What still is not independent

The final verifier and detector still execute on GitHub-hosted runners.

Therefore Stage 32 establishes an **external cryptographic root and external
approval policy**, not complete resistance to a malicious verifier or total
compromise of GitHub's execution/control plane.

To remove that final dependency, the verification/decision step itself must
move into a separately administered execution domain, such as a confidential VM
or an external attestation/verifier service.
