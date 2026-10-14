# Stage 32 AWS external signing root

This directory contains the infrastructure required for a signing root whose
private key and approval policy are outside GitHub Actions.

## Security properties

The stack creates:

- an AWS KMS asymmetric `ECC_NIST_P256` key with `SIGN_VERIFY` usage;
- a Lambda signer whose role can call `kms:Sign` but cannot export the key;
- an SSM Parameter containing the **administrator-approved policy SHA-256**;
- a GitHub OIDC role that can invoke the signer and read the public key;
- no permission for GitHub Actions to modify the approved digest.

The signer refuses every request except the digest already approved in SSM.

Therefore a compromised GitHub runner cannot obtain a valid signature for a
different policy merely by changing its request payload.

## Required external setup

1. Deploy `stage32-external-root.yaml` from an AWS administrative context that
   is not controlled by this GitHub workflow.
2. Build the deterministic Stage-32 policy in GitHub and note
   `stage32_policy/policy.sha256`.
3. Independently review that policy.
4. From the AWS administrative context, update the SSM parameter printed by the
   stack output to exactly that SHA-256.
5. Read the KMS public key once from the administrative context, convert it to
   PEM, calculate SHA-256 of the PEM bytes, and record that fingerprint outside
   the repository.
6. Configure the GitHub **environment** `stage32-external` with repository
   variables:
   - `STAGE32_AWS_ROLE_ARN`
   - `STAGE32_AWS_REGION`
   - `STAGE32_SIGNER_FUNCTION`
   - `STAGE32_KMS_KEY_ARN`
   - `STAGE32_KMS_PUBLIC_KEY_SHA256`

The fingerprint and approved digest should be compared with the values kept in
the external administrative record before enabling the integration run.

## Why approval must stay outside GitHub

If GitHub Actions were allowed to update the SSM approved digest, an attacker
controlling GitHub could first authorize a malicious policy and then ask KMS to
sign it. Stage 32 intentionally does not grant that permission.

## Remaining boundary

AWS KMS provides external key custody and a separate approval policy, but the
blind detector and final verifier still execute on GitHub-hosted runners.
Full independence from a compromised GitHub verifier would require moving the
verification/decision point into a separately administered execution domain as
well.
