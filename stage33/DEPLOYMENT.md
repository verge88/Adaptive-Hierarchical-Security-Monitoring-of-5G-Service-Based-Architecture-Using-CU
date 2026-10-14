# External verifier deployment checklist

The external verifier must be deployed from an administrative context separate
from GitHub Actions.

## 1. Generate the verifier verdict key

Example on the external administrator workstation:

    openssl genpkey -algorithm ED25519 -out stage33-verdict-private.pem
    openssl pkey -in stage33-verdict-private.pem -pubout -out stage33-verdict-public.pem
    base64 -w0 stage33-verdict-private.pem
    sha256sum stage33-verdict-public.pem

Store the private-key base64 only in the external hosting service secret store.

Record the public-key SHA-256 independently for the GitHub audit configuration.

## 2. Build and review policy

GitHub produces `stage33_policy/policy.json` and its SHA-256.

Review the policy and update the Stage-32 external AWS approved-digest parameter
from the external AWS administrative context.

GitHub must not have permission to perform this update.

## 3. Configure the external verifier

Set:

- `STAGE33_EXPECTED_KMS_KEY_ARN`
- `STAGE33_EXPECTED_KMS_PUBLIC_KEY_SHA256`
- `STAGE33_EXPECTED_POLICY_SHA256`
- `STAGE33_VERDICT_PRIVATE_KEY_PEM_B64`
- `STAGE33_API_TOKEN`

Deploy `stage33/Dockerfile` to the independent hosting platform.

## 4. Configure GitHub final-run environment

Set the Stage-33 final-run environment values:

- external verifier URL;
- verifier public-key SHA-256;
- Stage-32 AWS invoke-only variables.

Store the verifier API token as a GitHub secret.

GitHub never receives the external verifier private key.

## 5. Run final experiment

The final workflow is allowed to start the eight held-out Open5GS runners only
after both the Stage-32 KMS approval and external verifier configuration are
present.
