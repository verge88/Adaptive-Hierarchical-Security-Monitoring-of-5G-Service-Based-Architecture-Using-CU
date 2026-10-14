# Stage 27 — software-attested third trust domain

Stage 26 showed that all frozen detector channels can detect a sustained false
NRF state when the NF-side witness remains outside the NRF trust domain.

Stage 27 moves to the next trust boundary: the NRF and the NF-side witness layer
are both compromised and deliberately present the same false state.

## Research question

Can detection be restored when both ordinary observation branches agree on the
same false state, provided that a third cryptographically separated trust domain
supplies an independently signed deployment-state contract?

## Coordinated compromise

The native Open5GS NRF is the audited Stage-26 v2.7.6 research build. During
each 12-sample attack episode it injects a persistent phantom NSSF profile into
NF Discovery inside `nrf_nnrf_handle_nf_discover()`.

Separately, the NF-side witness layer starts from real NSSF-local state and
injects the same phantom claim on the same frozen episode schedule. It does not
copy the NRF response.

Both false views are mapped to the same ordinal representation:

    nssf-1 REGISTERED
    nssf-2 REGISTERED
    nssf-3 REGISTERED

The capture job rejects a runner unless the compromised NRF projection and the
compromised witness projection are exactly equal at every tick. Thus the
ordinary pair contains no discrepancy evidence by construction.

## Third software-rooted trust domain

A separate GitHub Actions job acts as a software attestation authority. It does
not start Open5GS and does not read NRF Discovery or NF-side runtime witness
state.

The authority creates an ephemeral Ed25519 key pair and signs a canonical
deployment-state manifest declaring the expected two-NSSF state:

    nssf-1 NSSF REGISTERED
    nssf-2 NSSF REGISTERED

The manifest is also bound to SHA-256 digests of `live/nssf.yaml` and
`live/nssf2.yaml`.

Only these artifacts leave the authority job:

- `manifest.json`;
- `public_key.pem`;
- `signature.bin`;
- public provenance.

The private Ed25519 key is destroyed before artifact upload and is never
downloaded by capture or blind-detection jobs.

## Blind protocol

The capture matrix receives neither the attestation manifest nor the signing
key. It uploads only:

- label-free compromised NRF/witness telemetry;
- separate private attack labels and native-NRF audit logs.

The blind detector downloads only label-free telemetry and the public signed
attestation bundle. It verifies the Ed25519 signature before constructing the
third trusted representation.

Two frozen-detector evaluations are then run on the same observations:

1. **compromised pair** — compromised NF witness versus compromised NRF;
2. **attested third domain** — signed two-NSSF contract versus compromised NRF.

The Stage-21 detector stack is reused unchanged; no threshold, window,
calibration rule or recovery parameter is retuned.

Preregistered live seeds: **9401..9408**.

## Expected falsification pattern

If the trust model is correct:

- the compromised pair should have recall near zero because both sides expose
  the same false state;
- the signed third-domain comparison should recover discrepancy evidence;
- tampering with the signed manifest must fail signature verification;
- no observed false alarms should be introduced on clean gaps.

## Claim boundary

Stage 27 is **software-rooted attestation**, not hardware-rooted runtime
attestation.

A positive result supports this statement:

> A common-mode failure of NRF and the NF-side witness can be made observable
> again by introducing a third cryptographically separated software trust
> domain whose signed deployment-state contract is unavailable to the
> compromised observation branches.

It does not prove that the live NSSF processes are measured by TPM, vTPM, TEE,
SEV-SNP, TDX or another hardware root of trust. That remains the next stronger
trust level.

## Files

- `research/stage27_attestation_authority.py`
- `research/stage27_capture.py`
- `research/stage27_live_detect.py`
- `research/stage27_report.py`
- `stage27_tests/test_stage27.py`
- `.github/workflows/stage27-software-attestation.yml`
