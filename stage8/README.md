# Stage 8 — Dynamic native NRF discovery with semantic controls

**Scope:** Real HTTP/2 discovery responses are fetched from an unmodified
Open5GS NRF on EVERY request. A laboratory consumer-side gateway harmlessly
permutes order of native NF profiles across requests and can inject one
NF profile corruption into its **forwarded copy**. Native Open5GS NRF/AUSF/
NSSF binaries and actual instance registrations stay intact. This is NOT
a compromised native NF or an attack on a production SBI connection.

## Scientific question

Under variable but semantically equivalent serialization of real 5G NRF
discovery JSON, does independently signed active KIE discover profile
corruption more effectively than fair PASSIVE semantic analysis?

Controls:
- Direct native NRF nfInstanceId set monitoring, no CU;
- naive passive byte fingerprint (may false-alarm on benign profile order);
- strong order-invariant full semantic baseline, no CU;
- fixed/local/zone active KIE, same 2 checks/tick and payload budget;
- KIE HMAC covers a separate research attestor's independently fetched NRF
  response, NOT a signature from actual native Open5GS NFs.

Attacks to forwarded lab gateway copy:
- substitution of a target real nfInstanceId (same length);
- modification of nfStatus on a selected real profile.
Neither modifies real native NRF; online NRF state should remain stable.

Each of four CI runners executes 4 randomized attack episodes using real
wall clock and actual native NRF HTTP/2 data. Schedulers start before
tampering begins, attacks start at a randomized offset. A full trace
and original seed-level data are saved.

**Primary analysis:** semantic passive full-content baseline versus zonal
KIE; report recall, false alerts during harmless native profile permutations,
detection latency and CU overhead. Detection is not expected to be unique
to KIE. An order-invariant baseline is a meaningful stronger competitor
than bytewise comparison. Each active method uses 52 CUs/episode.

## Limitations

Legitimate *dynamicity in this experiment* is primarily the order of real
NF profiles in the LAB GATEWAY, not demonstrated time-varying native NF
application semantics. It does not reproduce real subscriber/5G auth
processing or compromised native SBI handlers. Order changes must not be
confused with a new 3GPP protocol behavior.

The external HMAC attestor knows the true directly fetched NRF profile,
which creates an independent trust path. If the attestor or true NRF source
is compromised, HMAC cannot prove native NF integrity. No new NWDAF model,
production security guarantees, or bibliographic priority are asserted.

Reproduce in GitHub Actions using stage8-dynamic-nrf.yml. Deploy native
Open5GS with live/compose.yaml + live/stage5-compose.yaml, run
python -m research.stage8_dynamic_nrf --seed 2401 --output stage8_shard,
and view the report and raw observation traces.
