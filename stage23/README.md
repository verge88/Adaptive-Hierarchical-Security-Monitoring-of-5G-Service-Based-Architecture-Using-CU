# Stage 23 — native Open5GS SCP in-process integrity validation

Stage 22 validated the trust-boundary principle with an external research facade
placed after a genuine native SCP -> NRF exchange.  That result did not establish
that the same monitor works when the false representation is produced inside the
native Open5GS SCP process itself.

Stage 23 closes that methodological gap with a deliberately instrumented,
disposable Open5GS v2.7.6 build.

## Research question

Can the frozen Stage-21 multichannel detector identify false service data when
the consumer-visible response is changed inside open5gs-scpd, provided that the
reference observation bypasses the SCP process?

The experiment does not exploit a CVE.  Instead, the exact Open5GS v2.7.6
src/scp/sbi-path.c source is pinned in the repository and contains a
research-only instrumentation function.  The function runs in
response_handler(), immediately before the stock
ogs_sbi_server_send_response() call.

The consumer connects directly to the native SCP HTTP/2 endpoint.  There is no
Python proxy or post-SCP response facade on that path.

## Frozen in-process schedule

Each runner has:

- 30 clean warm-up samples;
- six 12-sample monitoring episodes;
- four clean samples after each episode;
- nfStatus mutation at local episode samples 0, 4 and 8.

Thus each runner contains 18 mutations generated inside open5gs-scpd.  The
native SCP writes an audit marker to its own Open5GS log for every actual
mutation.  Those markers are stored with private labels and are unavailable to
the blind detector.

The detector remains the frozen Stage-21 detector.  No Stage-23 threshold or
feature parameter is tuned.

## Observation topology

    direct native NRF ------------------------> trusted reference
             ^
             |
    consumer -> instrumented open5gs-scpd -> native NRF
                       |
                       +-- response_handler()
                           changes consumer-visible nfStatus
                           before stock server send

The direct NRF observation is outside the SCP process and therefore outside the
component being tested.

A common-path negative control is generated from the same label-free telemetry
by assigning both observations the consumer-visible SCP representation.  It
tests the expected common-mode limitation of pairwise consistency.

## Provenance

For every runner Stage 23 records:

- Open5GS source ref v2.7.6;
- SHA-256 of the instrumented src/scp/sbi-path.c;
- SHA-256 of the executed open5gs-scpd binary;
- confirmation that the binary contains the Stage-23 instrumentation marker;
- the count and exact private tick positions emitted by the native SCP log.

The audit rejects a run if the native SCP log does not match the preregistered
schedule.

## Claim boundary

A positive Stage-23 result supports the statement that the monitor detects a
false service representation produced inside the native Open5GS SCP process
when the reference observation is outside the SCP trust domain.

It does not support the statement that an unknown vulnerability or a production
Open5GS CVE was exploited.  The process is intentionally built with a
research-only modification; the security property under test is detection after
component compromise, not initial compromise acquisition.

## Files

- live/stage23-sbi-path.c
- live/stage23-scp.Dockerfile
- live/stage23-scp-compose.yaml
- research/stage23_capture.py
- research/stage23_live_detect.py
- research/stage23_report.py
- stage23_tests/test_stage23.py
- .github/workflows/stage23-native-scp.yml

Preregistered live seeds are 9001..9008.
