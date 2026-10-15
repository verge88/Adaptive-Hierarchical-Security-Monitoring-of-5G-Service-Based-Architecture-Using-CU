# Stage 35 — transition-race, external freshness and availability

Stage 34 closed two important gaps: GitHub no longer created detector telemetry,
and identity-bound relational comparison detected count-preserving attacks.

Stage 35 addresses the next operational gaps without retuning the relational
detector rule.

## 1. Attacks during legitimate convergence

The external collector performs three real NSSF lifecycle transitions:

- graceful stop of nssf2;
- start of nssf2;
- restart of nssf1.

Native NRF relational response mutations are injected while those transitions
are converging.

For each transition the verifier accepts either the clean stable old endpoint
state or the clean stable new endpoint state. A relational state that matches
neither endpoint is anomalous.

The attack set contains endpoint substitution, service-relation injection, and
identity replacement at 12 preregistered transition-window ticks per run.

## 2. Freshness outside the verifier process

Stage 34 kept nonce and sequence state in one verifier process.

Stage 35 adds a third external service: a freshness anchor. Both verifier A and
verifier B consult the same anchor.

The experiment submits each signed telemetry package to verifier A and then
replays the identical signed package to verifier B. Verifier B has never seen
the package locally, so rejection demonstrates that replay state does not reside
only in verifier A memory.

The free-tier anchor uses process memory. This survives verifier replacement but
is not crash-durable if the anchor itself restarts. No TPM monotonic counter is
claimed.

## 3. External client authentication

Collector-to-verifier and verifier-to-anchor calls use distinct bearer tokens
stored only in Render service environments.

Every experimental run also submits the package to verifier A without the
collector credential first. That negative-control request must return 401.

GitHub does not possess either external service-to-service token.

## 4. Direct external data path

The data path is:

    external Open5GS
        -> external signed collector
            -> authenticated verifier A
                -> external freshness anchor
                    -> signed verdict
                        -> GitHub audit

GitHub receives the signed package and signed verdict only after the external
decision has completed. Private attack labels are stored separately and joined
only by the final audit.

## 5. Long clean soak

After transition recovery the fault hook is disabled and 300 clean observations
are collected per run.

With 16 held-out runs this provides 4,800 post-transition clean soak samples in
addition to clean observations inside the transition windows.

## 6. Availability and latency

After the held-out block the external collector performs 100 sequential
full-path requests through:

    collector signature
      -> authenticated verifier
        -> freshness anchor
          -> verifier signature

The report includes success fraction, p50/p95/p99 latency, maximum latency, and
sequential full-path throughput.

This is not a saturation/concurrency benchmark; it measures normal sequential
full-path service performance.

## Held-out block

Preregistered seeds: **13001..13016**.

Each run contains:

- three real NSSF lifecycle transitions;
- 12 native-NRF relational mutation ticks inside transition windows;
- 300 clean post-transition soak ticks;
- unauthenticated-request negative control;
- authenticated verifier A decision;
- replay to verifier B.

## Remaining boundary

Collector, both verifier instances, and freshness anchor are software services
under one Render control plane. The anchor is not durable across its own
restart. Internal Open5GS SBI remains the h2c laboratory configuration rather
than a production mTLS/OAuth2 SBA deployment.
