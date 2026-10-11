# Stage 21 — monitoring overhead and scalability benchmark

This experiment measures the cost of the frozen Stage-21 monitoring design on a
dedicated clean Open5GS block. No detector parameter, feature or threshold is
changed.

## Protocol

Dedicated evaluation-only block:

- **64 independent Open5GS runners**
- seeds **8801..8864**
- **80 baseline + 80 monitored cycles per runner**
- **5,120 baseline cycles**
- **5,120 monitored cycles**
- **15,360 measured genuine native SCP -> NRF requests**
- **20,000 runner-cluster bootstrap resamples**
- research fault gateway excluded
- native Open5GS binaries unmodified
- h2c laboratory transport; no production mTLS/OAuth/SEPP

Canonical workflow:

- run **38169182709**
- evaluation SHA **c0c8f00eec06fcf2abf149fed0bb4480b3d57b82**
- all **64 / 64** benchmark runners succeeded
- final audit succeeded
- result artifact **stage21-64-run-monitoring-overhead-report**
- artifact ID **11713461239**
- SHA-256:
  **df35a812acc7afc6a00c0983ac70ebeb1e8f9f33486b2fb5b635a3f13d51eb68**

Each baseline cycle contains one genuine native SCP -> NRF request.

Each monitored cycle contains two independent genuine native SCP -> NRF
requests, corresponding to the consumer-side observation and the nearby trusted
reference, followed by local structural and semantic feature extraction.

The research-only post-SCP fault gateway is deliberately excluded, because the
goal is to measure monitoring cost rather than fault-injection harness cost.

## Network and latency overhead

Runner-median estimates with 95% cluster-bootstrap confidence intervals:

| Quantity | Estimate |
|---|---:|
| Single native SCP -> NRF request latency | **1.570 ms [1.532, 1.596]** |
| Sequential paired monitoring-cycle latency | **4.027 ms [3.908, 4.066]** |
| Incremental paired-cycle latency | **+2.456 ms [2.387, 2.478]** |
| Monitored / baseline latency ratio | **2.554 [2.539, 2.565]** |
| HTTP/2 wire-byte ratio | **2.000 [2.000, 2.000]** |
| Native request-count amplification | **2.0x by design** |

The central operational result is therefore straightforward: the dominant cost
of the current paired-observation architecture is the second independent native
SCP -> NRF request.

The 2x figure applies to a **monitored transaction**, not to all 5G traffic.
Overall network overhead depends on the sampling fraction. Under the simple
equal-size approximation used by this lab path, monitoring a fraction q of
otherwise comparable transactions adds approximately q of baseline transaction
traffic. Consequently, a global traffic-overhead target below 1% would require
a sampling fraction of roughly below 1%, or an alternative design that batches,
reuses or otherwise amortizes the independent reference. This experiment does
not claim that the current every-sample paired design itself satisfies a
production-wide 1% traffic target.

## Local feature extraction cost

The current feature path constructs:

- canonical JSON byte accounting;
- value-independent structural token counters;
- stable scalar-path semantic SHA-256 equality tokens.

Measured cost:

| Quantity | Estimate |
|---|---:|
| Feature extraction for one paired observation | **0.8459 ms [0.8197, 0.8515]** |
| Feature microbenchmark per response | **0.3545 ms [0.3480, 0.3569]** |
| Feature extraction throughput | **2820.7 responses/s [2802.0, 2872.7]** |
| Single extraction peak traced memory | **23,865 bytes** |

The paired-observation feature work is therefore below 1 ms on the measured
GitHub-hosted Python runners. It is substantially smaller than the network cost
of performing the second native request.

## Frozen detector cost

The complete frozen Stage-21 detector includes the historical Page-Hinkley,
directional Stage-17, Stage-19 sparse memory, Stage-20 structural channel and
Stage-21 semantic channel.

Measured cost:

| Quantity | Estimate |
|---|---:|
| Detector update per telemetry tick | **0.24529 ms [0.24214, 0.24759]** |
| Detector throughput | **4076.8 tick updates/s [4038.9, 4129.8]** |
| Peak traced memory for an 80-tick detector batch | **425,112 bytes** |

No clean benchmark batch triggered a Stage-21 alarm.

Combining the measured feature and detector arithmetic gives approximately
1.1 ms of local Python processing per monitored paired observation in this
laboratory implementation. This is descriptive evidence that detector
computation is not the dominant cost. It must not be treated as a production
CPU-capacity guarantee because runner hardware, Python runtime, connection reuse
and concurrent load differ from an operator core.

## Local telemetry representation

Current research telemetry serializes full hexadecimal SHA-256 equality tokens.

| Quantity | Estimate |
|---|---:|
| Raw JSON body bytes for two responses | **2,358 bytes** |
| Serialized structural + semantic telemetry | **11,811 bytes** |
| Local telemetry / raw-body ratio | **5.01x** |

This 5.01x ratio is a **local research-telemetry storage representation**. These
bytes are not injected into the native 5G SBI transaction and therefore are not
5G network-wire overhead.

The result nevertheless identifies an optimization target for a deployable
collector: binary digest encoding, dictionary/path identifiers, digest
truncation with an explicit collision analysis, and aggregation could reduce
local storage and transport to the analytics layer. No such optimization is
applied retroactively to the evaluated detector.

## Relation to the dissertation overhead requirement

The dissertation specifies a method-level requirement of low signaling and
processing overhead. The present benchmark supports only part of that claim.

What is supported in the current laboratory implementation:

- incremental sequential monitored-cycle latency is **2.456 ms** in the measured
  h2c Open5GS environment;
- local feature extraction is about **0.846 ms per pair**;
- detector processing is about **0.245 ms per tick**;
- all are below 10 ms in this specific lab benchmark.

What is **not** established:

- production latency under mutual TLS, OAuth authorization and SEPP;
- production CPU utilization under concurrent core load;
- a global traffic overhead below 1% for arbitrary monitoring rates;
- performance with persistent multiplexed HTTP/2 connections;
- multi-vendor or operator-scale throughput.

The paired-reference architecture doubles request count and measured HTTP/2
wire bytes for each transaction selected for monitoring. Therefore the paper
and dissertation should not state an unconditional '<1% traffic overhead'
validation for Stage 21. The correct statement is that local computational
overhead is small in the lab, while network overhead is controlled primarily by
the monitoring sampling rate.

## Recommended paper-level conclusion

A defensible formulation is:

> In 64 independent clean Open5GS deployments, a native SCP -> NRF request had a
> median latency of 1.57 ms, while a sequential paired monitoring cycle required
> 4.03 ms, corresponding to an incremental 2.46 ms and a 2x request/wire-byte
> amplification for monitored samples. Local structural/semantic feature
> extraction required 0.846 ms per pair and the full frozen detector 0.245 ms
> per update. Thus computation was not the dominant laboratory cost; the main
> deployment cost is acquisition of the independent reference observation.
> These values characterize the h2c laboratory implementation and do not
> constitute a production mTLS/OAuth/SEPP capacity guarantee.

## Reuse restriction

Seeds **8801..8864** are evaluation-only after this benchmark and must not be
used for detector tuning or feature redesign.
