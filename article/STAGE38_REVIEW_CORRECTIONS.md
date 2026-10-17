# Stage38 review corrections

This is a post-hoc reanalysis of the frozen Open5GS corpus, not a new live experiment.

- Frozen experiment: [run 38777767686](https://github.com/verge88/Adaptive-Hierarchical-Security-Monitoring-of-5G-Service-Based-Architecture-Using-CU/actions/runs/38777767686), commit 017770d04756256e83cb22dde4b1dbe05f9cd7c9.
- Scenario statistics: [run 39043012507](https://github.com/verge88/Adaptive-Hierarchical-Security-Monitoring-of-5G-Service-Based-Architecture-Using-CU/actions/runs/39043012507).
- Full review: [run 39046010598](https://github.com/verge88/Adaptive-Hierarchical-Security-Monitoring-of-5G-Service-Based-Architecture-Using-CU/actions/runs/39046010598), commit 9a957ad3017a493d156113beb72fcacb89f7e725.
- [Full report artifact](https://github.com/verge88/Adaptive-Hierarchical-Security-Monitoring-of-5G-Service-Based-Architecture-Using-CU/actions/runs/39046010598/artifacts/12105991560), SHA-256 f2a7edbedee1696b11ab780a63fc18d50d1d05cd655fb847799fffb3e7b081b0.

## Findings

All confusion matrices use NF type × observation tick, including unattacked types during attacked ticks. The corpus has 4,067 positive and 59,369 negative pairs.

| Method | TP | FN | FP | TN |
|---|---:|---:|---:|---:|
| Frozen relational with witness | 4067 | 0 | 0 | 59369 |
| Relational without witness | 4067 | 0 | 0 | 59369 |
| Full initial snapshot | 4067 | 0 | 26085 | 33284 |
| Full profile without transition allowance | 4067 | 0 | 5177 | 54192 |
| Full pre-or-post snapshot | 4067 | 0 | 276 | 59093 |
| Count/status | 33 | 4034 | 276 | 59093 |

All attacks were detected in 256/256 scenarios by all full-profile methods. Zero type-level false positives throughout a scenario occurred in 256 scenarios for the relational methods, 28 for full pre-or-post and count/status, and zero for the initial-snapshot and no-transition-allowance variants.

The benefit measured here is fewer false positives under authorized lifecycle changes. Disabling the witness does not alter content decisions on accepted packages; recall on this corpus does not establish its incremental security benefit.

## Temporal and trust scope

The collector finishes the scenario and captures post-transition references before it submits a package. This is batch retrospective verification. Verifier request latency is not attack-to-alert latency. All transition-aware baselines receive the same references.

The witness binds UUID/type and configured endpoint to process existence and TCP reachability. It does not independently certify FQDN, service contents, executable integrity or socket ownership. Eight synthetic reference-poisoning cases (FQDN and services for four NF types) pass the actual witness binding predicate with unchanged valid witness signatures. These are logical counterexamples, not attacks on the complete collector signature pipeline. A separately supplied full-profile policy rejects them in a fixture, but the fixture is not an independently deployed policy source.

## Statistical interpretation

4,067/4,067 is descriptive. All attacks were detected in 256/256 scenarios. A two-sided exact interval [0.985694, 1] applies to whole-scenario success only under an additional iid Bernoulli assumption. Fixed topology allocation and shared infrastructure do not establish that assumption. Each topology has 32/32 successes, with pointwise conditional interval [0.891119, 1]. The conservative Hoeffding interval [0.915119, 1] for mean scenario recall permits nonidentical distributions but still requires independent scenarios. No bound is claimed for arbitrary cross-scenario dependence or arbitrary attacks. Analysis is conditional on retained completed attempts.

## Reconciled clean observations

1,044 steady-pre + 3,116 transition + 1,023 steady-post + 7,680 final clean ticks = 12,863 fully clean ticks. Each final clean segment has 30 ticks. Discovery-call timings plus configured sleeps give a lower duration estimate with mean 1.865 s and range 1.535–2.376 s; loop overhead is omitted. This is not a wall-clock duration or long soak test.

## Reproduction and validation

The dedicated workflow downloads pinned original archives with Actions read access, checks their SHA-256, revalidates verifier and witness signatures and the verdict/package hash binding, then runs scenario statistics and comparison replay. The original collector signature is not retained as a separate file, so it cannot be reverified from this archive; original verification is recorded in evidence.json.

Three statistical tests and eight formal/baseline boundary tests passed in Actions. Signed per-type decisions and count/status decisions are reproduced for every saved observation. Original frozen code and artifacts remain unchanged.

```sh
python -m unittest discover -s research -p test_statistical_reanalysis.py -v
python -m unittest discover -s research -p test_review_reanalysis.py -v
python research/download_stage38_statistics.py
python research/statistical_reanalysis.py --input stage38_input --output stage38_review
python research/review_reanalysis.py --input stage38_input --output stage38_review
```

The downloader requires GH_TOKEN with read access to the repository's Actions artifacts. It does not contact the live Render deployment. Source artifacts currently have a retention deadline; archive them for long-term reproduction before expiry.
