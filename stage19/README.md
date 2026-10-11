# Stage 19 — Stability-gated sparse directional evidence

Stage 18 showed that the frozen Stage-17 directional e-process transferred to
real Open5GS/SCP traffic for persistent signed response tampering, but both it
and Page-Hinkley missed both sparse live fault families.

Stage 19 targets that limitation without tuning on Stage-18 live artifacts.

## Development history

Several sparse-memory variants were evaluated only on synthetic development
blocks.

### Rejected variants

1. **Multiscale log-e memory** increased sparse recall but exceeded the
   predeclared false-alarm ceiling.
2. **Bounded leaky tail cluster** reduced the effect of single extreme outliers
   but still exceeded the ceiling.
3. **Finite-window directional quorum** also produced too many clean alarms in
   the continuous-noise regime.
4. A first **stability-gated quorum** passed tuning but failed a separate
   live-like validation block at 0.694 false alarms / 1000 clean ticks.

That validation block was then considered inspected and was not reused for
parameter selection.

## Final detector

The selected design keeps the Stage-17 fast directional e-process unchanged and
adds a sparse quorum only when warm-up accounting is structurally stable.

The sparse path is enabled only if at least 90% of warm-up signed discrepancies
are effectively zero. If the calibration is noisy, the sparse path is disabled
and the detector reduces to the frozen Stage-17 behavior.

When enabled, the sparse path requires two same-direction mismatches of at least
2% within a finite 16-tick window. The current tick must itself carry a signed
mismatch; stale quorum state cannot alarm on its own.

Frozen configuration:

- warm-up stability fraction >= 0.90
- zero epsilon = 1e-12
- quorum window = 16 ticks
- required same-direction hits = 2
- mismatch magnitude >= 0.020
- Stage-17 fast path unchanged

## Conservative development gate

After the first stability-gated validation failure, fresh blocks were declared:

- tuning: **15001..15060**
- live-like validation: **16001..16120**
- continuous-noise stress: **17001..17080**

The tuning rule required **zero false alarms** across the entire tuning block
before recall or delay were considered.

Selected detector on tuning:

- event recall: 0.992
- minimum family recall: 0.983
- false alarms: 0 / 1000

Fresh live-like validation:

- event recall: 0.992
- sparse positive recall: 0.983
- sparse negative recall: 0.983
- false alarms: 0 / 1000

Fresh continuous-noise stress:

- sparse quorum enabled fraction: 0.000
- behavior matched the Stage-17 directional detector
- false alarms: 0 / 1000

Only after these results were obtained were the parameters frozen for live
Open5GS evaluation.

## Untouched live Open5GS block

Live seeds **8201..8206** were captured only after the Stage-19 configuration
was frozen.

The same blind architecture as Stage 18 was used:

1. genuine Open5GS v2.7.6 NRF/NSSF/AUSF/SCP containers capture live traffic;
2. telemetry and private labels are uploaded separately;
3. detector jobs download telemetry only;
4. labels are joined only in the final audit job.

GitHub Actions run: **38144359542**.

All static tests, six capture jobs, six blind detector jobs, and the final audit
completed successfully.

## Final live result

| Detector | Event recall | Horizon-penalized delay (ticks) | FA / 1000 clean ticks |
|---|---:|---:|---:|
| Page-Hinkley | 0.278 | 10.03 | 0.000 |
| Stage-17 directional e-process | 0.500 | 10.00 | 0.000 |
| **Stage-19 stability-gated quorum** | **0.750** | **4.50** | **0.000** |

Stage 19 minus Stage 17:

- event recall: **+0.250**
- 95% runner-cluster bootstrap CI: **[+0.250, +0.250]**
- horizon-penalized delay: **-5.50 ticks**
- 95% CI: **[-5.50, -5.50]**
- false-alarm difference: **0.000**

Per-family live recall:

| Fault family | Page-Hinkley | Stage 17 | Stage 19 |
|---|---:|---:|---:|
| profile_drop | 0.611 | 1.000 | 1.000 |
| profile_duplicate | 0.500 | 1.000 | 1.000 |
| padding_sparse | 0.000 | 0.000 | **1.000** |
| metadata_strip_sparse | 0.000 | 0.000 | 0.000 |

The sparse quorum was enabled on all six live runners from label-free warm-up
calibration.

## Interpretation

Stage 19 solves one of the two sparse live families without sacrificing
persistent detection or clean false-alarm performance. It also materially
reduces aggregate horizon-penalized delay.

The remaining failure is **metadata_strip_sparse**. Its signed byte discrepancy
is evidently not large or repeated enough to cross the frozen 2% quorum
criterion. Because seeds 8201..8206 are now evaluation data, this threshold must
not be retuned on them.

A scientifically clean next stage should change the observed feature rather than
retune the Stage-19 byte threshold. The natural candidate is structural
integrity evidence: canonical field-set / response-structure fingerprints that
can detect small semantic deletions even when byte-size change is below 2%.
