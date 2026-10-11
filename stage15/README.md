# Stage 15 — hierarchical sequential evidence detector

This stage redesigns the synthetic detector benchmark so that a static point
threshold is no longer advantaged by an unrealistically clean separation.

## Why this stage exists

Earlier synthetic stages use a robust passive score plus a point rule on the
difference between an NF-reported counter and an independent SCP/gateway
counter. That is useful as a baseline, but it does not solve the sequential
change-detection problem: low-and-slow attacks can remain below a fixed
threshold for many checks, while a single threshold cannot adapt to unknown
attack magnitudes.

The recent literature points to three requirements that are directly relevant
to this repository:

1. **5G Core anomaly detection must be evaluated under drift and adaptive
   attackers, not only IID test splits.** SAGE-5GC explicitly argues for
   security-aware evaluation under realistic, adversarial conditions.
2. **Sequential change detection should optimize detection delay subject to a
   false-alarm constraint.** E-detectors provide a nonparametric framework for
   this objective and construct Shiryaev-Roberts/CUSUM-style detectors from
   e-processes.
3. **Conformal/e-process methods are attractive when post-change laws are
   unknown, but naive conformal martingales can be inefficient.** Recent work
   develops faster constructions and highlights the importance of detection
   delay, not only validity.

Stage 15 therefore introduces a **hierarchical e-CUSUM** detector. The name
describes the construction; it is not a claim of scientific priority.

## Literature used for the design

- 3GPP TS 33.501, *Security architecture and procedures for 5G System*:
  https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3169
- C. Manca et al., *SAGE-5GC: Security-Aware Guidelines for Evaluating Anomaly
  Detection in the 5G Core Network*, arXiv:2602.03596:
  https://arxiv.org/abs/2602.03596
- J. Shin, A. Ramdas, A. Rinaldo, *E-detectors: a nonparametric framework for
  sequential change detection*, arXiv:2203.03532:
  https://arxiv.org/abs/2203.03532
- S. Bhattacharyya, A. Ramdas, *Change detection with conformal martingales:
  new optimal constructions, and suboptimality of existing methods*,
  arXiv:2609.27179:
  https://arxiv.org/abs/2609.27179
- *Nonparametric Shiryaev-Roberts change-point detection procedures based on
  modified empirical likelihood*, Journal of Applied Statistics 51(13), 2024:
  https://doi.org/10.1080/02664763.2024.2307532
- D. M. Manias et al., *A Model Drift Detection and Adaptation Framework for
  5G Core Networks*, arXiv:2209.06852:
  https://arxiv.org/abs/2209.06852

## Simulator changes

research/stage15_simulation.py preserves a matched 24-NF / 3-zone world and
the same fixed CU budget, but adds nuisance structure absent from the original
simple simulator:

- slow clean traffic concept drift;
- two superposed seasonal components;
- zone-shared noise;
- zone-wide maintenance shifts;
- NF-local benign bursts;
- counter noise that grows with traffic volume;
- sparse clean reconciliation outliers;
- four attack profiles: persistent step, counter-only, gradual ramp and
  intermittent low-and-slow corruption.

The attack labels are never passed into a detector. Every comparator sees the
same passive samples and the same deterministic schedule of four CU checks
every five seconds.

## Detector construction

For every checked NF, the new detector forms:

1. an **integrity discrepancy** between the independent transit counter and the
   NF-reported counter;
2. a **hierarchical corroborated score** that multiplies the discrepancy by a
   bounded combination of passive zone risk and processing anomaly.

The clean warm-up fixed schedule supplies empirical upper-tail ranks for both
scores. The ranks are mapped to a convex mixture of power-betting e-values for
three bet sizes, avoiding commitment to one attack magnitude. The resulting
evidence is accumulated independently for each NF by a CUSUM-style recurrence:

    C_t = max(1, C_{t-1}) * e_t

An alarm requires the statistic to cross its threshold **and** two consecutive
integrity-tail observations. Passive risk can therefore strengthen an
integrity anomaly but cannot create an alarm by itself.

Because Stage-15 traffic is temporally dependent and nonstationary, this
implementation does **not** claim exact anytime-valid false-alarm guarantees.
The e-value machinery is used as a principled sequential evidence design and
is validated empirically on held-out seeds.

## Strong baseline and held-out protocol

The comparison includes both:

- legacy_static: the original threshold family;
- tuned_static: the same static family with thresholds selected on tuning
  seeds 1001..1020;
- hierarchical_e_cusum: the new sequential detector, with its parameters
  frozen before evaluation.

The held-out block is 2001..2080. The primary endpoints are event recall,
mean censored detection delay, and false alarms per 1000 clean CU checks.
Checked-sample F1 is retained only for continuity: a change detector emits
sparse event alarms and is not intended to label every sample inside an attack.

## Reproduce

~~~bash
python -m unittest discover -s stage15_tests -v
python -m research.stage15_experiment \
  --start-seed 2001 --seeds 80 --output stage15_results
~~~

The experiment writes runs.csv, runs.json, summary.json, and REPORT.md.
The Stage-15 GitHub Actions workflow publishes the same outputs as an artifact.

## Scope and limitations

This is still a synthetic model. A positive held-out result can demonstrate
that the new detector is better than the static baseline **inside the declared
simulator**, not that it is superior on operator traffic or that it is novel
relative to every published IDS. The next validation step should use real
Open5GS/SCP transaction traces from the live branches, blind fault injection,
cross-run calibration, and attacks that can manipulate some detector-visible
features.
