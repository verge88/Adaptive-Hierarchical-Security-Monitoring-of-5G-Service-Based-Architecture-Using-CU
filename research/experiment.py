"""Predeclared paired comparison, confidence intervals, CSV and Markdown report."""
import argparse
import csv
import json
from pathlib import Path
import random
import statistics
from .simulation import World, run_policy, DURATION, WARMUP, STEP_SECONDS, N_NF, CU_BYTES

POLICIES = ("passive", "fixed", "local_adaptive", "zone_adaptive")


def paired_ci(diffs, seed=76543, n_boot=3000):
    rng = random.Random(seed)
    n = len(diffs)
    means = sorted(statistics.mean(diffs[rng.randrange(n)] for _ in range(n))
                   for _ in range(n_boot))
    return [means[int(.025*(n_boot-1))], means[int(.975*(n_boot-1))]]


def run(seeds):
    results = []
    for seed in seeds:
        world = World(seed)
        for policy in POLICIES:
            results.append(run_policy(world, policy))
    return results


def summarize(results):
    out = {}
    for p in POLICIES:
        rows = [r for r in results if r['policy'] == p]
        out[p] = {k: statistics.mean(r[k] for r in rows) for k in (
            'event_recall', 'mean_censored_delay_s', 'f1',
            'false_alarms_per_1000_checks', 'cu_bytes_per_s', 'probes')}
    fixed = {r['seed']: r for r in results if r['policy'] == 'fixed'}
    adaptive = {r['seed']: r for r in results if r['policy'] == 'zone_adaptive'}
    common = sorted(set(fixed) & set(adaptive))
    diffs = [fixed[s]['mean_censored_delay_s'] - adaptive[s]['mean_censored_delay_s'] for s in common]
    recalls = [adaptive[s]['event_recall'] - fixed[s]['event_recall'] for s in common]
    out['paired_effect'] = dict(n_seeds=len(common),
                               delay_reduction_s=statistics.mean(diffs),
                               delay_reduction_ci95_s=paired_ci(diffs),
                               recall_increase=statistics.mean(recalls),
                               recall_increase_ci95=paired_ci(recalls, seed=12345))
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--seeds', type=int, default=12)
    parser.add_argument('--output', default='results')
    args = parser.parse_args()
    if args.seeds < 2:
        parser.error('At least two paired seeds required')
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=True)
    results = run(range(101, 101+args.seeds))
    summary = summarize(results)
    records = [{k:v for k,v in r.items() if k != 'delays'} for r in results]
    with (root/'runs.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=records[0].keys())
        writer.writeheader(); writer.writerows(records)
    (root/'runs.json').write_text(json.dumps(results, indent=2), encoding='utf8')
    (root/'summary.json').write_text(json.dumps(summary, indent=2), encoding='utf8')
    e = summary['paired_effect']
    lines = ['# 5G SBA CU simulation: reproducible paired experiment', '',
             '**Scope:** abstract 5G SBA and SCP counters are synthetic; NOT Open5GS or operator measurements. '
             'Scientific priority is not established by this experiment.', '',
             f'Seeds: {args.seeds}; NFs: {N_NF}; timestep: {STEP_SECONDS}s; '
             f'duration: {DURATION}s (warmup {WARMUP}s); assumed CU traffic: {CU_BYTES} bytes/probe.', '',
             '| Policy | Event recall | Mean censored detection delay (s) | F1 / checked sample | False alarms / 1000 clean checks | CU bytes/s |',
             '|---|---:|---:|---:|---:|---:|']
    for p in POLICIES:
        x = summary[p]
        lines.append(f"| {p} | {x['event_recall']:.3f} | {x['mean_censored_delay_s']:.1f} | {x['f1']:.3f} | {x['false_alarms_per_1000_checks']:.2f} | {x['cu_bytes_per_s']:.2f} |")
    lines.extend(['', f"Paired delay benefit (fixed minus zone adaptive): **{e['delay_reduction_s']:.2f} s**, "
                   f"95% seed-bootstrap CI [{e['delay_reduction_ci95_s'][0]:.2f}, {e['delay_reduction_ci95_s'][1]:.2f}].",
                  f"Paired event-recall benefit: **{e['recall_increase']:.3f}**, "
                   f"95% CI [{e['recall_increase_ci95'][0]:.3f}, {e['recall_increase_ci95'][1]:.3f}].",
                  '', 'A confidence interval crossing zero does not support superiority in this simulation.',
                  'No-detection events receive the remaining observation time as censored delay.',
                  'The passive baseline has more observation points, hence F1/check is not directly comparable. '
                  'All three CU policies have exactly the same number of probes and nominal traffic budget.', '',
                  '## Threat model and limitations',
                  'A compromised NF owns the valid CU MAC key but falsifies its report; an independent trusted SCP '
                  'observer supplies counts when the CU is checked. The attacker is not assumed to control SCP. '
                  'HMAC-SHA256 is used, with LAB-ONLY deterministic nonces. The 5G names are abstractions; no '
                  'HTTP/2 network stack, 3GPP-compliant NRF heartbeat/authorization, dynamic autoscaling, or '
                  'real traffic was evaluated. The anomaly scoring and hyperparameters are exploratory and not '
                  'externally validated. Next stage: actual Open5GS/SCP integration, calibration and blinded tests.', ''])
    (root/'REPORT.md').write_text('\n'.join(lines), encoding='utf8')
    print('\n'.join(lines[:13]))

if __name__ == '__main__':
    main()