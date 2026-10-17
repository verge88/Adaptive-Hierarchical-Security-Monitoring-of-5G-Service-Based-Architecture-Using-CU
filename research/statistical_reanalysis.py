"""Post-hoc scenario-level analysis of frozen Stage38 evidence (stdlib only)."""
import argparse
import csv
import json
import math
from pathlib import Path


def exact_interval(k, n, alpha=0.05):
    """Two-sided Clopper-Pearson interval, conditional on iid Bernoulli trials."""
    if not 0 <= k <= n or n < 1:
        raise ValueError('invalid binomial counts')
    def tail(p, start):
        return sum(math.comb(n, j) * p**j * (1-p)**(n-j)
                   for j in range(start, n+1))
    def inverse(start, target):
        lo, hi = 0.0, 1.0
        for _ in range(80):
            mid = (lo+hi)/2
            if tail(mid, start) < target:
                lo = mid
            else:
                hi = mid
        return (lo+hi)/2
    return [inverse(k, alpha/2) if k else 0.0,
            inverse(k+1, 1-alpha/2) if k < n else 1.0]


def load(root, name):
    result = {}
    for path in root.rglob(name):
        doc = json.loads(path.read_text())
        seed = int(doc['seed'])
        if seed in result:
            raise ValueError(f'duplicate {name}: {seed}')
        result[seed] = doc
    return result


def scenario_row(lab, signed):
    verdict = signed['verdict']
    if int(verdict['seed']) != int(lab['seed']):
        raise ValueError('seed mismatch')
    if verdict['challenge_nonce'] != lab['challenge_nonce']:
        raise ValueError('nonce mismatch')
    alerts = {int(a['tick']): a for a in verdict['alerts']}
    if len(alerts) != len(verdict['alerts']):
        raise ValueError('duplicate alert tick')
    entries = lab['attack_entries']
    if not entries:
        raise ValueError('scenario without attacks')
    ticks = {int(e['tick']) for e in entries}
    detected = sum(bool(alerts[int(e['tick'])]['relational_alert_by_nf_type'][e['target_nf_type']]) for e in entries)
    clean = [a for t, a in alerts.items() if t not in ticks]
    if not clean:
        raise ValueError('scenario without clean observations')
    false = sum(bool(a['relational_alert']) for a in clean)
    return dict(seed=int(lab['seed']), topology=int(lab['topology_template_id']),
                attacks=len(entries), detected=detected, recall=detected/len(entries),
                all_attacks_detected=int(detected == len(entries)),
                clean_ticks=len(clean), false_alerts=false,
                clean_scenario=int(false == 0),
                joint_success=int(detected == len(entries) and false == 0))


def summarize(rows):
    n = len(rows)
    result = {'scenarios': n}
    for key in ('all_attacks_detected', 'clean_scenario', 'joint_success'):
        k = sum(r[key] for r in rows)
        result[key] = {'successes': k, 'fraction': k/n,
                       'conditional_iid_exact95': exact_interval(k, n)}
    mean = sum(r['recall'] for r in rows)/n
    # Bounded independent scenario recalls need not have identical distributions.
    radius = math.sqrt(math.log(40)/(2*n))
    result['macro_recall'] = mean
    result['independent_scenarios_hoeffding95'] = [max(0, mean-radius), min(1, mean+radius)]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    labels = load(args.input, 'private_labels.json')
    signed = load(args.input, 'signed_verdict.json')
    expected = set(range(18001, 18257))
    if set(labels) != expected or set(signed) != expected:
        raise ValueError('expected exactly 256 frozen seeds')
    if len({d['private_plan_sha256'] for d in labels.values()}) != 256:
        raise ValueError('nonunique plans')
    rows = [scenario_row(labels[s], signed[s]) for s in sorted(expected)]
    strata = {str(t): summarize([r for r in rows if r['topology'] == t]) for t in range(8)}
    if any(s['scenarios'] != 32 for s in strata.values()):
        raise ValueError('expected eight strata of 32 scenarios')
    # Each row is one completed scenario, never one attack or retry.
    report = {'analysis': 'post-hoc scenario-level correction; detector unchanged',
              'source_run': 38777767686,
              'source_commit': '017770d04756256e83cb22dde4b1dbe05f9cd7c9',
              'assumptions': [
                  'Attack-level counts are descriptive; no independent-attack CI is used for inference.',
                  'Pooled exact intervals are sensitivity results under iid scenario Bernoulli outcomes, not established guarantees.',
                  'Fixed topology allocation is reported separately; stratum intervals are pointwise, not simultaneous.',
                  'Hoeffding bounds allow different scenario distributions but require independent scenarios and a fixed detector.',
                  'Shared infrastructure, a common generator, retries and systematic blind spots can limit independence and generalization.',
                  'Analysis conditions on retained completed scenarios; operational failures are not detection successes.',
                  'No inference is made to arbitrary attacks, other generators or production networks.',
                  'Bootstrap of all-success scenarios would be degenerate and is not presented as uncertainty evidence.'],
              'overall': summarize(rows), 'by_topology': strata,
              'descriptive_totals': {k: sum(r[k] for r in rows) for k in ('attacks','detected','clean_ticks','false_alerts')}}
    original = json.loads((args.input / 'original_report' / 'summary.json').read_text())
    totals = report['descriptive_totals']
    if (totals['attacks'], totals['detected'], totals['clean_ticks'], totals['false_alerts']) != (
            original['attacks']['total'], original['attacks']['relational_detected'],
            original['all_clean']['ticks'], original['all_clean']['false_alerts']):
        raise ValueError('recomputed totals differ from original frozen report')
    report['operational_attempts'] = json.loads((args.input/'meta'/'attempt_summary.json').read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    with (args.output/'scenarios.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    s = report['overall']
    k = s['all_attacks_detected']['successes']
    lo, hi = s['all_attacks_detected']['conditional_iid_exact95']
    hlo, hhi = s['independent_scenarios_hoeffding95']
    text = f'''# Статистическая переоценка финального блока Stage38

Единица анализа — завершённый сценарий, а не отдельное воздействие.
Это дополнительный постфактум-анализ замороженных данных; новые атаки не запускались.

Полное обнаружение всех воздействий: {k}/256 сценариев.
Сценарии без тревог на полностью чистых отсчётах: {s['clean_scenario']['successes']}/256.
Совместное выполнение этих условий: {s['joint_success']['successes']}/256.
Средняя по сценариям полнота: {s['macro_recall']:.6f}.
Описательные итоги: {totals['detected']}/{totals['attacks']} воздействий;
{totals['false_alerts']} тревог на {totals['clean_ticks']} полностью чистых отсчётах.

При дополнительном предположении независимых одинаково распределённых сценарных
исходов двусторонний точный 95%-й интервал Клоппера—Пирсона для вероятности
обнаружить все воздействия сценария составляет [{lo:.6f}; {hi:.6f}].
Это другая оцениваемая величина, чем полнота по воздействиям.
Предположение iid не установлено экспериментом; объединённый интервал дан как
условный анализ чувствительности. Топологии распределены фиксированно: по 32 серии.

При независимых, но не обязательно одинаково распределённых сценариях
консервативная двусторонняя 95%-я граница Хёффдинга для средней ожидаемой
сценарной полноты данного дизайна: [{hlo:.6f}; {hhi:.6f}]. Она также не действует
при произвольной зависимости между сценариями.

| Топология | Сценарии с полным обнаружением | Условный точный 95% интервал |
|---|---:|---|
'''
    for topology, item in strata.items():
        metric = item['all_attacks_detected']
        a, b = metric['conditional_iid_exact95']
        text += f"| {topology} | {metric['successes']}/{item['scenarios']} | [{a:.6f}; {b:.6f}] |\n"
    text += '''
Интервалы по топологиям являются отдельными, без одновременного покрытия всех восьми.
Интервал Уилсона по 4067 воздействиям не используется для вывода о независимых
испытаниях. Общая инфраструктура и генератор могут создавать зависимость и общие
слепые области. Повторные операционные попытки не увеличивают размер выборки;
оценка условна на сохранённых завершённых сценариях. Нулевое число ошибок не
доказывает нулевую вероятность ошибки. Результат относится к данному генератору,
диапазону сценариев и стенду, а не к произвольным атакам.

Архив исходного отчёта не изменён. Итоги пересчитаны из меток и подписанных решений
и сверены с исходным summary.json. SHA-256 исходных ZIP проверены конвейером;
это не новая независимая криптографическая аттестация экспериментального стенда.
'''
    (args.output/'REPORT_RU.md').write_text(text, encoding='utf8')
    print(text)


if __name__ == '__main__':
    main()
