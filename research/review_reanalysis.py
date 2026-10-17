"""Reproducible post-hoc baselines, type-tick metrics and trust counterexamples."""
import argparse
import ast
import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from statistical_reanalysis import load

NF_TYPES = ('NSSF','AUSF','BSF','UDM')


def frozen_functions():
    """Load actual frozen pure functions without service startup or network calls."""
    src = Path('stage38/multi_nf_verifier_service.py').read_text()
    tree = ast.parse(src)
    names = {'canonical_bytes','projection_equal','state_counts','slot_profile',
             'slots_of_type','profile_count_across_refs','type_transition_alert',
             'reference_witness_consistent'}
    nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names
             or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='SLOTS' for t in n.targets)]
    ns = {'json':json,'NF_TYPES':NF_TYPES,'STAGE':38}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<frozen pure functions>','exec'),ns)
    return ns


def predictions(package, ns):
    refs = package['reference_states']
    events = {e['phase']:e for e in package['lifecycle_plan']['events']}
    result = []
    for row in package['observations']:
        event = events.get(row['phase'])
        pre = refs[event['pre_reference']] if event else refs['initial' if row['phase']=='steady_pre' else 'ref_2']
        post = refs[event['post_reference']] if event else pre
        record = {'tick':int(row['tick']), 'phase':row['phase'], 'methods':defaultdict(dict)}
        for typ in NF_TYPES:
            observed = row['projections'][typ]
            rel = ns['type_transition_alert'](typ,observed,pre[typ],post[typ],event['slot']) if event else not ns['projection_equal'](observed,pre[typ])
            record['methods']['relational_without_witness'][typ] = rel
            record['methods']['full_initial_snapshot'][typ] = not ns['projection_equal'](observed,refs['initial'][typ])
            record['methods']['no_transition_allowance'][typ] = not ns['projection_equal'](observed,pre[typ])
            moving_type = ns['SLOTS'][event['slot']]['type'] if event else None
            allowed = [pre[typ],post[typ]] if typ == moving_type else [pre[typ]]
            record['methods']['full_pre_or_post'][typ] = all(not ns['projection_equal'](observed,r) for r in allowed)
            record['methods']['count_status'][typ] = ns['state_counts'](observed) not in [ns['state_counts'](r) for r in allowed]
        result.append(record)
    return result


def matrix():
    return {'TP':0,'FN':0,'FP':0,'TN':0}


def add(matrix, truth, prediction):
    matrix['TP' if truth and prediction else 'FN' if truth else 'FP' if prediction else 'TN'] += 1


def semantic_policy_matches(ref, expected):
    """Optional independently supplied full-profile policy, not learned from NRF."""
    return ref == expected


def poison_checks(package, ns):
    """Logical counterexamples, not new live attacks or forged signatures."""
    original = package['reference_states']['initial']
    bundle = package['witness_snapshots']['initial']
    cases = {}
    for typ in NF_TYPES:
        uuid = next(iter(original[typ]['profiles']))
        for field in ('fqdn','nfServices'):
            changed = copy.deepcopy(original)
            attrs = changed[typ]['profiles'][uuid]
            if field == 'fqdn':
                attrs[field] = 'poisoned.invalid'
            else:
                attrs[field] = attrs.get(field,[]) + [{'serviceName':'unauthorized-test-service'}]
            # The signed witness is unchanged: Stage38 does not bind either field.
            ns['reference_witness_consistent'](changed,bundle,'initial',package['challenge_nonce'])
            cases[typ+'/'+field] = {
                'frozen_witness_accepts_changed_reference':True,
                'self_comparison_alert':changed != changed,
                'independent_full_policy_rejects':not semantic_policy_matches(changed,original),
                'policy_fixture_origin':'original clean snapshot for demonstration only; not independent deployed policy'}
    return cases


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    packages = load(args.input,'telemetry_package.json')
    labels = load(args.input,'private_labels.json')
    signed = load(args.input,'signed_verdict.json')
    expected = set(range(18001,18257))
    if any(set(g)!=expected for g in (packages,labels,signed)):
        raise ValueError('incomplete frozen corpus')
    ns = frozen_functions()
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    import base64
    def verify_signature(key,doc,sig):
        key.verify(base64.b64decode(sig,validate=True),ns['canonical_bytes'](doc),ec.ECDSA(hashes.SHA256()))
    ns['verify_signature'] = verify_signature
    stats = defaultdict(matrix)
    per_nf = defaultdict(lambda:defaultdict(matrix))
    clean_phases = Counter()
    soak_lower_ms = []
    scenario_counts = defaultdict(Counter)
    counterexamples = None
    for seed in sorted(expected):
        package, lab, verdict = packages[seed],labels[seed],signed[seed]['verdict']
        path = next(args.input.rglob(f'{seed}/verifier_public_key.pem'))
        key_bytes = path.read_bytes()
        if hashlib.sha256(key_bytes).hexdigest() != '061fe394c428600d7807d53d54abcae847032f0cffc0dd2b5a2de202ff317479':
            raise ValueError('unexpected verifier key')
        verify_signature(serialization.load_pem_public_key(key_bytes),verdict,signed[seed]['signature_base64'])
        if hashlib.sha256(ns['canonical_bytes'](package)).hexdigest()!=verdict['collector_package_sha256']:
            raise ValueError('signed verdict/package binding mismatch')
        if lab['challenge_nonce']!=package['challenge_nonce'] or verdict['challenge_nonce']!=package['challenge_nonce']:
            raise ValueError('nonce mismatch')
        witnessed_key = path.with_name('witness_public_key.pem').read_bytes()
        ns.update(POLICY_SHA256=package['policy_sha256'],WITNESS_PUBLIC_KEY_SHA256=hashlib.sha256(witnessed_key).hexdigest(),
                  WITNESS_PUBLIC_KEY=serialization.load_pem_public_key(witnessed_key))
        if ns['WITNESS_PUBLIC_KEY_SHA256']!='b7f1a1a372e4f81c91feeb028b6e96691d0d6be3970666149f727b151574881f':
            raise ValueError('unexpected witness key')
        for name, ref in package['reference_states'].items():
            ns['reference_witness_consistent'](ref,package['witness_snapshots'][name],name,package['challenge_nonce'])
        if counterexamples is None:
            counterexamples = poison_checks(package,ns)
        truth = {(int(e['tick']),e['target_nf_type']) for e in lab['attack_entries']}
        if len(truth)!=len(lab['attack_entries']):
            raise ValueError('multiple entries per type-tick need a different metric')
        original = {int(a['tick']):a for a in verdict['alerts']}
        hits = defaultdict(list)
        false = Counter()
        for row in predictions(package,ns):
            tick = row['tick']
            row['methods']['frozen_signed_method'] = original[tick]['relational_alert_by_nf_type']
            if row['methods']['relational_without_witness']!=row['methods']['frozen_signed_method']:
                raise ValueError('frozen decision mismatch')
            if row['methods']['count_status']!=original[tick]['legacy_alert_by_nf_type']:
                raise ValueError('baseline reproduction mismatch')
            if not any((tick,t) in truth for t in NF_TYPES):
                clean_phases[row['phase']]+=1
            for method, decisions in row['methods'].items():
                for typ in NF_TYPES:
                    attacked = (tick,typ) in truth
                    prediction = bool(decisions[typ])
                    add(stats[method],attacked,prediction)
                    add(per_nf[method][typ],attacked,prediction)
                    if attacked:
                        hits[method].append(prediction)
                    elif prediction:
                        false[method]+=1
        for method, detected in hits.items():
            scenario_counts[method]['all_attacks_detected']+=int(all(detected))
            scenario_counts[method]['no_type_tick_false_alerts']+=int(false[method]==0)
        soak = [r for r in package['observations'] if r['phase']=='clean_soak']
        if len(soak)!=30:
            raise ValueError('unexpected clean segment')
        soak_lower_ms.append(sum(r['collector_discovery_latency_ms'] for r in soak)+30*3)
    for values in stats.values():
        values['recall']=values['TP']/(values['TP']+values['FN'])
        values['false_positive_rate']=values['FP']/(values['FP']+values['TN'])
    report = {'analysis_kind':'post-hoc replay; no new live experiments',
              'unit':'NF type x observation tick; all un-attacked types included',
              'source_run':38777767686,'scenarios':256,'methods':dict(stats),
              'per_nf_type':{k:dict(v) for k,v in per_nf.items()},
              'scenario_outcomes':{k:dict(v) for k,v in scenario_counts.items()},
              'fully_clean_ticks_by_phase':dict(clean_phases),
              'soak_duration_lower_bound_seconds':{'min':min(soak_lower_ms)/1000,'mean':sum(soak_lower_ms)/256000,'max':max(soak_lower_ms)/1000,
                  'meaning':'sum of measured discovery calls plus configured sleeps; excludes loop overhead, not a wall-clock measurement'},
              'reference_poisoning_counterexamples':counterexamples,
              'limitations':['All transition-aware offline comparators have the same pre/post references, including future reference availability.',
                  'Removing the witness does not change content decisions on this already accepted corpus; benefit under compromised references is not established by recall.',
                  'Synthetic poisoning checks exercise the real witness-binding predicate with unchanged valid witness signatures, not the entire signed collection pipeline.',
                  'Independent semantic policy is a demonstrated optional guard, not a deployed independent source.',
                  'No attack-to-alert time or long-duration soak claim can be inferred.']}
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'review_summary.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    lines = ['# Дополнительная проверка замечаний','',
             'Повторный анализ сохранённых данных. Единица матрицы ошибок: тип NF × отсчёт.', '',
             '| Метод | TP | FN | FP | TN | Полнота | FPR |','|---|---:|---:|---:|---:|---:|---:|']
    for name,m in stats.items():
        lines.append(f"| {name} | {m['TP']} | {m['FN']} | {m['FP']} | {m['TN']} | {m['recall']:.6f} | {m['false_positive_rate']:.6f} |")
    lines += ['', 'Полные результаты, проверки отравления эталона и ограничения находятся в review_summary.json.']
    (args.output/'REVIEW_RU.md').write_text('\n'.join(lines)+'\n',encoding='utf8')


if __name__=='__main__':
    main()
