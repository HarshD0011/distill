"""Train a transparent, abstaining feature-table adviser from reviewed labels.

Input is evaluate_corpus.py output with disjoint group/split fields. This model
can skip advisory LLM calls; it cannot authorize unknown commands. JSON keeps
runtime inference dependency-free and reviewable; no ONNX runtime is required.
"""
import argparse
import collections
import hashlib
import json
from pathlib import Path
from offline_common import private_write


def signature(features):
    return json.dumps(features, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def train(rows, minimum_support, minimum_probability):
    training = [r for r in rows if r.get('reviewed') and r.get('split') == 'train']
    test = [r for r in rows if r.get('reviewed') and r.get('split') == 'test']
    if not training or not test:
        raise ValueError('Reviewed train and held-out test records are required')
    train_groups = {r.get('group') for r in training}
    test_groups = {r.get('group') for r in test}
    if None in train_groups | test_groups or train_groups & test_groups:
        raise ValueError('Train/test groups must be explicit and disjoint')
    train_commands = {r.get('report', {}).get('command_digest') for r in training}
    test_commands = {r.get('report', {}).get('command_digest') for r in test}
    if (train_commands & test_commands) - {None}:
        raise ValueError('Exact commands must not leak across the evaluation split')
    buckets = collections.defaultdict(collections.Counter)
    levels = {'safe', 'low', 'medium', 'high', 'critical'}
    for row in training:
        if row['expected_severity'] in levels:
            buckets[signature(row['features'])][row['expected_severity']] += 1
    table = []
    for key, counts in sorted(buckets.items()):
        severity, count = counts.most_common(1)[0]
        table.append({'signature': key, 'severity': severity, 'support': sum(counts.values()), 'probability': count / sum(counts.values())})
    lookup = {r['signature']: r for r in table}
    predicted = 0
    errors = []
    for row in test:
        bucket = lookup.get(signature(row['features']))
        if not bucket or bucket['support'] < minimum_support or bucket['probability'] < minimum_probability:
            continue
        predicted += 1
        if row['expected_severity'] in {'high', 'critical'} and bucket['severity'] in {'safe', 'low'}:
            errors.append(row['id'])
    return {'schema_version': 1, 'feature_scheme': 'ir-gaps-effects-v1', 'reviewed_labels': True, 'advisory_only': True,
            'training_samples': len(training), 'training_groups': sorted(train_groups), 'test_groups': sorted(test_groups),
            'label_digest': hashlib.sha256(json.dumps([(r['id'], r['expected_severity']) for r in rows], sort_keys=True).encode()).hexdigest(),
            'validation': {'held_out': len(test), 'predictions': predicted, 'abstentions': len(test) - predicted, 'dangerous_false_low_predictions': errors, 'scope': 'Fixed reviewed split; not a general accuracy guarantee'},
            'buckets': table}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evaluation', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--minimum-support', type=int, default=20)
    parser.add_argument('--minimum-probability', type=float, default=0.99)
    args = parser.parse_args()
    if args.minimum_support < 1 or not 0.5 <= args.minimum_probability <= 1:
        parser.error('Invalid abstention thresholds')
    data = json.loads(args.evaluation.read_text())
    model = train(data['results'], args.minimum_support, args.minimum_probability)
    if model['validation']['dangerous_false_low_predictions']:
        raise SystemExit('Held-out dangerous false-low predictions prevent model export')
    private_write(args.output, json.dumps(model, indent=2) + '\n')
    print(json.dumps(model['validation']))


if __name__ == '__main__':
    main()
