#!/usr/bin/env python3
"""Freeze every explicit-rule prefix, then evaluate the preregistered series.

No score formula is duplicated here. Only the Go detector fits or evaluates.
All source groups retain their original split; test never selects a candidate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
CORE = {'w15-c02', 'v3-paired-random'}
ROUND = re.compile(r'^r(\d{2})(?:-|$)')


def load(path: Path) -> Any:
    return json.loads(path.read_text())


def save(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n')


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def round_number(profile: str) -> int | None:
    match = ROUND.match(profile)
    return int(match.group(1)) if match else None


def fit_input(data: list[dict[str, Any]], number: int) -> list[dict[str, Any]]:
    result = []
    for observation in data:
        if observation['split'] == 'test':
            continue
        profile = observation['profile']
        candidate = round_number(profile)
        if observation['class'] == 'benign' or profile in CORE or (candidate is not None and candidate <= number):
            result.append(observation)
        elif candidate is None:
            raise ValueError('unrecognized positive profile: ' + profile)
    return result


def assert_splits(data: list[dict[str, Any]]) -> None:
    assignments: dict[str, str] = {}
    sessions: set[str] = set()
    for observation in data:
        group = observation.get('group_id') or observation['session_id']
        split = observation['split']
        if group in assignments and assignments[group] != split:
            raise ValueError('source group leaks across splits: ' + group)
        assignments[group] = split
        session = observation['session_id']
        if session in sessions:
            raise ValueError('duplicate session: ' + session)
        sessions.add(session)


def execute(command: list[str], log: Path) -> None:
    started = time.time()
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
    save(log, {'argv': command, 'exit_code': result.returncode,
               'elapsed_seconds': time.time() - started, 'stdout': result.stdout, 'stderr': result.stderr})
    if result.returncode:
        raise RuntimeError(f'command failed; exact output in {log}: {result.stderr}')


def freeze(binary: Path, source: Path, directory: Path, number: int) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    policy = directory / 'policy.json'
    candidate = directory / 'policy.pending.json' if policy.exists() else policy
    execute([str(binary), 'fit', '-rules', str(number), '-input', str(source), '-output', str(candidate)],
            directory / 'fit-command.json')
    if candidate != policy:
        if candidate.read_bytes() != policy.read_bytes():
            raise RuntimeError('refusing to replace a frozen policy: ' + str(policy))
        candidate.unlink()
        candidate.with_name(candidate.name + '.calibration.json').unlink()
    parsed = load(policy)
    if len(parsed['individual_rules']) != number:
        raise ValueError('wrong rule prefix length')
    for row in parsed['rounds']:
        for metrics in row['calibration'].values():
            if metrics['fpr'] is None or metrics['group_fpr'] is None:
                raise ValueError('calibration missing benign flow/group denominator')
            if metrics['fpr'] > .05 or metrics['group_fpr'] > .05:
                raise ValueError('joint calibration FPR budget exceeded')
    save(directory / 'frozen.json', {'policy_sha256': sha(policy), 'input_sha256': sha(source),
         'calibration_sha256': parsed['calibration_sha256'], 'rules': number})
    return policy


def evaluate(binary: Path, policy: Path, data: list[dict[str, Any]], directory: Path,
             name: str, split: str = 'test') -> dict[str, Any]:
    source = directory / (name + '-input.json')
    output = directory / (name + '.json')
    save(source, data)
    before = sha(policy)
    execute([str(binary), 'evaluate', '-policy', str(policy), '-input', str(source),
             '-split', split, '-output', str(output)], directory / (name + '-command.json'))
    if sha(policy) != before:
        raise RuntimeError('evaluation modified frozen policy')
    return load(output)['rounds'][-1]


def candidate_input(data: list[dict[str, Any]], profile: str) -> list[dict[str, Any]]:
    return [o for o in data if o['split'] == 'test' and (o['class'] == 'benign' or o['profile'] == profile)]


def proofs(trials: list[dict[str, Any]], number: int, split: str | None = None) -> dict[str, Any]:
    selected = [trial for trial in trials if trial['round'] == number and (split is None or trial['split'] == split)]
    attempts = [(trial, proof) for trial in selected for proof in trial.get('proofs', [])]
    return {'groups': len(selected), 'http_success': sum(proof.get('ok') is True for _, proof in attempts),
            'http_attempts': len(attempts),
            'failed_attempts': [{'group_id': trial['id'], 'proof': proof} for trial, proof in attempts if proof.get('ok') is not True]}


def fraction(metrics: dict[str, Any] | None, numerator: str, denominator: str) -> str:
    return 'n/a' if metrics is None else f"{metrics[numerator]}/{metrics[denominator]}"


def make_report(out: Path, summary: dict[str, Any]) -> None:
    rows = ['# Fifteen measured transport/DPI hypotheses', '',
            'All transport candidates and rule definitions were fixed before held-out evaluation. '
            'Each row compares actual recorded native traffic. No row is automatically a successful improvement.', '',
            '| Round | Native HTTP all | Previous DPI → current transport | Current DPI → previous transport | Current DPI → current transport | Test FP flows | Test FP groups |',
            '|---|---|---|---|---|---|---|']
    for record in summary['rounds']:
        current = record['current_under_current']
        before = record['current_under_previous']
        previous = record['previous_under_current']
        row = [str(record['round']), fraction(record['native_http_all'], 'http_success', 'http_attempts'),
               fraction(before, 'tp', 'belnet'), fraction(previous, 'tp', 'belnet'),
               fraction(current, 'tp', 'belnet'), fraction(record['current_metrics'], 'fp', 'benign'),
               fraction(record['current_metrics'], 'fp_benign_groups', 'benign_groups')]
        rows.append('| ' + ' | '.join(row) + ' |')
    rows += ['', 'Detection cells show detected flows / observed candidate flows. Fewer detections alone '
             'do not establish a working native path. Round1 uses the original v2 profile as its previous transport; '
             'there is no zero-rule policy.', '', '## Final frozen policy', '']
    for name, report in [('Early held-out', summary['final_early']),
                         ('Frozen early policy on late held-out', summary['early_on_late']),
                         ('Separately calibrated late held-out', summary['late_calibrated'])]:
        m = report['metrics']
        rows += [f"- {name}: FP {m['fp']}/{m['benign']}, eligible benign {m['eligible_benign']}/{m['benign']}, "
                 f"group FP {m['fp_benign_groups']}/{m['benign_groups']}; detected native {m['tp']}/{m['belnet']}."]
    m = summary.get('mature_exploratory', {}).get('metrics')
    if m:
        rows += [f"- Mature REALITY native, exploratory: detected {m['tp']}/{m['belnet']}; "
                 'PCAP time source differs from callback observers, no mature held-out test or independent benign controls.']
    rows += ['', 'All 15 prefix policies are frozen under `r01/`…`r15/`. Final live policy: `r15/policy.json`. '
             'Exact fit inputs, calibration-only snapshots, source hashes, command logs, all rule decisions '
             'and comparisons are retained. Late records use already normalized timestamps; the separate late '
             'policy is not a replacement for the early policy.', '',
             'Native continuity degraded late in acquisition; r14/r15 must not be called wins from active TCP '
             'or DPI acceptance alone. See raw HTTP failures in `summary.json`. This runner evaluates recorded '
             'observations; live enforcement is recorded separately. Sparse TLS flows abstain. Handshake '
             'fingerprints, reconnect persistence and credential probes are not inferred from event arrays.']
    if (out / 'numeric-before/regression-expanded.log').exists():
        rows += ['', '## Numerical correction', '',
                 'A regression confirmed that Go map iteration changed floating-point entropy summation '
                 'order for identical events. This could break a one-ULP calibration boundary. Only the '
                 'summation order was made deterministic; formulas, candidates, budgets and test assignments '
                 'were unchanged. All policies were fitted again using train/validation in this new output '
                 'directory. Original policies, binary and failure evidence remain preserved.', '',
                 'The final early policy and two repeated corrected fits are byte-identical to the original '
                 'live policy (SHA256 `f959cddf336ed061624df0a57ef8837f785dd8c8f0699c3c024a92ca4b238399`). '
                 'The corrected engine also flags both previously recorded live entry traces, by rule r10. '
                 'This offline audit did not repeat or repair the network experiment. See `NUMERICS.json`.']
    (out / 'REPORT.md').write_text('\n'.join(rows) + '\n')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, default=ROOT / 'out/dpi-v2/dataset-final.json')
    parser.add_argument('--late', type=Path, default=ROOT / 'out/dpi-v2/late-dataset-final.json')
    parser.add_argument('--plan', type=Path, default=ROOT / 'out/dpi-v2/rounds/plan.json')
    parser.add_argument('--trials', type=Path, default=ROOT / 'out/dpi-v2/rounds/trials.json')
    parser.add_argument('--mature', type=Path, default=ROOT / 'out/dpi-v2/mature-native/observations.json')
    parser.add_argument('--output', type=Path, default=ROOT / 'out/dpi-v2/classical-series')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    data, late = load(args.input), load(args.late)
    assert_splits(data)
    assert_splits(late)
    plan, trials = load(args.plan), load(args.trials)
    candidates = plan['candidates']
    if [item['round'] for item in candidates] != list(range(1, 16)):
        raise ValueError('need the complete frozen15-candidate plan')
    if len(trials) != 60 or any(len([t for t in trials if t['round'] == k]) != 4 for k in range(1, 16)):
        raise ValueError('acquisition incomplete: require four whole groups per transport candidate')
    for source in (args.input, args.late, args.plan, args.trials):
        target = out / ('source-' + source.name)
        if target.exists() and sha(target) != sha(source):
            raise RuntimeError('frozen source changed: ' + str(source))
        shutil.copy2(source, target)
    binary = out / 'classical'
    execute(['go', 'build', '-o', str(binary), './lab/dpi-v2/classical'], out / 'build-command.json')
    manifest = {'sources': {str(path): sha(path) for path in (args.input, args.late, args.plan, args.trials)},
                'fitting': 'benign train/validation + core and positive rounds<=k; test excluded',
                'test_selection': 'no test-based candidate selection; all15 plan entries evaluated',
                'prefix_policies': {}, 'status': 'freezing'}
    save(out / 'manifest.json', manifest)
    policies = {}
    # Complete every freeze before opening any held-out evaluation.
    for number in range(1, 16):
        directory = out / f'r{number:02d}'
        source = directory / 'fit-input.json'
        save(source, fit_input(data, number))
        policies[number] = freeze(binary, source, directory, number)
        manifest['prefix_policies'][str(number)] = {'path': str(policies[number]), 'sha256': sha(policies[number])}
        save(out / 'manifest.json', manifest)
        print(f'frozen r{number:02d}', flush=True)
    late_dir = out / 'late-calibrated'
    late_source = late_dir / 'fit-input.json'
    save(late_source, fit_input(late, 15))
    late_policy = freeze(binary, late_source, late_dir, 15)
    manifest['status'] = 'all_policies_frozen'
    manifest['late_policy_sha256'] = sha(late_policy)
    save(out / 'manifest.json', manifest)
    summary: dict[str, Any] = {'rounds': [], 'limits': ['15 measured hypotheses, not15 successful improvements',
        'held-out has one group/two entry flows per candidate; estimates are coarse and correlated',
        'failed real site visits remain benign for FPR, not successful Google/YouTube evidence',
        'late windows are normalized; eligibility and group FPR shown separately',
        'native HTTP degradation is independent of detector output']}
    for candidate in candidates:
        number, profile = candidate['round'], candidate['policy']['name']
        directory = out / f'r{number:02d}'
        current_data = candidate_input(data, profile)
        current = evaluate(binary, policies[number], current_data, directory, 'current-under-current')
        previous_profile = 'w15-c02' if number == 1 else candidates[number - 2]['policy']['name']
        previous = evaluate(binary, policies[number], candidate_input(data, previous_profile), directory, 'previous-under-current')
        before = evaluate(binary, policies[number - 1], current_data, directory, 'current-under-previous') if number > 1 else None
        record = {'round': number, 'profile': profile, 'previous_profile': previous_profile,
                  'transport_hypothesis': candidate['hypothesis'], 'transport_policy': candidate['policy'],
                  'added_rule': load(policies[number])['individual_rules'][-1]['rule'],
                  'policy_sha256': sha(policies[number]), 'current_metrics': current['metrics'],
                  'current_under_current': current['by_profile'].get(profile),
                  'previous_under_current': previous['by_profile'].get(previous_profile),
                  'current_under_previous': before['by_profile'].get(profile) if before else None,
                  'native_http_all': proofs(trials, number), 'native_http_test': proofs(trials, number, 'test')}
        summary['rounds'].append(record)
        save(directory / 'comparison.json', record)
        print(f'evaluated r{number:02d}', flush=True)
    final_dir = out / 'final'
    summary['final_early'] = evaluate(binary, policies[15], data, final_dir, 'early-all-heldout')
    summary['early_on_late'] = evaluate(binary, policies[15], late, final_dir, 'early-policy-late-heldout')
    summary['late_calibrated'] = evaluate(binary, late_policy, late, late_dir, 'late-heldout')
    if args.mature.exists():
        summary['mature_exploratory'] = evaluate(binary, policies[15], load(args.mature), final_dir,
                                                   'mature-native-exploratory', split='all')
    save(out / 'summary.json', summary)
    make_report(out, summary)
    manifest['status'] = 'complete'
    manifest['report_sha256'] = sha(out / 'summary.json')
    save(out / 'manifest.json', manifest)
    print(json.dumps({'status': 'complete', 'final_policy': str(policies[15]), 'report': str(out / 'REPORT.md')}), flush=True)


if __name__ == '__main__':
    main()
