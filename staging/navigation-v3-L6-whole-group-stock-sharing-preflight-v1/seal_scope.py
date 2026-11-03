#!/usr/bin/env python3
"""Hash small owned outputs; inherit a truly measured large summary pin by stat."""
import hashlib
import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent
RAW_CAP = 6291456
DECODED_CAP = 67108864
cache = {}
read_receipts = []
raw_additional = 0


def stat_tuple(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read_small(name):
    global raw_additional
    if name in cache:
        return cache[name]
    p = BASE / name
    before = stat_tuple(p)
    assert before[2] <= 65536, (name, before[2])
    with p.open('rb') as handle:
        raw = handle.read(65537)
    assert handle.closed and len(raw) == before[2]
    assert stat_tuple(p) == before
    raw_additional += len(raw)
    cache[name] = raw
    read_receipts.append({'name': name, 'bytes': len(raw),
                          'SHA256': hashlib.sha256(raw).hexdigest(),
                          'stat_before': before, 'stat_after': stat_tuple(p),
                          'handle_closed': handle.closed})
    return raw


budget = json.loads(read_small('preseal-artifact-read-budget.json'))
audit = json.loads(read_small('own-summary-audit-and-bound.json'))
prep = json.loads(read_small('final-document-preparation-read-counts.json'))
bound = json.loads(read_small('conditional-capacity-bound-proof.json'))
assert bound['original_universal_predicate'] is False
assert bound['optimistic_complete_group_only_bound']['maximum_rows'] == 10772
assert bound['optimistic_complete_group_only_bound']['remaining_gap_rows'] == 60587
assert len(bound['counterexamples']) == 2
selected = audit['selected_summary_actual_read_pin']
selected_name = Path(selected['path']).name
selected_path = BASE / selected_name
selected_before = stat_tuple(selected_path)
assert selected_before == selected['stat_before'] == selected['stat_after']
assert selected_before[2] == selected['bytes'] == 633064

old_pins = {
    'staging/navigation-native-lane-tree-cow-append-v1/emitted-cow-groups.jsonl.gz':
        [45826, 537989, 4631695, 1791316778870852234, 1791317197595582430],
    'staging/navigation-v3-L6-exact-record-reuse-upper-bound-v1/target-multiplicity-stock-hits.u32le.gz':
        [45826, 539829, 11207, 1791359309805498736, 1791359309805498736],
}
old_stats = []
for path, pin in old_pins.items():
    p = Path(path)
    assert stat_tuple(p) == pin
    old_stats.append({'path': path, 'actual_stat': pin,
                      'actual_mode': oct(p.stat().st_mode & 0o777),
                      'verification': 'stat only, no content read or chmod'})

original_read_pins = {Path(x['path']).name: x for x in prep['actual_normal_artifact_reads']}
names = sorted(p.name for p in BASE.iterdir() if p.is_file())
assert 'sealed-files.json' not in names, 'sealer is a one-time close operation'
assert sum((BASE / n).stat().st_size for n in names) < 1048576
rows = []
for name in names:
    p = BASE / name
    before = stat_tuple(p)
    if name == selected_name:
        assert before == selected_before
        digest = selected['SHA256']
        provenance = {'method': 'inherited SHA from actual own summary read 6cf791, exact unchanged stat before freeze',
                      'fresh_sealer_content_read_bytes': 0,
                      'actual_prior_read_bytes': selected['bytes'],
                      'actual_prior_decoded_bytes': selected['decoded_bytes'],
                      'actual_prior_decoded_SHA256': selected['decoded_SHA256']}
    else:
        raw = read_small(name)
        digest = hashlib.sha256(raw).hexdigest()
        provenance = {'method': 'actual fresh small-file read by this sealer',
                      'fresh_sealer_content_read_bytes': len(raw)}
        if name in ('proof.json', 'result-summary.json'):
            assert digest == original_read_pins[name]['sha256']
    assert stat_tuple(p) == before
    os.chmod(p, 0o444)
    after = stat_tuple(p)
    assert before[:4] == after[:4]
    assert p.stat().st_mode & 0o777 == 0o444
    rows.append({'path': str(p.relative_to(Path.cwd())), 'bytes': before[2],
                 'SHA256': digest, 'mode_after_freeze': '0444',
                 'stat_before_freeze': before, 'stat_after_freeze': after,
                 'content_hash_provenance': provenance})

raw_before_readback = budget['raw_artifact_bytes'] + raw_additional
decoded_before_readback = budget['decoded_artifact_bytes'] + raw_additional
manifest = {
    'schema': 'finite-artifact-scope-seal/v1',
    'scope': BASE.name,
    'files': rows,
    'original_source_stat_checks': old_stats,
    'actual_sealer_small_file_reads': read_receipts,
    'selected_summary_fresh_sealer_content_read': False,
    'selected_summary_hash_reused_from_actual_audit': '6cf791',
    'source_or_IMG_content_reads_by_sealer': 0,
    'original_source_modes_preserved': True,
    'original_predicate_universal_FALSE_preserved': True,
    'conditional_complete_group_only_capacity_bound': {'maximum_rows': 10772, 'required_rows': 71359},
    'budget': {
        'raw_cap': RAW_CAP, 'decoded_cap': DECODED_CAP,
        'before_sealer_raw': budget['raw_artifact_bytes'],
        'before_sealer_decoded': budget['decoded_artifact_bytes'],
        'actual_sealer_small_reads': raw_additional,
        'raw_before_seal_readback': raw_before_readback,
        'decoded_before_seal_readback': decoded_before_readback,
        'seal_readback_bytes': 0, 'final_raw_artifact_bytes': 0,
        'final_decoded_artifact_bytes': 0,
    },
    'explicit_stat_only_inheritance_not_full_sealer_reread': True,
    'excluded_self_references': ['sealed-files.json', 'actual-sealer-terminal-receipt.json'],
    'no_new_execution_beyond_ordinary_metadata_sealer': True,
    'scope_stopped_after_seal': True,
}
for _ in range(10):
    raw = (json.dumps(manifest, ensure_ascii=False, indent=2) + '\n').encode()
    count = len(raw)
    target = (count, raw_before_readback + count, decoded_before_readback + count)
    current = tuple(manifest['budget'][k] for k in (
        'seal_readback_bytes', 'final_raw_artifact_bytes', 'final_decoded_artifact_bytes'))
    if target == current:
        break
    for key, value in zip(('seal_readback_bytes', 'final_raw_artifact_bytes', 'final_decoded_artifact_bytes'), target):
        manifest['budget'][key] = value
else:
    raise AssertionError('seal length/count fixed point not reached')
assert len(raw) <= 65536
assert manifest['budget']['final_raw_artifact_bytes'] <= RAW_CAP
assert manifest['budget']['final_decoded_artifact_bytes'] <= DECODED_CAP
seal_path = BASE / 'sealed-files.json'
assert not seal_path.exists()
seal_path.write_bytes(raw)
os.chmod(seal_path, 0o444)
before = stat_tuple(seal_path)
with seal_path.open('rb') as handle:
    actual_readback = handle.read(65537)
assert handle.closed and actual_readback == raw and stat_tuple(seal_path) == before
all_final = rows + [{'path': str(seal_path.relative_to(Path.cwd())), 'bytes': len(raw),
                     'SHA256': hashlib.sha256(raw).hexdigest(),
                     'mode_after_freeze': '0444', 'stat_after_freeze': before}]
payload = sum(x['bytes'] for x in all_final)
assert payload < 1048576
print(json.dumps({
    'finite_scope_sealed': True, 'files': len(rows), 'payload_bytes': payload,
    'seal': all_final[-1],
    'small_report_pins': [x for x in all_final if Path(x['path']).name in (
        'scope-summary.json', 'conditional-capacity-bound-proof.json',
        'proof.json', 'result-summary.json', 'HANDOFF.md')],
    'budget': manifest['budget'],
    'actual_seal_readback_handle_closed': handle.closed,
    'selected_summary_hash_inherited_from_actual_audit_only': True,
    'IMGreads': 0,
}, ensure_ascii=False))
