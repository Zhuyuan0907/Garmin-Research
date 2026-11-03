#!/usr/bin/env python3
"""Second, explicit bounded ordinary-file pass, preserving the failed first pass."""
import ast
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUT_CAP = 1048576
FIRST_PASS_BYTES = 392843


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def compact(value, depth=0):
    if isinstance(value, dict):
        if depth > 7:
            return {'_omitted_nested_object_keys': list(value)}
        return {k: compact(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > 12:
            return {'_original_list_count': len(value), '_retained_first12':
                    [compact(v, depth + 1) for v in value[:12]], '_remaining_items_omitted': True}
        return [compact(v, depth + 1) for v in value]
    if isinstance(value, str) and len(value) > 2048:
        return {'_original_string_characters': len(value), '_retained_prefix': value[:2048],
                '_remaining_characters_omitted': True}
    return value


def main():
    first_source = HERE / 'read_small_evidence.py'
    source_stat = first_source.stat()
    with first_source.open('rb') as f:
        first_raw = f.read(source_stat.st_size + 1)
    if len(first_raw) != source_stat.st_size:
        raise ValueError('Owned failed source length')
    tree = ast.parse(first_raw.decode())
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == 'PATHS' for t in n.targets))
    paths = ast.literal_eval(node.value)
    pre = [(name, ROOT / name, (ROOT / name).stat()) for name in paths]
    planned = sum(s.st_size for _, _, s in pre)
    if planned != FIRST_PASS_BYTES or FIRST_PASS_BYTES + len(first_raw) + planned > INPUT_CAP:
        raise ValueError('Explicit reread accounting/preflight')
    capture = {}
    receipts = []
    reread = 0
    for name, p, initial in pre:
        if initial.st_size > 98304:
            raise ValueError('Predetermined small-evidence limit')
        if identity(initial) != identity(p.stat()):
            raise ValueError('Source changed before normal read')
        with p.open('rb') as f:
            raw = f.read(initial.st_size + 1)
        reread += len(raw)
        if len(raw) != initial.st_size or identity(initial) != identity(p.stat()):
            raise ValueError('Source length/stat changed')
        if FIRST_PASS_BYTES + len(first_raw) + reread > INPUT_CAP:
            raise ValueError('Aggregate input cap')
        text = raw.decode('utf-8')
        if p.suffix == '.json':
            parsed = json.loads(text)
            capture[name] = {'parsed': parsed if len(raw) <= 32768 else compact(parsed),
                             'retained_view_complete': len(raw) <= 32768,
                             'source_top_keys': list(parsed) if isinstance(parsed, dict) else None}
        else:
            capture[name] = {'text': text, 'retained_view_complete': True}
        receipts.append({'path': name, 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest(),
                         'stat': identity(initial), 'mode': oct(initial.st_mode & 0o777)})
    decoded = (json.dumps(capture, ensure_ascii=False, sort_keys=True) + '\n').encode()
    compressed = gzip.compress(decoded, mtime=0)
    if len(compressed) > 49152:
        raise ValueError('Focused retained capture budget')
    result = {
        'scope': HERE.name, 'phase': 'explicit second normal source pass',
        'first_failure': {'actual_terminal': 'af531b EXIT1', 'failure': 'Own retained snapshot65536B guard',
                          'input_bytes': FIRST_PASS_BYTES, 'all30_file_reads_preceded_guard': True,
                          'hash_or_content_journal_from_attempt_saved': False,
                          'count_basis': 'Executed fixed30-path source reached post-read guard; exact source sizes preflighted again',
                          'system_or_access_rejection': False, 'native_or_device_attempt': False},
        'failed_source_read': {'bytes': len(first_raw), 'sha256': hashlib.sha256(first_raw).hexdigest(),
                               'stat': identity(source_stat)},
        'second_pass_raw_bytes': reread, 'raw_input_bytes': FIRST_PASS_BYTES + len(first_raw) + reread,
        'raw_input_cap': INPUT_CAP, 'reads': receipts,
        'cache': {'path': 'small-evidence-source-capture.json.gz', 'bytes': len(compressed),
                  'sha256': hashlib.sha256(compressed).hexdigest(), 'decoded_bytes': len(decoded),
                  'decoded_sha256': hashlib.sha256(decoded).hexdigest()},
        'large_JSON_fields_explicitly_compacted_only_after_full_normal_read': True,
        'no_singlepass_claim': True, 'reviewed_producer_import_or_execution': False,
        'guest_firmware_RAM_IMG_device_audio_service_compile_callsite': False,
    }
    result_raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    if sum(p.stat().st_size for p in HERE.iterdir() if p.is_file()) + len(compressed) + len(result_raw) > 131072:
        raise ValueError('Total output preflight budget')
    for name, data in [('small-evidence-source-capture.json.gz', compressed),
                       ('actual-normal-read-receipts.json', result_raw)]:
        with (HERE / name).open('xb') as f:
            f.write(data)
    print(json.dumps({'raw_input_bytes': result['raw_input_bytes'], 'second_pass_raw_bytes': reread,
                      'cache': result['cache'], 'read_receipt_bytes': len(result_raw),
                      'all30_second_pass_normal_reads_completed': True}))


if __name__ == '__main__':
    main()
