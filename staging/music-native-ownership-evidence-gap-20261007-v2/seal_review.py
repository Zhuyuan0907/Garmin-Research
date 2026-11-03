#!/usr/bin/env python3
"""Verify and seal own small file-review artifacts; never reopen external inputs."""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    paths = sorted(p for p in HERE.iterdir() if p.is_file())
    if any(p.name in ('sealed-files.json', 'actual-sealer-terminal-receipt.json') for p in paths):
        raise ValueError('Unique source review seal')
    sizes = {p.name: p.stat().st_size for p in paths}
    total = sum(sizes.values())
    allowance = sizes['review_small_inputs.py'] + sizes['seal_review.py']
    if total + 8192 > 65536 or 67751 + allowance + total + 8192 > 262144:
        raise ValueError('Own closure/output budget before content reads')
    contents = {}
    rows = []
    for p in paths:
        os.chmod(p, 0o444)
        before = p.stat()
        with p.open('rb') as f:
            raw = f.read(before.st_size + 1)
        after = p.stat()
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise ValueError('Owned artifact changed')
        contents[p.name] = raw
        rows.append({'path': str(p), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'stat': identity(after), 'mode': '0444'})
    journal = json.loads(contents['actual-input-read-journal.json'])
    proof = json.loads(contents['proof.json'])
    plan = json.loads(contents['preflight.json'])
    selected = json.loads(contents['selected-scalar-evidence.json'])
    if not journal['all_declared_reads_completed'] or not journal['all_source_handles_closed']:
        raise ValueError('Complete real file journal required')
    if len(journal['reads']) != 11 or sum(r['bytes'] for r in journal['reads']) != 64596:
        raise ValueError('Actual predeclared source byte count')
    pins = {r['path']: r for r in journal['reads']}
    for row in plan['files']:
        actual = pins[row['path']]
        if row['stat'] != actual['stat'] or row['bytes'] != actual['bytes']:
            raise ValueError('Preflight and actual-read binding')
    for ref in proof['source_refs'].values():
        if pins[ref['path']]['sha256'] != ref['sha256']:
            raise ValueError('Review source pin differs from real journal')
    for fields in selected['selected_scalar_fields'].values():
        if any(isinstance(v, (dict, list)) for v in fields.values()):
            raise ValueError('Only selected scalar fields may be retained')
    result = {'schema': 'music-native-ownership-gap-readonly-seal/v2', 'scope': HERE.name,
              'finite_file_review_complete': True, 'native_playable_or_install_proven': False,
              'all11_source_pins_and_preflight_stats_bound': True,
              'own_read_bytes': total, 'conservative_own_interpreter_source_load_allowance': allowance,
              'raw_input_bytes_before_seal_readback': 67751 + allowance + total,
              'raw_input_cap': 262144, 'output_cap': 65536,
              'additional_external_source_reads': 0, 'files': rows,
              'postseal_receipt_excluded_from_self_reference': True, 'scope_closed': True,
              'guest_firmware_emulator_producer_import_compile_patch_device_audio_service': False}
    encoded = (json.dumps(result, sort_keys=True, indent=2) + '\n').encode()
    if total + len(encoded) + 2048 > 65536:
        raise ValueError('Exact final output budget')
    p = HERE / 'sealed-files.json'
    with p.open('xb') as f:
        f.write(encoded)
    os.chmod(p, 0o444)
    with p.open('rb') as f:
        back = f.read(len(encoded) + 1)
    if back != encoded:
        raise ValueError('Actual seal readback')
    print(json.dumps({'finite_review_closed': True, 'native_playable': False,
                      'seal': {'bytes': len(back), 'sha256': hashlib.sha256(back).hexdigest()},
                      'report_pins': {Path(r['path']).name: {'bytes': r['bytes'], 'sha256': r['sha256']}
                                      for r in rows if Path(r['path']).name in
                                      ('proof.json', 'missing-ABI-matrix.md', 'actual-input-read-journal.json',
                                       'actual-tool-receipts.json', 'HANDOFF.md')},
                      'conservative_raw_input_bytes': 67751 + allowance + total + len(back),
                      'output_bytes': total + len(back), 'new_external_source_reads': 0}))


if __name__ == '__main__':
    main()
