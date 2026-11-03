#!/usr/bin/env python3
"""Close own partial artifacts only. No further external evidence reads."""
import hashlib
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
INPUT_CAP = 1048576
OUTPUT_CAP = 131072


def stat_fields(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    paths = sorted(p for p in HERE.iterdir() if p.is_file())
    if any(p.name in ('sealed-files.json', 'actual-closure-terminal-receipt.json') for p in paths):
        raise ValueError('Unique partial closure only')
    sizes = {p.name: p.stat().st_size for p in paths}
    x, y, z = [sizes[n] for n in ('read_small_evidence.py', 'read_small_evidence_v2.py',
                                  'read_minimal_evidence_v3.py')]
    # Actual executed fixed-list readers reached their post-loop guards.
    source_body_base = 392843 * 2 + x * 2 + y + 154388
    # Explicit conservative allowance for interpreter loading of our own script sources.
    own_source_load_allowance = x + y + z + sizes['seal_partial.py']
    base = source_body_base + own_source_load_allowance
    planned = sum(sizes.values())
    if base + planned + 12288 > INPUT_CAP or planned + 12288 > OUTPUT_CAP:
        raise ValueError('Partial closure budget before own artifact reads')
    files = []
    read_bytes = 0
    for p in paths:
        os.chmod(p, 0o444)
        initial = p.stat()
        with p.open('rb') as f:
            raw = f.read(initial.st_size + 1)
        read_bytes += len(raw)
        final = p.stat()
        if len(raw) != initial.st_size or stat_fields(initial) != stat_fields(final):
            raise ValueError('Owned partial artifact changed')
        files.append({'path': str(p), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                      'stat': stat_fields(final), 'mode': '0444'})
    result = {'schema': 'music-native-readonly-partial-closure/v1',
              'status': 'STOPPED_PARTIAL_READER_OUTPUT_GUARD', 'native_or_full_file_review_passed': False,
              'all_owned_partial_artifacts_hash_closed': True, 'files': files,
              'fixed_reader_source_body_bytes': source_body_base,
              'fixed_reader_byte_count_not_full_saved_source_journal': True,
              'own_interpreter_source_load_conservative_allowance': own_source_load_allowance,
              'closure_actual_owned_read_bytes': read_bytes,
              'conservative_raw_input_bytes_before_seal_readback': base + read_bytes,
              'raw_input_cap': INPUT_CAP, 'output_cap': OUTPUT_CAP,
              'additional_external_source_reads': 0, 'guest_firmware_device_audio_service_compile_patch': False,
              'postseal_receipt_excluded_from_self_reference': True, 'scope_stopped': True}
    packed = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    if base + read_bytes + len(packed) + 2048 > INPUT_CAP or planned + len(packed) + 2048 > OUTPUT_CAP:
        raise ValueError('Partial closure exact seal budget')
    p = HERE / 'sealed-files.json'
    with p.open('xb') as f:
        f.write(packed)
    os.chmod(p, 0o444)
    with p.open('rb') as f:
        actual = f.read(len(packed) + 1)
    if actual != packed:
        raise ValueError('Actual partial seal readback')
    print(json.dumps({'partial_closed': True, 'native_or_complete_review_passed': False,
                      'seal': {'path': str(p), 'bytes': len(actual), 'sha256': hashlib.sha256(actual).hexdigest()},
                      'reported_pins': {Path(r['path']).name: {'bytes': r['bytes'], 'sha256': r['sha256']}
                                        for r in files if Path(r['path']).name in
                                        ('partial-proof.json', 'feature-acceptance-matrix.md',
                                         'actual-tool-receipts.json', 'HANDOFF.md')},
                      'conservative_raw_input_bytes': base + read_bytes + len(actual),
                      'output_bytes': planned + len(actual), 'external_source_reads': 0}))


if __name__ == '__main__':
    main()
