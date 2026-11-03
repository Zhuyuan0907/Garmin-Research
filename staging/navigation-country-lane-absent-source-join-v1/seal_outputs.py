#!/usr/bin/env python3
"""Seal this scope only; never reopen input ledgers, maps or geometry."""
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import json
import os

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def digest(path):
    before = path.stat()
    h = hashlib.sha256()
    n = 0
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(data)
            n += len(data)
    after = path.stat()
    ident = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if ident(before) != ident(after) or n != before.st_size:
        raise ValueError('Output changed during sealing: ' + str(path))
    return dict(path=str(path.relative_to(ROOT)), bytes=n, sha256=h.hexdigest(), stat_unchanged=True)


def main():
    target = HERE / 'seal.json'
    if target.exists():
        raise ValueError('Fresh seal required')
    proof = json.loads((HERE / 'proof.json').read_text())
    expected = {}
    for value in proof['artifacts'].values():
        for item in value if isinstance(value, list) else [value]:
            path = ROOT / item['path']
            if not path.is_relative_to(HERE):
                raise ValueError('Seal artifact outside own scope')
            expected[path] = item
    entries = []
    for path in sorted(HERE.rglob('*')):
        if path.is_file():
            if path.is_symlink() or path.suffix == '.pyc':
                raise ValueError('Unexpected artifact')
            receipt = digest(path)
            if path in expected:
                pin = expected.pop(path)
                if receipt['sha256'] != pin['sha256'] or receipt['bytes'] != pin['bytes']:
                    raise ValueError('Output artifact pin mismatch: ' + str(path))
                for key in ['rows', 'uncompressed_sha256', 'uncompressed_bytes']:
                    if key in pin:
                        receipt[key] = pin[key]
            entries.append(receipt)
    if expected:
        raise ValueError('Missing output artifacts')
    seal = dict(schema='lane-absent-source-join-seal/v1',
                sealed_utc=datetime.now(timezone.utc).isoformat(), artifacts=entries,
                all_fresh_compressed_or_file_hashes_verified=True,
                plain_EOF_order_and_provenance_audit='output-readback-proof.json',
                no_original_inputs_reopened=True,
                ready_planning_targets=58233, held_targets=18616,
                ready_actual_parent_count=20613,
                overall_prepared_source_read_attempts=2,
                source_attempt_scope='One failed partial scan and one corrected full scan.',
                corrected_join_process_peak_RSS_KiB=424240,
                unchanged_memory_guard_KiB=512000,
                native_write_ready=False, device_or_native_files_changed=False,
                historical_frozen_sources_or_proofs_modified=False)
    with target.open('x') as stream:
        json.dump(seal, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(dict(files=len(entries), seal=digest(target)), ensure_ascii=False))


if __name__ == '__main__':
    main()
