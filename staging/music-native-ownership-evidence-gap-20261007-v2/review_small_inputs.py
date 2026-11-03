#!/usr/bin/env python3
"""Read only the predeclared small files; retain scalar selections, not input dumps."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUT_CAP = 262144
OUTPUT_CAP = 65536


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def scalars(v, prefix='', skip=False):
    if any(p in prefix for p in ('source_sha256', 'artifacts_sha256', 'inherited_guest_patches',
                                 'source_backed_flash_page', 'GP16', 'source_hashes')):
        return {}
    if isinstance(v, dict):
        out = {}
        for k, child in v.items():
            out.update(scalars(child, prefix + '/' + str(k)))
        return out
    if isinstance(v, list):
        if len(v) > 8:
            return {}
        out = {}
        for i, child in enumerate(v):
            out.update(scalars(child, prefix + '/' + str(i)))
        return out
    if v is None or isinstance(v, (bool, int, float)):
        return {prefix: v}
    if isinstance(v, str) and len(v) <= 1024 and not (len(v) == 64 and all(c in '0123456789abcdef' for c in v)):
        return {prefix: v}
    return {}


def main():
    p = HERE / 'preflight.json'
    initial = p.stat()
    pre_raw = p.read_bytes()
    if len(pre_raw) != initial.st_size or identity(initial) != identity(p.stat()):
        raise ValueError('Own preflight changed')
    plan = json.loads(pre_raw)
    if plan['source_input_planned_bytes'] != 64596 or len(plan['files']) != 11:
        raise ValueError('Exact predeclared scope')
    measured = len(pre_raw)
    journal = {'scope': HERE.name, 'preflight_read': {'bytes': len(pre_raw),
                'sha256': hashlib.sha256(pre_raw).hexdigest(), 'stat': identity(initial)},
               'reads': [], 'raw_input_bytes': measured, 'all_declared_reads_completed': False,
               'producer_import_execution_guest_compile_callsite_firmware_device_audio': False}
    selections = {}
    excerpts = {}
    for row in plan['files']:
        name = row['path']
        p = ROOT / name
        before = p.stat()
        if identity(before) != row['stat'] or before.st_size != row['bytes']:
            raise ValueError('Source stat no longer equals preflight')
        with p.open('rb') as f:
            raw = f.read(before.st_size + 1)
        measured += len(raw)
        if len(raw) != before.st_size or identity(before) != identity(p.stat()) or measured > INPUT_CAP:
            raise ValueError('Source size/stat/input cap')
        digest = hashlib.sha256(raw).hexdigest()
        journal['reads'].append({'path': name, 'bytes': len(raw), 'sha256': digest,
                                 'stat': identity(before), 'mode': oct(before.st_mode & 0o777)})
        journal['raw_input_bytes'] = measured
        # Save the measured file journal before any retained output serialization.
        (HERE / 'actual-input-read-journal.json').write_text(json.dumps(journal, indent=2, sort_keys=True) + '\n')
        text = raw.decode('utf-8')
        if p.suffix == '.json':
            obj = json.loads(text)
            flat = scalars(obj)
            # Only scalar paths concerning readiness, actor/provenance, ownership and lifetime.
            keys = ('passed', 'scope', 'target', 'HWID', 'software', 'priority', 'initialized', 'ready',
                    'POST', 'WAIT', 'CURRENT', 'callback', 'worker', 'TCB', 'tcb', 'adapter', 'controller',
                    'ownership', 'witness', 'fixture', 'pinned', 'lease', 'PCM', 'SBC', 'STOP', 'stop',
                    'reclaim', 'unload', 'device', 'install', 'physical', 'App', 'epoch', 'generation',
                    'source_record', 'anchor', 'full_return', 'full_returns', 'initializer', 'result',
                    'decoded', 'frames', 'streams', 'speaker', 'mixer', 'factory', 'reader', 'held',
                    'runtime_guest', 'exit_code', 'chunk_id', 'native_owner', 'failure', 'failed', 'next')
            chosen = {k: v for k, v in flat.items() if any(word in k for word in keys)}
            selections[name] = chosen
            print(json.dumps({'path': name, 'sha256': digest, 'selected_scalars': chosen}, ensure_ascii=False))
        elif p.suffix == '.h':
            lines = text.splitlines()
            indices = set()
            for i, line in enumerate(lines):
                if any(k in line for k in ('ownership_snapshot', 'umcn_owner', 'epoch', 'future_callbacks',
                                           'prepare_session', 'native_source_token', 'cleanup_begin',
                                           'after_native_iteration', 'prepare_resident')):
                    indices.update(range(max(0, i - 3), min(len(lines), i + 6)))
            kept = {str(i + 1): lines[i] for i in sorted(indices)}
            excerpts[name] = kept
            print(json.dumps({'path': name, 'sha256': digest, 'selected_header_lines': kept}, ensure_ascii=False))
        elif p.suffix == '.c':
            excerpts[name] = {'complete_tiny_C_source': text}
            print(json.dumps({'path': name, 'sha256': digest, 'tiny_C_source': text}))
        else:
            matches = [(i + 1, s) for i, s in enumerate(text.splitlines())
                       if any(k in s for k in ('ownership_snapshot', 'actual native reservation',
                                             'prepare_session', 'No original MAIN', 'STOP_DONE',
                                             'call sites are currently not wired'))]
            # Retain only four relevant paragraph lines; every value is a bounded scalar string.
            chosen = {str(i): s for i, s in matches[:4] if len(s) <= 2048}
            excerpts[name] = chosen
            print(json.dumps({'path': name, 'sha256': digest, 'selected_document_lines': chosen}, ensure_ascii=False))
    journal['all_declared_reads_completed'] = True
    journal['all_source_handles_closed'] = True
    journal_raw = (json.dumps(journal, indent=2, sort_keys=True) + '\n').encode()
    selected_raw = (json.dumps({'selected_scalar_fields': selections, 'bounded_text_excerpts': excerpts,
                               'full_input_bodies_not_copied': True}, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    existing = sum(p.stat().st_size for p in HERE.iterdir() if p.is_file() and p.name != 'actual-input-read-journal.json')
    if existing + len(journal_raw) + len(selected_raw) + 16384 > OUTPUT_CAP:
        raise ValueError('Final scalar output + closure reserve cap')
    (HERE / 'actual-input-read-journal.json').write_bytes(journal_raw)
    with (HERE / 'selected-scalar-evidence.json').open('xb') as f:
        f.write(selected_raw)
    print(json.dumps({'all11_reads_completed': True, 'raw_input_bytes': measured,
                      'selected_scalar_bytes': len(selected_raw), 'journal_bytes': len(journal_raw),
                      'input_sha256_stat_journal_saved': True, 'reviewed_producer_import_execution': False}))


if __name__ == '__main__':
    main()
