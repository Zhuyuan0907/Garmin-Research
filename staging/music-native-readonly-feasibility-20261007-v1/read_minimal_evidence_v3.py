#!/usr/bin/env python3
"""Final narrow ordinary-file pass. A failed guard ends this review."""
import ast
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 1048576
FIRST = 392843
PATHS = [
    'native/os20-task-bridge/resident-contract-v1.json',
    'native/os20-audio-source-v1/contract-v1.json',
    'staging/native-os20-worker-fifo-v1/contract-v1.json',
    'staging/native-os20-source-ready-v1/contract-v1.json',
    'staging/native-os20-source-media-v1/contract-v1.json',
    'staging/native-os20-mixer-allocator-v1/contract-v1.json',
    'staging/native-os20-mixer-admission-readonly-review-v1/review.json',
    'staging/native-os20-mixer-admission-readonly-review-v1/actual-readonly-tool-receipt.json',
    'staging/native-os20-mixer-admission-v1/guest-v1/terminal-tool-receipt.json',
    'staging/native-os20-resident-music-v2/guest-proof.json',
    'evidence/firmware-analysis/native-music-endpoint-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-ready-checkpoint-audit.json',
    'evidence/native-marker-physical-positive-20261005.json',
    'evidence/native-marker-physical-original-control-20261005T044607Z.json',
    'evidence/native-marker-original-voice-restore-20261005.json',
    'native/ui-music-native-adapter/ADAPTER_BINDING.md',
]


def ident(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def compact(v, depth=0):
    if isinstance(v, dict):
        if depth >= 3:
            return {'_nested_keys': list(v), '_values_omitted': True}
        return {k: compact(w, depth + 1) for k, w in v.items()}
    if isinstance(v, list):
        return {'_count': len(v), '_first2': [compact(w, depth + 1) for w in v[:2]],
                '_remaining_omitted': len(v) > 2}
    if isinstance(v, str) and len(v) > 512:
        return {'_characters': len(v), '_prefix512': v[:512], '_remaining_omitted': True}
    return v


def main():
    own_reads = []
    for name in ('read_small_evidence.py', 'read_small_evidence_v2.py'):
        p = HERE / name
        s = p.stat()
        raw = p.read_bytes()
        if len(raw) != s.st_size or ident(s) != ident(p.stat()):
            raise ValueError('Failed-source pin changed')
        own_reads.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                          'stat': ident(s)})
    failed_v1_size = own_reads[0]['bytes']
    # v2 read the v1 source once before completing its second 30-file pass.
    prior = FIRST * 2 + failed_v1_size
    own_bytes = sum(r['bytes'] for r in own_reads)
    pre = [(n, ROOT / n, (ROOT / n).stat()) for n in PATHS]
    planned = sum(s.st_size for _, _, s in pre)
    if planned != 154388 or prior + own_bytes + planned + 65536 > CAP:
        raise ValueError('Final narrow input and closure reserve cap')
    views = {}
    receipts = []
    read_bytes = 0
    for name, p, initial in pre:
        if ident(initial) != ident(p.stat()):
            raise ValueError('Input changed since bounded preflight')
        with p.open('rb') as f:
            raw = f.read(initial.st_size + 1)
        read_bytes += len(raw)
        if len(raw) != initial.st_size or ident(initial) != ident(p.stat()):
            raise ValueError('Input length/stat changed')
        receipts.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                         'stat': ident(initial), 'mode': oct(initial.st_mode & 0o777)})
        text = raw.decode()
        if p.suffix == '.json':
            obj = json.loads(text)
            view = obj if len(raw) < 32768 else compact(obj)
            views[name] = {'view': view, 'complete_content_view': len(raw) < 32768}
            print(json.dumps({'path': name, 'sha256': receipts[-1]['sha256'], 'view': view}, ensure_ascii=False))
        else:
            views[name] = {'text': text, 'complete_content_view': True}
            print(json.dumps({'path': name, 'sha256': receipts[-1]['sha256'], 'text': text}, ensure_ascii=False))
    packed = gzip.compress((json.dumps(views, ensure_ascii=False, sort_keys=True) + '\n').encode(), mtime=0)
    if len(packed) > 16384:
        raise ValueError('Final focused output reserve cap')
    result = {'scope': HERE.name, 'first_failure': 'af531b EXIT1 retained snapshot guard after392843B',
              'second_failure': 'e11856 EXIT1 retained snapshot guard after392843B plus ownv1source',
              'failed_attempt_hash_journals_saved': False, 'first_two_counts_basis':
              'Executed sources reached post-loop guards; exact fixed sizes checked by v2 and this preflight',
              'prior_input_bytes': prior, 'failed_sources_fresh_read_receipts': own_reads,
              'third_narrow_source_bytes': read_bytes, 'raw_input_bytes': prior + own_bytes + read_bytes,
              'raw_input_cap': CAP, 'closure_read_reserve': 65536, 'reads': receipts,
              'cache': {'bytes': len(packed), 'sha256': hashlib.sha256(packed).hexdigest()},
              'no_singlepass_claim': True, 'source_content_compaction_explicit': True,
              'guest_RAM_firmware_IMG_or_producer_import_execution': False,
              'guest_callsite_compile_device_audio_service': False}
    with (HERE / 'selected-evidence-view.json.gz').open('xb') as f:
        f.write(packed)
    with (HERE / 'actual-normal-read-receipts.json').open('x') as f:
        json.dump(result, f, ensure_ascii=False, sort_keys=True, indent=2)
        f.write('\n')
    print(json.dumps({'completed_narrow_pass': True, 'raw_input_bytes': result['raw_input_bytes'],
                      'cache': result['cache'], 'narrow_source_bytes': read_bytes}))


if __name__ == '__main__':
    main()
