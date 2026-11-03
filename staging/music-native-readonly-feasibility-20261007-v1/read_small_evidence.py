#!/usr/bin/env python3
"""Finite ordinary-file capture; no reviewed producer imports or execution."""
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
INPUT_CAP = 1048576
OUTPUT_CAP = 131072
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
    'staging/native-os20-source-ready-v1/HANDOFF.md',
    'staging/native-os20-worker-fifo-v1/HANDOFF.md',
    'staging/native-os20-mixer-allocator-v1/HANDOFF.md',
    'staging/native-os20-resident-music-v2/guest-proof.json',
    'evidence/firmware-analysis/sdp-service-templates.json',
    'evidence/firmware-analysis/sdp-activation.json',
    'evidence/firmware-analysis/native-music-endpoint-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-gate-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-policy-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-reply-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-dispatch-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-continuous-checkpoint-audit.json',
    'evidence/firmware-analysis/native-music-ready-checkpoint-audit.json',
    'staging/native-avdtp-reply-admission/ROOT-native-reply-admission-file-proof-v2.json',
    'staging/native-avdtp-reply-admission/native-reply-admission-v5-six-controls-proof.json',
    'evidence/native-marker-physical-positive-20261005.json',
    'evidence/native-marker-physical-original-control-20261005T044607Z.json',
    'evidence/native-marker-original-voice-restore-20261005.json',
    'native/ui-music-native-adapter/ADAPTER_BINDING.md',
    'native/ui-music-control-prototype/ADAPTER_CONTRACT.md',
    'staging/ui-music-control-prototype/verification.json',
]


def identity(s):
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    pre = []
    for name in PATHS:
        p = ROOT / name
        s = p.stat()
        if s.st_size > 98304:
            raise ValueError('Only predetermined small evidence files are permitted')
        pre.append((name, p, s))
    planned = sum(s.st_size for _, _, s in pre)
    if planned > INPUT_CAP:
        raise ValueError('Input preflight cap')
    capture = {}
    receipts = []
    total = 0
    for name, p, initial in pre:
        current = p.stat()
        if identity(current) != identity(initial):
            raise ValueError('Input changed since preflight')
        with p.open('rb') as f:
            raw = f.read(initial.st_size + 1)
        total += len(raw)
        if total > INPUT_CAP or len(raw) != initial.st_size:
            raise ValueError('Input budget/length')
        final = p.stat()
        if identity(initial) != identity(final):
            raise ValueError('Input changed across normal read')
        value = raw.decode('utf-8')
        if p.suffix == '.json':
            json.loads(value)
        capture[name] = value
        receipts.append({'path': name, 'bytes': len(raw),
                         'sha256': hashlib.sha256(raw).hexdigest(),
                         'stat': identity(final), 'mode': oct(final.st_mode & 0o777)})
    decoded = (json.dumps(capture, ensure_ascii=False, sort_keys=True) + '\n').encode()
    compressed = gzip.compress(decoded, mtime=0)
    if len(compressed) > 65536:
        raise ValueError('Small retained capture cap')
    result = {
        'scope': HERE.name, 'phase': 'finite normal file capture',
        'read_count': len(receipts), 'raw_input_bytes': total,
        'raw_input_cap': INPUT_CAP, 'output_cap': OUTPUT_CAP,
        'reads': receipts,
        'cache': {'path': 'small-evidence-source-capture.json.gz',
                  'bytes': len(compressed), 'sha256': hashlib.sha256(compressed).hexdigest(),
                  'decoded_bytes': len(decoded), 'decoded_sha256': hashlib.sha256(decoded).hexdigest()},
        'guest_RAM_firmware_IMG_or_recipe_read': False,
        'reviewed_producer_import_or_execution': False,
        'guest_callsite_patch_compile_device_audio_service': False,
    }
    result_raw = (json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode()
    if len(compressed) + len(result_raw) + Path(__file__).stat().st_size > OUTPUT_CAP:
        raise ValueError('Output preflight cap')
    with (HERE / 'small-evidence-source-capture.json.gz').open('xb') as f:
        f.write(compressed)
    with (HERE / 'actual-normal-read-receipts.json').open('xb') as f:
        f.write(result_raw)
    print(json.dumps({'raw_input_bytes': total, 'cache': result['cache'],
                      'read_receipt_bytes': len(result_raw), 'all30_normal_reads_completed': True}))


if __name__ == '__main__':
    main()
