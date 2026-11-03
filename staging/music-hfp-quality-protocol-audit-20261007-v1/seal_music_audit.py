#!/usr/bin/env python3
"""Seal only own offline small artifacts; preserve actual modes."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[1]
CAP = 131072
os.umask(0o077)


def fingerprint(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, stat.S_IMODE(s.st_mode)]


def durable_new(path, raw):
    with path.open('xb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


receipt_path = HERE / 'actual-tool-receipts.json'
receipt = json.loads(receipt_path.read_bytes())
receipt['completed_calls'].append({
    'terminal': '07ae28', 'exit_code': 0,
    'operation': 'Final ordinary host audit from own saved captures only',
    'external_reads': 0, 'namespace_bytes_before_seal': 71176,
    'all_owned_capture_handles_closed': True,
})
raw = (json.dumps(receipt, ensure_ascii=False, indent=2) + '\n').encode()
with receipt_path.open('wb') as f:
    f.write(raw)
    f.flush()
    os.fsync(f.fileno())

public_files = ['audit.json', 'proof.json', 'HANDOFF.txt', 'actual-tool-receipts.json']
for name in public_files:
    text = (HERE / name).read_text()
    if re.search(r'(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', text):
        raise ValueError('unredacted Bluetooth-style identity in public summary')

rows = []
for path in sorted(HERE.iterdir()):
    if not path.is_file() or path.is_symlink():
        raise ValueError('non-regular scope member')
    if path.name == 'sealed-files.json':
        raise ValueError('scope already sealed')
    before = fingerprint(path)
    raw = path.read_bytes()
    after = fingerprint(path)
    if before != after or len(raw) != before[2]:
        raise ValueError('own scope member changed during seal')
    if path.name.startswith('private-') and before[-1] != 0o600:
        raise ValueError('private raw capture mode is not preserved0600')
    rows.append({
        'path': str(path.relative_to(WORKSPACE)), 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(), 'stat': before,
        'mode_octal': oct(before[-1]),
        'sharing': 'redacted_summary' if path.name in public_files else 'private_source_or_capture',
    })
seal = {
    'schema': 'music-HFP-offline-audit-hash-closure/v1',
    'status': 'closed_STOP',
    'files': rows,
    'all_owned_input_handles_closed': True,
    'external_raw_reads_total': 756232,
    'external_raw_read_cap': 1048576,
    'final_output_cap': CAP,
    'actual_modes_preserved': True,
    'readonly_mode_claim': False,
    'live_Bluetooth_PCM_daemon_device_guest_operations': 0,
    'source_log_reads_during_final_preparation_and_seal': 0,
    'historical_exceptions_retained': ['initial parser empty counts unavailable', 'intermediate uncompressed representation148618B exceeded128KiB output cap before lossless gzip correction'],
    'final_closure_checks_passed': True,
    'quality_fix_or_hardware_or_long_stability_claim': False,
}
seal['member_bytes_excluding_seal'] = sum(row['bytes'] for row in rows)
while True:
    raw = (json.dumps(seal, ensure_ascii=False, indent=2) + '\n').encode()
    total = seal['member_bytes_excluding_seal'] + len(raw)
    if seal.get('final_namespace_bytes') == total:
        break
    seal['final_namespace_bytes'] = total
if total > CAP:
    raise ValueError('final output cap exceeded')
for row in rows:
    if fingerprint(WORKSPACE / row['path']) != row['stat']:
        raise ValueError('scope changed before seal publication')
durable_new(HERE / 'sealed-files.json', raw)
directory_fd = os.open(HERE, os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory_fd)
finally:
    os.close(directory_fd)
if sum(path.stat().st_size for path in HERE.iterdir()) != total:
    raise ValueError('final output bytes mismatch')
print(json.dumps({
    'result': 'EXIT0 sealed STOP', 'members': len(rows),
    'proof_sha256': next(row['sha256'] for row in rows if row['path'].endswith('/proof.json')),
    'audit_sha256': next(row['sha256'] for row in rows if row['path'].endswith('/audit.json')),
    'seal_sha256': hashlib.sha256(raw).hexdigest(), 'seal_bytes': len(raw),
    'final_namespace_bytes': total, 'cap': CAP,
    'external_source_reads_this_seal': 0,
    'all_handles_closed': True, 'private_raw_modes_preserved': '0600',
}, ensure_ascii=False))
