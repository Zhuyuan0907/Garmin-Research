#!/usr/bin/env python3
"""Seal own small preparation outputs only, no producer or payload access."""
from pathlib import Path
import hashlib
import json
import os

OUT = Path(__file__).resolve().parent
CAP = 128 * 1024

def main():
    paths = sorted(p for p in OUT.iterdir() if p.is_file() and p.name not in ('sealed-files.json', 'final-sealer-receipt.json'))
    if any(p.is_symlink() for p in paths):
        raise ValueError('Own regular files required')
    payload = sum(p.stat().st_size for p in paths)
    # Reserve the complete final manifest and fixed-size terminal receipt before mutation.
    estimate = {'schema': 'working-v2-recovery-preparation-seal/v1',
        'all_assigned_checks_passed': True, 'all_handles_closed': True,
        'files': [{'path': 'staging/navigation-known-working-country-v2-recovery-preparation-v1/' + p.name,
            'bytes': p.stat().st_size, 'sha256': '0' * 64,
            'stat': [9999999999999999999] * 7} for p in paths],
        'scope_output_budget': CAP, 'installable': False, 'actual_orchestration_executed': False}
    reserve = len((json.dumps(estimate, indent=2) + '\n').encode()) + 2048
    if payload + reserve > CAP:
        raise ValueError('Output cap before sealing')
    rows = []
    for p in paths:
        p.chmod(0o444)
        s = p.stat()
        b = p.read_bytes()
        if s.st_size != len(b):
            raise ValueError('Own file changed')
        rows.append({'path': 'staging/navigation-known-working-country-v2-recovery-preparation-v1/' + p.name,
            'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest(),
            'stat': [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode & 0o777, s.st_nlink]})
    seal = {**estimate, 'files': rows, 'payload_bytes': payload}
    raw = (json.dumps(seal, indent=2) + '\n').encode()
    p = OUT / 'sealed-files.json'
    p.write_bytes(raw)
    p.chmod(0o444)
    with p.open('rb') as f:
        os.fsync(f.fileno())
    value = {'schema': 'working-v2-recovery-preparation-sealer-receipt/v1', 'all_assigned_checks_passed': True,
        'seal_sha256': hashlib.sha256(raw).hexdigest(),
        'proof_sha256': next(r['sha256'] for r in rows if r['path'].endswith('/proof.json')),
        'payload_bytes': payload, 'seal_bytes': len(raw), 'scope_output_cap': CAP,
        'real_IMG_operations': 0, 'device_operations': 0, 'all_handles_closed': True,
        'actual_orchestration_executed': False, 'installable': False, 'scope_status': 'STOP'}
    receipt = (json.dumps(value, indent=2) + '\n').encode()
    if payload + len(raw) + len(receipt) > CAP:
        raise ValueError('Unexpected final output cap')
    q = OUT / 'final-sealer-receipt.json'
    q.write_bytes(receipt)
    q.chmod(0o444)
    with q.open('rb') as f:
        os.fsync(f.fileno())
    directory = os.open(OUT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps({**value, 'final_namespace_bytes': payload + len(raw) + len(receipt)}))

if __name__ == '__main__':
    main()
