#!/usr/bin/env python3
"""Seal only this completed scope; source and captured proofs are not rerun."""
from pathlib import Path
import hashlib
import json

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    assert not (HERE/'sealed-files.json').exists()
    proof = json.loads((HERE/'proof.json').read_bytes())
    assert proof['assigned_bounded_checks_passed'] and proof['all_scope_handles_closed']
    assert proof['durable_original_guest_cases'] == 3
    assert not proof['AP_physical_opener_proved']
    assert not proof['v3_road_regression_rootcause_proved']
    rows = []
    for p in sorted(HERE.iterdir()):
        assert p.is_file(), str(p)
        b = p.read_bytes()
        p.chmod(0o444)
        assert p.stat().st_mode & 0o777 == 0o444
        rows.append(dict(path=str(p.relative_to(ROOT)), bytes=len(b), sha256=sha(b), mode='0444'))
    out = dict(schema='garmin-bounded-readonly-scope-seal/v1',
        scope=str(HERE.relative_to(ROOT)), files=rows, file_count=len(rows),
        all_assigned_checks_passed=True,
        all_assigned_checks_scope='bounded captured-byte audit and three durable original guards; unresolved physical opener/overlay/rootcause explicitly retained',
        scope_closed_with_gaps=True, all_handles_closed=True,
        device_or_shared_source_mutation=False, full_goal_completed=False)
    p = HERE/'sealed-files.json'
    p.write_text(json.dumps(out, indent=2) + '\n')
    p.chmod(0o444)
    print(json.dumps(dict(sealed_files=str(p.relative_to(ROOT)), sha256=sha(p.read_bytes()),
        files=len(rows), bytes=sum(r['bytes'] for r in rows), all_modes='0444',
        proof_sha256=sha((HERE/'proof.json').read_bytes()),
        witness_sha256=sha((HERE/'actual-call-chain-witnesses.json').read_bytes()),
        all_handles_closed=True, closed_with_gaps=True)))


if __name__ == '__main__':
    main()
