"""Final seal of own ordinary DATA review; external stat checks, no content reread."""
from pathlib import Path
import hashlib
import json
import os
import stat
from datetime import datetime,timezone

HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')

def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    assert not(HERE/'sealed-files.json').exists()
    proof=json.loads((HERE/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] is True
    assert proof['normal_DATA_scanner_or_runtime_guard_cases_executed'] is False
    assert proof['external_artifact_bytes']==126054<=131072
    receipt=json.loads((HERE/'input-read-receipts.json').read_text())
    assert receipt['external_artifact_bytes']==126054
    assert len(receipt['reads'])==10
    for row in receipt['reads']:
        s=(ROOT/row['path']).stat()
        assert fp(s)==row['stat_after']
        assert oct(stat.S_IMODE(s.st_mode))==row['actual_mode']
    audit=dict(schema='garmin-observer-review-output-audit/v1',
        all_assigned_checks_passed=True,ten_external_input_stats_still_stable=True,
        external_artifact_content_reopens=0,source_mode_chmods=0,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        proof_sha256=sha((HERE/'proof.json').read_bytes()),
        handles_closed=True)
    (HERE/'output-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    sealer=dict(schema='garmin-observer-review-own-sealer-receipt/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,external_input_content_reads=0,
        external_input_stat_checks=10,actual_modes_preserved=True,
        proof_sha256=audit['proof_sha256'],
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        all_handles_closed=True,scope_stopped=True)
    (HERE/'sealer-receipt.json').write_text(json.dumps(sealer,indent=2)+'\n')
    rows=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='sealed-files.json' or '__pycache__' in p.parts:
            continue
        before=p.stat()
        with p.open('rb') as f:raw=f.read()
        after=p.stat()
        assert fp(before)==fp(after) and len(raw)==before.st_size
        rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(after.st_mode),'04o'),stat_at_seal=fp(after)))
    assert sum(row['bytes'] for row in rows)<1048576
    seal=dict(schema='garmin-independent-observer-review-files/v1',
        all_assigned_checks_passed=True,created_utc=datetime.now(timezone.utc).isoformat(),
        file_count=len(rows),total_bytes=sum(row['bytes'] for row in rows),files=rows,
        hash_size_stat_and_actual_mode_seal=True,readonly_mode_not_implied=True,
        external_content_reads=126054,external_content_limit=131072,
        scanner_runtimeguard_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        actual_modes_preserved_no_chmod=True,all_handles_closed=True,scope_stopped=True)
    path=HERE/'sealed-files.json'
    with path.open('x') as f:
        f.write(json.dumps(seal,indent=2)+'\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(rows),
        proof_sha256=audit['proof_sha256'],seal_sha256=sha(path.read_bytes()),
        total_sealed_bytes=seal['total_bytes'],external_content_reopens=0,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,all_handles_closed=True,
        scope_stopped=True)))

if __name__=='__main__':main()
