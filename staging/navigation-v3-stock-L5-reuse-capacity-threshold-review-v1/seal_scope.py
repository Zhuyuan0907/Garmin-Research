"""Seal own small numeric artifacts; no external content reread or chmod."""
from pathlib import Path
import hashlib,json,os,stat
from datetime import datetime,timezone

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    assert not(HERE/'sealed-files.json').exists()
    proof=json.loads((HERE/'proof.json').read_text())
    assert proof['all_assigned_checks_passed'] is True
    assert proof['exact_minimum_additional_L5_rows_saved']==77245
    assert proof['own_scanner_IMG_MAIN_PBF_CPU_guest_audio_device']==0
    receipt=json.loads((HERE/'input-read-receipts.json').read_text())
    assert receipt['external_artifact_bytes']==27380<=98304 and len(receipt['reads'])==6
    for row in receipt['reads']:
        s=(ROOT/row['path']).stat()
        assert fp(s)==row['stat_after']
        assert stat.S_IMODE(s.st_mode)==int(row['actual_mode'],8)
    digest=sha((HERE/'proof.json').read_bytes())
    audit=dict(all_assigned_checks_passed=True,six_external_input_stats_stable=True,
        external_content_reopens=0,source_mode_changes=0,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,proof_sha256=digest,
        all_handles_closed=True)
    (HERE/'output-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    (HERE/'sealer-receipt.json').write_text(json.dumps(dict(
        schema='garmin-stock-L5-threshold-own-sealer/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        external_content_reads=0,external_stat_checks=6,actual_modes_preserved_no_chmod=True,
        proof_sha256=digest,scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        all_handles_closed=True,scope_stopped=True),indent=2)+'\n')
    rows=[]
    for p in sorted(HERE.rglob('*')):
        if not p.is_file() or p.name=='sealed-files.json' or '__pycache__' in p.parts:continue
        before=p.stat()
        with p.open('rb') as f:raw=f.read()
        after=p.stat();assert fp(before)==fp(after) and len(raw)==before.st_size
        rows.append(dict(path=str(p.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(after.st_mode),'04o'),stat_at_seal=fp(after)))
    seal=dict(schema='garmin-stock-L5-capacity-threshold-review-seal/v1',
        all_assigned_checks_passed=True,file_count=len(rows),total_bytes=sum(r['bytes'] for r in rows),
        files=rows,hash_size_stat_and_actual_mode_seal=True,readonly_mode_not_implied=True,
        actual_modes_preserved_no_chmod=True,external_artifact_bytes=27380,
        external_limit_bytes=98304,scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        all_handles_closed=True,scope_stopped=True)
    assert seal['total_bytes']<1048576
    target=HERE/'sealed-files.json'
    with target.open('x') as f:f.write(json.dumps(seal,indent=2)+'\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(all_assigned_checks_passed=True,file_count=len(rows),
        proof_sha256=digest,seal_sha256=sha(target.read_bytes()),
        total_sealed_bytes=seal['total_bytes'],external_content_reopens=0,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,all_handles_closed=True,scope_stopped=True)))

if __name__=='__main__':main()
