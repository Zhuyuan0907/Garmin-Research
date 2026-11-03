"""Seal only own numerical artifacts; no external content reopen."""
from pathlib import Path
import hashlib,json,os,stat
from datetime import datetime,timezone

HERE=Path(__file__).resolve().parent
ROOT=Path('/root/garmin')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    assert not(HERE/'sealed-files.json').exists()
    p=json.loads((HERE/'proof.json').read_text())
    assert p['all_assigned_checks_passed'] is True
    assert p['exact_additional_L4_rows_needed_if_only128bit_L4_shrinks']==184273
    assert p['own_scanner_IMG_MAIN_PBF_CPU_guest_audio_device_reads_execution']==0
    receipt=json.loads((HERE/'input-read-receipts.json').read_text())
    assert receipt['external_artifact_bytes']==54518<=98304 and len(receipt['reads'])==7
    for row in receipt['reads']:
        s=(ROOT/row['path']).stat()
        assert fp(s)==row['stat_after']
        assert stat.S_IMODE(s.st_mode)==int(row['actual_mode'],8)
    ownproofsha=sha((HERE/'proof.json').read_bytes())
    audit=dict(schema='garmin-capacity-review-output-audit/v1',
        all_assigned_checks_passed=True,seven_external_input_stats_stable=True,
        external_content_reopens=0,proof_sha256=ownproofsha,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        source_or_mode_mutations=0,all_handles_closed=True)
    (HERE/'output-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
    (HERE/'sealer-receipt.json').write_text(json.dumps(dict(
        schema='garmin-capacity-review-own-sealer-receipt/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True,external_content_reads=0,
        external_stat_checks=7,actual_modes_preserved_no_chmod=True,
        proof_sha256=ownproofsha,scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,
        all_handles_closed=True,scope_stopped=True),indent=2)+'\n')
    rows=[]
    for path in sorted(HERE.rglob('*')):
        if not path.is_file() or path.name=='sealed-files.json' or '__pycache__' in path.parts:continue
        before=path.stat()
        with path.open('rb') as f:raw=f.read()
        after=path.stat()
        assert fp(before)==fp(after) and len(raw)==before.st_size
        rows.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
                         mode=format(stat.S_IMODE(after.st_mode),'04o'),stat_at_seal=fp(after)))
    assert sum(r['bytes'] for r in rows)<1048576
    seal=dict(schema='garmin-numeric-capacity-independent-review-files/v1',
        all_assigned_checks_passed=True,file_count=len(rows),
        total_bytes=sum(r['bytes'] for r in rows),files=rows,
        hash_size_stat_and_actual_mode_seal=True,readonly_mode_not_implied=True,
        actual_modes_preserved_no_chmod=True,external_artifact_bytes=54518,
        external_artifact_limit_bytes=98304,external_content_reopens=0,
        scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,all_handles_closed=True,scope_stopped=True)
    target=HERE/'sealed-files.json'
    with target.open('x') as f:f.write(json.dumps(seal,indent=2)+'\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(dict(all_assigned_checks_passed=True,files=len(rows),
        proof_sha256=ownproofsha,seal_sha256=sha(target.read_bytes()),
        sealed_bytes=seal['total_bytes'],all_handles_closed=True,
        external_content_reopens=0,scanner_IMG_MAIN_PBF_CPU_guest_audio_device=0,scope_stopped=True)))

if __name__=='__main__':main()
