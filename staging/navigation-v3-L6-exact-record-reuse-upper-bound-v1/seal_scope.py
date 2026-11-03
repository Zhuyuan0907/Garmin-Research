"""Own final hash/stat/mode seal; no source IMG reopen or rescanning."""
from pathlib import Path
import hashlib,json,os,stat
from datetime import datetime,timezone

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(raw):return hashlib.sha256(raw).hexdigest()
def fp(s):return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]

def main():
    assert not(HERE/'sealed-files.json').exists()
    p=json.loads((HERE/'proof.json').read_text())
    assert p['all_assigned_checks_passed'] is True
    assert p['actual_IMG_bytes']==17604590<=p['actual_IMG_cap']==20000000
    assert p['sampled_current_mm_peak_KiB']==36512<=131072
    assert p['actual_target_dict_bytes']==10968080<33554432
    assert p['optimistic_L6_savings_upper_bound']==73772
    assert p['exact_L6_capacity_savings_required']==71359
    assert p['safe_actual_group_reuse_or_compactor_ready'] is False
    assert p['source_stat_before']==p['source_stat_after']
    start=json.loads((HERE/'actual-run-start.json').read_text())
    assert start['source_sha256']==sha((HERE/'measure_upper_bound.py').read_bytes())
    assert sha((HERE/'proof.actual-run.json').read_bytes())=='a5c8d753f2b11e26eed66ff16d475afb872f2fd6d045b6a55cef8a04a36874ce'
    assert json.loads((HERE/'output-audit.json').read_text())['all_assigned_checks_passed'] is True
    receipt=json.loads((HERE/'input-read-receipts.json').read_text())
    assert receipt['external_artifact_bytes']==82983 and len(receipt['reads'])==7
    for row in receipt['reads']:
        s=(ROOT/row['path']).stat();assert fp(s)==row['stat_after']
        assert stat.S_IMODE(s.st_mode)==int(row['mode'],8)
    proofsha=sha((HERE/'proof.json').read_bytes())
    (HERE/'sealer-receipt.json').write_text(json.dumps(dict(
        schema='garmin-L6-upper-bound-own-sealer/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,
        external_artifact_content_reopens=0,source_IMG_reopens_or_statchecks=0,
        measured_source_exactSHA_unchanged=True,actual_modes_preserved_no_chmod=True,
        proof_sha256=proofsha,all_handles_closed=True,scope_stopped=True),indent=2)+'\n')
    rows=[]
    for f in sorted(HERE.rglob('*')):
        if not f.is_file() or f.name=='sealed-files.json' or '__pycache__' in f.parts:continue
        before=f.stat()
        with f.open('rb') as handle:raw=handle.read()
        after=f.stat();assert fp(before)==fp(after) and len(raw)==before.st_size
        rows.append(dict(path=str(f.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),
            mode=format(stat.S_IMODE(after.st_mode),'04o'),stat_at_seal=fp(after)))
    seal=dict(schema='garmin-L6-upper-bound-closed-files/v1',
        all_assigned_checks_passed=True,file_count=len(rows),total_bytes=sum(r['bytes'] for r in rows),
        files=rows,hash_size_stat_and_actual_mode_seal=True,readonly_mode_not_implied=True,
        actual_IMG_read_bytes=17604590,actual_IMG_cap=20000000,
        current_mm_peak_KiB=36512,current_mm_cap_KiB=131072,
        target_dict_bytes=10968080,target_dict_cap_bytes=33554432,
        source_write_or_MAIN_native_CPU_guest_PBF_audio_device_IO=0,
        raw_keys_coordinates_private_addresses_or_IDs_output=False,
        all_handles_closed=True,scope_stopped=True)
    assert seal['total_bytes']<1048576
    target=HERE/'sealed-files.json'
    with target.open('x') as out:out.write(json.dumps(seal,indent=2)+'\n');out.flush();os.fsync(out.fileno())
    print(json.dumps(dict(all_assigned_checks_passed=True,files=len(rows),
        total_sealed_bytes=seal['total_bytes'],proof_sha256=proofsha,
        seal_sha256=sha(target.read_bytes()),source_IMG_reopens=0,
        all_handles_closed=True,scope_stopped=True)))

if __name__=='__main__':main()
