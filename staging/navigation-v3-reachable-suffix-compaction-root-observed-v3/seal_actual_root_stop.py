#!/usr/bin/env python3
"""Close root's actual receipt; preserve presealed preparation files/stat."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os

ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent

def sha(raw):return hashlib.sha256(raw).hexdigest()

def save(name,obj):
    raw=json.dumps(obj,ensure_ascii=False,indent=2).encode()+b'\n'
    with (HERE/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))

def main():
    assert not (HERE/'proof.json').exists()
    prepraw=(HERE/'prepared-files.json').read_bytes()
    assert sha(prepraw)=='d1082be32fa78cab592bf5f978a5889ca038cc8772160409b23fd582de2e91fa'
    prep=json.loads(prepraw)
    for row in prep['files']:
        p=ROOT/row['path'];raw=p.read_bytes();s=p.stat()
        assert len(raw)==row['bytes'] and sha(raw)==row['sha256']
        assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==row['stat_at_seal']
        assert s.st_mode&0o777==0o444
    rr=(HERE/'actual-root-tool-receipt.json').read_bytes()
    assert sha(rr)=='d2e5a1ed8b5b786fd0a9eaa14781e1d8d7e708abbfd0181d5e8edc1a66738aa4'
    rootreceipt=json.loads(rr);assert rootreceipt['exit_code']==1 and rootreceipt['chunk_id']=='19798a'
    raw=(HERE/'actual-failure.json').read_bytes()
    assert sha(raw)=='9c2e22b5ccfe05c5b3667e621a3475a8e9f154a689878dabadfaa08fea62fbd4'
    failure=json.loads(raw)
    phase=(HERE/'actual-phase-observations.jsonl').read_bytes()
    assert sha(phase)=='aff0d3b424bf5474542b40eabcffbf71c7d61efa4e34e194eeaae18ebfe31cfa'
    rows=[json.loads(line) for line in phase.splitlines()]
    assert len(rows)==2 and rows[0]['ru_maxrss_KiB']==424240 and rows[0]['proc_status']['VmRSS_KiB']==17824
    assert rows[0]['proc_status']['VmHWM_KiB']==17824 and rows[0]['RSS_cap_KiB']==393216
    assert failure['source_inputs']==[] and failure['actual_IMG_bytes_read']==0 and failure['actual_IMG_read_ops']==0
    assert failure['source_handle_closed'] and not failure['actual_MDR_stream_started']
    proof=save('proof.json',dict(schema='garmin-v3-root-context-actual-observed-stop-proof/v3',
        created_utc=datetime.now(timezone.utc).isoformat(),actual_failure_and_observability_sealed=True,
        actual_normal_DATA_program_exit_code=1,actual_terminal='19798a',all_reachability_feasibility_checks_passed=False,
        own_python_budget_exception_not_platform_or_approval_or_system_risk=True,
        initial_actual_historical_ru_maxrss_KiB=424240,current_VmRSS_KiB=17824,current_VmHWM_KiB=17824,
        numeric_RSS_guard_KiB=393216,actual_IMG_bytes_read=0,actual_IMG_read_ops=0,
        no_source_IMG_handle_mapper_or_field_array_or_MDR_stream_executed=True,
        execution_context_low_baseline_assumption_not_verified=True,physical_RAM_shortage_not_inferred=True,
        original_preparation_files_and_source_bytes_and_stat_preserved=True,
        original_preparation_manifest=dict(path=str((HERE/'prepared-files.json').relative_to(ROOT)),bytes=len(prepraw),sha256=sha(prepraw)),
        actual_root_receipt=dict(path=str((HERE/'actual-root-tool-receipt.json').relative_to(ROOT)),bytes=len(rr),sha256=sha(rr)),
        actual_failure=dict(path=str((HERE/'actual-failure.json').relative_to(ROOT)),bytes=len(raw),sha256=sha(raw)),
        actual_observations=dict(path=str((HERE/'actual-phase-observations.jsonl').relative_to(ROOT)),rows=2,bytes=len(phase),sha256=sha(phase)),
        source_IMG_stat_after_inherited_from_failure_stat_only=failure['source_stat_after'],
        guard_raised_removed_skipped_or_counter_reset=False,closed_scanner_replayed=False,
        v4_measurement_revision_or_scanner_not_executed_in_this_scope=True,
        new_IMG_or_MAIN_guest_audio_PBF_bigsourceledger_or_device_IO=False,
        original_shared_IMG_seal_report_or_canonical_modified=False,
        all_own_and_source_handles_closed=True,compression_native_UI_renderer_or_install_success_verified=False))
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        # Never chmod an already sealed/prepared file: that would change ctime.
        if path.stat().st_mode&0o777!=0o444:path.chmod(0o444)
        raw=path.read_bytes();s=path.stat()
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',
            stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
    for row in prep['files']:
        s=(ROOT/row['path']).stat()
        assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]==row['stat_at_seal']
    seal=save('sealed-files.json',dict(schema='garmin-v3-root-context-actual-stop-seal/v3',
        actual_root_attempt_exit_code=1,actual_terminal='19798a',actual_failure_evidence_and_observability_preserved=True,
        all_reachability_feasibility_checks_passed=False,actual_IMG_bytes_read=0,
        original_presealed_preparation_files_byte_and_stat_unchanged=True,
        no_retry_or_guard_raise_or_counter_reset=True,files=files,file_count=len(files),
        all_own_and_source_handles_closed=True,IMG_or_device_IO_during_sealer=False,scope_stopped=True))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(actual_stop_sealed=True,proof_sha256=proof['sha256'],seal_sha256=seal['sha256'],
        file_count=len(files),preparation_files_unchanged=True,source_handles_closed=True)))

if __name__=='__main__':main()
