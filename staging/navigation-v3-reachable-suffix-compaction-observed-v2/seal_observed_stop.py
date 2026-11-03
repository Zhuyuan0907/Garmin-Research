#!/usr/bin/env python3
"""Finalize exact observed preparation stop; no data scanner or IMG read."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os

ROOT=Path('/root/garmin'); HERE=Path(__file__).resolve().parent

def sha(raw):return hashlib.sha256(raw).hexdigest()

def save(name,obj):
    raw=json.dumps(obj,ensure_ascii=False,indent=2).encode()+b'\n'
    with (HERE/name).open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    return dict(path=str((HERE/name).relative_to(ROOT)),bytes=len(raw),sha256=sha(raw))

def main():
    assert not (HERE/'proof.json').exists()
    p=HERE/'observed_analyzer.py';raw=p.read_bytes()
    assert sha(raw)=='6bf697390bf3440843cd33257c99e9c4de05d828b23122506cf4906d38fcd943'
    fraw=(HERE/'actual-failure.json').read_bytes();failure=json.loads(fraw)
    observations=(HERE/'actual-phase-observations.jsonl').read_bytes()
    rows=[json.loads(line) for line in observations.splitlines()]
    assert len(rows)==2
    first=rows[0]
    assert first['phase']=='initial before any input parse or field array allocation'
    assert first['ru_maxrss_KiB']==424240 and first['RSS_cap_KiB']==393216
    assert first['proc_status']=={'VmHWM_KiB':17824,'VmPeak_KiB':28672,'VmRSS_KiB':17824,'VmSize_KiB':28608}
    assert failure['actual_RSS_guard_value_KiB']==424240 and failure['actual_IMG_bytes_read']==0
    assert failure['source_inputs']==[] and failure['source_stat_before'] is None
    assert failure['source_handle_closed'] and not failure['actual_MDR_stream_started']
    # Small source identity read during finalization, never its main or IMG data.
    prep_pins=[]
    for path,pin in [
      ('staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py','a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274'),
      ('staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/sealed-files.json','2dd746f8a1286cecd31b68c79726a5009a2536a9eb757a4863be4b359caee442'),
      ('staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py','a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095')]:
        q=ROOT/path;raw=q.read_bytes();assert len(raw)<40000 and sha(raw)==pin
        prep_pins.append(dict(path=path,bytes=len(raw),sha256=pin,only_small_source_identity_read=True,
                              historical_main_or_CPU_not_executed=True))
    receipt=save('actual-execution-receipt.json',dict(schema='garmin-observed-data-preparation-actual-exit-receipt/v2',
        command='python3 staging/navigation-v3-reachable-suffix-compaction-observed-v2/observed_analyzer.py',
        actual_terminal='90fb2a',exit_code=1,wall_time_seconds_as_reported_by_tool=0.000022093,
        exception_type='OwnBudgetError',classification='Own Python historical-RSS assertion; not platform/approval/system block',
        initial_phase=first['phase'],actual_ru_maxrss_KiB=424240,actual_guard_KiB=393216,
        actual_current_address_space=first['proc_status'],observed_peak_predates_source_parse_and_arrays=True,
        source_or_launcher_peak_cause_inferred=False,actual_IMG_bytes_read=0,actual_IMG_read_ops=0,
        actual_source_IMG_handle_ever_opened=False,actual_field_arrays_allocated=False,
        actual_source_inputs_read_or_parsed_by_observed_program=False,actual_MDR_scan_started=False,
        actual_threshold_value_phase_and_budget_durable=True,no_retry_or_guard_increase_or_removal=True,
        no_IMG_or_guest_audio_or_device_executed=True))
    proof=save('proof.json',dict(schema='garmin-v3-observed-preparation-stop-proof/v2',created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_preparation_observability_checks_completed=True,full_reachability_feasibility_checks_passed=False,
        actual_program_exit_code=1,actual_terminal='90fb2a',own_assertion_not_system_platform_or_autoapproval=True,
        failed_source=dict(path=str(p.relative_to(ROOT)),bytes=p.stat().st_size,sha256='6bf697390bf3440843cd33257c99e9c4de05d828b23122506cf4906d38fcd943'),
        actual_phase_and_memory=first,actual_guard_value_KiB=424240,actual_guard_threshold_KiB=393216,
        current_VmRSS_and_VmHWM_KiB=17824,ru_maxrss_is_historical_peak=True,
        actual_guard_unit_and_threshold_unchanged=True,peak_cause_not_inferred=True,
        actual_IMG_read_bytes=0,actual_IMG_read_ops=0,actual_IMG_read_cap=160000000,
        actual_small_input_reads_or_mapper_parsing_or_field_array_allocation_before_stop=False,
        source_IMG_handle_never_opened=True,actual_MDR_stream_bytes=0,
        active_poststock_counts_remap_groups_or_compacted_size_not_computed=True,
        stock_prefix_plan_and_whole_v2prefix_plan_results=None,
        external_lower_record_ID_reference_ABIs_unknown=True,L3_JAI_ID_preservation_plan_unexecuted=True,
        original_closed_failed_scope_and_all_shared_seals_unmodified=True,
        small_original_source_identity_pins=prep_pins,
        root_independent_buffer_diagnostic_is_different_scope_not_full_algorithm_peak=True,
        artifacts=dict(execution=receipt,observations=dict(path=str((HERE/'actual-phase-observations.jsonl').relative_to(ROOT)),
          rows=2,bytes=len(observations),sha256=sha(observations)),
          original_failure=dict(path=str((HERE/'actual-failure.json').relative_to(ROOT)),bytes=len(fraw),sha256=sha(fraw))),
        same_numeric_RSS_cap_maintained=True,retry_or_guard_raise_or_removed=False,
        MAIN_nativeCPU_guest_PBF_bigsourceledger_audio_or_device_IO=0,new_IMG_fulltables_or_remapped_records_written=False,
        original_IMG_seal_report_or_canonical_modified=False,all_own_and_source_handles_closed=True,
        native_UI_renderer_fix_or_install_acceptance_proven=False,full_Taiwan_complete=False,
        next_scope_needed='Separate explicit choice of historical-peak versus current-address-space budget accounting; this scope does not alter the guard'))
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        path.chmod(0o444);raw=path.read_bytes();s=path.stat()
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',
            stat_at_seal=[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]))
    assert sum(r['bytes'] for r in files)<1048576
    seal=save('sealed-files.json',dict(schema='garmin-v3-observed-preparation-stop-seal/v2',
        all_assigned_observability_checks_completed=True,all_reachability_feasibility_checks_passed=False,
        actual_program_exit_code=1,actual_terminal='90fb2a',observed_initial_ru_maxrss_KiB=424240,
        current_VmRSS_KiB=17824,unchanged_guard_KiB=393216,actual_IMG_bytes_read=0,
        actual_platform_or_system_or_approval_interruption=False,source_failed_program_and_failure_preserved=True,
        no_retry_or_guard_removal_or_raise=True,files=files,file_count=len(files),total_bytes=sum(r['bytes'] for r in files),
        all_own_and_source_handles_closed=True,IMG_or_device_IO_during_sealer=False,scope_stopped=True))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(observed_stop_sealed=True,proof_sha256=proof['sha256'],seal_sha256=seal['sha256'],
        file_count=len(files),total_bytes=sum(r['bytes'] for r in files),actual_IMG_bytes_read=0,handles_closed=True)))

if __name__=='__main__':main()
