#!/usr/bin/env python3
"""Preserve finite failed-attempt evidence; no IMG open or rerun."""
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
    source=HERE/'analyze_reachable.py';raw=source.read_bytes()
    assert sha(raw)=='a1a7a9c94df6a8b715eca28366a9c94ed8895d6e0176fd05a4f076d506beb274'
    failure=HERE/'actual-failure.json';fraw=failure.read_bytes()
    assert json.loads(fraw)['error']=='Bounded RSS guard'
    candidate=ROOT/'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
    s=candidate.stat() # stat only; no IMG handle, bytes, hash or link mutation.
    status=dict(dev=s.st_dev,ino=s.st_ino,bytes=s.st_size,mtime_ns=s.st_mtime_ns,
                ctime_ns=s.st_ctime_ns,nlink=s.st_nlink,mode=oct(s.st_mode&0o777))
    assert [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns]==[45826,538039,153346048,1791317242895661512]
    assert s.st_nlink==2 and status['mode']=='0o444'
    receipt=save('actual-execution-receipt.json',dict(schema='garmin-data-reachability-actual-failed-attempt-receipt/v1',
        actual_command='python3 staging/navigation-v3-reachable-suffix-compaction-feasibility-v1/analyze_reachable.py',
        terminal_chunk='9ada66',exit_code=1,wall_time_seconds_as_reported_by_tool=0.000020852,
        failure_classification='own Python RSS-budget assertion, not tool-platform/system/approval interruption',
        exception_type='ValueError',message='Bounded RSS guard',
        guard_source='analyze_reachable.py:45 rss() → need(value<=RSS_CAP_KIB)',
        measurement_method='resource.getrusage(resource.RUSAGE_SELF).ru_maxrss',
        measurement_is_historical_peak_not_current_RSS=True,guard_KiB=393216,
        actual_guard_value=None,actual_guard_value_not_persisted=True,
        assertion_observed_value_above_guard=True,launcher_peak_or_actual_allocation_cause_unresolved=True,
        physical_RAM_exhaustion_proved=False,actual_metadata_read_counter_not_persisted=True,
        metadata_read_upper_bound_bytes=200000,metadata_read_bytes_derived_from_pinned_layout=70144,
        derived_metadata_bytes_not_saved_actual_counter=True,actual_MDR_stream_bytes=0,
        actual_MDR_tables_decoded=0,reachability_or_remap_or_compacted_size_results_obtained=False,
        retry_or_raised_cap_or_source_guard_relaxation=False,
        source_handle_closed_by_with_on_exception=True,candidate_stat_after_stat_only=status,
        source_bytes_reread_during_finalization=False,source_or_device_or_shared_report_modified=False))
    plan=save('finite-plan-and-gap.json',dict(schema='garmin-v3-reachability-finite-unexecuted-plan/v1',
        analysis_status='stopped at own historical-RSS assertion before MDR data stream',
        source_candidate=dict(path=str(candidate.relative_to(ROOT)),bytes=153346048,
          inherited_root_readback_sha256='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
          source_content_stat_pinned_before_open_in_failed_runner=True,failed_before_stat_snapshot_not_persisted=True,
          current_stat_after=status,whole_IMG_hash_not_repeated=True),
        known_layout_from_sealed_small_evidence=dict(MDR_bytes=149220356,L3_count=47870,L3_first_width=23,L3_stride=112,
          current_lower_counts={'4':4896236,'5':3077845,'6':2062771},lower_strides={'4':128,'5':126,'6':68},
          original_stock_counts={'4':2133948,'5':2341096,'6':1973316}),
        memory_plan=dict(fixed_fields_payload_bytes=64175632,fields=['first_uint32','count_uint16','rawflags_uint16'],
          one_based_unused_slot_per_L3_L4_L5_table=True,anticipated_bitsets_bytes=1254608,
          rank_arrays_and_bounded_range_alias_arrays_planned=True,actual_RSS_guard_KiB=393216,
          actual_current_RSS_not_measured=True,actual_peak_RSS_not_saved=True),
        intended_method=['One actual MDR monotonic EOF stream matched to sealed component SHA',
          'Preserve all stock lower prefixes plus all47870 L3 roots; mark valid forward child intervals',
          'Conservatively retain suffixes for invalid/unclassified next-level/range encodings',
          'Retain complete child intervals so overlapping aliases remain contiguous under dense monotonic ID mapping',
          'Quantify unique group and source-parent first-pointer remaps, preserve stock lowIDs and all JAI L3 IDs',
          'Calculate same-profile six-component4K capacity with GMP and other component bytes unchanged',
          'Compare stronger allcurrent-v2prefix-retained variant using RAM fields only'],
        actual_reachability_results=None,actual_poststock_active_counts=None,
        actual_groups_needing_pointer_remap=None,actual_contiguity_or_alias_results=None,
        actual_4K_compacted_size_estimate=None,compaction_4K_success_proven=False,
        known_remaining_limits=['External lower IDs in MDR non-table prefix/other components/native caches unknown',
          'Unknown highflag meanings must remain held even when their generic childrange is preserved',
          'Current task did not prove live/native query/UI preservation or physical header/checksum acceptance'],
        required_next_scope='Separate ordinary cold baseline current-RSS/peak measurement, then lower-memory design; no current attempt rerun authorized',
        whole_IMG_or_PBF_or_source_ledger_or_MAIN_or_CPU_guest_or_audio_or_device_required=False))
    proof=save('proof.json',dict(schema='garmin-v3-reachability-finite-failed-attempt-proof/v1',
        created_utc=datetime.now(timezone.utc).isoformat(),finite_attempt_and_gap_recorded=True,
        all_assigned_reachability_feasibility_checks_passed=False,actual_exit_code=1,actual_terminal='9ada66',
        own_Python_assertion_not_system_platform_or_approval_block=True,
        original_failed_source=dict(path=str(source.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw)),
        original_failure=dict(path=str(failure.relative_to(ROOT)),bytes=len(fraw),sha256=sha(fraw)),
        actual_stderr=dict(path=str((HERE/'actual-stderr.txt').relative_to(ROOT)),
          sha256=sha((HERE/'actual-stderr.txt').read_bytes())),
        actual_guard_value=None,ru_maxrss_historical_peak_measurement=True,guard_KiB=393216,
        physical_RAM_shortage_or_tool_policy_interruption_not_inferred=True,
        fixed_array_payload_bytes=64175632,actual_IMG_read_exact_counter_unknown=True,
        RSS_budget_units=dict(host_platform='Linux',ru_maxrss_comparison_unit='KiB',
          RSS_CAP_KIB_expression='384*1024',comparison_threshold_KiB=393216,
          threshold_equals_MiB=384,unit_mismatch_found_in_static_source=False,
          actual_failed_run_value_not_saved=True),
        independent_root_measurement_not_this_attempt=dict(path='staging/navigation-compaction-host-RSS-measurement-v1/proof.json',
          sha256='8c0f93d10217bd4aa9ed1fc5efe22ad15c4d49cc0929380b0fda8c7e40b19a69',
          does_not_recover_failed_run_actual_value_or_prove_full_algorithm_peak=True,
          fixed64MB_payload_does_not_establish_physical384MiB_exhaustion=True),
        actual_IMG_metadata_read_upper_bound=200000,actual_MDR_stream_bytes=0,actual_read_cap=160000000,
        actual_reachability_active_suffix_counts_unknown=True,actual_remap_and_4K_compacted_size_unknown=True,
        source_candidate_current_stat_only=status,failed_run_before_stat_not_persisted=True,
        source_inherited_whole_SHA256='1f468eb78cc1268951873c82ffce4abe3292dcece69c0eee405c5d7aca3cc360',
        source_whole_hash_repeat_or_full_copy=False,source_bytes_reread_in_finalization=False,
        source_small_pins_verified_by_failed_runner=[
          {'path':'staging/navigation-country-native-house-merge-v1/proof.json','sha256':'bfc55b01f1f567cbad495ba3e35301d358cf54d1fdddea9fe1b8a9e6c8412a41'},
          {'path':'staging/navigation-native-L3-width-policy-static-v1/candidate-layout-and-CPU-facts.json','sha256':'3305e1aa1019c1920fee5e8993936d21aa0fe0ebb79d745a624ae900978868e9'},
          {'path':'staging/navigation-country-native-lane-candidate-v3/proof.json','sha256':'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0'},
          {'path':'staging/navigation-country-native-lane-candidate-v3/sealed-files.json','sha256':'dfc47744887137f944d710dffeb5ea6f6821c24eb8abbeb522cb406576754335'},
          {'path':'staging/navigation-native-lane-tree-cow-append-v1/proof.json','sha256':'1cde367d1d3aba44290b7f44be40c9cb5d04bf911a3e8bd3898e071a1329b4e9'},
          {'path':'staging/navigation-minimal-lane-render-isolation-plan-v1/prepare_control.py','sha256':'a20877fce09cbfe36f1f5621144f2ade44a031c26e4c6d330d07b2a1b86c4095'}],
        artifacts=dict(execution=receipt,finite_plan_and_gap=plan),
        original_failed_source_guard_not_modified_or_replayed=True,retry_or_increased_RSS_or_readcap=False,
        ordinary_host_data_program_only=True,MAIN_PBF_or_bigsourceledger_bytes_read=0,
        guest_CPU_audio_device_IO=False,new_IMG_or_full_tables_or_record_remap_generated=False,
        shared_original_IMG_or_seal_or_report_or_canonical_modified=False,
        all_own_and_source_handles_closed=True,compaction_fix_install_UI_or_renderer_verified=False,
        full_Taiwan_or_App_complete=False))
    files=[]
    for path in sorted(HERE.iterdir()):
        assert path.is_file() and path.name!='sealed-files.json'
        path.chmod(0o444);raw=path.read_bytes();q=path.stat()
        files.append(dict(path=str(path.relative_to(ROOT)),bytes=len(raw),sha256=sha(raw),mode='0444',
            stat_at_seal=[q.st_dev,q.st_ino,q.st_size,q.st_mtime_ns,q.st_ctime_ns]))
    assert sum(r['bytes'] for r in files)<1048576
    seal=save('sealed-files.json',dict(schema='garmin-v3-compaction-failed-attempt-seal/v1',
        finite_attempt_and_gap_sealed=True,all_assigned_feasibility_checks_passed=False,
        actual_attempt_exit_code=1,actual_attempt_terminal='9ada66',
        guard_classification='own Python historical-RSS assertion, not platform or automated approval interruption',
        original_source_and_failure_preserved=True,no_attempt_retry_or_guard_relaxation=True,
        own_small_artifact_hashes_verified=True,files=files,file_count=len(files),total_sealed_bytes=sum(r['bytes'] for r in files),
        all_own_and_source_handles_closed=True,source_IMG_bytes_opened_during_sealer=False,
        new_IMG_or_tables_or_remapped_records_or_device_IO=False,scope_stopped=True))
    (HERE/'sealed-files.json').chmod(0o444)
    print(json.dumps(dict(finite_attempt_and_gap_sealed=True,actual_attempt_exit_code=1,
        proof_sha256=proof['sha256'],seal_sha256=seal['sha256'],sealed_file_count=len(files),
        total_sealed_bytes=sum(r['bytes'] for r in files),source_handle_closed=True)))

if __name__=='__main__':main()
