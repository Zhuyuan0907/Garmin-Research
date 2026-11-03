#!/usr/bin/env python3
"""Verify sealed controller runs, native font input history and public claims."""
from pathlib import Path
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re,subprocess,sys,urllib.request
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
BASE='staging/native-player-controller-gir-integration/'
def read(path):return json.loads((ROOT/path).read_text())
@lru_cache(None)
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def registry(values,target):
    for path,digest in values.items():
        assert sha(path)==digest,path
        assert path not in target or target[path]==digest,path
        target[path]=digest

def main():
    snapshots=read(BASE+'previous-checkpoint.json')
    for row in snapshots['snapshots']:assert sha(row['snapshot'])==row['sha256']
    prior=read(BASE+'previous-audit.json');before=read(BASE+'previous-state.json')
    assert prior['all_passed'] and len(prior['scope_checks'])==34 and prior['state_sha256']==sha(BASE+'previous-state.json')
    protected={};registry(prior['protected_sources'],protected);assert len(protected)==608
    native_deps={};suites=prior['selected_frozen_suites']
    for suite in suites:
        assert sha(suite['path'])==suite['sha256'];doc=read(suite['path'])
        assert doc['all_passed'] and doc['case_count']==suite['case_count'] and all(case['passed']for case in doc['cases'])
        registry(doc['source_sha256'],native_deps)
    assert len(suites)==40 and len(native_deps)==437
    firstmeta_path=BASE+'runtime/terminal-metadata.json';first=read(firstmeta_path);firstprobe=read(first['probe'])
    for key in ['runner','runner_snapshot','inputs','probe']:assert sha(first[key])==first[key+'_sha256']
    assert first['session_id']==38139 and first['terminal_exit_code']==1 and not first['full_scoped_final_guards_passed']
    registry(read(first['inputs'])['source_sha256'],protected)
    assert len(firstprobe['component_calls'])==9 and sum(row['returned']for row in firstprobe['component_calls'])==8
    assert firstprobe['error']=='Font lower input destination is not writable'
    assert firstprobe['registers']['pc']=='0x31cf22' and firstprobe['registers']['r1']=='0x35b7f1c' and firstprobe['registers']['r2']=='0x1cfc'
    first_STRD=[row for zone in firstprobe['journal_zones'].values()for row in zone['stores']if row['PC']=='0xea10174']
    assert [(row['address'],row['size'],row['value'])for row in first_STRD]==[('0x18320100',4,80),('0x18320104',4,1)]
    meta_path=BASE+'runtime-contiguous/terminal-metadata.json';meta=read(meta_path);probe=read(meta['probe']);actual=read(meta['actual_observer_state'])
    for key in ['runner','runner_snapshot','driver','driver_snapshot','inputs','probe','actual_observer_state','peer_review','sealer']:
        assert sha(meta[key])==meta[key+'_sha256'],key
        protected[meta[key]]=sha(meta[key])
    registry(read(meta['inputs'])['source_sha256'],protected)
    assert meta['terminal_exit_code']==(0 if meta['completed'] else 1) and meta['completed']==probe['completed']
    assert probe['source_sha256_before_run']==meta['driver_sha256']==actual['driver_sha256']
    assert actual['observer_sha256']==meta['runner_sha256']
    assert sum(row['returned']for row in probe.get('component_calls',[]))==meta['component_native_original_helpers_returned']
    pairs={0x2ca82c:0xea10264,0x2cabbc:0xea102dc,0x395980:0xea10380,0x2db540:0xea103dc,
        0x25dc80:0xea10438,0x41cc46:0xea104bc,0x41b15a:0xea10534,0x4df248:0xea10654,
        0x4de236:0xea106b4,0x4a388a:0xea10724,0x316276:0xea107e8}
    for doc in [firstprobe,probe]:
        for row in doc.get('component_calls',[]):
            assert int(row['caller'],16)==pairs[int(row['entry'],16)] and row['SP']=='0x9503f68'
            if row['returned']:assert row['return_SP']==row['SP']
    review=read(meta['peer_review']);registry(review['source_sha256'],protected);registry(review['verified_protected_sources'],protected)
    assert review['runner_sha256']==meta['runner_sha256'] and review['protected_hash_mismatches']==[]
    static_paths=[BASE+'gui-static/observer-scopes-and-runnable-input-plan.json',BASE+'gui-static/native-runner-static-review-024714df092f.json',
        BASE+'resource-static/font-provider-SQL-peer-review.json',BASE+'resource-static/font-stream-owner-supplement.json',
        BASE+'resource-static/font-cache-span-preflight.json',BASE+'fp-static/cold-controller-fp-recipe.json',
        BASE+'fp-static/new-dispatcher-followup/dispatcher-body-next-call-contract.json']
    statics=[]
    for path in static_paths:
        doc=read(path);registry(doc['source_sha256'],protected)
        for field in ['protected_sources','verified_frozen_dependency_hashes','rechecked_existing_source_registry']:
            if field in doc:registry(doc[field],protected)
        statics.append(doc)
    cache_preflight=read(BASE+'resource-static/font-cache-span-preflight.json')
    micro_path=BASE+'cache-hook-micro-v3/hook-order-controls.json';micro=read(micro_path)
    registry(micro['source_sha256'],protected)
    assert micro['all_passed']and micro['case_count']==3 and all(row['passed']for row in micro['cases'])
    assert micro['cases'][1]['observed_error']['errno']==6
    assert micro['cases'][0]['observed_error']is None and micro['cases'][2]['observed_error']is None
    assert micro['old85428_underlying_UcError_was_not_captured']and micro['old_failure_cause_is_inference_from_matching_PC_and_source_not_retroactive_observation']
    stock=NativeImage();expected=bytearray(0xc0000);native_store_count=0;raw_inputs=0
    for row in actual['whole_cache_journal']:
        offset=row['address']-0x34fa3bc;length=row['bytes'];assert 0<=offset and offset+length<=len(expected)
        assert expected[offset:offset+length].hex()==row['before_hex']
        payload=bytes.fromhex(row['after_hex']);assert len(payload)==length
        info=row['metadata']
        if info['kind']=='exact_original_MAIN_CPU_store':
            opcode=bytes.fromhex(info['opcode_hex']);assert stock.read(int(info['load_PC'],16),len(opcode))==opcode
            assert info['running_task']=='0x9503f90' and length==row['events']*info['width']
            native_store_count+=row['events']
        else:
            assert info['kind']=='raw_exact_backup_file_input' and row['events']==1
            path='backups/20261002T154458Z/files/'+info['path'][3:]
            raw=(ROOT/path).read_bytes();assert raw[info['file_offset']:info['file_offset']+length]==payload
            assert hashlib.sha256(payload).hexdigest()==info['input_sha256'];raw_inputs+=1
        expected[offset:offset+length]=payload
    assert native_store_count==actual['native_cache_CPU_store_count']==meta['native_cache_CPU_store_count']
    for row in actual['native_cache_allocations']:
        assert stock.read((row['LR']&~1)-4,4).hex()==row['caller_opcode_hex']
        if not row.get('failed'):
            assert row['units']==((row['requested_bytes']+7)>>3)+1 and row['capacity']==8*(row['units']-1)
            assert 0x34fa3bc<=row['pointer']-8 and row['pointer']+row['capacity']<=0x35ba3bc
            assert (row['pointer']-0x34fa3bc)%8==0
    for row in actual['native_cache_reader_frame_witnesses']:
        assert stock.read(0x264934,4).hex()==row['original_caller_opcode_hex']
    for coverage in actual['font_span_coverages']:
        cursor=int(coverage['pointer'],16);high=cursor+coverage['bytes']
        assert coverage['ownership']in ['actual_live_controller_font_call_stack_slice','original_live_native_cache_payload_and_context_parser_stream_read_binding']
        for span in coverage['contiguous_writable_segments']:
            assert int(span['low'],16)==cursor and span['permissions']&2
            cursor=int(span['high_exclusive'],16)
        assert cursor==high and coverage['native_critical_storage_excluded']
    passed=meta['full_scoped_final_guards_passed']
    if passed:
        assert probe['completed'] and len(probe['component_calls'])==11 and all(row['returned']for row in probe['component_calls'])
        assert probe['component_return']=='0x1' and probe['component_result20'][2:4]==[0x2ffc,1]
        memory=probe['memory'];assert memory['all_scoped_memory_guards_passed'] and memory['whole_original_shared_font_cache_replayed']
        assert memory['full_original_font_activation_index_path_and_selector_checked'] and memory['whole_original_cache_bytes']==len(expected)
        assert len(memory['resident_font_streams'])==8 and len(memory['actual_font_inventory'])==13 and memory['all_SQL_statements_closed']
        assert not actual['native_cache_alloc_pending'] and not actual['native_cache_free_pending'] and not actual['native_cache_returns_pending']
        assert not actual['native_cache_read_pending'] and actual['native_cache_reader_route_pending']is None
        assert all(row['actual_caller_return_observed']for row in actual['native_cache_allocations'])
        assert all(row['actual_caller_return_observed']for row in actual['native_cache_read_bindings'])
    else:assert not probe['completed'] and probe.get('error')
    state,task,public=[read(path)for path in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    findings=state['native_app_music']['static_findings']
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    for key in set(findings)-set(before['native_app_music']['static_findings']):
        entry=findings[key];assert sha(entry['evidence'])==entry['evidence_sha256']
    report=(ROOT/'reports/nuvi2565RT.html').read_text();progress=public['research_progress']
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1]for name in ['report-updated-time','research-updated-time']]
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10)as response:content,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    service_out=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True).stdout
    service=dict(line.split('=',1)for line in service_out.splitlines()if '='in line)
    checks={
        'previous34_scopes117_findings608_sources_preserved':all(prior['scope_checks'].values())and len(before['native_app_music']['static_findings'])==117,
        '40_frozen_successful_native_suites437_exact_dependencies':len(suites)==40 and len(native_deps)==437,
        'first38139_8of11_partial_preserved_not_certified':not first['completed']and first['component_native_original_helpers_returned']==8,
        'first_GIR_native_body_and_release_reached':any(row['entry']=='0x41cc46'and row['returned']and row['result']=='0x1'for row in firstprobe['component_calls']),
        'actual_STRD_two4byte_hook_events_separate_from_static_risk':len(first_STRD)==2,
        'new_run_terminal_exit_and_frozen_observer_driver_separately_attributed':meta['authoritative_exit_received_from_exec_tool']and actual['observer_sha256']!=actual['driver_sha256'],
        'native_top_helpers_exact_companion_callers_stack_and_returns':True,
        'first_settings_guards_pass_not_whole_component_guards':first['settings_all_scoped_guards_passed']and not first['full_scoped_final_guards_passed'],
        'final_static_peer_review_same_runner608_previous_sources':review['static_only']and review['protected_source_count']==608 and not review['new_emulation_executed'],
        'new_cache_contract12_CFG_with_original_allocator_free_read_route':cache_preflight['static_only']and cache_preflight['bounded_CFG_count']==12,
        '13_font_activation_and_resident_streams_separate_lifetimes':not findings['native_font_provider_SQL_lifetime_contract']['new_guest_execution'],
        'cold_FP_and_dispatcher_next_call_static_not_executed':statics[-1]['static_only']and not statics[-1]['emulator_guest_executed'],
        'captured_cache_history_replayed_unreached_final_memory_not_certified':len(expected)==786432,
        'cache_CPU_event_count_exact_MAIN_opcode_and_controller_checked':native_store_count==actual['native_cache_CPU_store_count'],
        'captured_native_allocations_checked_unreached_completion_not_certified':len(actual['native_cache_allocations'])==meta['original_cache_allocations_observed'],
        'captured_raw_read_witnesses_checked_unreached_font_endpoint_not_certified':True,
        'separate_three_single_instruction_hook_controls_passed':micro['all_passed']and micro['case_count']==3,
        'actual_host_read_error6_reproduced_before_native_mapping':micro['cases'][1]['events'][0]['event']=='CPU_write_callback'and not micro['cases'][1]['events'][0]['target_already_mapped'],
        'old85428_underlying_errno_remains_uncaptured_inferred_only':findings['native_font_cache_allocation_span_contract']['original85428_cause_is_inference'],
        'new_declared_cache_candidate_compiled_only_not_executed':not findings['native_font_cache_allocation_span_contract']['next_full_candidate_execution_verified']and not (ROOT/BASE/'runtime-cache-declared/outer-observer-at-run.py').exists(),
        'latest_full_guard_claim_matches_actual_terminal_endpoint':passed==probe['full_scoped_final_guards_passed']==findings['native_controller_GIR_contiguous_runtime']['full_scoped_final_guards_passed'],
        'seven_new_findings124_total_prior117_identical':len(findings)==124,
        'canonical_task_public_equal_active_goal_required_work':public['deep_research']==state and all(task[k]==state[k]for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research'])and state['goal_status']=='active'and not state['goal_complete']and bool(state['required_work_remaining']),
        '32_weighted_percent96_details_App10_time_and_bar':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and len(progress['completed'])==96 and sum(x['weight']*x['estimate_percent']/100 for x in progress['phases'])==32 and progress['phases'][4]['estimate_percent']==10 and times[0]==times[1]and times[0].endswith('+08:00')and 'value="32"'in report,
        'report_native_progress_and_installation_limits_visible':all(x in report for x in ['新增元件已進入原廠資源與字型流程','目前還沒有能安裝到車機的整合 App','手機直接藍牙音樂']),
        'no_private_MAC_or_ESN_in_public_HTML':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'fresh_HTTP200_no_store_exactbytes':status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes()and 'no-store'in cache,
        'fresh_enabled_active_report_service_PID_unchanged':service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled'and service['MainPID']==read(BASE+'previous-web.json')['service']['MainPID'],
        'no_device_IO_install_call_or_sound':not meta['device_io']and not meta['sounds_emitted']and not probe['sounds_emitted'],
        'App_direct_phone_music_menu_icon_still_unproven':not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and not state['native_app_music']['menu_icon_visible_on_device'],
    }
    assert all(checks.values()),[key for key,value in checks.items()if not value]
    for path in (ROOT/BASE).rglob('*'):
        if path.is_file()and path.suffix in ['.json','.py','.html']and '__pycache__'not in path.parts:protected[str(path.relative_to(ROOT))]=sha(str(path.relative_to(ROOT)))
    for path in ['scripts/publish_native_controller_gir_state.py','scripts/check_native_controller_gir_checkpoint.py',
                 'scripts/seal_native_controller_gir_contiguous.py','scripts/probe_native_controller_gir_cache_declared.py',
                 'scripts/probe_native_font_cache_hook_order.py','scripts/probe_native_font_cache_hook_order_v2.py',
                 'evidence/firmware-analysis/native-settings-vfp-checkpoint-audit.json']:
        protected[path]=sha(path)
    audit_path='evidence/firmware-analysis/native-controller-gir-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,previous_checkpoint_scopes=34,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),protected_sources=protected,
        latest_component_session=meta['session_id'],latest_component_terminal_exit_code=meta['terminal_exit_code'],
        latest_component_full_scoped_guards_passed=passed,cache_history_replayed_bytes=len(expected),native_cache_CPU_store_count=native_store_count,
        cache_raw_file_input_count=raw_inputs,physical_App_or_menu_or_direct_phone_music_verified=False)
    (ROOT/audit_path).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_settings_vfp_checkpoint']=dict(audit=BASE+'previous-audit.json',
        audit_sha256=sha(BASE+'previous-audit.json'),state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),
        fresh_revalidation_scopes=34,all_passed=True)
    latest.pop('current_native_settings_vfp_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,local_report_sha256=sha('reports/nuvi2565RT.html'),
        served_report_sha256=hashlib.sha256(content).hexdigest(),report_bytes=len(content),service=service,service_not_restarted=True,cache_control=cache,
        current_native_controller_gir_checkpoint=audit_path,checkpoint_sha256={audit_path:sha(audit_path)},goal_status='active',full_goal_complete=False,
        current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=34,native_frozen_suites_revalidated=40,native_unique_exact_dependencies=437,protected_source_count=len(protected),
        latest_component_session=meta['session_id'],terminal_exit_code=meta['terminal_exit_code'],full_scoped_guards_passed=passed,
        physical_App_verified=False,scope='Sealed actual native component progress and exact font input history. Full endpoint only if terminal guards passed; no foreground/device/accepted package claim.',device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=96,report_updated_time=times[0],research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scope_count=len(checks),findings=len(findings),protected_sources=len(protected),native_suites=40,
        latest_component_helpers_returned=meta['component_native_original_helpers_returned'],latest_component_final_guards_passed=passed,
        url=latest['url'],HTTP_status=status,report_bytes=len(content))))
if __name__=='__main__':main()
