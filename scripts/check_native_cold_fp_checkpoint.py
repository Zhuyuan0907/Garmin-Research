#!/usr/bin/env python3
"""Check scoped cold native evidence, preserved sources and live report bytes."""
from pathlib import Path
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re,subprocess,urllib.request
from publish_native_cold_fp_state import ROOT,BASE,RUNTIME,PROOF,STATIC,AUXILIARY,read
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def registry(d,target):
    for p,s in d.items():
        assert sha(p)==s,p
        assert p not in target or target[p]==s,p
        target[p]=s
def main():
    previous,before=read(BASE+'previous-audit.json'),read(BASE+'previous-state.json')
    for r in read(BASE+'previous-checkpoint.json')['snapshots']:assert sha(r['snapshot'])==r['sha256']
    protected,native_deps={},{};registry(previous['protected_sources'],protected)
    assert previous['all_passed']and len(previous['scope_checks'])==33 and len(protected)==707
    suites=list(previous['selected_frozen_suites']);assert len(suites)==41
    for s in suites:
        assert sha(s['path'])==s['sha256'];d=read(s['path'])
        assert d['all_passed']and d['case_count']==s['case_count']and all(c['passed']for c in d['cases'])
        registry(d['source_sha256'],native_deps)
    assert len(native_deps)==619
    proof,meta=read(PROOF),read(RUNTIME+'terminal-metadata.json');probe=read(meta['probe'])
    registry(proof['source_sha256'],native_deps);registry(proof['source_sha256'],protected);registry(proof['artifacts_sha256'],protected)
    assert proof['all_passed']and proof['case_count']==1 and proof['cases'][0]['passed']
    suites.append(dict(path=PROOF,sha256=sha(PROOF),case_count=1))
    for k in ['runner','runner_snapshot','inputs','probe','guard_copy_source','guard_copy_provenance','previous_checkpoint','sealer']:
        assert sha(meta[k])==meta[k+'_sha256'];protected[meta[k]]=sha(meta[k])
    docs={}
    for p in list(STATIC.values())+AUXILIARY:
        d=read(p);registry(d['source_sha256'],protected);docs[p]=d
        for f in ['verified_protected_sources','rechecked_existing_source_registry']:
            if f in d:registry(d[f],protected)
        protected[p]=sha(p)
    sig=docs[STATIC['native_SIG_requester_DLL_host_file_API_contract']]
    fp=docs[STATIC['native_cold_FP_boot_contract_and_review']]
    peer=docs[AUXILIARY[1]];guard_review=docs[AUXILIARY[0]];dispatcher=docs[STATIC['native_Dispatcher_full_run_actor_contract']]
    assert fp['assertions_passed']and peer['assertion_passed']and guard_review['assertion_passed']
    assert peer['reviewed_runner_sha256']==meta['runner_sha256']and not peer['guest_executed']
    boot=probe['cold_boot'];assert boot['whole_TCB108_unchanged']and boot['released_list_backend24_checked']
    assert meta['session_id']==76222 and meta['terminal_exit_code']==0 and meta['authoritative_terminal_result_received_from_exec']
    assert len(probe['component_calls'])==11 and all(r['returned']for r in probe['component_calls'])
    assert len(proof['independent_cold_boot_zone_replays'])==5 and len(proof['independent_component_zone_replays'])==22
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings'];prior_findings=before['native_app_music']['static_findings']
    for k,v in prior_findings.items():assert findings[k]==v,k
    for k in set(findings)-set(prior_findings):assert sha(findings[k]['evidence'])==findings[k]['evidence_sha256']
    report_bytes=(ROOT/'reports/nuvi2565RT.html').read_bytes();report=report_bytes.decode();progress=public['research_progress']
    times=[re.search(r'<time id="'+n+r'" datetime="([^"]+)"',report)[1]for n in ['report-updated-time','research-updated-time']]
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10)as response:served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    proc=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in proc.stdout.splitlines()if '='in line)
    checks={
        'prior33_scopes128_findings707_frozen_sources_preserved':all(previous['scope_checks'].values())and len(prior_findings)==128,
        '41_prior_suites619_deps_plus_one_new_cold_scenario':len(suites)==42 and proof['independent_cold_scenarios']==1,
        'terminal76222_authoritative_exit0_and_exact_source_snapshot':meta['terminal_exit_code']==0 and meta['runner_sha256']==sha(meta['runner_snapshot']),
        'cold_typed_metadata_before_original_firstbuilder_no_live_TCB_patch':boot['declared_cold_metadata_inputs'][0]['before_first_original_builder_only'],
        'whole16384_native_FF_stack_fill_verified_not_host_fill':probe['cold_fill']['whole16384_FF_checked']and not probe['cold_fill']['host_filled_stack'],
        'original_FP_boot_before_restore_registered_real_exit_listener':boot['original_FP_boot_executed']and boot['original_listener_registered'],
        'boot_actual_FPSCR03000000_owner0_before_lazy_handler':boot['FPSCR']=='0x03000000'and boot['FPowner']==0,
        'whole_boot_TCB108_unchanged_and_exact_released_list24':boot['whole_TCB108_unchanged']and boot['released_list_backend24_checked'],
        '5_whole_boot_zones_replayed_with_explicit_ready_fixture_distinct_from_CPU':all(r['independently_replayed']for r in proof['independent_cold_boot_zone_replays']),
        'all11_original_helpers_and_full_component_endpoint_returned':probe['component_return']=='0x1'and probe['component_result20'][2:4]==[0x2ffc,1],
        '22_final_whole_zones_independently_replayed':all(r['independently_replayed']for r in proof['independent_component_zone_replays']),
        'whole786432_cache356833_CPU112_raw_backup_inputs_verified':proof['native_cache_CPU_store_events']==356833 and proof['exact_raw_backup_input_chunks']==112 and probe['memory']['whole_original_cache_bytes']==786432,
        'original_cache_alloc280_free59_and_resident_font8_preserved':len(probe['native_cache_allocations'])==280 and sum(r['freed']for r in probe['native_cache_allocations'])==59 and len(probe['memory']['resident_font_streams'])==8,
        'SQL_closed_and_code_voice_APIs_DB_canary_guards_pass':probe['memory']['all_SQL_statements_closed']and probe['memory']['all_scoped_memory_guards_passed'],
        'native_TCB5_and_frames4_exact_inventory_preserved':len(probe['native_endpoint']['native_inventory']['tasks'])==5 and len(probe['native_endpoint']['resident_four_frames'])==4,
        'first_same_controller_FP_only_multiowner_not_claimed':proof['only_first_same_controller_FP_verified']and not proof['multiowner_FP_or_foreground_or_accepted_package_or_physical_App_or_direct_music_verified'],
        'frozen_guard_copies_only_declared_predicate_diffs_peer_checked':guard_review['original_guard_checks_preserved']and peer['assertion_passed'],
        'static_dispatcher19_phases_not_executed_or_fullclosure':len(dispatcher['phases'])==19 and not dispatcher['guest_execution']and not dispatcher['foreground_or_closure_claim'],
        'terminal_controllerSP_differs_from_companion_frame':probe['registers']['sp']=='0x9503f90'and probe['component_result20'][6]==0x9503f68,
        '3_DLL_fopen_profiles2_2_4_keep_distinct_layouts':sig['corrected_per_original_module_direct_fopen_caller_profile']=={'Chinese_Big5_MeiLing':2,'Chinese_GB_MeiLing':2,'English_American_Jill':4},
        'hostfile_API_callers_not_native_SIG_reader_or_verifier_join':sig['static_MAIN_to_original_module_file_binding']['no_SIG_requester_or_cryptographic_verifier_join']and not sig['captured_facts_in_this_run']['native_execution'],
        'failed_uniform_profile_preserved_reconstructed_hash_not_execution_capture':sig['earlier_failed_profile']['failed_source_bytes_reconstructed_from_exact_own_edit_diff']and not sig['earlier_failed_profile']['failed_source_sha256_captured_at_execution_time'],
        '128_old_findings_identical4_added132_total':len(findings)==132,
        'canonical_task_public_synced_active_full_goal_remaining':public['deep_research']==state and all(task[k]==state[k]for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research'])and state['goal_status']=='active'and not state['goal_complete']and bool(state['required_work_remaining']),
        '33_weighted104_details_App20_and_Taiwan_time_bar':progress['estimate_percent']==progress['weighted_estimate_percent']==33 and len(progress['completed'])==104 and progress['phases'][4]['estimate_percent']==20 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33 and times[0]==times[1]and times[0].endswith('+08:00')and 'value="33"'in report,
        'report_full_boot_progress_and_device_limits_visible':all(t in report for t in ['原廠浮點啟動與完整介面準備通過','目前還沒有能安裝到車機的整合 App','手機直接藍牙音樂','跨執行緒','完整公鑰驗證']),
        'no_private_MAC_or_ESN_in_HTML':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'fresh_HTTP200_no_store_exact_bytes':status==200 and served==report_bytes and 'no-store'in cache,
        'fresh_enabled_active_service_same_PID_no_restart':service['MainPID']==read(BASE+'previous-web.json')['service']['MainPID']and service['ActiveState']=='active'and service['SubState']=='running'and service['UnitFileState']=='enabled',
        'no_device_IO_calls_or_sounds':not meta['device_io']and not meta['sounds_emitted']and not probe['device_io']and not probe['sounds_emitted'],
        'App_menu_icon_direct_phone_music_unproven':not app['native_app_running']and not app['menu_icon_visible_on_device']and not app['direct_phone_music_verified'],
    }
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    protected[PROOF]=sha(PROOF)
    for p in (ROOT/BASE).rglob('*'):
        if p.is_file()and '__pycache__'not in p.parts:
            rel=str(p.relative_to(ROOT));protected[rel]=sha(rel)
    for p in ['scripts/publish_native_cold_fp_state.py','scripts/check_native_cold_fp_checkpoint.py',
              'scripts/seal_native_cold_fp_controller.py','scripts/verify_native_cold_fp_controller.py',
              'evidence/firmware-analysis/native-cache-declared-checkpoint-audit.json']:protected[p]=sha(p)
    out='evidence/firmware-analysis/native-cold-fp-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,previous_checkpoint_scopes=33,
        selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),protected_sources=protected,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        latest_component_session=76222,latest_component_terminal_exit_code=0,latest_component_full_scoped_guards_passed=True,
        original_cold_FP_boot_verified=True,multiowner_FP_or_foreground_or_device_App_verified=False)
    (ROOT/out).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_cache_declared_checkpoint']=dict(audit=BASE+'previous-audit.json',
        audit_sha256=sha(BASE+'previous-audit.json'),state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=33,all_passed=True)
    latest.pop('current_native_cache_declared_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(served).hexdigest(),report_bytes=len(served),
        service=service,service_not_restarted=True,cache_control=cache,current_native_cold_FP_checkpoint=out,checkpoint_sha256={out:sha(out)},
        goal_status='active',full_goal_complete=False,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),previous_checkpoint_scope_count=33,
        native_frozen_suites_revalidated=len(suites),native_unique_exact_dependencies=len(native_deps),protected_source_count=len(protected),
        latest_component_session=76222,terminal_exit_code=0,full_scoped_guards_passed=True,original_cold_FP_boot_verified=True,
        physical_App_verified=False,device_io=False,sounds_emitted=False,scope='One full cold FP boot/component scenario; first/same controller only. Foreground, cross-owner FP, accepted package and device music remain required.')
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=104,report_updated_time=times[0],research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),findings=len(findings),native_suites=len(suites),native_deps=len(native_deps),
        protected_sources=len(protected),url=latest['url'],HTTP_status=status,report_bytes=len(served),service_PID=service['MainPID'])))
if __name__=='__main__':main()
