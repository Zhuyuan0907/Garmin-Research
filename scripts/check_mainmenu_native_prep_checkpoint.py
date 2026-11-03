#!/usr/bin/env python3
"""Audit partial native development separately from adapter host tests."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re,struct,subprocess,urllib.request
from analyze_native_sections import ROOT

BASE='staging/native-player-mainmenu-native-prep/'
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def registry(d):
    for p,s in d.items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json')
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings']
    for k,v in before['native_app_music']['static_findings'].items():assert findings[k]==v,k
    suites=prior['selected_frozen_suites'];native={}
    for row in suites:
        assert sha(row['path'])==row['sha256'];doc=read(row['path'])
        assert doc['all_passed'] and doc['case_count']==row['case_count'];registry(doc['source_sha256'])
        for p,s in doc['source_sha256'].items():
            assert p not in native or native[p]==s;native[p]=s
    control=read('staging/ui-music-control-prototype/verification.json');registry(control['source_sha256'])
    registry(control['unchanged_frozen_source_sha256'])
    for row in control['compile_artifacts']:assert sha(row['path'])==row['sha256']
    deps=dict(native);deps.update(control['source_sha256']);assert len(deps)==435
    reviewold=read(findings['direct_music_integration_review']['evidence'])['exact_hash_audit']
    artifacts=0
    for row in reviewold['manifest_records']:
        assert sha(row['path'])==row['sha256'];registry(read(row['path'])['source_sha256'])
        for item in row['artifacts']:
            assert sha(item['path'])==item['sha256'] and (ROOT/item['path']).stat().st_size==item['bytes'];artifacts+=1
    for row in reviewold['source_references'].values():assert sha(row['path'])==row['sha256']
    newkeys=['native_settings_kernel_prep_development','native_settings_exact_raw_mutex_static',
        'native_GIR_controller_call_and_guard_static','native_music_source_adapter_prototype']
    for k in newkeys:assert sha(findings[k]['evidence'])==findings[k]['evidence_sha256']
    development=findings[newkeys[0]];meta=read(development['terminal_metadata']);probe=read(meta['probe'])
    assert sha(development['terminal_metadata'])==development['terminal_metadata_sha256']
    for k in ['runner','runner_snapshot','driver','probe']:assert sha(meta[k])==meta[k+'_sha256']
    first=read(BASE+'settings-prep-terminal-metadata.json')
    for k in ['source','source_snapshot','probe']:assert sha(first[k])==first[k+'_sha256']
    inputs=read(BASE+'journal-runtime/inputs-before-run.json');registry(inputs['source_sha256'])
    mutex=read(findings[newkeys[1]]['evidence']);gui=read(findings[newkeys[2]]['evidence']);adapter=read(findings[newkeys[3]]['evidence'])
    peer=read(development['peer_review']);assert sha(development['peer_review'])==development['peer_review_sha256']
    heap=read(development['next_heap_precondition_static'])
    assert sha(development['next_heap_precondition_static'])==development['next_heap_precondition_static_sha256']
    for d in [mutex,gui,adapter,peer,heap]:registry(d['source_sha256'])
    registry(heap['verified_previous_settings_source_hashes'])
    for d in [mutex,gui]:registry(d['verified_frozen_dependency_hashes'])
    registry(peer['verified_static_and_frozen_dependency_hashes'])
    registry(adapter['protected_source_sha256'])
    assert adapter['protected_source_sha256']==deps
    for row in adapter['artifacts']:
        assert sha(row['path'])==row['sha256'] and (ROOT/row['path']).stat().st_size==row['bytes']
    protected=dict(deps)
    for d in [inputs['source_sha256'],mutex['source_sha256'],gui['source_sha256'],peer['source_sha256'],heap['source_sha256'],adapter['source_sha256']]:
        for p,s in d.items():assert p not in protected or protected[p]==s;protected[p]=s
    report=(ROOT/'reports/nuvi2565RT.html').read_text();progress=public['research_progress']
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1]for name in ['report-updated-time','research-updated-time']]
    checks={
        'fresh_prior28_scope105_finding_checkpoint_preserved':prior['all_passed'] and len(prior['scope_checks'])==28 and prior['state_sha256']==sha(BASE+'previous-state.json'),
        '105_prior_findings_unchanged_four_new_evidence_records':len(before['native_app_music']['static_findings'])==105 and len(findings)==109,
        '39_successful_native_suites430_dependencies_remain_separate':len(suites)==39 and len(native)==430,
        '435_prior_native_and_control_sources_unchanged':len(deps)==435,
        'seven_prior_manifests_twenty_artifacts_still_exact':len(reviewold['manifest_records'])==7 and artifacts==20,
        'prior_control27_host_groups_and_ARM_artifacts_retained':control['all_passed'] and control['host_tests']['case_count']==27,
        'terminal25280_initial_missing_BSS_read_preserved':first['session_id']==25280 and first['terminal_exit_code']==1 and not first['full_scoped_final_guards_passed'],
        'terminal20581_exact_runner_driver_and_probe_attribution':meta['session_id']==20581 and meta['terminal_exit_code']==1 and not meta['completed'] and probe['source_sha256_before_run']==meta['driver_sha256'],
        'five_native_raw_init_bodies_six_original_zero_stores_observed':len(probe['settings_init_rows'])==5 and all(r['original_body_executed'] and len(r['native_zero_writes'])==6 and not r['host_seeded_backend_bytes']for r in probe['settings_init_rows']),
        'second_original_condition_ctor_lock_and_Timer_transfer_observed':any(r['pointer']=='0x148e8ec' and r['native_constructor_returned'] and r['original_mutex_lock_and_owner_store_executed']for r in probe['condition_constructor_runs']) and any(r['condition']=='0x148e8ec' and r['owner_matches_timer']for r in probe['native_owner_transfers']),
        'settings_run_failure_not_upgraded_to_full_guard_or_App_proof':not probe['completed'] and not probe['full_scoped_final_guards_passed'] and not development['full_settings_initializer_returned'] and not development['full_scoped_final_guards_passed'],
        'next_boundary_actual_heap_query_lock_before_body':probe['registers']['pc']=='0x3009a0' and probe['registers']['lr']=='0x388813' and probe['registers']['r0']=='0x3a7f18c' and '0x388812'in probe['error'],
        '36_exact_raw_call_rows_and39_settings_CFGs_static_only':mutex['assertions_passed'] and len(mutex['raw_mutex_calls'])==36 and len(mutex['settings_module_CFGs'])==39 and not mutex['device_io'],
        '21_GIR_controller_CFGs_and11_source_methods_static_only':gui['static_only'] and gui['complete_bounded_local_CFG_count']==21 and len(gui['source_method_evidence'])==11 and not gui['new_emulation_executed'],
        'peer_checks_raw_calls_and_narrow_journal_scope':peer['review_completed'] and peer['all_primary_raw_call_checks_passed'] and peer['exact_raw_settings_calls_checked']==36 and not peer['new_emulation_executed'],
        '26_heap_CFGs11_heap12_list_calls_static_cold_init_required':heap['assertions_passed'] and len(heap['functions'])==26 and len(heap['raw_mutex_calls'])==11 and len(heap['listener_mutex_calls'])==12 and heap['static_only'] and not heap['new_guest_execution'],
        'new_adapter_ARM_REL_zero_unresolved_not_old_loader_image':adapter['all_passed'] and adapter['ARM_machine']=='ARM' and adapter['ARM_ELF_type']=='REL' and not adapter['ARM_unresolved_symbols'] and not adapter['old_music_build_linked'],
        '12_actual_adapter_host_groups_ASan_UBSan_pass':adapter['host_tests']['all_passed'] and adapter['host_tests']['case_count']==12 and adapter['host_sanitizers']==['AddressSanitizer','UndefinedBehaviorSanitizer'] and not adapter['host_test_execution']['stderr'],
        'full_cleanup_bridge64byte_single_record_signature_compile_only':adapter['original_cleanup']['new_wrapper_frame_bytes']==64 and adapter['original_cleanup']['resume']=='0x3b9e07' and not adapter['original_cleanup']['native_execution_verified'],
        'missing_native_ownership_session_and_call_sites_not_substituted':len(adapter['missing_integration_bindings'])==6 and adapter['exact_map_helper_returns_BINDING_MISSING'] and not adapter['callback_count_or_cancel_return_zero_used_as_stop_done'],
        'resident_single_bootstrap_no_free_reset_unload_route9_pending':adapter['single_bootstrap_resident_no_reset_unload_free'] and adapter['route9_unsupported_fail_closed'],
        'adapter_hosttests_never_claim_native_audio_physical_App':not adapter['guest_emulator_or_original_native_instructions_executed'] and not adapter['native_kernel_IRQ_audio_GUI_or_integrated_App_proven'] and not adapter['device_install_candidate'],
        'canonical_task_public_same_active_goal':public['deep_research']==state and all(task[k]==state[k]for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']) and state['last_goal_turn']['goal_status']=='active' and not state['goal_complete'],
        'previous_status_only_turn_classified_no_progress_current_progress':previous['prior_turn_classification']=='no_progress' and state['last_goal_turn']['previous_goal_turn_classification']=='no_progress' and state['last_goal_turn']['classification']=='progress',
        '32_weighted_milestone83_details_App10_time_and_bar':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and len(progress['completed'])==83 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and progress['phases'][4]['estimate_percent']==10 and times[0]==times[1] and 'value="32"'in report,
        'report_partial_native_failure_and_host_adapter_limits_visible':all(t in report for t in ['原廠設定初始化與音訊接線層','完整設定初始化和最終檢查尚未通過','目前還沒有能安裝到車機的整合 App']),
        'report_has_no_private_identifiers':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report,
        'no_device_calls_sound_or_firmware_install_this_turn':not probe['device_io'] and not probe['sounds_emitted'] and not adapter['device_service_IO'] and not adapter['sounds_emitted'] and not state['last_goal_turn']['native_firmware_or_research_package_written'],
        'native_app_direct_music_and_foreground_remain_unproven':not app['native_app_running'] and not app['menu_icon_visible_on_device'] and not app['direct_phone_music_verified'] and not development['foreground_or_device_App_or_safe_cleanup_verified'],
    }
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    path='evidence/firmware-analysis/native-mainmenu-prep-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        previous_checkpoint_scopes=28,state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        selected_frozen_suites=suites,native_unique_exact_dependencies=len(native),protected_sources=protected,
        native_settings_terminal20581_full_scoped_guards_passed=False,settings_runtime_is_development_not_success=True,
        separate_adapter_host_groups=12,native_device_App_not_proven=True)
    (ROOT/path).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10)as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store'in cache
    result=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1)for line in result.stdout.splitlines()if'='in line)
    assert service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled' and int(service['MainPID'])>0
    latest['historical_offline_checkpoint_audits']['prior_independent_signal_checkpoint']=dict(
        audit=BASE+'previous-audit.json',audit_sha256=sha(BASE+'previous-audit.json'),
        state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=28,all_passed=True)
    latest.pop('current_native_independent_signal_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),report_bytes=len(content),
        service=service,service_not_restarted=True,cache_control=cache,current_native_mainmenu_prep_checkpoint=path,
        checkpoint_sha256={path:hashlib.sha256((ROOT/path).read_bytes()).hexdigest()},goal_status='active',full_goal_complete=False,
        current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=28,native_frozen_suites_revalidated=39,native_unique_exact_dependencies=430,
        protected_source_count=len(protected),settings_runtime_session=20581,settings_terminal_exit_code=1,
        settings_full_scoped_guards_passed=False,separate_adapter_host_groups=12,separate_adapter_native_runtime_verified=False,
        scope='Partial settings development reaches missing heap lock after five native init bodies and second condition transfer. Static call/guard review and compiled adapter host tests retained as distinct scopes.',
        device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=83,report_updated_time=times[0],research_updated_time=times[1],
        partial_native_failure_and_host_only_adapter_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scope_count=len(checks),findings=109,protected_sources=len(protected),
        host_adapter_groups=12,native_settings_final_guards_passed=False,url=latest['url'],HTTP_status=status,report_bytes=len(content))))

if __name__=='__main__':main()
