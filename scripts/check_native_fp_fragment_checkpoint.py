#!/usr/bin/env python3
"""Validate fragment controls separately from preserved full native scenarios."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re,subprocess,urllib.request
from publish_native_fp_fragment_state import ROOT,BASE,RUNTIME,PROOF,STATIC,AUXILIARY,read

@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def registry(d,target):
    for p,s in d.items():
        assert sha(p)==s,p
        assert p not in target or target[p]==s,p
        target[p]=s
def main():
    previous,before=read(BASE+'previous-audit.json'),read(BASE+'previous-state.json')
    snapshot=read(BASE+'previous-checkpoint.json')
    for r in snapshot['snapshots']:assert sha(r['snapshot'])==r['sha256']
    protected,native_deps,fragment_deps={},{},{}
    registry(previous['protected_sources'],protected)
    assert previous['all_passed'] and all(previous['scope_checks'].values()) and len(previous['scope_checks'])==31 and len(protected)==751
    suites=list(previous['selected_frozen_suites']);assert len(suites)==42
    for s in suites:
        assert sha(s['path'])==s['sha256'];d=read(s['path'])
        assert d['all_passed'] and d['case_count']==s['case_count'] and all(c['passed'] for c in d['cases'])
        registry(d['source_sha256'],native_deps)
    assert len(native_deps)==711
    proof,metadata,probe=read(PROOF),read(RUNTIME+'terminal-metadata.json'),read(RUNTIME+'terminal-probe.json')
    registry(proof['source_sha256'],protected);registry(proof['source_sha256'],fragment_deps)
    for k in ['runner','runner_snapshot','inputs','probe']:
        assert sha(metadata[k])==metadata[k+'_sha256'];protected[metadata[k]]=sha(metadata[k])
    assert proof['all_passed'] and proof['case_count']==5 and all(c['passed'] for c in proof['cases'])
    assert metadata['authoritative_terminal_result_received_from_exec'] and metadata['terminal_exit_code']==0 and metadata['exec_chunk_id']=='17e393'
    assert metadata['runner_sha256']==sha(metadata['runner_snapshot'])=='8fc0a2bcf6319f9a2b5a00c15c1f9c213b1717f6c55105b0785433e594a4cab4'
    docs={}
    for p in list(STATIC.values())+AUXILIARY:
        d=read(p);registry(d['source_sha256'],protected);docs[p]=d
        for f in ['rechecked_existing_source_registry','verified_protected_sources']:
            if f in d:registry(d[f],protected)
        protected[p]=sha(p)
    fp=docs[STATIC['native_multiowner_FP_exact_observer_contract']]
    gui=docs[STATIC['native_Dispatcher_actor_shape_helper_contract']]
    package=docs[STATIC['native_outer_voice_event_loader_contract']]
    controls=read(gui['host_controls']['path']);assert sha(gui['host_controls']['path'])==gui['host_controls']['sha256']
    registry(controls['source_sha256'],protected)
    state,task,public=[read(p) for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings'];old=before['native_app_music']['static_findings']
    for k,v in old.items():assert findings[k]==v,k
    for k in set(findings)-set(old):assert sha(findings[k]['evidence'])==findings[k]['evidence_sha256']
    progress=public['research_progress'];report_bytes=(ROOT/'reports/nuvi2565RT.html').read_bytes();report=report_bytes.decode()
    times=[re.search(r'<time id="'+n+r'" datetime="([^"]+)"',report)[1] for n in ['report-updated-time','research-updated-time']]
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10) as response:served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    proc=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1) for line in proc.stdout.splitlines() if '=' in line)
    rows=probe['original_handler_rows'];allocations=probe['native_allocations'];replays=proof['independent_whole_zone_replays']
    checks={
        'prior31_scope_checkpoint132_findings751_sources_preserved':len(old)==132 and all(previous['scope_checks'].values()),
        'snapshot_bytes_exact_and_prior42_native_suites711_dependencies_unchanged':len(suites)==42 and len(native_deps)==711,
        'new_fragment_suite_separate_from_complete_cold_scenarios':proof['original_fragment_controls'] and not proof['complete_cold_boot_or_Dispatcher_integration_scenario'],
        'actual_terminal_exit0_exact_source_snapshot_no_reentry':metadata['terminal_exit_code']==0 and metadata['runner_sha256']==metadata['runner_snapshot_sha256'],
        '5_original_handler_controls_all_complete':len(rows)==5 and all(r['original_handler_entered'] and r['original_exception_return_seen'] and r['original_opcode_retry_reached'] for r in rows),
        'explicit_virtual_TCB_metadata_task_selection_UND_inputs_visible':probe['explicit_two_TCB_metadata_pool_and_task_selection_fixtures'] and probe['undefined_entry_is_explicit_architectural_fixture'],
        'original_save148_advance152_and_clone40_allocations':[a['request'] for a in allocations]==[148,148,40] and [a['advance'] for a in allocations]==[152,152,40],
        'native_allocator_no_capacity_check_external256_guard_retained':all(a['original_allocator_capacity_check'] is False and a['external_pool_budget']==256 for a in allocations),
        '3_VSTM128_saves_actual8byte_callbacks_independently_replayed':len(proof['independent_VSTM128_coverage'])==3 and all(c['complete'] and c['bytes']==128 and c['actual_callback_widths']==[8] for c in proof['independent_VSTM128_coverage']),
        'control_STM_uses_actual_four_registers_enabled_FPEXC':all(r['actual_control_register_words'][0]=='0x40000000' for r in rows if r['save_complete']),
        'first_C_to_D_saves_without_D_restore':rows[1]['save_complete'] and not rows[1]['restore_complete'] and rows[1]['expected_retry_bank_source']=='actual_fault_bank',
        'D_to_C_clone_and_saved_C_restore':rows[2]['save_complete'] and rows[2]['restore_complete'] and [a['request'] for a in rows[2]['allocation_rows']]==[148,40],
        'C_to_D_reuses_context_and_restores_saved_D':rows[3]['save_complete'] and rows[3]['restore_complete'] and not rows[3]['allocation_rows'],
        'same_owner_slot_valid_keeps_fault_bank_no_restore':not rows[4]['save_complete'] and not rows[4]['restore_complete'] and rows[4]['new_context_before']!='0x0' and rows[4]['before']['D16']==rows[4]['after_native_handler']['D16'],
        'saved_owner_restore_differs_from_old_fault_bank':all(r['before']['D16']!=r['after_native_handler']['D16'] for r in rows[2:4]),
        'GP15_CPSR_and_native_exception_return_preserved':all(r['before']['GP15']==r['after_native_handler']['GP15'] and r['before']['CPSR']==r['after_native_handler']['CPSR'] for r in rows),
        '8_wholezones145_originalCPUevents_independent_replay':len(replays)==8 and all(r['independently_replayed'] for r in replays) and proof['exact_original_CPU_store_events']==145,
        'unchanged_original_code_fragments_no_host_FP_owner_context_write':probe['original_fragments_unchanged'] and probe['original_MAIN_patch_bytes']==0 and all(not r['host_wrote_FP_enable_or_context'] for r in rows),
        'metadata_clone40_object32_distinct_from_TCB_owned32':any(int.from_bytes(bytes.fromhex(s['original_metadata_hex'])[32:36],'little')==0x8805220 for s in read(RUNTIME+'inputs-before-run.json')['task_inputs'].values()),
        'static_FP_contract_and_branch_clarification_no_guest_execution':fp['assertions_passed'] and fp['static_only'] and not fp['guest_executed'] and docs[AUXILIARY[0]]['assertion_passed'],
        'exact_executed_helper_and_verifier_peer_review_passes_fragment_scope':docs[AUXILIARY[1]]['assertions_passed'] and not docs[AUXILIARY[1]]['concrete_micro_blockers'] and not docs[AUXILIARY[1]]['guest_executed_by_this_review'],
        'pure_GUI_shape35_controls_not_native_body_execution':controls['all_passed'] and controls['control_count']==35 and not controls['guest_execution'] and not gui['guest_execution'],
        'higher_voicequeue_selection_BIN_static_only_no_SIG_requester':package['limits']['static_instruction_bytes_captured'] and not package['limits']['emulator_executed'] and not package['BIN_reader_and_generic_member_boundary']['SIG_requester_identified'],
        'modified_code_acceptance_not_mount_active_fread_or_metadata':not package['minimal_acceptance_observation_contract']['physical_or_offline_acceptance_run_performed_here'] and not package['limits']['physical_modified_DLL_code_accepted'],
        'all132_old_findings_identical4_added136_total':len(findings)==136 and len(old)==132,
        'canonical_task_public_synced_active_full_goal_remaining':public['deep_research']==state and all(task[k]==state[k] for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']) and state['goal_status']=='active' and not state['goal_complete'] and bool(state['required_work_remaining']),
        '33_weighted108_details_App20_Taiwan_time_and_progressbar':progress['estimate_percent']==progress['weighted_estimate_percent']==33 and len(progress['completed'])==108 and progress['phases'][4]['estimate_percent']==20 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33 and times[0]==times[1] and times[0].endswith('+08:00') and 'value="33"' in report,
        'report_fragment_vs_fullboot_and_device_limits_visible':all(t in report for t in ['原廠浮點保存與恢復小型測試通過','還不是完整選單派送或車機實測','目前還沒有能安裝到車機的整合 App','手機直接藍牙音樂']),
        'no_private_MAC_or_ESN_in_HTML':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
        'fresh_HTTP200_no_store_exact_bytes':status==200 and served==report_bytes and 'no-store' in cache,
        'fresh_enabled_active_report_service_same_PID_no_restart':service['MainPID']==read(BASE+'previous-web.json')['service']['MainPID'] and service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled',
        'no_device_IO_install_calls_or_sounds':not probe['device_io'] and not probe['sounds_emitted'] and not metadata['device_io'] and not metadata['sounds_emitted'],
        'App_menu_icon_direct_phone_music_unproven':not app['native_app_running'] and not app['menu_icon_visible_on_device'] and not app['direct_phone_music_verified'],
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    protected[PROOF]=sha(PROOF)
    for p in (ROOT/BASE).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            rel=str(p.relative_to(ROOT));protected[rel]=sha(rel)
    for p in ['scripts/probe_native_multiowner_vfp.py','scripts/verify_native_multiowner_vfp_micro.py',
              'scripts/publish_native_fp_fragment_state.py','scripts/check_native_fp_fragment_checkpoint.py',
              'evidence/firmware-analysis/native-cold-fp-checkpoint-audit.json']:protected[p]=sha(p)
    out='evidence/firmware-analysis/native-fp-fragment-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,previous_checkpoint_scopes=31,
        selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),
        selected_original_fragment_suites=[dict(path=PROOF,sha256=sha(PROOF),case_count=5)],fragment_unique_exact_dependencies=len(fragment_deps),
        protected_sources=protected,state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        native_FP_fragment_controls_verified=True,complete_native_Dispatcher_FP_integration_verified=False,
        original_cold_FP_boot_verified=True,foreground_or_device_App_verified=False)
    (ROOT/out).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_cold_FP_checkpoint']=dict(audit=BASE+'previous-audit.json',audit_sha256=sha(BASE+'previous-audit.json'),
        state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=31,all_passed=True)
    latest.pop('current_native_cold_FP_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(served).hexdigest(),report_bytes=len(served),
        service=service,service_not_restarted=True,cache_control=cache,current_native_FP_fragment_checkpoint=out,checkpoint_sha256={out:sha(out)},
        goal_status='active',full_goal_complete=False,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),previous_checkpoint_scope_count=31,
        native_frozen_suites_revalidated=42,native_unique_exact_dependencies=711,original_fragment_suites=1,original_fragment_controls=5,
        protected_source_count=len(protected),native_FP_fragment_controls_verified=True,complete_native_Dispatcher_FP_integration_verified=False,
        physical_App_verified=False,device_io=False,sounds_emitted=False,
        scope='Five original-fragment FP controls under explicit virtual task inputs, separate from42 preserved frozen native suites; complete cold Dispatcher integration remains required.')
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=108,report_updated_time=times[0],research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),findings=len(findings),native_suites=42,native_deps=711,
        fragment_controls=5,protected_sources=len(protected),url=latest['url'],HTTP_status=status,report_bytes=len(served),service_PID=service['MainPID'])))
if __name__=='__main__':main()
