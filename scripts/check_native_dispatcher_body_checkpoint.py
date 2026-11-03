#!/usr/bin/env python3
"""Keep positive cold-prefix proof distinct from failed body and host controls."""
from datetime import datetime, timezone
from functools import lru_cache
import hashlib, json, re, subprocess, urllib.request
from publish_native_dispatcher_body_state import ROOT, BASE, RUNTIME, PREFIX, STATIC, PEERS, read

@lru_cache(None)
def sha(p):
    return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def registry(d, target):
    for p,s in d.items():
        assert sha(p)==s,p
        assert p not in target or target[p]==s,p
        target[p]=s

def main():
    previous,before=read(BASE+'previous-audit.json'),read(BASE+'previous-state.json')
    for row in read(BASE+'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot'])==row['sha256']
    protected,native_deps,fragment_deps={},{},{}
    registry(previous['protected_sources'],protected)
    assert previous['all_passed'] and len(previous['scope_checks'])==33 and len(protected)==781
    suites=list(previous['selected_frozen_suites'])
    assert len(suites)==42
    for suite in suites:
        assert sha(suite['path'])==suite['sha256']
        d=read(suite['path'])
        assert d['all_passed'] and d['case_count']==suite['case_count'] and all(c['passed'] for c in d['cases'])
        registry(d['source_sha256'],native_deps)
    assert len(native_deps)==711
    fragments=list(previous['selected_original_fragment_suites'])
    assert len(fragments)==1 and fragments[0]['case_count']==5
    for suite in fragments:
        assert sha(suite['path'])==suite['sha256']
        d=read(suite['path'])
        assert d['all_passed'] and d['original_fragment_controls'] and not d['complete_cold_boot_or_Dispatcher_integration_scenario']
        registry(d['source_sha256'],fragment_deps)
    prefix=read(PREFIX)
    registry(prefix['source_sha256'],protected)
    registry(prefix['source_sha256'],native_deps)
    registry(prefix['artifacts_sha256'],protected)
    assert prefix['all_passed'] and prefix['case_count']==1 and all(c['passed'] for c in prefix['cases'])
    suites.append(dict(path=PREFIX,sha256=sha(PREFIX),case_count=1,
        scope='Complete cold component prefix only; subsequent original Dispatcher body failed at396B4E.'))
    meta,probe=read(RUNTIME+'terminal-metadata.json'),read(RUNTIME+'terminal-probe.json')
    receipt=read(RUNTIME+'terminal-tool-receipt.json')
    for k in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix']:
        assert sha(meta[k])==meta[k+'_sha256'],k
        protected[meta[k]]=sha(meta[k])
    docs={}
    for p in list(STATIC.values())+PEERS:
        d=read(p);registry(d['source_sha256'],protected);docs[p]=d
        for key in ['verified_protected_sources','artifacts_sha256']:
            if key in d:registry(d[key],protected)
        protected[p]=sha(p)
    fp=docs[PEERS[0]];first=docs[PEERS[1]];gui=docs[PEERS[2]];music=docs[STATIC['native_UI_music_single_bootstrap_REL_preflight']]
    failed=read(BASE+'prefix-verifier-v1-failure/failure.json')
    state,task,public=[read(p) for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];old=before['native_app_music']['static_findings'];findings=app['static_findings']
    for k,v in old.items():assert findings[k]==v,k
    for k in set(findings)-set(old):
        assert sha(findings[k]['evidence'])==findings[k]['evidence_sha256'],k
    progress=public['research_progress'];report_bytes=(ROOT/'reports/nuvi2565RT.html').read_bytes();report=report_bytes.decode()
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1] for name in ['report-updated-time','research-updated-time']]
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10) as response:
        served,status,cache=response.read(),response.status,response.headers.get('Cache-Control','')
    proc=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1) for line in proc.stdout.splitlines() if '=' in line)
    prior_web=read(BASE+'previous-web.json')
    row=probe['original_lazy_handler_rows'][0]
    checks={
        'prior33_scope_checkpoint_and781_protected_sources_preserved':len(old)==136 and all(previous['scope_checks'].values()),
        'prior42_complete_native_suites711_dependencies_preserved':len(previous['selected_frozen_suites'])==42 and previous['native_unique_exact_dependencies']==711,
        'prior5_FP_fragment_controls_preserved_as_separate_suite':len(fragments)==1 and fragments[0]['case_count']==5,
        'authoritative67576_terminal_failure_exact_source_snapshot':meta['session_id']==receipt['session_id']==67576 and meta['terminal_exit_code']==receipt['actual_exec_result']['exit_code']==1 and receipt['actual_exec_result']['chunk_id']=='e87969' and 'session_id' not in receipt['actual_exec_result'] and meta['authoritative_terminal_result_received_from_exec'] and meta['runner_sha256']==meta['runner_snapshot_sha256']=='a0315eadfe40ab66ea8e601c236d9c358731ed1513983a3a2e2bc88c9b05a4e0',
        'cold_prefix_positive_independent_of_later_body_failure':prefix['all_passed'] and meta['cold_prefix_full_guards_passed'] and prefix['subsequent_body_terminal_exit_code']==1 and not prefix['subsequent_Dispatcher_body_or_multiowner_scheduling_or_foreground_verified'],
        '5_boot22_component_zones_and11_helpers_independently_replayed':len(prefix['independent_cold_boot_zone_replays'])==5 and len(prefix['independent_component_zone_replays'])==22 and prefix['cases'][0]['native_helpers_returned']==11,
        'whole786432_cache_raw112_inputs_and_actual356834_CPU_events':prefix['native_cache_CPU_store_events']==356834 and prefix['exact_raw_backup_input_chunks']==112,
        'one_same_byte_store_difference_exact_final_cache_bytes_preserved':prefix['exact_prior_cache_event_difference']['whole_cache_final_bytes_equal'] and prefix['whole_cache_replay_sha256']=='5eb8c4f79003fc8bb7d7b7fba66277286fc4de54235969d7ab23c7b29df958e3',
        'failed_hardcoded_previous_event_count_verifier_preserved':failed['verifier_assertion_failed'] and not failed['positive_proof_written'] and not failed['guest_reexecuted'],
        'queued_original_Dispatcher_entered_not_host_invoked_callback':probe['callback_entry_seen'] and probe['callback_entry_reached'] and bool(probe['independent_signal']),
        'first_native_C_to_D_original_getter_save_and_opcode_retry_complete':len(probe['original_lazy_handler_rows'])==1 and row['old_owner']=='0x9503f90' and row['new_owner']=='0x8804fb8' and row['actual_original_current_getter_result']=='0x8804fb8' and row['original_opcode_retry_reached'] and row['save_complete'],
        'first_D_FP_use_has_no_D_restore_no_clone_or_later_exchange_claim':not row['restore_complete'] and len(probe['native_FP_allocations'])==1 and probe['native_FP_allocations'][0]['request']==148 and probe['native_FP_allocations'][0]['advance']==152,
        'VSTM128_real8byte_store_coverage_and_no_host_FP_context_write':len(row['VSTM_callbacks'])==16 and all(s['size']==8 for s in row['VSTM_callbacks']) and row['VSTM_full128_readback_passed'] and not row['host_wrote_FP_enable_or_context'],
        'post_first_exchange_GP15_CPSR_and_native_resume_preserved':row['before']['GP15']==row['after_native_handler']['GP15'] and row['before']['CPSR']==row['after_native_handler']['CPSR'] and row['same_task_registers_stack_memory_resumed'] and row['original_function_not_reentered'],
        'FP8_and_body4_and_inherited22_are_partial_guards_only':len(probe['partial_FP_zone_verification'])==8 and all(z['whole_zone_replayed'] for z in probe['partial_FP_zone_verification']) and len(probe['partial_body_zone_verification'])==4 and all(z['whole_zone_replayed'] for z in probe['partial_body_zone_verification']) and len(probe['partial_inherited_zone_verification'])==22 and all(z['whole_net_zone_matches_original_stores'] for z in probe['partial_inherited_zone_verification']),
        'initialized_bank_partial_original_CPU_history_no_unrecorded_mutation':probe['partial_initialized_bank_verification']['whole_bank_matches_original_CPU_write_history'] and not probe['partial_initialized_bank_verification']['host_unrecorded_mutation'],
        'native_manager_initialization_zero_stores_observed':len(probe['body_actor_observations']['initializers'])>=2 and all(r['original_body_executed'] and not r['host_seeded_backend_bytes'] for r in probe['body_actor_observations']['initializers']),
        '396B4E_original_mutex_next_boundary_preserved':probe['phase']=='actual_Dispatcher405340_body' and '0x396b4e' in probe['error'] and not probe['completed'] and not probe['callback_return_seen'],
        'fullbody_foreground_three_stage_exchange_still_unverified':not probe['body_full_guards_passed'] and not state['last_goal_turn']['complete_native_Dispatcher_FP_integration_verified'] and not state['last_goal_turn']['native_foreground_or_multiowner_FP_verified'],
        'exact_FP_runner_peer_review_no_concrete_observer_blocker':fp['assertions_passed'] and not fp['concrete_FP_integration_blockers'] and not fp['guest_executed_by_review'],
        'first_exchange_independent_replay_remains_partial':first['all_passed'] and not first['complete_native_cold_Dispatcher_suite_verified'],
        'GUI_source_prefix_actor_review_static_only':bool(gui['source_sha256']) and not gui['guest_execution'] and not gui['VM_imported_or_instantiated'] and not gui['claims']['full_Dispatcher_body_verified'],
        'ARMv6_single_bootstrap_REL12_external_symbols':music['all_passed'] and music['ARM_artifact']['machine']=='ARM' and music['ARM_artifact']['type']=='REL' and len(music['ARM_artifact']['undefined_symbols'])==12,
        '8_host_controls1_host_scenario_ASan_UBSan_not_native_App':music['host_tests']['all_passed'] and music['host_tests']['group_count']==8 and music['host_tests']['complete_host_scenarios']==1 and music['host_ASan_UBSan'] and not music['host_tests']['native_instructions_or_GUI_constructors_executed'],
        'next_image_data_BSS_accessor_binding_review_frozen':bool(docs[PEERS[3]]['source_sha256']) and len(docs[PEERS[3]]['symbol_boundaries'])==12 and not docs[PEERS[3]]['limits']['compiled_build_or_host_tests_performed'] and not docs[PEERS[3]]['limits']['full_ELF_or_App_installed'],
        'canonical_public_task_consistent141_findings113_details':len(findings)==141 and len(progress['completed'])==113 and public['deep_research']==state and task['last_goal_turn']==state['last_goal_turn'],
        'all108_prior_progress_details_preserved':progress['completed'][:108]==read(BASE+'previous-public.json')['research_progress']['completed'],
        'weighted33_App20_milestone_estimate_goal_remaining':progress['estimate_percent']==33 and progress['weighted_estimate_percent']==33.0 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==33 and progress['phases'][4]['estimate_percent']==20 and state['required_work_remaining'] and not state['goal_complete'] and state['goal_status']=='active',
        'two_matching_Taiwan_timestamps_and_progress_bar_visible':times[0]==times[1] and times[0].endswith('+08:00') and 'value="33"' in report and '0x396B4E' in report,
        'current_body_failure_and_no_installed_App_limits_visible':'尚未還原的原廠鎖操作停止' in report and '沒有前景播放器或可安裝到車機的 App' in report,
        'LAN_HTTP200_latest_bytes_no_store':status==200 and served==report_bytes and 'no-store' in cache,
        'enabled_active_report_service_PID_unchanged':service['ActiveState']=='active' and service['UnitFileState']=='enabled' and service['MainPID']==prior_web['service']['MainPID']=='357833',
        'public_HTML_no_private_Bluetooth_identifier_or_ESN':not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b',report) and 'REDACTED_PRIVATE_ID' not in report,
        'no_device_writes_calls_or_sounds_this_turn':not meta['device_io'] and not meta['sounds_emitted'] and not probe['device_io'] and not probe['sounds_emitted'] and not state['last_goal_turn']['device_files_written'],
        'App_icon_direct_phone_music_still_unverified':not app['native_app_running'] and not app['menu_icon_visible_on_device'] and not app['direct_phone_music_verified'],
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    for p in (ROOT/BASE).rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            rel=str(p.relative_to(ROOT));protected[rel]=sha(rel)
    for p in ['scripts/probe_native_dispatcher_body_fp.py','scripts/native_dispatcher_multiowner_vfp.py',
              'scripts/seal_native_dispatcher_body.py','scripts/verify_native_dispatcher_prefix.py',
              'scripts/verify_native_dispatcher_prefix_v2.py','scripts/publish_native_dispatcher_body_state.py',
              'scripts/check_native_dispatcher_body_checkpoint.py',PREFIX,
              'evidence/firmware-analysis/native-fp-fragment-checkpoint-audit.json']:
        protected[p]=sha(p)
    out='evidence/firmware-analysis/native-dispatcher-body-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        previous_checkpoint_scopes=33,selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),
        selected_original_fragment_suites=fragments,fragment_unique_exact_dependencies=len(fragment_deps),
        selected_native_partial_exchange_proofs=[dict(path=PEERS[1],sha256=sha(PEERS[1]),scope='First C→D FP save/noDrestore under actual queued Dispatcher; body later fails396B4E.')],
        protected_sources=protected,state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        first_native_C_to_D_FP_exchange_verified=True,complete_native_Dispatcher_FP_integration_verified=False,
        latest_body_terminal_exit_code=1,cold_prefix_all_guards_passed=True,foreground_or_device_App_verified=False)
    (ROOT/out).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_FP_fragment_checkpoint']=dict(
        audit=BASE+'previous-audit.json',audit_sha256=sha(BASE+'previous-audit.json'),
        state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=33,all_passed=True)
    latest.pop('current_native_FP_fragment_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(served).hexdigest(),
        report_bytes=len(served),service=service,service_not_restarted=True,cache_control=cache,
        current_native_Dispatcher_body_checkpoint=out,checkpoint_sha256={out:sha(out)},goal_status='active',
        full_goal_complete=False,current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=33,native_frozen_suites_revalidated=len(suites),native_unique_exact_dependencies=len(native_deps),
        original_fragment_suites=1,original_fragment_controls=5,partial_native_exchange_proofs=1,protected_source_count=len(protected),
        first_native_C_to_D_FP_exchange_verified=True,complete_native_Dispatcher_FP_integration_verified=False,
        latest_body_terminal_exit_code=1,cold_prefix_all_guards_passed=True,physical_App_verified=False,device_io=False,sounds_emitted=False,
        scope='43 preserved/full cold-prefix native suites and5 separate fragment controls; actual queued Dispatcher first FP exchange partial proof, followed by terminal396B4E failure. No full body/foreground/App proof.')
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=113,report_updated_time=times[0],research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,visual_browser_render_not_performed=True,
        current_cold_prefix_success_and_body_failure_separated_visible=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),findings=141,native_suites=len(suites),native_deps=len(native_deps),
        fragment_controls=5,partial_native_exchange_proofs=1,protected_sources=len(protected),url=latest['url'],
        HTTP_status=status,report_bytes=len(served),service_PID=service['MainPID'])))

if __name__=='__main__':main()
