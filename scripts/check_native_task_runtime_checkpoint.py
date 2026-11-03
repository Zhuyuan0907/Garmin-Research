#!/usr/bin/env python3
"""Audit guarded native task and signal scopes with preserved prior proofs."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re
from analyze_native_sections import ROOT,EXPECTED

BASE='staging/native-player-task-runtime-full/'
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def hashes(doc):
    for p,s in doc['source_sha256'].items():assert sha(p)==s,p

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    snapshots=read(BASE+'previous-publication-snapshots.json')
    for row in snapshots.values():assert sha(row['snapshot'])==row['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings']
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    review=read(findings['direct_music_integration_review']['evidence'])['exact_hash_audit']
    suites=list(review['selected_suite_records']);dependencies={}
    newkeys=['native_task_runtime_full','native_gui_foreground_boot_static','native_source9_lifecycle_static']
    signal='native_signal_dispatch_full'in findings
    if signal:newkeys.append('native_signal_dispatch_full')
    for key in newkeys:
        row=findings[key];assert sha(row['evidence'])==row['evidence_sha256'];doc=read(row['evidence']);hashes(doc)
        if 'case_count'in doc:suites.append(dict(path=row['evidence'],sha256=row['evidence_sha256'],case_count=doc['case_count']))
        for p,s in row.get('continued_parallel_review_sha256',{}).items():
            assert sha(p)==s;extra=read(p)
            for label in ['source_sha256','review_inputs_sha256','frozen_positive_dependency_sha256']:
                for q,t in extra.get(label,{}).items():assert sha(q)==t,q
            for ref in extra.get('source_references',{}).values():assert sha(ref['path'])==ref['sha256']
            for ref in extra.get('frozen_evidence',{}).values():
                if isinstance(ref,dict)and 'path'in ref and 'sha256'in ref:assert sha(ref['path'])==ref['sha256']
                if isinstance(ref,list):
                    for item in ref:
                        if 'path'in item and 'sha256'in item:assert sha(item['path'])==item['sha256']
    for row in suites:
        assert sha(row['path'])==row['sha256'];doc=read(row['path']);hashes(doc)
        assert doc['all_passed'] and doc['case_count']==row['case_count']
        for p,s in doc['source_sha256'].items():
            assert p not in dependencies or dependencies[p]==s,p
            dependencies[p]=s
    artifacts=0
    for row in review['manifest_records']:
        assert sha(row['path'])==row['sha256'];hashes(read(row['path']))
        for entry in row['artifacts']:
            assert sha(entry['path'])==entry['sha256'] and (ROOT/entry['path']).stat().st_size==entry['bytes'];artifacts+=1
    for row in review['source_references'].values():assert sha(row['path'])==row['sha256']
    meta=read(BASE+'full-runtime-terminal-metadata.json');proof=read(meta['complete_proof']);background=read(meta['background_development'])
    for key in ['source','source_snapshot','complete_proof','background_development']:assert sha(meta[key])==meta[key+'_sha256']
    assert proof['source_sha256'][meta['source']]==meta['source_sha256']
    inventory=proof['cases'][1]['inventory'];memory=proof['cases'][2]['snapshot'];first=proof['cases'][0]
    gui=read(findings['native_gui_foreground_boot_static']['evidence']);music=read(findings['native_source9_lifecycle_static']['evidence'])
    for label in ['original_GUI_stack_fill_analysis','native_task_lifetime_preflight']:
        row=findings['native_task_runtime_full'];assert sha(row[label])==row[label+'_sha256'];hashes(read(row[label]))
    index=read(BASE+'preserved-development-evidence-index.json')
    for row in index['runs']:
        assert sha(row['metadata'])==row['metadata_sha256'];m=read(row['metadata'])
        assert m['session_id']==row['session_id'] and m['terminal_exit_code']==row['terminal_exit_code']
        assert sha(m['source'])==m['source_sha256']
        if 'probe'in m:assert sha(m['probe'])==m['probe_sha256']
    progress=public['research_progress'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1]for name in ['report-updated-time','research-updated-time']]
    checks={
        'fresh16_scope98_finding_prior_checkpoint_preserved':prior['all_passed'] and len(prior['scope_checks'])==16 and
            prior['state_sha256']==previous['state']['sha256'] and len(before['native_app_music']['static_findings'])==98,
        'all98_prior_finding_values_preserved':len(findings)==101+signal,
        'all37_prior_suites_plus_new_full_scoped_proofs_exact_hashes':len(suites)==38+signal and len(dependencies)==428+signal,
        'seven_frozen_manifests_twenty_artifacts_exact':len(review['manifest_records'])==7 and artifacts==20,
        'terminal_3875_three_passed_pre_background_groups_106_dependencies':meta['session_id']==3875 and
            meta['terminal_exit_code']==0 and proof['all_passed'] and proof['case_count']==len(proof['cases'])==3 and
            len(proof['source_sha256'])==106 and proof['full_scoped_nonmutating_memory_and_native_inventory_guards_passed'],
        'original_singleton_broadcast_condition_reacquisition_seven_actual_resumes':first['singleton']=='0x8800520' and
            len(first['kernel_restores'])==7 and all(row['original_task_resume_destination_reached']for row in first['kernel_restores']) and
            first['condition_waits'][0]['original_wait_returned'] and first['condition_waits'][0]['native_reacquisition_verified'] and
            first['condition_broadcasts'][0]['original_broadcast_returned'] and not first['host_context_restore_or_fakewake'],
        'native_ALL_ready_owned_and_resident_contexts_checked_without_unload':inventory['whole_native_ready_ALL_and_owned_list_checked'] and
            inventory['all_tasks']==['0x88092b0','0x8804fb8','0x2d227c8','0x9503f90','0x9508f90'] and
            inventory['ready']==['0x9503f90','0x88092b0','0x8804fb8','0x9508f90'] and
            inventory['tasks_and_condition_token_remain_resident'] and not inventory['task_quiescence_or_safe_unload_verified'],
        'whole_code_voice_private_API_GUI_DB_storage_descriptor_stack_guards_pass':memory['original_voice_RAM_and40_exports_unchanged'] and
            memory['whole_RX_extension_code_unchanged'] and memory['all_allocation_storage_descriptor_and_stack_boundaries_intact'] and
            memory['backup_and_inmemory_DB_unchanged'] and memory['native_closed_file_inventory_verified'] and
            not memory['guest_memory_or_counters_rewritten_by_guard'] and not memory['outer_cleanup_task_quiescence_or_safe_unload_verified'],
        'both_native16384_FF_fills_complete_with_post_fill_guard_baselines':len(memory['original_GUI_stack_canary_inputs'])==2 and all(
            row['whole16384_native_fill_verified'] and row['original_stack_fill_body_returned'] and
            row['original_stack_fill_bytes']==16384 and row['original_stack_fill_byte']==255 and
            row['leading64_after_native_fill_hex']=='ff'*64 and not row['host_filled_GUI_stack']for row in memory['original_GUI_stack_canary_inputs']),
        'two_harness_failures_preserved_not_native_fault_or_positive_proof':[row['session_id']for row in index['runs']]==[89190,22074,3875] and
            [row['terminal_exit_code']for row in index['runs']]==[1,1,0] and
            not read(index['runs'][0]['metadata'])['complete_native_VM_failure_snapshot_available'] and
            not read(index['runs'][1]['metadata'])['full_scoped_final_guards_passed'],
        'subsequent_background_idle_journal_kept_separate_from_complete_memory_scope':background['idle_sentinel_reached'] and
            background['running_task']==background['ready_head']=='0x9508f90' and not background['original_controller_wait_returned'] and
            not background['pending_mutex_operations'] and not background['invalid_accesses'] and not background['native_fatal_entries'] and
            not background['full_scoped_background_final_guards_passed'] and not meta['full_scoped_background_final_guards_passed'],
        '32_bounded_signal_GUI_root_foreground_CFGs_static_only':gui['all_static_assertions_passed'] and
            gui['complete_bounded_local_CFG_count']==len(gui['functions'])==32 and not gui['new_runtime_executed'] and
            gui['original_GUI_main_actor']['separate_from_Dispatcher'] and
            gui['most_direct_next_input']['no_guest_code_or_vtable_patch_required'],
        '29_source9_CFGs_static_only_start_stop_lifetime_remain_requirements':music['all_static_assertions_passed'] and
            music['complete_bounded_CFG_count']==len(music['functions'])==29 and music['static_only'] and
            not music['guest_execution_performed'] and not music['device_install_candidate'] and
            findings['native_source9_lifecycle_static']['stop_return_zero_is_not_completion'],
        'canonical_task_public_active_goal_and_user_presence_agree':public['deep_research']==state and all(task[k]==state[k]for k in
            ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research']) and
            not state['user_resting'] and not task['user_away'] and state['attended_testing']['user_present'] and
            state['last_goal_turn']['goal_status']=='active' and not state['last_goal_turn']['full_goal_complete'],
        'latest_true_memory_claim_explicitly_pre_background_not_unloading':state['last_goal_turn']['latest_dispatcher_run_full_scoped_final_guards_passed'] and
            not state['last_goal_turn']['latest_background_development_final_guards_passed'] and
            'pre-background'in state['last_goal_turn']['latest_dispatcher_full_guard_scope'],
        '32_weighted_percent75_or76_details_App10_seven_phases_consistent':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and
            len(progress['completed'])==75+signal and len(progress['phases'])==7 and progress['phases'][4]['estimate_percent']==10 and
            sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and not progress['goal_completed'] and
            'value="32"'in report and times[0]==times[1],
        'report_full_partial_static_scopes_and_no_private_identifiers':all(t in report for t in
            ['背景初始化、菜單回呼與播放控制','三組完整檢查','停止要求送出後還須確認實際完成','目前還沒有能安裝到車機的整合 App','該紀錄沒有再次完成全部記憶體檢查']) and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report,
        'no_foreground_device_App_direct_phone_music_or_safe_cleanup_claim':not app['native_app_running'] and
            not app['direct_phone_music_verified'] and not app['menu_icon_visible_on_device'] and
            not proof['physical_kernel_IRQ_GUI_foreground_App_direct_phone_music_or_safe_cleanup_verified'],
        'three_parallel_research_branches_explicitly_authorized':state['parallel_research']['user_explicitly_authorized'] and
            state['parallel_research']['agent_count']==3 and state['parallel_research']['continued_round'],
        'this_turn_no_device_IO_firmware_write_call_or_sound':not proof['device_io'] and not proof['sounds_emitted'] and
            not gui['device_io'] and not gui['sounds_emitted'] and not music['device_io'] and not music['sounds_emitted'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['native_firmware_or_research_package_written'],
    }
    if signal:
        sf=findings['native_signal_dispatch_full'];sp=read(sf['evidence']);sm=read('staging/native-player-signal-dispatch/signal-dispatch-terminal-metadata.json')
        assert sha(sm['probe'])==sm['probe_sha256'] and sha(sm['source'])==sm['source_sha256']
        assert sha(sf['original_member_holder_metadata_erratum'])==sf['original_member_holder_metadata_erratum_sha256']
        assert not sf['deep_endpoint_owned_mutex_timed_node_and_idle_POST_inventory_fully_checked']
        checks.update(
            four_native_signal_dispatch_groups_107_dependencies=sp['all_passed'] and sp['case_count']==4 and len(sp['source_sha256'])==107,
            actual_dispatcher_vtables_adapter_stop_before_callback_body=sp['cases'][-1]['callback_body_executed'] is False and
                sp['cases'][-1]['signal_chain'][-1]['entry']=='0x405340' and sp['cases'][-1]['signal_chain'][-1]['running_task']=='0x8804fb8' and
                not sp['callback_body_foreground_device_App_direct_music_or_safe_cleanup_verified'] and not sp['host_wrote_owner_context_ready_or_fake_callback'],
            native_idle_POST_controller_WAIT_real_resume_with_resident_idle_continuation=sp['cases'][1]['original_controller_WAIT_return']==1 and
                sp['cases'][1]['idle_POST_continuation_still_resident'] and not sp['cases'][1]['host_wrote_ready_links_mailbox_or_saved_context'])
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),task_sha256=sha('evidence/task-state.json'),
        public_sha256=sha('reports/findings.json'),report_sha256=sha('reports/nuvi2565RT.html'),MAIN_sha256=EXPECTED,
        audit_script_sha256=sha('scripts/check_native_task_runtime_checkpoint.py'),publisher_script_sha256=sha('scripts/publish_native_task_runtime_state.py'),
        prior_checkpoint=previous,selected_frozen_suites=suites,existing_frozen_suites=len(suites),unique_exact_dependencies=len(dependencies),
        new_complete_full_runtime_proofs=1+signal,latest_full_runtime_session=3875,
        full_scoped_pre_background_guards_passed=True,full_scoped_background_final_guards_passed=False,
        signal_dispatch_before_callback_body_verified=signal,goal_status='active',device_io=False,sounds_emitted=False)
    path='evidence/firmware-analysis/native-task-runtime-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),prior_scopes=16,frozen_suites=len(suites),exact_dependencies=len(dependencies),
        estimate_percent=32,findings=len(findings),signal_callback_entry=signal)))

if __name__=='__main__':main()
