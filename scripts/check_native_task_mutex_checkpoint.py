#!/usr/bin/env python3
"""Audit fresh parallel-analysis evidence without widening runtime claims."""
from datetime import datetime,timezone
from functools import lru_cache
import hashlib,json,re
from analyze_native_sections import ROOT,EXPECTED

BASE='staging/native-player-task-mutex/'
def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()
def source_hashes(doc):
    for path,digest in doc['source_sha256'].items():assert sha(path)==digest,path

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous.values():assert sha(row['path'])==row['sha256']
    before=read(previous['state']['path']);prior=read(previous['audit']['path'])
    snapshots=read(BASE+'previous-publication-snapshots.json')
    for row in snapshots.values():assert sha(row['snapshot'])==row['sha256']
    state,task,public=[read(p)for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app=state['native_app_music'];findings=app['static_findings']
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    mutex=read(findings['native_task_mutex_static']['evidence'])
    gui=read(findings['native_gui_worker_boot_static']['evidence'])
    music=read(findings['direct_music_integration_review']['evidence'])
    aux=read(findings['native_task_mutex_static']['auxiliary_wrapper_evidence'])
    err=read(findings['native_gui_worker_boot_static']['erratum_and_inputs'])
    for doc in [mutex,gui,aux,err]:source_hashes(doc)
    for item in [findings['native_task_mutex_static'],findings['native_gui_worker_boot_static'],findings['direct_music_integration_review']]:
        assert sha(item['evidence'])==item['evidence_sha256']
    assert sha(findings['native_task_mutex_static']['auxiliary_wrapper_evidence'])==findings['native_task_mutex_static']['auxiliary_wrapper_evidence_sha256']
    assert sha(findings['native_gui_worker_boot_static']['erratum_and_inputs'])==findings['native_gui_worker_boot_static']['erratum_and_inputs_sha256']
    review=music['exact_hash_audit'];dependencies={}
    for suite in review['selected_suite_records']:
        proof=read(suite['path']);assert sha(suite['path'])==suite['sha256']
        assert proof['all_passed'] and proof['case_count']==suite['case_count']
        source_hashes(proof)
        for path,digest in proof['source_sha256'].items():
            assert path not in dependencies or dependencies[path]==digest,path
            dependencies[path]=digest
    artifact_count=0
    for row in review['manifest_records']:
        assert sha(row['path'])==row['sha256'];source_hashes(read(row['path']))
        for entry in row['artifacts']:
            assert sha(entry['path'])==entry['sha256'] and (ROOT/entry['path']).stat().st_size==entry['bytes']
            artifact_count+=1
    for row in review['source_references'].values():assert sha(row['path'])==row['sha256']
    assert music['inputs']['canonical_state']['sha256']==previous['state']['sha256']
    assert music['inputs']['public_findings']['sha256']==snapshots['reports/findings.json']['sha256']
    indexpath=BASE+'preserved-development-evidence-index.json';index=read(indexpath)
    for path,digest in index['source_artifact_sha256'].items():assert sha(path)==digest,path
    for run in index['runs']:
        assert sha(run['metadata'])==run['metadata_sha256']
        meta=read(run['metadata'])
        for key in ['source','probe']:assert sha(meta[key])==meta[key+'_sha256']
        probe=read(meta['probe'])
        assert probe['source_sha256_before_run']==meta['source_sha256']
        assert not probe['device_io'] and not probe['sounds_emitted'] and not probe['full_scoped_final_guards_passed']
    observation=app['development_observations']['native_multi_task_mutex_runtime']
    meta=read(observation['terminal_metadata']);probe=read(meta['probe'])
    for key in ['terminal_metadata','development_evidence','source']:
        assert sha(observation[key])==observation[key+'_sha256']
    progress=public['research_progress'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1]for name in ['report-updated-time','research-updated-time']]
    checks={
        'prior_fresh28_scope95_finding_checkpoint_preserved':prior['all_passed'] and len(prior['scope_checks'])==28 and
            prior['state_sha256']==previous['state']['sha256'] and len(before['native_app_music']['static_findings'])==95 and len(findings)==98,
        'all95_previous_finding_values_and37_selected_frozen_suites_425_dependencies_retained':len(review['selected_suite_records'])==37 and
            review['selected_frozen_suite_count']==37 and len(dependencies)==review['unique_recorded_dependencies']==425,
        'seven_manifests_twenty_artifacts_exact_hashes':len(review['manifest_records'])==review['manifest_count']==7 and artifact_count==review['verified_artifact_count']==20,
        'thirty_bounded_mutex_CFGs37_mode_changes_four_literal_tails_static_only':mutex['complete_bounded_CFG_count']==len(mutex['functions'])==30 and
            mutex['verified_mode_transition_count']==37 and mutex['verified_literal_tail_count']==4 and
            not mutex['new_runtime_execution'] and not mutex['complete_kernel_or_interrupt_exit_verified'],
        'twentyfive_GUI_worker_CFGs_native_notify_static_not_runtime_unblocking':gui['complete_bounded_Thumb_CFG_count']==len(gui['functions'])==25 and
            gui['all_assertions_passed'] and gui['condition_notification_path']['second_worker_does_not_request_global_singleton_before_initial_notification'] and
            not gui['real_GUI_boot_or_schedule_or_condition_notification_verified'],
        'seven_auxiliary_wrapper_CFGs_exact_vtable_tag_callers_and_preserved_first_rejection':aux['complete_bounded_CFG_count']==len(aux['functions'])==7 and
            aux['wrapper']['vtable']=='0xc1b5c4' and aux['wrapper']['native_diagnostic_tag_address']=='0x46c2c8' and
            aux['wrapper']['lock_continuation']=='0x46c2ae' and aux['wrapper']['unlock_continuation']=='0x46c2be' and not aux['new_runtime_execution'],
        'historical_failed_and_latest_runtime_sources_preserved_separate_from_full_controls':[run['session_id']for run in index['runs']]==[64774,4903] and
            meta['session_id']==4903 and not probe['full_scoped_final_guards_passed'] and
            not state['last_goal_turn']['latest_dispatcher_run_full_scoped_final_guards_passed'],
        'per_task_development_no_guest_owner_fakewake_or_python_context_restore':not probe['host_wrote_guest_mutex_owner_waiter_links_or_context_restore'] and
            not observation['host_wrote_guest_mutex_owner_waiter_links_or_context_restore'] and
            all(row['python_CPU_context_restore'] is False for row in probe['kernel_restores']) and
            all(row['semaphore_fields_written_by_original_only'] for row in probe['native_mutex_operations']),
        'scoped_controller_singleton_condition_broadcast_handoff_return_with_two_resident_worker_ops':probe['completed'] and
            probe['original_singleton_returned'] and probe['singleton']=='0x8800520' and
            probe['running_task']==probe['ready_head']==probe['registers']['sp']=='0x9503f90' and probe['registers']['pc']=='0x10000' and
            len(probe['kernel_restores'])==7 and all(row['original_task_resume_destination_reached']for row in probe['kernel_restores']) and
            len(probe['native_condition_waits'])==1 and probe['native_condition_waits'][0]['original_wait_returned'] and
            probe['native_condition_waits'][0]['native_reacquisition_verified'] and probe['native_condition_waits'][0]['original_return']==0 and
            len(probe['native_condition_notifications'])==1 and probe['native_condition_notifications'][0]['original_broadcast_returned'] and
            len(probe['native_full_releases'])==4 and probe['native_full_releases'][-1]['native_owner_after']=='0x8804fb8' and
            not probe['pending_condition_waits'] and not probe['pending_releases'] and not probe['pending_lower_waits'] and
            sum(len(rows)for rows in probe['pending_mutex_ops'].values())==2 and probe['mutex_inventory']['0x34a59ac']==1 and
            probe['scoped_allocation_descriptor_guards_passed'] and not probe['invalid_accesses'] and not probe['native_fatal_entries'] and not probe['audio_requests'],
        'captured_original_GUI_descriptors_match_symbolic_stores_with_initialized_gate_erratum':len(probe['native_task_descriptors'])==5 and
            probe['native_task_descriptors'][3]['words']==['0x5d215d','0x8805024','0x8805024','0x55c1408','0x8800fe0'] and
            probe['native_task_descriptors'][4]['words']==['0x261d29','0x0','0x8809320','0x55c0000','0x8805240'] and
            all(row['base_priority_E']==92 and row['field_F']==5 for row in probe['native_task_descriptors'][3:]) and
            err['all_assertions_passed'] and not err['new_runtime_executed'] and
            findings['native_gui_worker_boot_static']['F08C87_and_F00510_are_initialized_data_not_zero_BSS'],
        'music_UI_composition_review_never_claims_device_direct_music_or_combined_candidate':not music['result']['native_App_running_on_device'] and
            not music['result']['phone_direct_music_verified'] and music['result']['no_combined_UI_and_direct_music_candidate_exists_in_current_variant'] and
            findings['direct_music_integration_review']['bootstrap_must_run_once'] and
            findings['direct_music_integration_review']['source9_WAV_and_channel8_continuous_music_not_integrated'],
        'canonical_task_public_status_user_presence_and_active_goal_agree':public['deep_research']==state and
            all(task[key]==state[key]for key in ['updated_utc','current_priority','next_actions','last_goal_turn','attended_testing','parallel_research']) and
            not state['user_resting'] and not task['user_away'] and state['attended_testing']['user_present'] and
            state['last_goal_turn']['goal_status']=='active' and not state['last_goal_turn']['full_goal_complete'],
        '32percent_weighted_milestones72_details7_phases_App10_not_artifact_counts':progress['estimate_percent']==32 and
            progress['weighted_estimate_percent']==32 and len(progress['completed'])==72 and len(progress['phases'])==7 and
            progress['phases'][4]['estimate_percent']==10 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases'])==32 and
            not progress['goal_completed'] and times[0]==times[1] and 'value="32"'in report,
        'report_static_runtime_full_kernel_scope_and_no_private_identifiers':all(text in report for text in [
            '多線研究與首頁啟動','四組完整原廠事件與切換控制通過','尚未通過完整檢查','目前還沒有能安裝到車機的整合 App']) and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID'not in report,
        'current_no_foreground_App_direct_phone_music_or_safe_lifetime_claim':not app['native_app_running'] and not app['direct_phone_music_verified'] and
            not app['menu_icon_visible_on_device'] and not probe['actual_foreground_device_App_direct_phone_music_or_safe_lifetime_verified'] and
            not observation['full_scoped_final_guards_passed'],
        'three_agents_authorized_and_first_round_finished':state['parallel_research']['user_explicitly_authorized'] and
            state['parallel_research']['agent_count']==3 and state['parallel_research']['first_round_completed'],
    }
    assert all(checks.values()),[key for key,value in checks.items()if not value]
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),task_sha256=sha('evidence/task-state.json'),
        public_sha256=sha('reports/findings.json'),report_sha256=sha('reports/nuvi2565RT.html'),MAIN_sha256=EXPECTED,
        audit_script_sha256=sha('scripts/check_native_task_mutex_checkpoint.py'),
        prior_checkpoint=previous,new_static_evidence={item['evidence']:item['evidence_sha256']for item in [
            findings['native_task_mutex_static'],findings['native_gui_worker_boot_static'],findings['direct_music_integration_review']]},
        existing_frozen_suites=37,unique_exact_dependencies=425,new_complete_full_runtime_proofs=0,
        latest_development_runtime_session=meta['session_id'],original_singleton_returned=probe['original_singleton_returned'],
        full_scoped_final_guards_passed=False,goal_status='active',device_io=False,sounds_emitted=False)
    path='evidence/firmware-analysis/native-task-mutex-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),prior_scopes=28,frozen_suites=37,exact_dependencies=425,
        estimate_percent=32,findings=98,development_session=meta['session_id'])))

if __name__=='__main__':main()
