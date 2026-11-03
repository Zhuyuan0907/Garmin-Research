#!/usr/bin/env python3
"""Audit native heap controls and incomplete general-menu development evidence."""
from datetime import datetime,timezone
from functools import lru_cache
from pathlib import Path
import hashlib,json,re
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import artifacts

def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    findings=state['native_app_music']['static_findings'];item=findings['native_heap_callback'];proof=read(item['evidence'])
    build=read(proof['build_manifest']);artifacts(build)
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    previous=item['previous_checkpoint'];before,prior=read(previous['state']),read(previous['audit'])
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering','native_player_resources',
        'native_mainmenu_dependencies','native_custom_page_root','native_menu_signals']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for p,s in old['source_sha256'].items():assert sha(p)==s,p
        counts.append(old['case_count'])
    static,release=read(item['static_evidence']),read(item['release_static_evidence'])
    for doc in [static,release]:
        for p,s in doc['source_sha256'].items():assert sha(p)==s,p
    index=read(item['preserved_development_evidence'])
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    for m in index['failed_focused_runs']:
        assert sha(m['path'])==m['sha256'];doc=read(m['path'])
        for key in ['source','VM_source','probe']:assert sha(doc[key])==doc[key+'_sha256']
    meta=read(index['general_menu_terminal_metadata']);dev=read(meta['probe'])
    assert sha(meta['probe'])==meta['probe_sha256']and sha(meta['source'])==meta['source_sha256']
    c0,c1,c2,c3,c4=proof['cases'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    checks={
        'fresh_prior12_scope_snapshot87_findings_preserved':prior['all_passed']and len(prior['scope_checks'])==12 and
            prior['state_sha256']==sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']and
            len(before['native_app_music']['static_findings'])==87 and len(findings)==88,
        '29_frozen_selected_suites_all_source_and_artifact_hashes_retained':counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5,6,5,3,3],
        'five_complete_controls92_exact_sources_and_frozen_player_package':proof['all_passed']and proof['case_count']==len(proof['cases'])==5 and
            all(c['passed']for c in proof['cases'])and len(proof['source_sha256'])==item['source_artifact_count']==92 and proof['MAIN_sha256']==EXPECTED and
            sha(item['evidence'])==item['evidence_sha256']and build['extension_bytes']==54976 and build['VM_MAIN_patch_bytes']==0 and
            not build['patch_plan']and build['code_RX_data_RW_segments']and 'EMULATION-ONLY'in build['package'],
        'four_heap_two_release_complete_CFGs_original_LR_and_indirect_dispatch':static['complete_bounded_CFG_count']==4 and
            release['complete_bounded_CFG_count']==2 and all(not f['unresolved_exits']and not f['instruction_limit_reached']for d in [static,release]for f in d['functions'].values())and
            all(static['functions'][hex(a)]['balanced_original_LR_popped_to_r3_return_verified']for a in [0x388804,0x388af4,0x388e92])and
            sha(item['static_evidence'])==item['static_evidence_sha256']and sha(item['release_static_evidence'])==item['release_static_evidence_sha256'],
        'native_validation_executes_not_synthetic_success_opaque_translation_explicit':c0['original_validator_body_executed']and
            not c0['host_returned_validation_success']and all(r['original_validation_body_executed']and not r['host_returned_validation_success']for r in proof['heap_descriptor_entries'])and
            len(proof['native_heap_validation_returns'])>0 and proof['descriptor_canaries_verified'],
        'registration_three_queries_preserve_callback_flags_and_replacement_not_unregister':c1['low3_flags_after']==6 and not c1['actual_callback_executed']and
            c2['native_query_count']==3 and c2['registered_callback_unchanged']and c2['descriptor_fields_not_reseeded_by_host']and
            c3['final_callback']==0 and c3['low3_flags_after_zero_store']==6 and c3['zero_callback_store_not_proven_as_safe_unregister_or_lifetime_cleanup']and
            {r['original_writer_PC']for r in proof['heap_registration_writes']}=={'0x388b0c','0x388b14'},
        'two_native_invalid_descriptor_cases_unlock_and_fatal_no_loop':len(c4['controls'])==2 and
            [c['kind']for c in c4['controls']]==['invalid_low_flags','mismatched_backlink']and
            all(c['original_fatal']['arguments'][0]=='0x6e5d8002'and c['unconditional_fatal_loop_not_executed']for c in c4['controls']),
        'release_flags6_branch_has_no_NULL_guard_core_cleanup_unverified':release['low3_flag_truth_table']==[dict(flags=n,takes_callback=(n&6)==6)for n in range(8)]and
            not release['callback_pointer_NULL_check_before_indirect_call']and release['callback_called_after_mutex_unlock_before_relock']and
            release['zero_callback_store_with_flags6_does_not_disable_release_indirect_call']and not release['actual_callback_execution_and_deallocator_or_safe_lifetime_verified']and
            not proof['actual_callback_delivery_release_resize_or_full_heap_lifetime_verified'],
        'two_focused_failures_distinct_from114_native_validations_in_partial_MainMenu':len(index['failed_focused_runs'])==2 and
            all(m['terminal_exit_code']==1 for m in index['failed_focused_runs'])and meta['session_id']==56115 and meta['terminal_exit_code']==1 and
            not dev['completed']and len(dev['heap_descriptor_entries'])==len(dev['native_heap_validation_returns'])==114 and
            dev['registers']['pc']=='0x2ca8a4'and dev['invalid_accesses'][-1]['address']=='0x0'and
            item['latest_settings_write_entry']=='0x2ca82c'and item['latest_original_MainMenu_caller']=='0x405310'and
            item['latest_missing_settings_write_cache_is_fixture_gap_not_device_failure']and not dev['full_integration_checkpoint']and
            not item['full_general_MainMenu_final_guards_passed']and not item['general_MainMenu_controller_executed'],
        'whole_voice40_code_canary_DB_and_conditional_data_final_guards':proof['original_voice_RAM_and40_exports_unchanged']and proof['raw_DB_backup_unchanged']and
            proof['no_GUI_conditional_initialized_data_changes']and proof['snapshot']['stock_and_loaded_code_unchanged']and proof['snapshot']['all_allocation_guards_intact']and
            proof['load']['native_private12_and_player2_tables_match'],
        'canonical_task_public31_percent57_details7_phases_times_and_private_identifiers':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==57 and len(public['research_progress']['phases'])==7 and
            '<progress id="research-progress" max="100" value="31"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '記憶體回呼登記與查詢已驗證'in report and '只把回呼清成零，不能算作安全解除登記'in report and '首頁整體尚未完成'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'asleep_offline_no_device_sound_install_App_music_or_goal_completion':state['user_resting']and task['user_away']and
            not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return']and state['attended_testing']['no_pending_question']and
            not proof['device_io']and not proof['sounds_emitted']and not dev['device_io']and not dev['sounds_emitted']and
            not state['last_goal_turn']['device_files_written']and not state['last_goal_turn']['automatic_calls_or_sound']and
            not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and
            state['microphone_amplifier']['status']=='cancelled_by_user'and state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and
            state['last_goal_turn']['goal_status']=='active'and not state['last_goal_turn']['full_goal_complete']and
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']}
    failed=[k for k,v in checks.items()if not v]
    if failed:raise ValueError('Checkpoint failed: '+', '.join(failed))
    out=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        heap_proof_sha256=sha(item['evidence']),prior_state_snapshot_sha256=sha(previous['state']),prior_audit_snapshot_sha256=sha(previous['audit']),
        audit_script_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),current_turn_device_IO=False,goal_status='active',full_goal_complete=False,
        full_general_MainMenu_or_visible_player_App_verified=False)
    path='evidence/firmware-analysis/native-heap-callback-checkpoint-audit.json';(ROOT/path).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),frozen_suites=len(counts),focused_groups=5)))

if __name__=='__main__':main()
