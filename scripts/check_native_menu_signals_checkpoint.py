#!/usr/bin/env python3
"""Verify signal checkpoint, frozen history and explicit incomplete-menu limits."""
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
    findings=state['native_app_music']['static_findings'];item=findings['native_menu_signals'];proof=read(item['evidence'])
    build=read(proof['build_manifest']);artifacts(build)
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    previous=item['previous_checkpoint'];before,prior=read(previous['state']),read(previous['audit'])
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering','native_player_resources',
        'native_mainmenu_dependencies','native_custom_page_root']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for p,s in old['source_sha256'].items():assert sha(p)==s,p
        counts.append(old['case_count'])
    static=read(item['static_evidence']);index=read(item['preserved_development_evidence'])
    for p,s in static['source_sha256'].items():assert sha(p)==s,p
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    for m in index['metadata']:
        assert sha(m['path'])==m['sha256'];doc=read(m['path'])
        for key in ['source','probe']:assert sha(doc[key])==doc[key+'_sha256']
    first,second=read(index['before_signal_init_failure']),read(index['after_signal_init_failure'])
    c0,c1,c2=proof['cases'];signals=c1['signals'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    rows={int(r['address'],16):r for f in static['functions'].values()for r in f['instructions']}
    reached=[r for r in second['signal_context_entries']if r['entry']=='0x36294e'and r['caller']=='0x441a4e']
    checks={
        'fresh_prior17_scope_audit_state_exact_snapshots_and86_findings_unchanged':prior['all_passed']and len(prior['scope_checks'])==17 and
            prior['state_sha256']==sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']and
            len(before['native_app_music']['static_findings'])==86 and len(findings)==87,
        '28_frozen_selected_suites_and_all_dependencies_unchanged':counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5,6,5,3],
        'three_scoped_native_groups_and_all_exact_source_artifacts_final_guards':proof['all_passed']and proof['case_count']==len(proof['cases'])==3 and
            all(c['passed']for c in proof['cases'])and proof['MAIN_sha256']==EXPECTED and sha(item['evidence'])==item['evidence_sha256']and
            item['source_artifact_count']==len(proof['source_sha256']),
        'same_frozen54976_byte_player_RX_RW_package_still_emulation_only':build['extension_bytes']==54976 and build['code_RX_data_RW_segments']and
            build['VM_MAIN_patch_bytes']==0 and not build['patch_plan']and not build['unresolved_symbols']and
            'EMULATION-ONLY'in build['package']and sha(proof['build_manifest'])==proof['build_manifest_sha256'],
        'seven_bounded_static_CFGs_native_global_load_and_initializer_subscription':static['complete_bounded_CFG_count']==len(static['functions'])==7 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in static['functions'].values())and
            rows[0x4a384a]['literal_value']=='0x3471c30'and rows[0x441a36]['instruction']=='ldr r0, [r0]'and
            rows[0x441a4a]['direct_call']=='0x36294e'and sha(item['static_evidence'])==item['static_evidence_sha256'],
        'eight_original_shared_owners_two_entry_trees_no_host_constructed_links':c0['owner_values_before']==[0]*8 and not c0['host_seeded_owners']and
            len(signals)==8 and len({r['owner']for r in signals})==8 and len({r['shared_control']for r in signals})==8 and
            all(r['native_reference_counts']==[1,1]and r['original_tree_node_count']==2 and r['original_two_entry_tree_initialized']for r in signals)and
            len(c1['original_constructor_calls'])==len(c1['original_shared_constructor_calls'])==8 and not c1['host_seeded_signals_or_tree_links'],
        'original_empty_callback_rejection_nine_output_bytes_and_guards_no_subscription':c2['output_bytes_cleared']==9 and
            c2['surrounding_canaries_intact']and not c2['actual_map_subscription_executed']and not c2['callback_delivery_verified'],
        'before_after_development_new_nonzero_owner_and_explicit_next_heap_boundary':not first['completed']and
            first['registers']['pc']=='0x3518ec'and first['signal_context_entries'][-1]['arguments'][1]=='0x0'and
            not second['completed']and second['original_shared_signal_initializer_returned']and len(reached)==1 and
            reached[0]['arguments'][1]==second['shared_signal_global_after_initializer'][0]and reached[0]['arguments'][1]!='0x0'and
            second['registers']['pc']=='0x388e92'and second['registers']['lr']=='0x388b0d'and
            not item['full_general_MainMenu_final_guards_passed']and not item['general_MainMenu_constructor_returned'],
        'five_preserved_failures_sources_terminal_statuses_and_harness_errors_distinct':index['failed_or_partial_run_count']==len(index['metadata'])==5 and
            all(m['terminal_exit_code']==1 for m in index['metadata'])and sha(item['preserved_development_evidence'])==item['preserved_development_evidence_sha256']and
            not index['full_general_MainMenu_final_guards_passed'],
        'whole_voice40_code_canary_DB_no_GUI_conditional_data_changes':proof['original_voice_RAM_and40_exports_unchanged']and proof['raw_DB_backup_unchanged']and
            proof['no_GUI_conditional_initialized_data_changes']and proof['snapshot']['stock_and_loaded_code_unchanged']and
            proof['snapshot']['all_allocation_guards_intact']and proof['load']['native_private12_and_player2_tables_match'],
        'canonical_task_public31_percent55_details7_phases_Taiwan_time_and_privacy':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==55 and len(public['research_progress']['phases'])==7 and
            '<progress id="research-progress" max="100" value="31"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '找到一般首頁缺少的通知初始化'in report and '一般首頁仍未完整通過'in report and '頁面仍隱藏且在畫面外'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'asleep_offline_only_goal_active_no_App_music_install_or_event_delivery_claims':state['user_resting']and task['user_away']and
            not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return']and state['attended_testing']['no_pending_question']and
            not proof['device_io']and not proof['sounds_emitted']and not proof['callback_delivery_verified']and
            not proof['actual_boot_initializer_order_or_event_meanings_verified']and not state['last_goal_turn']['device_files_written']and
            not state['last_goal_turn']['automatic_calls_or_sound']and not state['native_app_music']['native_app_running']and
            not state['native_app_music']['direct_phone_music_verified']and state['microphone_amplifier']['status']=='cancelled_by_user'and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and state['last_goal_turn']['goal_status']=='active'and
            not state['last_goal_turn']['full_goal_complete']and state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']}
    failed=[k for k,v in checks.items()if not v]
    if failed:raise ValueError('Checkpoint failed: '+', '.join(failed))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        signal_proof_sha256=sha(item['evidence']),prior_state_snapshot_sha256=sha(previous['state']),
        prior_audit_snapshot_sha256=sha(previous['audit']),audit_script_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),
        current_turn_device_IO=False,goal_status='active',full_goal_complete=False,full_general_MainMenu_or_visible_player_App_verified=False)
    path='evidence/firmware-analysis/native-menu-signals-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),frozen_suites=len(counts),focused_groups=3)))

if __name__=='__main__':main()
