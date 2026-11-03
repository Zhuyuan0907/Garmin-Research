#!/usr/bin/env python3
"""Audit original settings controls separately from incomplete general menu."""
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
    findings=state['native_app_music']['static_findings'];item=findings['native_settings_writer'];proof=read(item['evidence'])
    build=read(proof['build_manifest']);artifacts(build)
    for p,s in proof['source_sha256'].items():assert sha(p)==s,p
    previous=item['previous_checkpoint'];before,prior=read(previous['state']),read(previous['audit'])
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering','native_player_resources',
        'native_mainmenu_dependencies','native_custom_page_root','native_menu_signals','native_heap_callback']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for p,s in old['source_sha256'].items():assert sha(p)==s,p
        counts.append(old['case_count'])
    static=read(item['static_evidence'])
    for p,s in static['source_sha256'].items():assert sha(p)==s,p
    index=read(item['preserved_development_evidence'])
    for p,s in index['source_artifact_sha256'].items():assert sha(p)==s,p
    for run in index['runs']:
        assert sha(run['metadata'])==run['metadata_sha256'];doc=read(run['metadata'])
        for key in ['source','VM_source','probe','proof']:
            if key in doc:assert sha(doc[key])==doc[key+'_sha256'],key
    prefix='staging/native-player-settings-writer/'
    meta=read(prefix+'general-menu-settings-terminal-metadata.json');dev=read(meta['probe'])
    c0,c1,c2,c3,c4=proof['cases'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    programs=[e for e in proof['storage_events']if e['operation']=='program']
    checks={
        'fresh_prior12_scope_snapshot88_findings_preserved':prior['all_passed']and len(prior['scope_checks'])==12 and
            prior['state_sha256']==sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']and
            len(before['native_app_music']['static_findings'])==88 and len(findings)==89,
        '30_frozen_selected_suites_all_exact_sources_and_artifacts_retained':counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5,6,5,3,3,5],
        'five_complete_controls93_exact_sources_frozen_emulation_only_package':proof['all_passed']and proof['case_count']==len(proof['cases'])==5 and
            all(c['passed']for c in proof['cases'])and len(proof['source_sha256'])==item['source_artifact_count']==93 and
            proof['MAIN_sha256']==EXPECTED and sha(item['evidence'])==item['evidence_sha256']and build['extension_bytes']==54976 and
            build['VM_MAIN_patch_bytes']==0 and not build['patch_plan']and build['code_RX_data_RW_segments']and 'EMULATION-ONLY'in build['package'],
        'twelve_complete_bounded_CFGs_original_initializer_cursor_setter_reader_wrappers':static['complete_bounded_CFG_count']==len(static['functions'])==12 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in static['functions'].values())and
            static['original_initializer']=='0x2cbd16'and static['fields']['writer_cursor_pointer']==16 and
            sha(item['static_evidence'])==item['static_evidence_sha256']and static['erased_first_header_13bit_length_align4_can_skip8192_before_state_probe'],
        'native_initialization_ready_headers_and_cursor_not_host_seeded_geometry_explicit':c0['ready_set_by_original']and
            not c0['host_seeded_headers_or_cursor']and c0['logical_sectors']==c0['physical_sectors']==2 and c0['free_bytes']==16364 and
            c0['cursor']=='0x18001014'and c0['fictional_geometry']['sector_bytes']==16384 and
            not c0['actual_device_flash_geometry_or_kernel_condition_owner_verified'],
        'missing_key_lookup_copy_reject_and_outputs_unchanged_no_fake_defaults':c1['key']=='0x121e'and c1['read_result']==c1['copy_result']=='0xffffffff'and
            c1['outputs_unchanged']and c1['native_lookup_not_replaced_with_host_inventory']and
            any(e['entry']=='0x2cab14'for e in proof['settings_native_entries']),
        'original_program_payload_commit_read_copy_all_NOR_changes_one_to_zero':c2['native_record_header']=='0x121ec006'and
            c2['cursor_advanced_bytes']==8 and c2['native_copy_bytes']==2 and c2['unchanged_input_and_output_guards']and
            [e['bytes']for e in c2['program_writes']]==[4,4,2]and len(programs)>0 and
            all(e['one_to_zero_only']and all((a&b)==b for a,b in zip(bytes.fromhex(e['before_hex']),bytes.fromhex(e['incoming_hex'])))for e in programs)and
            all(not e['physical_device_or_backup_written']for e in proof['storage_events']),
        'cached_identical_skip_changed_replacement_and_three_native_rejections':c3['identical_result']==1 and
            c3['identical_no_storage_or_cursor_change']and c3['replacement_result']==0 and c3['original_old_record_invalidation_and_new_lookup']and
            c3['old_data_pointer']!=c3['new_data_pointer']and [x['length']for x in c4['controls']]==[0,8192,2]and
            all(x['original_result']==2 for x in c4['controls'])and c4['no_storage_operations_or_cursor_changes'],
        'condition_bootstrap_and_temporary_heap_explicit_full_voice_code_canary_DB_guards':len(proof['condition_bootstrap_tokens'])==1 and
            proof['condition_bootstrap_tokens'][0]['retained_at_original_initializer_return']and
            not proof['condition_bootstrap_tokens'][0]['real_kernel_thread_owner_or_condition_wait_verified']and
            proof['storage_and_temporary_index_buffer_guards_verified']and proof['descriptor_canaries_verified']and
            proof['original_voice_RAM_and40_exports_unchanged']and proof['raw_DB_backup_unchanged']and
            proof['no_GUI_conditional_initialized_data_changes']and proof['snapshot']['stock_and_loaded_code_unchanged']and
            proof['snapshot']['all_allocation_guards_intact']and proof['load']['native_private12_and_player2_tables_match'],
        'six_preserved_terminal_runs_separate_focused_pass_from_bank139_partial_general_menu':len(index['runs'])==6 and
            [r['terminal_exit_code']for r in index['runs']]==[1,1,1,0,0,1]and meta['session_id']==30668 and
            meta['terminal_exit_code']==1 and not dev['completed']and dev['registers']['pc']=='0x26a300'and
            dev['registers']['r0']=='0x8b'and dev['registers']['r2']=='0x8'and dev['registers']['lr']=='0x35d455'and
            len(dev['heap_descriptor_entries'])==len(dev['native_heap_validation_returns'])==82 and
            not dev['full_general_MainMenu_final_guards_passed']and not dev['general_MainMenu_controller_executed']and
            dev['full_constructor_GUI_data_voice_allocation_SQL_final_guards_not_run']and
            not any(e['entry']=='0x2ca82c'and e['arguments'][0]in ['0x121e','0x121f']for e in dev['settings_native_entries']),
        'canonical_task_public31_percent59_details7_phases_time_private_identifiers':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==59 and
            len(public['research_progress']['phases'])==7 and '<progress id="research-progress" max="100" value="31"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '原廠設定儲存流程已驗證'in report and '一般首頁仍未返回'in report and
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
        settings_proof_sha256=sha(item['evidence']),prior_state_snapshot_sha256=sha(previous['state']),prior_audit_snapshot_sha256=sha(previous['audit']),
        audit_script_sha256=sha(str(Path(__file__).resolve().relative_to(ROOT))),current_turn_device_IO=False,goal_status='active',full_goal_complete=False,
        full_general_MainMenu_or_visible_player_App_verified=False)
    (ROOT/'evidence/firmware-analysis/native-settings-writer-checkpoint-audit.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scopes=len(checks),frozen_suites=len(counts),focused_groups=5)))

if __name__=='__main__':main()
