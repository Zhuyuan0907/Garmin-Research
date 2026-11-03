#!/usr/bin/env python3
"""Audit focused dependencies and hidden custom-Page root, preserving history."""
from datetime import datetime,timezone
from pathlib import Path
from functools import lru_cache
import hashlib,json,re
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import artifacts

def read(p):return json.loads((ROOT/p).read_text())
@lru_cache(None)
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()

def main():
    state,task,public=read('evidence/deep-research-state.json'),read('evidence/task-state.json'),read('reports/findings.json')
    findings=state['native_app_music']['static_findings'];item=findings['native_mainmenu_dependencies'];rootitem=findings['native_custom_page_root']
    focused,root=read(item['evidence']),read(rootitem['evidence']);build=read(focused['build_manifest']);artifacts(build)
    for proof in [focused,root]:
        for p,expected in proof['source_sha256'].items():assert sha(p)==expected,p
    previous=read('staging/native-player-mainmenu/previous-checkpoint.json');before,prior=read(previous['state']),read(previous['audit'])
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection','native_voice_outer','native_voice_compatibility',
        'native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch','native_l2cap_send',
        'native_music_reply','native_music_loaded','native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget','native_player_page',
        'native_player_grid','native_player_text','native_player_external_fonts','native_player_rendering','native_player_resources']
    counts=[]
    for name in names:
        old=read(findings[name]['evidence']);assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for p,expected in old['source_sha256'].items():assert sha(p)==expected,p
        counts.append(old['case_count'])
    for name,value in before['native_app_music']['static_findings'].items():assert findings[name]==value,name
    static=read(item['static_evidence']);index=read(item['preserved_development_evidence'])
    for p,expected in static['source_sha256'].items():assert sha(p)==expected,p
    for p,expected in index['source_artifact_sha256'].items():assert sha(p)==expected,p
    for meta in index['metadata']:
        assert sha(meta['path'])==meta['sha256'];doc=read(meta['path'])
        for field in ['source_sha256','probe_sha256']:assert doc[field]in index['source_artifact_sha256'].values()
    failure=read(index['general_MainMenu_latest_failure']);terminated=read(index['terminated_self_loop_run'])
    ctor='staging/native-player-mainmenu/audio-condition-ownership-boundary-failure.json';audio_failure=read(ctor)
    c0,c1,c2,c3,c4=focused['cases'];r0,r1,r2=root['cases'];report=(ROOT/'reports/nuvi2565RT.html').read_text()
    main_source=(ROOT/'scripts/probe_native_player_mainmenu.py').read_text();root_source=(ROOT/'scripts/probe_native_player_root_registration.py').read_text()
    checks={
        'five_scoped_native_dependency_groups90_exact_sources_full_final_guards':focused['all_passed']and focused['case_count']==len(focused['cases'])==5 and
            all(c['passed']for c in focused['cases'])and len(focused['source_sha256'])==90 and focused['MAIN_sha256']==EXPECTED and
            sha(item['evidence'])==item['evidence_sha256']and not focused['full_MainMenu_integration_checkpoint'],
        'three_custom_Page_root_groups98_exact_sources_and_full_scoped_final_guards':root['all_passed']and root['case_count']==len(root['cases'])==3 and
            all(c['passed']for c in root['cases'])and len(root['source_sha256'])==98 and root['MAIN_sha256']==EXPECTED and
            sha(rootitem['evidence'])==rootitem['evidence_sha256']and root['full_scoped_custom_Page_root_final_guards_passed']and
            not root['full_general_MainMenu_integration'],
        'same_frozen_resource_player54976_byte_RX_RW_package_remains_EMULATION_ONLY':focused['build_manifest']==root['build_manifest']=='staging/native-player-resources/manifest.json'and
            sha(focused['build_manifest'])==focused['build_manifest_sha256']==root['build_manifest_sha256']and build['extension_bytes']==54976 and
            build['combined_ram_bytes']==2462860 and build['remaining_reservation_bytes']==682868 and
            build['code_RX_data_RW_segments']and not build['unresolved_symbols']and not build['patch_plan']and
            build['VM_MAIN_patch_bytes']==0 and build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT']and
            build['package_checks']['all_other_members_byte_identical']and 'EMULATION-ONLY'in build['package'],
        '23_static_CFGs_exact_pop_return_tail_resolution_and_unresolved_PNG_kept_separate':static['complete_bounded_CFG_count']==len(static['functions'])==23 and
            all(not f['unresolved_exits']and not f['instruction_limit_reached']for f in static['functions'].values())and
            static['functions']['0x3ec5c6']['explicit_balanced_stack_pop_r3_original_LR_return_verified']and
            static['functions']['0x3ec6aa']['resolved_tail_to_included_CFG']=='0x3ec5c6'and
            static['original_PNG_filter_dispatcher_computed_branch_unresolved_not_in_complete_CFG_count']and
            sha(item['static_evidence'])==item['static_evidence_sha256'],
        'missing_setting_original_negative_output_preserved_no_host_value':c0['ID']=='0x100d'and c0['returned']==-1 and
            c0['output_and_guards_unchanged']and c0['only19B_inventory_record_provided']and not c0['host_supplied100D_setting_value']and
            focused['missing_setting_searches'][0]['host_supplied_setting_value']is False,
        'counter_original_store_status_exact_readonly_single_word_MMIO_no_hardware_claim':c1['returned_status']==0 and c1['output_counter_word']==0 and
            c1['surrounding_canaries_intact']and not c1['hardware_counter_clock_or_GPS_time_verified']and
            focused['clock_counter_reads']==[dict(address='0x101e8090',size=4,original_PC='0x1076e2',
                emulated_counter_word=0,actual_hardware_clock_or_GPS_time_verified=False)]and
            'self.uc.mem_protect(0x101e8000,0x1000,UC_PROT_READ)'in main_source,
        'original_list_self_sentinel_and12_original_empty_GPS_queries':c2['original_sentinel_next_and_previous_equal_self']and
            not c2['host_seeded_list_links']and c3['native_results']==[255]*12 and len(focused['GPS_inventory_queries'])==12 and
            all(r['caller']=='0x1f4728'and r['emulated_satellite_record_count']==0 for r in focused['GPS_inventory_queries'])and
            not c3['actual_GPS_receiver_or_signal_verified'],
        'native_audio_unowned_condition_diagnosis_and_explicit_failure_FF_unlock':audio_failure['native_fatal_entries'][0]['arguments'][0]=='0x6e5d8016'and
            audio_failure['native_fatal_entries'][0]['caller']=='0x3ec5ea'and static['native_fatal_code16']=='0x6e5d8016'and
            c4['returned_pool_index']==255 and c4['fixture_wait_failure_status']==1 and c4['all_fixture_mutexes_released']and
            not c4['real_condition_variable_scheduling_pool_or_speaker_verified']and len(focused['unavailable_audio_pool_waits'])==1,
        'original_custom_Page_manager_catalog_parent_and_category_getter_ownership':r0['Page_vtable']=='0xc0e5f0'and r0['manager_vtable']=='0xc02558'and
            any(r['Page']==r0['Page']for r in r0['catalog_after'])and r0['original_parent_assignment_verified']and
            r1['returned_Page']==r1['independent_catalog_last_matching_Page']==r0['Page']and r1['temporary_shared_holder_released']and
            root['native_tree']['parent']==r0['manager']and rootitem['native_manager_catalog_owns_custom_Page'],
        'Page_still_hidden_offscreen_no_visible_player_or_activation':r2['native_frame']==root['native_tree']['frame']==[480,0,480,272]and
            r2['native_visibility_flags']==root['native_tree']['flags84_85']==[0,0]and root['custom_Page_hidden_and_offscreen_after_stock_transition']and
            not r2['custom_Page_is_visible_foreground_player_App']and not r2['host_supplied_Page_or_child_frames']and not r2['audio_requests']and
            root['snapshot']['native_menu_state']==focused['snapshot']['native_menu_state']==[1,1,0,0,0,0],
        '37_clock_inputs17_guarded_original_transition_storage_not_actual_time_RAM':len(root['virtual_clock_ticks'])==37 and
            [r['supplied_virtual_milliseconds']for r in root['virtual_clock_ticks']]==list(range(20,741,20))and
            all(r['word']=='0xf09098'and not r['real_wall_time_kernel_tick_and_scheduler_verified']for r in root['virtual_clock_ticks'])and
            len(root['original_transition_buffer_heap_requests'])==17 and all(r['caller']=='0x6f8364'and r['alignment']==8 and
                r['guarded_storage_only_no_host_pixel_content']and not r['physical_free_RAM_verified']for r in root['original_transition_buffer_heap_requests'])and
            'self.uc.mem_map(0x0e800000,0x800000'in root_source,
        'whole_voice40_code_canon_two_native_once_words_font_DB_and_allocation_guards':all(p['original_voice_RAM_and40_exports_unchanged']and
            p['snapshot']['stock_and_loaded_code_unchanged']and p['snapshot']['all_allocation_guards_intact']and
            p['load']['native_private12_and_player2_tables_match']for p in [focused,root])and focused['raw_DB_backup_unchanged']and
            root['raw_font_backups_and_DB_unchanged']and root['inherited_non_font_handle_release_and_font_resident_canary_rules_retained']and
            root['snapshot']['full_conditional_data_region_matches_two_native_word_allowances']and
            [r['address']for r in root['snapshot']['original_GUI_initialized_data_mutations']]==['0x551c80c','0x551c7f4']and
            all(r['writer_PC']=='0x385450'and not r['guest_memory_rewritten_by_test']for r in root['snapshot']['original_GUI_initialized_data_mutations']),
        '13_preserved_failed_partial_metadata_terminated_loop_not_success_root_dev_distinct':index['failed_or_partial_run_metadata_count']==13 and
            len(index['metadata'])==14 and sha(item['preserved_development_evidence'])==item['preserved_development_evidence_sha256']and
            index['first_returning_root_development_not_counted_as_final_guard_pass']and
            terminated['run_terminated_with_SIGTERM']and terminated['no_terminal_probe_generated_for_this_run']and
            terminated['prior_probe_file_must_not_be_attributed_to_this_run']and not terminated['constructor_returned'],
        'full_general_MainMenu_still_NULL_context_failure_controller_not_executed':not failure['completed']and
            failure['registers']['pc']=='0x3518ec'and failure['registers']['r1']=='0x0'and failure['invalid_accesses'][0]['address']=='0x34'and
            not item['general_MainMenu_constructor_returned']and not item['general_MainMenu_controller_executed']and
            not item['null_context_semantics_recovered']and not rootitem['visible_player_App_verified'],
        'fresh_prior18_scope_snapshot26_frozen_suites84_findings_retained':len(before['native_app_music']['static_findings'])==84 and
            len(findings)==86 and prior['all_passed']and len(prior['scope_checks'])==18 and prior['state_sha256']==sha(previous['state'])and
            sha(previous['state'])==previous['state_sha256']and sha(previous['audit'])==previous['audit_sha256']and
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4,5,5,6],
        'canonical_task_public31_percent53_details7_phases_Taiwan_time_limits_and_privacy':public['deep_research']==state and
            all(task[k]==state[k]for k in ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities'])and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==53 and
            len(public['research_progress']['phases'])==7 and '<progress id="research-progress" max="100" value="31"'in report and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in ['report-updated-time','research-updated-time'])and
            '最新離線進展：主選單依賴與頁面掛接局部驗證'in report and '頁面仍隱藏且在畫面外'in report and '一般首頁尚未完成'in report and
            '前輪紀錄：播放器圖示與文字已畫入模擬畫布'in report and '第四參數設定錯誤'in report and
            not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report)and 'REDACTED_PRIVATE_ID'not in report,
        'user_asleep_no_device_IO_sound_writes_install_or_goal_completion':state['user_resting']and task['user_away']and
            not state['attended_testing']['user_present']and state['attended_testing']['waiting_for_user_return']and
            state['attended_testing']['no_pending_question']and all(not p['device_io']and not p['sounds_emitted']for p in [focused,root])and
            not state['last_goal_turn']['device_files_written']and not state['last_goal_turn']['automatic_calls_or_sound']and
            not state['native_app_music']['native_app_running']and not state['native_app_music']['direct_phone_music_verified']and
            not root['real_kernel_GUI_thread_touch_display_or_package_acceptance_verified']and
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests']and state['microphone_amplifier']['status']=='cancelled_by_user'and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized']and state['latest_user_instruction']['goal_completion_forbidden_by_user']and
            state['native_android_auto']['requested']and state['google_maps']['research_deferred_by_user']and state['goal_status']=='active'and
            not state['goal_complete']and state['required_work_remaining']}
    assert all(checks.values()),[k for k,v in checks.items()if not v]
    target='evidence/firmware-analysis/native-mainmenu-checkpoint-audit.json'
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        focused_proof_sha256=sha(item['evidence']),custom_Page_root_proof_sha256=sha(rootitem['evidence']),
        prior_state_snapshot_sha256=sha(previous['state']),prior_audit_snapshot_sha256=sha(previous['audit']),
        build_manifest_sha256=sha(focused['build_manifest']),audit_script_sha256=sha(str(Path(__file__).relative_to(ROOT))),
        current_turn_device_IO=False,goal_status='active',full_goal_complete=False,
        full_general_MainMenu_or_visible_player_App_verified=False)
    (ROOT/target).write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(dict(audit=target,scopes=len(checks),all_passed=True)))

if __name__=='__main__':main()
