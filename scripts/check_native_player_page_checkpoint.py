#!/usr/bin/env python3
"""Audit Page/input evidence, frozen prior findings and published limits."""
from datetime import datetime,timezone
from pathlib import Path
import json
import re
from analyze_native_sections import ROOT,EXPECTED
from check_native_music_stream_checkpoint import read,sha,artifacts


def main():
    state,task=read('evidence/deep-research-state.json'),read('evidence/task-state.json')
    public=read('reports/findings.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    finding=state['native_app_music']['static_findings'];item=finding['native_player_page']
    proof=read(item['evidence']);build=read(proof['build_manifest']);artifacts(build)
    for path,expected in proof['source_sha256'].items():assert sha(path)==expected,path
    previous=read('staging/native-player-page/previous-checkpoint.json')
    before,prior=read(previous['state']),read(previous['audit'])
    for name,value in before['native_app_music']['static_findings'].items():assert finding[name]==value,name
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
        'native_voice_outer','native_voice_compatibility','native_music_endpoint','native_music_configuration_gate',
        'native_music_policy','native_music_dispatch','native_l2cap_send','native_music_reply','native_music_loaded',
        'native_music_stream','native_music_runtime','native_music_ready','native_music_continuous',
        'native_player_menu','native_player_menu_loaded','native_player_menu_selection','native_player_widget']
    counts=[]
    for name in names:
        old=read(finding[name]['evidence']);assert sha(finding[name]['evidence'])==finding[name]['evidence_sha256'],name
        for path,expected in old['source_sha256'].items():assert sha(path)==expected,path
        if name in ['native_music_loaded','native_music_stream','native_music_runtime','native_music_ready',
                    'native_music_continuous','native_player_menu_loaded','native_player_menu_selection','native_player_widget']:
            assert sha(old['build_manifest'])==old['build_manifest_sha256'];artifacts(read(old['build_manifest']))
        if name=='native_player_menu':
            b=read(old['build_manifest']);assert sha(old['build_manifest'])==old['build_sha256']
            assert sha(b['elf'])==b['elf_sha256'] and sha(b['flat_binary'])==b['flat_binary_sha256']
        counts.append(old['case_count'])
    constructor,event,controls=proof['cases'];load,snap=proof['load'],proof['snapshot']
    runtime=read('staging/native-music-stream/emulator-runtime.json')
    failed=read('staging/native-player-page/partial-region-guard-failure.json')
    expected_mutations=[{'address':hex(a),'word_before':0,'word_after':1,'writer_PC':'0x385450',
        'original_instruction_executed':True,'guest_memory_rewritten_by_test':False}for a in [0x0551c80c,0x0551c7f4]]
    request_rows=[event['actions'][2],controls['restored_visible_enabled']]
    requests_match=all(len(r['new_audio_API_requests'])==2 and
        r['new_audio_API_requests'][0]['registers']==[9,22,11] and
        r['new_audio_API_requests'][0]['stack']==[38,0,0] and
        r['new_audio_API_requests'][1]['arguments']==[9,0] for r in request_rows)
    source=(ROOT/'scripts/emulate_native_player_page_integration.py').read_text()
    checks={
        'three_complete_groups_exact_MAIN_unchanged_build_and_dependency_hashes':
            proof['all_passed'] and proof['case_count']==len(proof['cases'])==3 and
            all(c['passed']for c in proof['cases']) and proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and
            sha(item['evidence'])==item['evidence_sha256'] and
            sha(proof['build_manifest'])==proof['build_manifest_sha256'] and
            item['source_artifact_count']==len(proof['source_sha256']) and item['source_artifact_count']>=90,
        'same_original_outer_loader_automatic_entry_and_native_file_callbacks':
            load['native_readback_bytes']==build['combined_file_bytes'] and
            load['native_readback_sha256']==build['combined_sha256'] and
            load['original_loader_result']==load['original_control_result']==11 and
            all(load['native_file_callback_entries'].values()) and load['entry_events'][0]['from_original_loader'] and
            load['install_callers'][0]['inside_loaded_component'],
        'complete_original7C4_Page_constructor_four_children_and_three_holders':
            constructor['allocation_bytes_from_original_caller_literal']==0x7c4 and
            constructor['vtable']=='0xc0e5f0' and constructor['original_children']==4 and
            [h['offset']for h in constructor['three_child_holders']]==['0x7ac','0x7b4','0x7bc'] and
            all(int(h['child'],16) and int(h['control_block'],16)for h in constructor['three_child_holders']) and
            not constructor['page_controller_switch_or_automatic_grid_population_executed'],
        'native_SQL_slot_clear_observed_sparse_fixture_then_explicit_reselection_no_generalization':
            constructor['slot15_after_constructor']==[0,0] and
            any(r['arguments'][1:]==[0,15,0]for r in constructor['original_SQL_setter_entries']) and
            constructor['slot_clear_cause_beyond_this_fixture_not_generalized'] and event['normal_lookup']['matched']==1 and
            event['normal_lookup']['caption']=='Pi 播放器',
        'original_parent_child_assignment_and_visibility_propagation_no_host_flags':
            event['stock_parent_API']=='0x37707a' and event['Page_children_after_attach']==5 and
            event['original_parent']==constructor['page'] and
            event['stock_Page_and_Widget_event_dispatch_executed'] and event['parent_restores_input_coordinates'] and
            event['Widget_flag112_remains_zero_no_capture_flag_fabricated'] and
            all(proof['original_Page_event_entry_visits'][hex(a)]for a in [0x37707a,0x376df8,0x376bf6,0x27a502]),
        'numeric0_1_state_only_numeric2_loaded_player_twice_correct_WAV_API_requests':
            [r['numeric_action']for r in event['actions']]==[0,1,2] and
            [r['Widget_state_C8_C9_CA']for r in event['actions']]==[[1,2,2],[1,0,0],[1,0,0]] and
            [len(r['new_audio_API_requests'])for r in event['actions']]==[0,0,2] and requests_match and
            snap['native_menu_state']==[1,1,2,0x13528000,2,2] and
            proof['original_Page_event_entry_visits']['0x31649a']==2 and
            not event['host_invoked_signal_or_compiled_player_directly'] and 'vm.invoke(0x27a98' not in source,
        'hidden_disabled_outside_bounds_suppress_player_restored_state_activates':
            all(not controls[k]['new_audio_API_requests']for k in ['hidden','disabled','outside_Page']) and
            controls['outside_Page']['point']==[480,272] and
            len(controls['restored_visible_enabled']['new_audio_API_requests'])==2 and
            controls['only_original_state_APIs_used_for_visibility_and_enabled'],
        'explicit_geometry_numeric_input_and_nondefault_click_sound_setting_no_physical_input_claim':
            event['test_supplied_geometry']=={'Page':[0,0,480,272],'Widget':[100,200,100,40]} and
            event['test_sound_selector']==0x36 and event['stock_sound_selector_API']=='0x27abf8' and
            event['optional_click_sound_wait_skipped_by_nondefault_test_setting'] and
            not event['original_input_driver_classification_or_real_touch_executed'] and
            not proof['physical_input_event_classification_executed'] and not proof['rendered_touchable_icon_verified'] and
            not proof['automatic_grid_population_or_page_controller_switch_executed'],
        'kernel_wake_ack_boundary_not_delivered_OS_callback_or_capture':
            proof['original_kernel_wake_boundary_fixture']['entry']=='0x2fcf44' and
            proof['original_kernel_wake_boundary_fixture']['result']==0 and
            bool(proof['original_kernel_wake_boundary_fixture']['requests']) and
            not proof['original_kernel_wake_boundary_fixture']['kernel_thread_or_notification_delivery_executed'] and
            proof['virtual_VFP_access_supplied'] and proof['original_GUI_timer_constructor_invoked_by_test'] and
            all(r['startup_zero_provenance']for r in proof['mapped_startup_zero_pages']),
        'two_exact_native_RAM_guard_words_full_region_code_canary_checks_not_blanket_removal':
            snap['original_GUI_initialized_data_mutations']==expected_mutations and
            snap['full_conditional_data_region_matches_two_native_word_allowances'] and
            proof['only_two_original_GUI_guard_words_change_conditional_initialized_data'] and
            snap['stock_and_loaded_code_unchanged'] and snap['all_allocation_guards_intact'] and
            not build['patch_plan'] and build['VM_MAIN_patch_bytes']==0,
        'backup_SQL15_rows_restored_native_finalize_original_voice_RAM40_exports_retained':
            proof['all15_DB_rows_restored_in_memory'] and proof['original_SQL_statement_finalization'] and
            proof['database_backup_unchanged'] and
            proof['database_sha256']=='1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99' and
            proof['original_voice_RAM_and40_exports_retained_after_Page_events'] and
            load['original40_and_original_runtime_preserved'] and load['native_private12_and_player2_tables_match'],
        'resident_module_original_reservation_RX_RW_package_for_emulation_only':
            build['extension_bytes']==54906 and build['combined_file_bytes']==2353926 and
            build['combined_ram_bytes']==2462860 and build['remaining_reservation_bytes']==682868 and
            load['original_3MiB_reservation_retained'] and not build['unresolved_symbols'] and
            build['code_RX_data_RW_segments'] and build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT'] and
            'EMULATION-ONLY' in build['package'] and not proof['device_install_candidate'] and
            not proof['actual_package_acceptance_verified'] and
            proof['Page_Widget_holders_callbacks_resources_and_module_remain_pinned'],
        'validated214_library_guard_controls_partial_failed_run_preserved':
            proof['emulator_binding_version']=='2.1.4' and proof['emulator_native_version']==[2,1,33621247] and
            sha(runtime['successful_runtime']['native_library'])==runtime['successful_library_sha256'] and
            sha(runtime['successful_runtime']['binding_file'])==runtime['successful_binding_sha256'] and
            len(proof['guard_fault_controls'])==2 and all(c['passed']for c in proof['guard_fault_controls']) and
            failed['terminal_exit']==1 and failed['groups_reported_before_guard']==3 and
            not failed['full_suite_complete'] and sha(failed['source_at_failure'])==failed['source_sha256'],
        'frozen20_selected_suites_all_previous_findings_exact_prior16_scope_state_snapshot':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3] and
            prior['all_passed'] and len(prior['scope_checks'])==16 and prior['state_sha256']==sha(previous['state']),
        'canonical_task_public31_percent44_details_Taiwan_time_privacy_limits':
            public['deep_research']==state and all(task[k]==state[k]for k in
                ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==44 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)for ident in
                ['report-updated-time','research-updated-time']) and
            all(text in report for text in ['最新離線進展：原廠菜單頁接上播放器事件','三組完整驗證通過',
                '座標與事件仍由測試提供','第十五格','原機 App 和手機直接藍牙音樂尚未完成',
                '前輪紀錄：原廠按鈕建構與播放器訊號']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
        'user_sleeping_no_IO_sound_unchanged_physical_evidence_preferences_full_goal_active':
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['device_io'] and
            not proof['device_files_modified'] and not proof['sounds_emitted'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining']}
    assert all(checks.values()),[name for name,value in checks.items()if not value]
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':checks,
        'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':sha(item['evidence']),'build_manifest_sha256':sha(proof['build_manifest']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False}
    out='evidence/firmware-analysis/native-player-page-checkpoint-audit.json'
    (ROOT/out).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'audit':out,'scopes':len(checks),'all_passed':True}))


if __name__=='__main__':main()
