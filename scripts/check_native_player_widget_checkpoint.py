#!/usr/bin/env python3
"""Audit native Widget construction/signal proof and its explicit boundaries."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from analyze_native_sections import ROOT, EXPECTED
from check_native_music_stream_checkpoint import read, sha, artifacts


def main():
    state, task = read('evidence/deep-research-state.json'), read('evidence/task-state.json')
    public = read('reports/findings.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    findings = state['native_app_music']['static_findings']
    item = findings['native_player_widget']
    proof, build = read(item['evidence']), read(item['build_manifest'])
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    artifacts(build)
    previous = read('staging/native-player-widget/previous-checkpoint.json')
    before, prior = read(previous['state']), read(previous['audit'])
    names = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
             'native_voice_outer', 'native_voice_compatibility', 'native_music_endpoint',
             'native_music_configuration_gate', 'native_music_policy', 'native_music_dispatch',
             'native_l2cap_send', 'native_music_reply', 'native_music_loaded', 'native_music_stream',
             'native_music_runtime', 'native_music_ready', 'native_music_continuous',
             'native_player_menu', 'native_player_menu_loaded', 'native_player_menu_selection']
    counts = []
    for name in names:
        assert findings[name] == before['native_app_music']['static_findings'][name], name
        old = read(findings[name]['evidence'])
        assert sha(findings[name]['evidence']) == findings[name]['evidence_sha256'], name
        for path, expected in old['source_sha256'].items():
            assert sha(path) == expected, path
        if name in ['native_music_loaded', 'native_music_stream', 'native_music_runtime', 'native_music_ready',
                    'native_music_continuous', 'native_player_menu_loaded', 'native_player_menu_selection']:
            assert sha(old['build_manifest']) == old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        if name == 'native_player_menu':
            b = read(old['build_manifest'])
            assert sha(old['build_manifest']) == old['build_sha256']
            assert sha(b['elf']) == b['elf_sha256'] and sha(b['flat_binary']) == b['flat_binary_sha256']
        counts.append(old['case_count'])
    normal, flag1, node = proof['cases']
    load, snap = proof['load'], proof['snapshot']
    runtime = read('staging/native-music-stream/emulator-runtime.json')
    failure = read('staging/native-player-widget/host-crash.json')
    partial = read('staging/native-player-widget/partial-region-guard-failure.json')
    original = (ROOT / build['original_binary']).read_bytes()
    combined = (ROOT / build['combined_binary']).read_bytes()
    source = (ROOT / 'scripts/emulate_native_player_widget_integration.py').read_text()
    mutable = [{'address': '0x551c80c', 'word_before': 0, 'word_after': 1, 'writer_PC': '0x385450',
                'original_instruction_executed': True, 'guest_memory_rewritten_by_test': False}]
    checks = {
        'three_complete_groups_exact_MAIN_build_proof_and_dependencies':
            proof['all_passed'] and proof['case_count'] == len(proof['cases']) == 3 and
            all(c['passed'] for c in proof['cases']) and
            item['source_artifact_count'] == len(proof['source_sha256']) == 83 and
            proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED and
            sha(item['evidence']) == item['evidence_sha256'] and
            sha(proof['build_manifest']) == proof['build_manifest_sha256'],
        'same_original_outer_readback_loader_automatic_registry_and_GUI_VM':
            load['native_readback_bytes'] == build['combined_file_bytes'] and
            load['native_readback_sha256'] == build['combined_sha256'] and
            load['original_loader_result'] == load['original_control_result'] == 11 and
            all(load['native_file_callback_entries'].values()) and
            load['entry_events'][0]['from_original_loader'] and load['install_callers'][0]['inside_loaded_component'],
        'forty_voice_private12_player2_original_runtime_retained_after_GUI':
            load['original40_and_original_runtime_preserved'] and load['native_private12_and_player2_tables_match'] and
            proof['original_voice_RAM_and40_exports_retained_after_GUI'] and combined[12:len(original)] == original[12:],
        'original_normal_factory550_byte_Widget_vtable_and_nonempty_signal':
            normal['normal_lookup']['matched'] == 1 and normal['normal_lookup']['Widget_bytes'] == 0x550 and
            normal['normal_lookup']['vtable'] == '0xc00b38' and normal['normal_lookup']['event_slot'] == '0x27a503' and
            int(normal['normal_lookup']['click_signal'], 16) != 0 and
            normal['normal_lookup']['caption'] == 'Pi 播放器' and
            normal['normal_lookup']['factory_fifth_argument'] == 0 and
            proof['original_GUI_entry_visits']['0x315b64'] == 2 and
            proof['original_GUI_entry_visits']['0x6acf3a'] == 1,
        'two_software_Widget_signal_requests_original_member_to_loaded_callback':
            len(normal['software_signal_activations']) == 2 and
            all(len(row['new_audio_API_requests']) == 2 and
                row['new_audio_API_requests'][0]['registers'] == [9, 22, 11] and
                row['new_audio_API_requests'][0]['stack'] == [38, 0, 0] and
                row['new_audio_API_requests'][1]['arguments'] == [9, 0]
                for row in normal['software_signal_activations']) and
            proof['original_GUI_entry_visits']['0x31649a'] == 2 and
            snap['native_menu_state'] == [1, 1, 2, 0x13528000, 2, 2] and
            not normal['host_constructed_member_bind'] and not normal['host_called_compiled_callback_directly'] and
            'vm.invoke(0x27a98b, (obj,))' in source and
            not normal['input_driver_or_physical_touch'] and not normal['actual_clickable_page_or_rendering_verified'],
        'factory_flag1_constructed_Widget_but_no_launch_subscription':
            flag1['normal_lookup']['matched'] == 1 and flag1['normal_lookup']['factory_fifth_argument'] == 1 and
            flag1['vtable'] == '0xc00b38' and flag1['click_signal'] == flag1['software_signal_added_audio_requests'] == 0 and
            flag1['flag_semantics_beyond_observed_branch_unknown'] and
            flag1['separate_original_shared_ptr_holders_retained'] and
            normal['normal_lookup']['output_holder'] != flag1['normal_lookup']['output_holder'],
        'complete_Add_node8f4_ctor_stock_children_caption_ID_vtable_but_not_full_Add':
            node['node_bytes'] == 0x8f4 and node['vtable'] == '0xc15f38' and
            node['caption'] == 'Pi 播放器' and node['caption_auxiliary'] == 0 and
            node['id'] == 0x7f135201 and node['flags'] == [0, 1, 0] and node['constructor_returned'] and
            node['stock_base_and_child_constructors_executed'] and node['direct_constructor_test_call'] and
            not node['complete_Add_function_or_page_executed'] and
            all(proof['original_GUI_entry_visits'][hex(a)] for a in [0x6a56d8, 0x34163a, 0x361c02]),
        'original_instructions_execute_all20_GUI_entries_VFP_timer_zero_BSS_explicit':
            len(proof['original_GUI_entry_visits']) == 20 and all(proof['original_GUI_entry_visits'].values()) and
            proof['virtual_VFP_access_supplied'] and proof['original_GUI_timer_constructor_invoked_by_test'] and
            proof['GUI_timer_expiry_or_event_loop_not_executed'] and
            all(row['startup_zero_provenance'] for row in proof['mapped_startup_zero_pages']) and
            len(proof['mapped_startup_zero_pages']) >= 4,
        'exact_single_original_GUI_guard_word_mutation_full_region_compare_and_code_guards':
            snap['original_GUI_initialized_data_mutations'] == mutable and
            snap['full_conditional_data_region_matches_single_native_word_allowance'] and
            proof['only_original_GUI_guard_word_changes_conditional_initialized_data'] and
            snap['stock_and_loaded_code_unchanged'] and snap['all_allocation_guards_intact'] and
            snap['declared_platform_fixture_changes'] == [{'address': '0x05400000', 'before': '0x0',
                'fixture': 1, 'purpose': 'Inherited platform active-byte fixture'}] and
            not build['patch_plan'] and build['VM_MAIN_patch_bytes'] == 0,
        'host_memory_SQL15_rows_restored_native_finalize_and_verified_backup_unchanged':
            proof['DB_ready_and_host_SQLite_engine_are_fixtures'] and proof['all15_rows_restored_in_memory'] and
            proof['all_statements_finalized_by_original_wrappers'] and proof['database_backup_unchanged'] and
            proof['database_sha256'] == '1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99',
        'build54906_code2353926_file2462860_RAM_original_reservation_RX_RW_no_install':
            build['extension_bytes'] == 54906 and build['combined_file_bytes'] == 2353926 and
            build['combined_ram_bytes'] == 2462860 and build['BSS_bytes'] == 18036 and
            build['remaining_reservation_bytes'] == 682868 and load['original_3MiB_reservation_retained'] and
            not build['unresolved_symbols'] and build['code_RX_data_RW_segments'] and
            build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members'] == ['DLLIMG.BIN', 'DLLINFO.TXT'] and
            not build['real_package_acceptance_verified'] and not proof['actual_package_acceptance_verified'] and
            not build['device_install_candidate'] and 'EMULATION-ONLY' in build['package'],
        'guarded_resident_holders_module_callbacks_no_release_render_touch_speaker_claim':
            proof['Widget_holders_callbacks_module_and_UI_resources_remain_pinned'] and
            snap['loaded_module_and_callback_remain_resident'] and snap['outer_files_and_temporary_handles_closed'] and
            not proof['rendered_touchable_icon_verified'] and not snap['speaker_or_DAC_executed'] and
            not snap['UI_thread_timing_proven'] and item['software_signal_request_not_physical_touch'] and
            not item['complete_Add_builder_or_Page_executed'],
        'isolated214_library_integrity_guards_host_crash_and_partial_scope_preserved':
            proof['emulator_binding_version'] == '2.1.4' and proof['emulator_native_version'] == [2, 1, 33621247] and
            sha(runtime['successful_runtime']['native_library']) == runtime['successful_library_sha256'] and
            sha(runtime['successful_runtime']['binding_file']) == runtime['successful_binding_sha256'] and
            len(proof['guard_fault_controls']) == 2 and all(c['passed'] for c in proof['guard_fault_controls']) and
            failure['terminal_exit'] == 139 and not failure['specific_crash_root_cause_identified'] and
            sha(failure['source_at_failure']) == failure['source_sha256'] and
            partial['terminal_exit'] == 1 and not partial['full_suite_complete'] and
            sha(partial['source_at_failure']) == partial['source_sha256'],
        'frozen19_previous_suites_and_prior16_scope_exact_state_snapshot':
            counts == [10, 2, 6, 12, 15, 29, 189, 208, 18, 10, 112, 8, 21, 9, 14, 5, 4, 3, 3] and
            prior['all_passed'] and len(prior['scope_checks']) == 16 and prior['state_sha256'] == sha(previous['state']),
        'canonical_task_public31_percent43_details_Taiwan_times_privacy_and_current_scope':
            public['deep_research'] == state and all(task[key] == state[key] for key in
                ['last_goal_turn', 'next_actions', 'attended_testing', 'latest_user_instruction', 'ordered_priorities']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 43 and
            all(re.search('<time id="' + ident + '" datetime="[^\"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']) and
            all(text in report for text in ['最新離線進展：原廠按鈕建構與播放器訊號',
                '三組完整驗證通過', '仍未證明實機螢幕已有可觸控的 App', '原廠按鈕的軟體訊號兩次',
                '參數為 1 的控制案例', '完整新增菜單頁仍待接通', '物件、持有者與元件仍保留在記憶體']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
        'sleeping_no_IO_sound_physical_evidence_full_goal_preferences_preserved':
            state['audio']['native_WAV_tests'] == before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['device_io'] and
            not proof['device_files_modified'] and not proof['sounds_emitted'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status'] == 'cancelled_by_user' and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining'],
    }
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True, 'scope_checks': checks,
              'state_sha256': sha('evidence/deep-research-state.json'), 'report_sha256': sha('reports/nuvi2565RT.html'),
              'proof_sha256': sha(item['evidence']), 'build_manifest_sha256': sha(proof['build_manifest']),
              'audit_script_sha256': sha(str(Path(__file__).relative_to(ROOT))),
              'current_turn_device_IO': False, 'goal_status': 'active', 'full_goal_complete': False}
    path = 'evidence/firmware-analysis/native-player-widget-checkpoint-audit.json'
    (ROOT / path).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scopes': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
