#!/usr/bin/env python3
"""Audit caption correction and stock SQL selection without implying a rendered App."""
from datetime import datetime, timezone
import json
from pathlib import Path
import re
from analyze_native_sections import ROOT, EXPECTED
from check_native_music_stream_checkpoint import read, sha, artifacts


def main():
    state = read('evidence/deep-research-state.json')
    task = read('evidence/task-state.json')
    public = read('reports/findings.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    findings = state['native_app_music']['static_findings']
    item = findings['native_player_menu_selection']
    proof = read(item['evidence'])
    build = read(proof['build_manifest'])
    for path, digest in proof['source_sha256'].items():
        assert sha(path) == digest, path
    artifacts(build)
    previous = read('staging/native-player-menu-selection/previous-checkpoint.json')
    before = read(previous['state'])
    prior = read(previous['audit'])
    names = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
             'native_voice_outer', 'native_voice_compatibility', 'native_music_endpoint',
             'native_music_configuration_gate', 'native_music_policy', 'native_music_dispatch',
             'native_l2cap_send', 'native_music_reply', 'native_music_loaded', 'native_music_stream',
             'native_music_runtime', 'native_music_ready', 'native_music_continuous',
             'native_player_menu', 'native_player_menu_loaded']
    counts = []
    for name in names:
        assert findings[name] == before['native_app_music']['static_findings'][name], name
        old = read(findings[name]['evidence'])
        assert sha(findings[name]['evidence']) == findings[name]['evidence_sha256'], name
        for path, digest in old['source_sha256'].items():
            assert sha(path) == digest, path
        if name in ['native_music_loaded', 'native_music_stream', 'native_music_runtime',
                    'native_music_ready', 'native_music_continuous', 'native_player_menu_loaded']:
            assert sha(old['build_manifest']) == old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        if name == 'native_player_menu':
            b = read(old['build_manifest'])
            assert sha(old['build_manifest']) == old['build_sha256']
            assert sha(b['elf']) == b['elf_sha256']
            assert sha(b['flat_binary']) == b['flat_binary_sha256']
        counts.append(old['case_count'])
    poison, selected, add = proof['cases']
    stages = {row['name']: row for row in selected['stages']}
    result = stages['native_setter_getter_selects_loaded_callback']['result']
    load = selected['load']
    snap = selected['snapshot']
    root = add['root']['constructor_endpoint']
    original = (ROOT / build['original_binary']).read_bytes()
    combined = (ROOT / build['combined_binary']).read_bytes()
    database = next(path for path in proof['source_sha256'] if path.endswith('/custom_mm_icons.db'))
    expected_sql_visits = {'0x316276': 5, '0x315f16': 6, '0x392938': 11, '0x2fb78e': 11,
                           '0x2376dc': 11, '0x23762c': 21, '0x2378ae': 11, '0x237588': 54,
                           '0x237a70': 10, '0x2376b8': 11}
    checks = {
        'three_complete_groups81_dependencies52_build_sources_exact_MAIN':
            proof['all_passed'] and proof['case_count'] == len(proof['cases']) == 3 and
            all(row['passed'] for row in proof['cases']) and len(proof['source_sha256']) == 81 and
            len(build['source_sha256']) == 52 and proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED and
            sha(item['evidence']) == item['evidence_sha256'] and
            sha(proof['build_manifest']) == proof['build_manifest_sha256'],
        'poison_control_exposes_old_auxiliary_without_claiming_physical_UI_failure':
            poison['old_auxiliary_word'] == '0xa5a5a5a5' and poison['text_still_correct'] and
            poison['old_binary_unchanged'] and not poison['physical_UI_failure_proven'],
        'new16_byte_string20_byte_caption_auxiliary_zero':
            item['caption_string_bytes'] == 16 and item['caption_record_bytes'] == 20 and
            item['caption_auxiliary_initialized_to_zero'] and build['caption_auxiliary_word_initialized'] and
            selected['new_record_auxiliary_word'] == result['caption_auxiliary'] == root['caption_auxiliary'] == 0 and
            result['caption'] == root['caption'] == 'Pi 播放器',
        'original_outer_readback_loader_auto_registration_same_VM':
            load['native_readback_bytes'] == build['combined_file_bytes'] and
            load['native_readback_sha256'] == build['combined_sha256'] and
            load['original_loader_result'] == load['original_control_result'] == 11 and
            all(load['native_file_callback_entries'].values()) and
            len(load['entry_events']) == len(load['install_callers']) == 1 and
            load['entry_events'][0]['from_original_loader'] and load['install_callers'][0]['inside_loaded_component'] and
            snap['outer']['generic_API_binding_activation_region_read_unhooked'],
        'forty_original_voice_private12_player2_preserved_full_original_image':
            load['original40_and_original_runtime_preserved'] and load['native_private12_and_player2_tables_match'] and
            load['original_compatibility_result'] == 1 and load['current_voice_cache_is_fixture'] and
            combined[12:len(original)] == original[12:],
        'six_native_SQL_cell_selection_scenarios_exact_stock_wrapper_execution':
            len(stages) == item['SQL_selection_scenarios'] == 6 and
            selected['original_SQL_wrapper_visits'] == expected_sql_visits and
            stages['original_empty_cell']['result']['matched'] == 0 and result['matched'] == 1 and
            result['icon'] == 0x7f135201 and result['size'] == 0 and result['context'] == 0x13528000 and
            all(stages[name]['result']['matched'] == 0 and not stages[name]['result']['widget_requests']
                for name in ['normal_getter_rejects_size1', 'normal_getter_rejects_size2',
                             'unknown_icon_ID_rejected', 'missing_cell_rejected']) and
            stages['missing_cell_rejected']['result']['icon'] == 0xdead0001,
        'read_only_backup_host_memory_SQL_engine_fixture_all_rows_restored_and_finalized':
            selected['SQL_engine_is_host_SQLite_fixture'] and selected['DB_ready_handle_and_flag_are_fixtures'] and
            selected['all_statements_finalized_by_original_wrapper'] and selected['all15_rows_restored_in_memory'] and
            selected['database_backup_unchanged'] and sha(database) == proof['database_sha256'] ==
            '1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99' and
            item['SQLite_engine_is_host_in_memory_fixture'],
        'matched_lookup_factory_boundary_untouched_no_Widget_success_claim':
            item['widget_factory_is_boundary'] and len(result['widget_requests']) == 1 and
            result['widget_requests'][0]['entry'] == '0x315b64' and
            not result['widget_requests'][0]['widget_constructed'] and result['widget_output_untouched'] and
            not snap['full_Widget_SQL_touch_rendering_executed'] and not proof['rendered_touchable_icon_verified'],
        'chosen_resident_callback_original_member_dispatch_to_WAV_API_fixture':
            snap['state']['registration_result'] == 0 and snap['native_menu_state'] == [1, 1, 1, 0x13528000, 1, 1] and
            snap['catalog'][-1]['launch'] == hex(build['symbols']['native_player_menu_activate']['address']) and
            snap['original_entry_visits']['0x6acf3a'] == snap['original_entry_visits']['0x31649a'] == 1 and
            len(snap['audio_API_boundary_requests']) == 2 and
            snap['audio_API_boundary_requests'][0]['registers'] == [9, 22, 11] and
            snap['audio_API_boundary_requests'][0]['stack'] == [38, 0, 0] and
            snap['audio_API_boundary_requests'][1]['arguments'] == [9, 0] and not snap['speaker_or_DAC_executed'],
        'Add_nonroot_returns_root_stops_before_constructor_policy_is_fixture':
            add['nonroot']['category'] == 1 and add['nonroot']['returned'] and
            add['nonroot']['constructor_endpoint'] is None and add['root']['category'] == 0 and
            not add['root']['returned'] and root['entry'] == '0x6a56d8' and root['id'] == 0x7f135201 and
            root['stack_args'] == [0, 1, 0] and not root['constructor_executed'] and
            not root['full_Add_function_returned'] and not add['full_GUI_or_root_function_completion_proven'] and
            add['nonroot']['policy_boolean_is_fixture'] == add['root']['policy_boolean_is_fixture'] == 0,
        '54906_code2353926_file2462860_RAM18036_BSS_original_reservation_RX_RW_no_MAIN_patch':
            build['extension_bytes'] == 54906 and len(combined) == build['combined_file_bytes'] == 2353926 and
            build['combined_ram_bytes'] == 2462860 and build['BSS_bytes'] == 18036 and
            build['remaining_reservation_bytes'] == 682868 and load['original_3MiB_reservation_retained'] and
            not build['unresolved_symbols'] and build['code_RX_data_RW_segments'] and
            not any(token in build['segments'] for token in ['RWE', 'INTERP', 'DYNAMIC']) and
            not build['patch_plan'] and build['VM_MAIN_patch_bytes'] == 0 and
            snap['stock_and_loaded_code_unchanged'] and snap['all_allocation_guards_intact'] and
            snap['outer_files_and_temporary_handles_closed'] and snap['loaded_module_and_callback_remain_resident'] and
            snap['declared_platform_fixture_changes'] == [{'address': '0x05400000', 'before': '0x0',
                'fixture': 1, 'purpose': 'Inherited platform active-byte fixture'}],
        'container_other_members_unchanged_SIG_acceptance_not_install_candidate':
            build['package_checks']['DLL_blocks_contiguous'] and build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members'] == ['DLLIMG.BIN', 'DLLINFO.TXT'] and
            not build['package_checks']['signature_algorithm_or_enforcement_verified'] and
            not build['real_package_acceptance_verified'] and not proof['actual_package_acceptance_verified'] and
            not build['device_install_candidate'] and not proof['device_install_candidate'] and
            'EMULATION-ONLY' in build['package'],
        'frozen18_suites_and_exact_saved_prior14_scope_state':
            counts == [10, 2, 6, 12, 15, 29, 189, 208, 18, 10, 112, 8, 21, 9, 14, 5, 4, 3] and
            prior['all_passed'] and len(prior['scope_checks']) == 14 and prior['state_sha256'] == sha(previous['state']),
        'isolated214_guard_controls_and_native_cleanup_correction_recorded':
            proof['emulator_binding_version'] == '2.1.4' and proof['emulator_native_version'] == [2, 1, 33621247] and
            len(proof['guard_fault_controls']) == 2 and all(c['passed'] for c in proof['guard_fault_controls']) and
            state['native_app_music']['development_observations']['caption_and_Add_selection']
                 ['3954F0_is_Thumb_refcount_holder_cleanup_not_raw_free'] and
            not snap['UI_thread_timing_proven'],
        'canonical_public_task31_percent42_items_Taiwan_times_privacy_and_GUI_limits':
            public['deep_research'] == state and all(task[key] == state[key] for key in
                ['last_goal_turn', 'next_actions', 'attended_testing', 'latest_user_instruction', 'ordered_priorities']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 42 and
            all(re.search('<time id="' + ident + '" datetime="[^\"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']) and
            all(text in report for text in ['最新離線進展：名稱欄位修正與原廠菜單選取',
                '三組驗證通過，包含六項資料庫選取情境', '選取成功仍未證明按鈕已建立或畫面已顯示',
                '記憶體中的十五格已還原', '測試停在建構前', '不檢查按鈕工廠的回傳值']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
        'user_sleeping_no_device_IO_sound_physical_baseline_preserved_full_goal_active':
            state['audio']['native_WAV_tests'] == before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['device_io'] and
            not proof['device_files_modified'] and not proof['sounds_emitted'] and
            not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and
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
    path = 'evidence/firmware-analysis/native-player-menu-selection-checkpoint-audit.json'
    (ROOT / path).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scopes': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
