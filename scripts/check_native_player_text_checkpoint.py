#!/usr/bin/env python3
"""Audit original font/layout/state evidence without claiming physical UI."""
from datetime import datetime, timezone
from pathlib import Path
import json
import re
from analyze_native_sections import ROOT, EXPECTED, NativeImage
from check_native_music_stream_checkpoint import read, sha, artifacts


def main():
    state, task = read('evidence/deep-research-state.json'), read('evidence/task-state.json')
    public = read('reports/findings.json')
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    findings = state['native_app_music']['static_findings']
    item = findings['native_player_text']
    proof = read(item['evidence'])
    build = read(proof['build_manifest'])
    artifacts(build)
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    previous = read('staging/native-player-text/previous-checkpoint.json')
    before, prior = read(previous['state']), read(previous['audit'])
    for name, value in before['native_app_music']['static_findings'].items():
        assert findings[name] == value, name
    names = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
        'native_voice_outer', 'native_voice_compatibility', 'native_music_endpoint',
        'native_music_configuration_gate', 'native_music_policy', 'native_music_dispatch',
        'native_l2cap_send', 'native_music_reply', 'native_music_loaded', 'native_music_stream',
        'native_music_runtime', 'native_music_ready', 'native_music_continuous',
        'native_player_menu', 'native_player_menu_loaded', 'native_player_menu_selection',
        'native_player_widget', 'native_player_page', 'native_player_grid']
    counts = []
    for name in names:
        old = read(findings[name]['evidence'])
        assert sha(findings[name]['evidence']) == findings[name]['evidence_sha256'], name
        for path, expected in old['source_sha256'].items():
            assert sha(path) == expected, path
        if name in ['native_music_loaded', 'native_music_stream', 'native_music_runtime',
            'native_music_ready', 'native_music_continuous', 'native_player_menu_loaded',
            'native_player_menu_selection', 'native_player_widget', 'native_player_page', 'native_player_grid']:
            assert sha(old['build_manifest']) == old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        if name == 'native_player_menu':
            b = read(old['build_manifest'])
            assert sha(old['build_manifest']) == old['build_sha256']
            assert sha(b['elf']) == b['elf_sha256'] and sha(b['flat_binary']) == b['flat_binary_sha256']
        counts.append(old['case_count'])
    fonts, geometry, event, controls = proof['cases']
    load, snapshot = proof['load'], proof['snapshot']
    tables = read(fonts['embedded_tables'])
    im = NativeImage()
    # Check actual sfnt bytes independently of the recorded native queries.
    import hashlib
    for row in tables['fonts']:
        if row['kind'] == 2:
            assert hashlib.sha256(im.read(int(row['pointer'], 16), row['size'])).hexdigest() == row['sfnt_sha256']
    paint = read(proof['paint_probe'])
    paint_meta = read('staging/native-player-text/paint-no-pixels-metadata.json')
    layout_failure = read('staging/native-player-text/layout-assertion-failure.json')
    heap_failure = read('staging/native-player-text/containing-page-heap-failure.json')
    sql_failure = read('staging/native-player-text/containing-page-statement-failure.json')
    hit_failure = read('staging/native-player-text/native-hit-assertion-failure.json')
    parent_failure = read('staging/native-player-text/parent-ABI-failure.json')
    parent_probe = read(parent_failure['probe'])
    font_guard_failure = read('staging/native-player-text/font-ownership-guard-failure.json')
    pointer_guard_failure = read('staging/native-player-text/pointer-query-guard-failure.json')
    pointer_inventory = read(pointer_guard_failure['inventory'])
    candidates = read(item['prepared_external_font_candidate_inventory'])
    assert sha(item['prepared_external_font_candidate_inventory']) == item['prepared_external_font_candidate_inventory_sha256']
    for path, expected in candidates['source_sha256'].items():
        assert sha(path) == expected, path
    runtime = read('staging/native-music-stream/emulator-runtime.json')
    source = (ROOT/'scripts/emulate_native_player_text_integration.py').read_text()
    vm_source = (ROOT/'scripts/emulate_native_player_text.py').read_text()
    writes = [dict(address=hex(a), word_before=0, word_after=1, writer_PC='0x385450',
        original_instruction_executed=True, guest_memory_rewritten_by_test=False)
        for a in [0x0551c80c, 0x0551c7f4, 0x0551c7f8]]
    calls = controls['native_appearance_calls']
    request_rows = [event['actions'][2], controls['restored']]
    request_match = all(len(r['new_audio_API_requests']) == 2 and
        r['new_audio_API_requests'][0]['registers'] == [9, 22, 11] and
        r['new_audio_API_requests'][0]['stack'] == [38, 0, 0] and
        r['new_audio_API_requests'][1]['arguments'] == [9, 0] for r in request_rows)
    checks = {
        'four_complete_groups_exact_MAIN_build_dependency_hashes':
            proof['all_passed'] and proof['case_count'] == len(proof['cases']) == 4 and
            all(c['passed'] for c in proof['cases']) and proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED and
            sha(item['evidence']) == item['evidence_sha256'] and
            sha(proof['build_manifest']) == proof['build_manifest_sha256'] and
            item['source_artifact_count'] == len(proof['source_sha256']) >= 100,
        'original_outer_loader_resident_registration_original40_private12_player2_retained':
            load['native_readback_bytes'] == build['combined_file_bytes'] and
            load['native_readback_sha256'] == build['combined_sha256'] and
            load['original_loader_result'] == load['original_control_result'] == 11 and
            all(load['native_file_callback_entries'].values()) and load['entry_events'][0]['from_original_loader'] and
            load['install_callers'][0]['inside_loaded_component'] and load['original40_and_original_runtime_preserved'] and
            load['native_private12_and_player2_tables_match'] and len(build['private_api']) == 12 and
            len(build['player_api']) == 2 and proof['original_voice_RAM_and40_exports_retained_after_font_geometry_state_events'],
        'native_font_initializers13_records_embedded3_external_parameter0_declared':
            fonts['static_initializer'] == '0x4df248' and fonts['runtime_initializer'] == '0x4de236' and
            fonts['initializer_return'] == 0 and len(fonts['font_inventory']) == 13 and
            fonts['active_embedded_indices'] == tables['embedded_sfnt_indices'] == [3, 4, 5] and
            fonts['current_context_record'] == '0x14b5004' and fonts['cache_requested_bytes'] == 0xc0000 and
            fonts['original_reserved_cache_pointer'] == '0x34fa3bc' and
            fonts['test_requested_external_font_loading_parameter'] == 0 and
            not fonts['external_fonts_or_real_boot_resource_inventory_loaded'] and
            not fonts['host_constructed_current_font_context'] and not proof['real_boot_font_inventory_or_CJK_loaded'],
        'actual_sfnt_cmap_and_native_queries_agree_no_CJK_or_fabricated_metrics':
            tables['descriptor_table'] == '0xf088b0' and tables['descriptor_count'] == 13 and
            [r['size'] for r in tables['fonts'] if r['kind'] == 2] == [73272, 47360, 76860] and
            [r['native_glyph_indices']['0x50'] for r in fonts['native_glyph_queries']] == [49, 100, 49] and
            [r['native_glyph_indices']['0x69'] for r in fonts['native_glyph_queries']] == [74, 0, 74] and
            all(r['native_glyph_indices'][cp] == 0 for r in fonts['native_glyph_queries']
                for cp in ['0x64ad', '0x653e', '0x5668']) and
            all(all(g['glyph'] == 0 for g in r['selected_unicode_cmap'][cp])
                for r in tables['fonts'] if r['kind'] == 2 for cp in ['0x64ad', '0x653e', '0x5668']) and
            not fonts['CJK_glyphs_available_in_loaded_fonts'] and not proof['font_metrics_or_glyphs_mocked'] and
            not fonts['fonts_metrics_or_glyph_success_hooked_or_fabricated'] and
            candidates['candidate_count'] == 8 and candidates['hidden_backup_directory_included'] and
            not candidates['native_byte_transform_recovered_or_executed'] and
            not candidates['native_external_font_loading_verified'] and not candidates['actual_Chinese_UI_rendering_verified'] and
            any('DFHeiW5-A' in r['families'] and all(any(g['glyph'] for g in r['cmap_glyph_queries'][cp])
                for cp in ['0x64ad', '0x653e', '0x5668', '0x7afa', '0x539f']) for r in candidates['files']),
        'original_automatic_Grid_and_native_two_size_geometry_explicit_second_relayout':
            geometry['row_count'] == 15 and geometry['child_count'] == 19 and geometry['selected_cell'] == 12 and
            geometry['normal_mode'] == 0 and geometry['caption'] == 'Pi 播放器' and
            geometry['factory_initial_state'] == [1, 4, 4] and geometry['factory_initial_frame'] == [0, 0, 0, 0] and
            [r['outer_Grid_frame_supplied_by_test'] for r in geometry['layouts']] == [[0, 0, 480, 220], [40, 30, 360, 180]] and
            [r['original_calculated_Widget_frame'] for r in geometry['layouts']] == [[288, 146, 96, 73], [216, 120, 72, 60]] and
            [r['original_relayout_body_requested_by_test'] for r in geometry['layouts']] == [False, True] and
            all(any(0x20 <= int(w['offset'], 16) < 0x30 for w in r['native_Widget_writes']) for r in geometry['layouts']) and
            geometry['native_geometry_API'] == '0x377ab8' and geometry['native_Grid_geometry_body'] == '0x547020' and
            geometry['stock_MainMenu_direct_relayout_caller_verified'] == '0x403dee' and
            not geometry['GUI_resize_or_dirty_flag_notification_executed'] and
            not geometry['host_Widgets_frame_writes_or_geometry_success_hook'],
        'compiled_registered_updater_native_factory_refresh_outputs_unchanged_enable_disable':
            geometry['updater_pointer'] == geometry['native_appearance_symbol'] == '0x2f820ec' and
            len(calls) == 4 and [r['caller'] for r in calls] == ['0x315ba8', '0x54a364', '0x54a364', '0x54a364'] and
            [r['returned_state'] for r in calls] == [0, 0, 4, 0] and
            all(r['compiled_callback_executed'] and r['stock_output_objects_byte_unchanged'] and
                [n for p, n, before_hex in r['output_before']] == [56, 20, 4] for r in calls) and
            controls['compiled_updater_state'][:3] == [4, 1, 0x13528000] and
            event['state_before'] == [1, 4, 4] and event['state_after'] == [1, 0, 0] and
            event['compiled_updater_called_through_original_factory_and_refresh'] and
            not event['host_called_compiled_updater_or_enable0_API_or_signal_directly'] and
            'vm.invoke(0x30c91' not in source and 'vm.invoke(0x27a98' not in source,
        'numeric_events_at_native_frame_center_reach_resident_player_through_nested_parents':
            event['stock_parent_API_arguments'] == [int(geometry['Page'], 16), int(geometry['Grid'], 16), 0, 0] and
            event['Page_children_after_Grid_attach'] == 5 and event['Grid_parent'] == geometry['Page'] and
            event['native_Widget_frame'] == [216, 120, 72, 60] and event['outer_Grid_frame'] == [40, 30, 360, 180] and
            event['center_computed_by_test'] == [292, 180] and
            [r['numeric_action'] for r in event['actions']] == [0, 1, 2] and
            [len(r['new_audio_API_requests']) for r in event['actions']] == [0, 0, 2] and request_match and
            all(r['returned'] == geometry['Widget'] and len(r['player_Widget_inputs']) == 1 and
                r['player_Widget_inputs'][0]['point'] == [36, 30] for r in event['actions']) and
            snapshot['native_menu_state'] == [1, 1, 2, 0x13528000, 2, 2] and
            proof['native_font_geometry_state_entry_visits']['0x31649a'] == 2,
        'native_hidden_context_disabled_outside_controls_restore_requests_without_DB_context_change':
            all(not controls[k]['new_audio_API_requests'] for k in ['hidden', 'unexpected_context_disabled', 'outside_Grid_inside_Page']) and
            controls['unexpected_context_disabled']['Widget_state'] == [1, 4, 4] and
            controls['outside_Grid_inside_Page']['global_point'] == [400, 210] and
            len(controls['restored']['new_audio_API_requests']) == 2 and
            controls['test_modified_in_memory_row_context_only_then_restored'] and controls['DB_catalog_original_context_unchanged'] and
            controls['negative_context_return4_applied_by_native_Widget_setter'],
        'render_probe_zero_pixels_honest_reconstructed_source_root_touch_install_open':
            paint['completed'] and paint['phase'] == 'stock_Grid_paint_returned' and
            not paint['paint_pixel_buffer_changed'] and paint['paint_changed_bytes'] == 0 and not paint['paint_font_calls'] and
            paint_meta['terminal_exit'] == 0 and not paint_meta['full_final_guards_completed'] and
            paint_meta['source_reconstructed_after_run_by_reversing_only_observer_patch'] and
            not paint_meta['source_hash_independently_captured_before_run'] and
            sha('staging/native-player-text/source-at-paint-no-pixels.py') == paint_meta['source_sha256'] and
            not proof['real_rendering_or_display_verified'] and not proof['actual_page_controller_switch_executed'] and
            not proof['actual_input_classification_executed'] and event['test_nondefault_sound_selector36_via_original_API'] and
            event['Containing_Page_frame_written_by_test_for_input'] == [0, 0, 480, 272] and
            not event['native_Containing_Page_geometry_or_root_controller_completed'] and
            event['Widget_flag112_remains0'] and geometry['Containing_Page_still_requires_native_reselection_after_setting_failure'] and
            proof['original_kernel_wake_boundary_fixture']['result'] == 0 and
            bool(proof['original_kernel_wake_boundary_fixture']['requests']) and
            not proof['original_kernel_wake_boundary_fixture']['actual_kernel_wake_delivery'],
        'failed_layout_and_inherited_heap_limit_preserved_not_full_pass_or_hardware_failure':
            layout_failure['terminal_exit'] == 1 and layout_failure['groups_reported_before_failure'] == 1 and
            not layout_failure['full_suite_complete'] and sha(layout_failure['source']) == layout_failure['source_sha256'] and
            heap_failure['session'] == 52990 and heap_failure['exit_code'] == 1 and
            heap_failure['complete_case_groups_before_failure'] == 2 and not heap_failure['full_pass'] and
            sha(heap_failure['source']) == heap_failure['source_sha256'] and sha(heap_failure['VM_source']) == heap_failure['VM_source_sha256'] and
            sql_failure['session'] == 82254 and sql_failure['exit_code'] == 1 and
            sql_failure['complete_case_groups_before_failure'] == 2 and not sql_failure['full_pass'] and
            sha(sql_failure['source']) == sql_failure['source_sha256'] and sha(sql_failure['VM_source']) == sql_failure['VM_source_sha256'] and
            hit_failure['session'] == 66162 and hit_failure['exit_code'] == 1 and not hit_failure['full_pass'] and
            sha(hit_failure['source']) == hit_failure['source_sha256'] and
            parent_failure['session'] == 91107 and parent_failure['exit_code'] == 1 and not parent_failure['full_pass'] and
            sha(parent_failure['source']) == parent_failure['source_sha256'] and
            sha(parent_failure['probe']) == parent_failure['probe_sha256'] and
            parent_probe['Page_children'] == 4 and not parent_probe['all_numeric_Widget_inputs'] and
            font_guard_failure['session'] == 59547 and font_guard_failure['exit_code'] == 1 and
            font_guard_failure['complete_case_groups_before_failure'] == 4 and not font_guard_failure['full_pass'] and
            sha(font_guard_failure['source']) == font_guard_failure['source_sha256'] and
            sha(font_guard_failure['VM_source']) == font_guard_failure['VM_source_sha256'] and
            pointer_guard_failure['session'] == 48645 and pointer_guard_failure['exit_code'] == 1 and
            pointer_guard_failure['complete_case_groups_before_failure'] == 4 and not pointer_guard_failure['full_pass'] and
            sha(pointer_guard_failure['source']) == pointer_guard_failure['source_sha256'] and
            sha(pointer_guard_failure['VM_source']) == pointer_guard_failure['VM_source_sha256'] and
            sha(pointer_guard_failure['inventory']) == pointer_guard_failure['inventory_sha256'] and
            len(pointer_inventory['handles']) == 19 and all(not e['freed'] and e['locks'] == 0 for e in pointer_inventory['handles']),
        'three_native_once_words_full_region_code_canaries_and_persistent_font_nonfont_guards':
            snapshot['original_GUI_initialized_data_mutations'] == writes and
            snapshot['full_conditional_data_region_matches_three_native_word_allowances'] and
            proof['only_three_exact_original_GUI_guard_words_change_conditional_initialized_data'] and
            snapshot['stock_and_loaded_code_unchanged'] and snapshot['all_allocation_guards_intact'] and
            bool(snapshot['original_font_persistent_handles']) and
            len(snapshot['original_font_persistent_handles']) == 19 and
            all(e['locks'] == 0 and not e['freed'] for e in snapshot['original_font_persistent_handles']) and
            snapshot['original_font_resident_handles_fixture_locks0_prefixes_queries_and_canaries_verified'] and
            not snapshot['native_heap_pin_or_lock1_claim'] and bool(snapshot['original_font_pointer_queries']) and
            snapshot['released_font_temporaries_keep_inherited_ownership_checks'] and
            all(e['freed'] and e['locks'] == 0 for e in snapshot['original_font_temporary_handles_released']) and
            snapshot['inherited_outer_checks_retained_for_every_non_font_handle'] and
            'try:super().verify_released()' in vm_source and
            'self.next_gui_raw' not in vm_source,
        'SQL15_rows_restored_finalize_backup_unchanged_and_emulation_only_build_reservation':
            proof['all15_DB_rows_restored_in_memory'] and proof['original_SQL_statement_finalization'] and
            proof['database_backup_unchanged'] and proof['database_sha256'] == '1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99' and
            build['extension_bytes'] == 54982 and build['combined_file_bytes'] == 2354002 and
            build['combined_ram_bytes'] == 2462860 and build['BSS_bytes'] == 18060 and
            build['remaining_reservation_bytes'] == 682868 and load['original_3MiB_reservation_retained'] and
            not build['patch_plan'] and build['VM_MAIN_patch_bytes'] == 0 and not build['unresolved_symbols'] and
            build['code_RX_data_RW_segments'] and build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members'] == ['DLLIMG.BIN', 'DLLINFO.TXT'] and
            'EMULATION-ONLY' in build['package'] and proof['objects_fonts_contexts_handles_callbacks_module_remain_pinned'] and
            not proof['device_install_candidate'] and not proof['actual_package_acceptance_verified'],
        'isolated_Unicorn214_actual_library_and_two_guard_fault_controls':
            proof['emulator_binding_version'] == '2.1.4' and proof['emulator_native_version'] == [2, 1, 33621247] and
            sha(runtime['successful_runtime']['native_library']) == runtime['successful_library_sha256'] and
            sha(runtime['successful_runtime']['binding_file']) == runtime['successful_binding_sha256'] and
            len(proof['guard_fault_controls']) == 2 and all(c['passed'] for c in proof['guard_fault_controls']),
        'frozen22_selected_suites_all80_previous_findings_precise_prior16_scope_snapshot':
            counts == [10, 2, 6, 12, 15, 29, 189, 208, 18, 10, 112, 8, 21, 9, 14, 5, 4, 3, 3, 3, 3, 4] and
            len(before['native_app_music']['static_findings']) == 80 and prior['all_passed'] and
            len(prior['scope_checks']) == 16 and prior['state_sha256'] == sha(previous['state']),
        'canonical_task_public31_percent46_details_Taiwan_time_and_privacy':
            public['deep_research'] == state and all(task[k] == state[k] for k in
                ['last_goal_turn', 'next_actions', 'attended_testing', 'latest_user_instruction', 'ordered_priorities']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 46 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"', report) for ident in
                ['report-updated-time', 'research-updated-time']) and
            all(t in report for t in ['最新離線進展：原廠字型、格位佈局與播放器狀態', '四組完整離線驗證通過',
                '這次明確跳過外部字型載入', '画面與實機 App 仍未完成'.replace('画','畫'),
                '原機 App 和手機直接藍牙音樂尚未完成', '前輪紀錄：原廠自動格位建立播放器按鈕']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
        'user_sleeping_no_device_IO_sound_physical_evidence_priorities_goal_active':
            state['audio']['native_WAV_tests'] == before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['device_io'] and
            not proof['device_files_modified'] and not proof['sounds_emitted'] and
            not proof['native_App_running_on_device'] and not proof['phone_direct_music_verified'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status'] == 'cancelled_by_user' and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and state['native_android_auto']['requested'] and
            state['google_maps']['research_deferred_by_user'] and state['goal_status'] == 'active' and
            not state['goal_complete'] and state['required_work_remaining']}
    assert all(checks.values()), [name for name, value in checks.items() if not value]
    out = 'evidence/firmware-analysis/native-player-text-checkpoint-audit.json'
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True, scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'),
        proof_sha256=sha(item['evidence']), build_manifest_sha256=sha(proof['build_manifest']),
        audit_script_sha256=sha(str(Path(__file__).relative_to(ROOT))), current_turn_device_IO=False,
        goal_status='active', full_goal_complete=False)
    (ROOT/out).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(audit=out, scopes=len(checks), all_passed=True)))


if __name__ == '__main__':
    main()
