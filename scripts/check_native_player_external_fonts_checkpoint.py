#!/usr/bin/env python3
"""Audit raw-backup external fonts, original parser and retained UI limits."""
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
    item = findings['native_player_external_fonts']
    proof = read(item['evidence'])
    build = read(proof['build_manifest'])
    artifacts(build)
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    previous = read('staging/native-player-external-fonts/previous-checkpoint.json')
    before, prior = read(previous['state']), read(previous['audit'])
    for name, value in before['native_app_music']['static_findings'].items():
        assert findings[name] == value, name
    names = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
        'native_voice_outer', 'native_voice_compatibility', 'native_music_endpoint',
        'native_music_configuration_gate', 'native_music_policy', 'native_music_dispatch',
        'native_l2cap_send', 'native_music_reply', 'native_music_loaded', 'native_music_stream',
        'native_music_runtime', 'native_music_ready', 'native_music_continuous',
        'native_player_menu', 'native_player_menu_loaded', 'native_player_menu_selection',
        'native_player_widget', 'native_player_page', 'native_player_grid', 'native_player_text']
    counts = []
    for name in names:
        old = read(findings[name]['evidence'])
        assert sha(findings[name]['evidence']) == findings[name]['evidence_sha256'], name
        for path, expected in old['source_sha256'].items():
            assert sha(path) == expected, path
        if name in ['native_music_loaded', 'native_music_stream', 'native_music_runtime',
            'native_music_ready', 'native_music_continuous', 'native_player_menu_loaded',
            'native_player_menu_selection', 'native_player_widget', 'native_player_page',
            'native_player_grid', 'native_player_text']:
            assert sha(old['build_manifest']) == old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        if name == 'native_player_menu':
            b = read(old['build_manifest'])
            assert sha(old['build_manifest']) == old['build_sha256']
            assert sha(b['elf']) == b['elf_sha256'] and sha(b['flat_binary']) == b['flat_binary_sha256']
        counts.append(old['case_count'])
    reader, fonts, geometry, event, controls = proof['cases']
    load, snapshot = proof['load'], proof['snapshot']
    preflight = read('staging/native-player-external-fonts/byte-transform-path-preflight.json')
    candidates = read('staging/native-player-external-fonts/candidate-inventory.json')
    for path, expected in candidates['source_sha256'].items():
        assert sha(path) == expected, path
    developer = read('staging/native-player-external-fonts/first-native-CJK-glyphs-metadata.json')
    failed = read('staging/native-player-external-fonts/overbroad-file-boundary-failure.json')
    write_failure = read('staging/native-player-external-fonts/captured-zero-page-write-failure.json')
    runtime = read('staging/native-music-stream/emulator-runtime.json')
    im = NativeImage()
    source = (ROOT/'scripts/emulate_native_player_external_fonts_integration.py').read_text()
    vm_source = (ROOT/'scripts/emulate_native_player_external_fonts.py').read_text()
    requests = proof['generic_font_file_requests']
    original_read_requests = [r for r in requests if r['operation'] == 'read']
    for row in original_read_requests:
        raw_path = ROOT/'backups/20261002T154458Z/files/.System/ExtData'/Path(row['path']).name
        assert str(raw_path.relative_to(ROOT)) in proof['source_sha256']
        raw = raw_path.read_bytes()
        expected = raw[row['position_before']:row['position_before']+row['returned_bytes']]
        import hashlib
        assert hashlib.sha256(expected).hexdigest() == row['supplied_raw_bytes_SHA256']
    chinese = next(r for r in fonts['native_glyph_queries'] if r['font_index'] == 2)
    expected_chinese = {'0x50':81, '0x69':106, '0x64ad':13358, '0x653e':13503,
        '0x5668':9705, '0x7afa':19067, '0x539f':8992}
    writes = [dict(address=hex(a), word_before=0, word_after=1, writer_PC='0x385450',
        original_instruction_executed=True, guest_memory_rewritten_by_test=False)
        for a in [0x0551c80c, 0x0551c7f4, 0x0551c7f8]]
    calls = controls['native_appearance_calls']
    checks = {
        'five_complete_groups_exact_MAIN_unchanged_build_all_dependency_hashes':
            proof['all_passed'] and proof['case_count'] == len(proof['cases']) == 5 and
            all(c['passed'] for c in proof['cases']) and proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED and
            sha(item['evidence']) == item['evidence_sha256'] and
            sha(proof['build_manifest']) == proof['build_manifest_sha256'] and
            item['source_artifact_count'] == len(proof['source_sha256']) >= 100,
        'original_outer_loader_whole_voice40_private12_player2_after_font_GUI_retained':
            load['native_readback_bytes'] == build['combined_file_bytes'] and
            load['native_readback_sha256'] == build['combined_sha256'] and
            load['original_loader_result'] == load['original_control_result'] == 11 and
            load['entry_events'][0]['from_original_loader'] and load['install_callers'][0]['inside_loaded_component'] and
            all(load['native_file_callback_entries'].values()) and load['original40_and_original_runtime_preserved'] and
            load['native_private12_and_player2_tables_match'] and len(build['private_api']) == 12 and len(build['player_api']) == 2 and
            proof['original_voice_RAM_and40_exports_retained_after_font_geometry_state_events'],
        'original_font_read_XOR_and_path_offset_comes_from_exact_firmware':
            preflight['MAIN_sha256'] == EXPECTED and preflight['constant'] == 0x76 and
            preflight['original_XOR_constant_instruction'] == '0x1409a8' and
            preflight['native_descriptor_filename_offset'] == 50 and preflight['prefix'] == '0:/.System/ExtData/' and
            im.read(0x4de1b4, 40).decode('utf-16-le').rstrip('\0') == preflight['prefix'] and
            proof['native_font_geometry_state_entry_visits']['0x14098c'] > 0 and
            proof['native_font_geometry_state_entry_visits']['0x1409a8'] > 0 and
            proof['native_font_geometry_state_entry_visits']['0x1409ac'] > 0 and
            proof['native_XOR76_reader_executed'] and not proof['host_decoded_font_bytes_supplied'] and
            bool(original_read_requests) and all(not r['host_decoded_font_bytes_supplied'] and
                r['caller'] == '0x14099c' for r in original_read_requests),
        'eight_native_header_offset_controls_signed_partial_EOF_zero_and_missing_files':
            reader['raw_source_control_count'] == len(reader['controls']) == 8 and
            reader['original_read_transform'] == '0x14098c' and reader['original_XOR_instruction'] == '0x1409a8' and
            all(r['closed_through_original_wrapper'] and r['header']['native_decoded_bytes'].startswith('00010000') and
                r['nonzero_unaligned_offset']['byte_offset'] == 7 and
                r['header']['canaries_and_all_unreturned_bytes_unchanged'] and
                r['nonzero_unaligned_offset']['canaries_and_all_unreturned_bytes_unchanged'] for r in reader['controls']) and
            reader['signed_EOF_relative_partial_element']['returned_bytes'] == 7 and
            reader['signed_EOF_relative_partial_element']['returned_elements'] == 1 and
            reader['EOF_zero_return']['returned_elements'] == reader['zero_element_size_return']['returned_elements'] == 0 and
            len(reader['missing_file_controls']) == 2 and all(r['returned'] == 0 and not r['backup_file_present']
                for r in reader['missing_file_controls']) and reader['all_control_files_closed_before_font_initializer'] and
            reader['original_path_conversion_and_XOR_and_element_division_executed'] and
            reader['generic_file_manager_inventory_IO_is_fixture'],
        'native_initializer_parameter1_eight_external_three_embedded_two_absent_resource_slots':
            fonts['static_initializer'] == '0x4df248' and fonts['runtime_initializer'] == '0x4de236' and
            fonts['initializer_return'] == 0 and fonts['test_requested_external_font_loading_parameter'] == 1 and
            fonts['active_font_indices'] == [0,1,2,3,4,5,7,8,9,10,12] and
            fonts['active_external_font_indices'] == [0,1,2,7,8,9,10,12] and
            fonts['active_embedded_font_indices'] == [3,4,5] and fonts['missing_backup_descriptor_indices'] == [6,11] and
            len(fonts['font_inventory']) == 13 and all(not fonts['font_inventory'][n]['metadata_flags'][1] for n in [6,11]) and
            fonts['current_context_record'] == '0x14b5004' and fonts['cache_requested_bytes'] == 0xc0000 and
            fonts['original_reserved_cache_pointer'] == '0x34fa3bc' and
            not fonts['host_constructed_current_font_context'] and not proof['actual_boot_resource_setup_executed'],
        'native_CJK_glyph_indices_match_independent_backup_cmap_no_mock_or_render_claim':
            chinese['native_glyph_indices'] == item['native_CJK_glyph_indices'] == expected_chinese and
            chinese['matched_independent_candidate_cmap'] and all(r['matched_independent_candidate_cmap']
                for r in fonts['native_glyph_queries'] if r['font_index'] in fonts['active_external_font_indices']) and
            fonts['CJK_glyphs_available_in_loaded_fonts'] and fonts['raw_external_backup_fonts_loaded'] and
            proof['raw_backup_CJK_fonts_loaded_offline'] and not proof['font_metrics_or_glyphs_mocked'] and
            not fonts['fonts_metrics_or_glyph_success_hooked_or_fabricated'] and
            not proof['real_rendering_or_display_verified'] and not item['CJK_paint_or_display_newly_verified'],
        'generic_file_manager_scope_own_font_handles_delegates_unrelated_outer_cleanup':
            proof['font_file_manager_boundaries_fixture'] and item['unrelated_shared_file_manager_calls_delegate_to_inherited_backend'] and
            any(r['operation'] == 'delegate_non_font_close' and r['caller'] == '0x2d3324' and
                r['inherited_original_backend_retained'] for r in requests) and
            "caller==0x140978" in vm_source and 'return super().observe(uc,address,size,data)' in vm_source and
            snapshot['outer_files_and_temporary_handles_closed'] and
            sum(not e['closed'] for e in proof['resident_font_stream_inventory'].values()) == 8 and
            fonts['external_font_streams_remain_native_resident'],
        'direct_callback_memory_maps_only_exact_verified_startup_zero_BSS':
            bool(proof['callback_verified_startup_zero_mappings']) and
            all(r['exact_verified_startup_zero_provenance'] and any(
                z['runtime_start'] <= int(r['requested_slice'][0], 16) and
                int(r['requested_slice'][1], 16) <= z['runtime_end'] for z in im.zeros)
                for r in proof['callback_verified_startup_zero_mappings']) and
            'Font callback destination outside verified startup-zero BSS' in vm_source,
        'native_two_size_Widget_geometry_second_relayout_Page_frame_and_parent_fixture_explicit':
            geometry['caption'] == 'Pi 播放器' and geometry['row_count'] == 15 and geometry['child_count'] == 19 and
            geometry['selected_cell'] == 12 and geometry['factory_initial_state'] == [1,4,4] and
            [r['original_calculated_Widget_frame'] for r in geometry['layouts']] == [[288,146,96,73],[216,120,72,60]] and
            [r['original_relayout_body_requested_by_test'] for r in geometry['layouts']] == [False,True] and
            not geometry['host_Widgets_frame_writes_or_geometry_success_hook'] and not geometry['GUI_resize_or_dirty_flag_notification_executed'] and
            event['stock_parent_API_arguments'] == [int(geometry['Page'],16),int(geometry['Grid'],16),0,0] and
            event['Page_children_after_Grid_attach'] == 5 and event['Containing_Page_frame_written_by_test_for_input'] == [0,0,480,272] and
            not event['native_Containing_Page_geometry_or_root_controller_completed'] and not proof['actual_page_controller_switch_executed'],
        'native_updater_factory_refresh_and_nested_event_controls_no_host_activation_or_true_touch':
            [r['caller'] for r in calls] == ['0x315ba8','0x54a364','0x54a364','0x54a364'] and
            [r['returned_state'] for r in calls] == [0,0,4,0] and all(r['stock_output_objects_byte_unchanged'] for r in calls) and
            event['state_before'] == [1,4,4] and event['state_after'] == [1,0,0] and event['center_computed_by_test'] == [292,180] and
            [len(r['new_audio_API_requests']) for r in event['actions']] == [0,0,2] and
            all(r['player_Widget_inputs'][0]['point'] == [36,30] for r in event['actions']) and
            all(not controls[k]['new_audio_API_requests'] for k in ['hidden','unexpected_context_disabled','outside_Grid_inside_Page']) and
            len(controls['restored']['new_audio_API_requests']) == 2 and
            snapshot['native_menu_state'] == [1,1,2,0x13528000,2,2] and
            not event['host_called_compiled_updater_or_enable0_API_or_signal_directly'] and
            not proof['actual_input_classification_executed'] and event['test_nondefault_sound_selector36_via_original_API'] and
            not proof['original_kernel_wake_boundary_fixture']['actual_kernel_wake_delivery'] and
            'vm.invoke(0x27a98' not in source and 'vm.invoke(0x30c91' not in source,
        'precise_native_once_words_code_regions_canaries_font_prefix_pointer_query_and_nonfont_guards':
            snapshot['original_GUI_initialized_data_mutations'] == writes and
            snapshot['full_conditional_data_region_matches_three_native_word_allowances'] and
            proof['only_three_exact_original_GUI_guard_words_change_conditional_initialized_data'] and
            snapshot['stock_and_loaded_code_unchanged'] and snapshot['all_allocation_guards_intact'] and
            len(snapshot['original_font_persistent_handles']) == 35 and
            all(not e['freed'] and e['locks'] == 0 for e in snapshot['original_font_persistent_handles']) and
            snapshot['original_font_resident_handles_fixture_locks0_prefixes_queries_and_canaries_verified'] and
            not snapshot['native_heap_pin_or_lock1_claim'] and snapshot['inherited_outer_checks_retained_for_every_non_font_handle'] and
            snapshot['released_font_temporaries_keep_inherited_ownership_checks'] and 'GridVM.verify_released(self)' in vm_source,
        'preserved_partial_IO_failures_and_development_CJK_probe_not_full_success':
            write_failure['terminal_exit'] == 1 and not write_failure['full_pass'] and
            sha(write_failure['source']) == write_failure['source_sha256'] and sha(write_failure['probe']) == write_failure['probe_sha256'] and
            failed['session'] == 75665 and failed['terminal_exit'] == 1 and failed['groups_reported_before_failure'] == 5 and
            not failed['full_suite_complete'] and sha(failed['source']) == failed['source_sha256'] and
            sha(failed['VM_source']) == failed['VM_source_sha256'] and developer['terminal_exit'] == 0 and
            developer['development_probe_only'] and not developer['full_GUI_and_final_region_guards_completed'] and
            sha(developer['source']) == developer['source_sha256'] and sha(developer['probe']) == developer['probe_sha256'],
        'SQL15_restore_backup_fonts_unchanged_same_reservation_RX_RW_emulation_package_Unicorn214':
            proof['all15_DB_rows_restored_in_memory'] and proof['original_SQL_statement_finalization'] and
            proof['database_backup_unchanged'] and proof['font_backup_files_unchanged'] and
            proof['database_sha256'] == '1ae4071e1d93496cac562edf74093f5054f3f72497f4a5c40405a52df2ba2e99' and
            build['extension_bytes'] == 54982 and build['combined_file_bytes'] == 2354002 and build['combined_ram_bytes'] == 2462860 and
            build['remaining_reservation_bytes'] == 682868 and build['BSS_bytes'] == 18060 and load['original_3MiB_reservation_retained'] and
            build['code_RX_data_RW_segments'] and not build['unresolved_symbols'] and not build['patch_plan'] and build['VM_MAIN_patch_bytes'] == 0 and
            build['package_checks']['changed_members'] == ['DLLIMG.BIN','DLLINFO.TXT'] and build['package_checks']['all_other_members_byte_identical'] and
            'EMULATION-ONLY' in build['package'] and not proof['device_install_candidate'] and not proof['actual_package_acceptance_verified'] and
            proof['emulator_binding_version'] == '2.1.4' and proof['emulator_native_version'] == [2,1,33621247] and
            sha(runtime['successful_runtime']['native_library']) == runtime['successful_library_sha256'] and
            sha(runtime['successful_runtime']['binding_file']) == runtime['successful_binding_sha256'] and
            len(proof['guard_fault_controls']) == 2 and all(c['passed'] for c in proof['guard_fault_controls']),
        'frozen23_selected_suites_all81_prior_findings_exact_prior16_scope_state_snapshot':
            counts == [10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4,3,3,3,3,4,4] and
            len(before['native_app_music']['static_findings']) == 81 and prior['all_passed'] and
            len(prior['scope_checks']) == 16 and prior['state_sha256'] == sha(previous['state']),
        'canonical_task_public31_percent47_details_Taiwan_time_privacy_and_render_install_limits':
            public['deep_research'] == state and all(task[k] == state[k] for k in
                ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 47 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"', report)
                for ident in ['report-updated-time','research-updated-time']) and
            all(t in report for t in ['最新離線進展：原廠流程載入繁中字型','五組完整離線驗證通過',
                '字元能載入，畫面仍未完成','原機 App 和手機直接藍牙音樂尚未完成',
                '前輪紀錄：原廠字型、格位佈局與播放器狀態']) and
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
    out = 'evidence/firmware-analysis/native-player-external-fonts-checkpoint-audit.json'
    result = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True, scope_checks=checks,
        state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'),
        proof_sha256=sha(item['evidence']), build_manifest_sha256=sha(proof['build_manifest']),
        audit_script_sha256=sha(str(Path(__file__).relative_to(ROOT))), current_turn_device_IO=False,
        goal_status='active', full_goal_complete=False)
    (ROOT/out).write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(audit=out, scopes=len(checks), all_passed=True)))


if __name__ == '__main__':
    main()
