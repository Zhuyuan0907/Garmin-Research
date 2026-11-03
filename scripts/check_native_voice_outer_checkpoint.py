#!/usr/bin/env python3
"""Check current outer-file and compatibility evidence and report scope."""
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED, NativeImage
from analyze_native_voice_acceptance import RuntimeImage


def read(p): return json.loads((ROOT / p).read_text())
def sha(p): return hashlib.sha256((ROOT / p).read_bytes()).hexdigest()


def main():
    s = read('evidence/deep-research-state.json')
    f = s['native_app_music']['static_findings']
    keys = ['native_voice_outer', 'native_voice_compatibility']
    outer, compat = [read(f[k]['evidence']) for k in keys]
    for k, proof in zip(keys, [outer, compat]):
        assert sha(f[k]['evidence']) == f[k]['evidence_sha256'], k
        for path, h in proof['source_sha256'].items():
            assert sha(path) == h, path
    package = read(outer['package_manifest'])
    component = read(outer['component_manifest'])
    for b in [package, component]:
        for path, h in b['source_sha256'].items():
            assert sha(path) == h, path
    assert sha(package['package']) == package['package_sha256']
    assert sha(package['original_package']) == package['original_package_sha256']
    for path, h in [('combined_binary', 'combined_sha256'),
                    ('extension_flat', 'extension_flat_sha256'), ('extension_elf', 'extension_elf_sha256')]:
        assert sha(component[path]) == component[h], path
    before = read(s['last_goal_turn']['previous_state_snapshot'])
    prior = read(s['last_goal_turn']['previous_current_audit_snapshot'])
    frozen = []
    for key in ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
                'native_music_endpoint', 'native_music_configuration_gate', 'native_music_policy',
                'native_music_dispatch', 'native_l2cap_send', 'native_music_reply']:
        item = f[key]
        assert item == before['native_app_music']['static_findings'][key], key
        proof = read(item['evidence'])
        assert sha(item['evidence']) == item['evidence_sha256'], key
        for path, h in proof['source_sha256'].items():
            assert sha(path) == h, path
        frozen.append(proof['case_count'])
    oc = {c['name']: c for c in outer['cases']}
    cc = {c['name']: c for c in compat['cases']}
    loading = [c['selection'] for c in outer['cases'] if 'selection' in c]
    public = read('reports/findings.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    task = read('evidence/task-state.json')
    runtime = RuntimeImage(NativeImage())
    checks = {
        'fresh12_outer15_compatibility_cases_all_pass_current_dependencies':
            outer['all_passed'] and compat['all_passed'] and
            len(outer['cases']) == outer['case_count'] == 12 and
            len(compat['cases']) == compat['case_count'] == 15 and
            all(c['passed'] for c in outer['cases'] + compat['cases']) and
            outer['MAIN_sha256'] == compat['MAIN_sha256'] == EXPECTED,
        'current_package_component_artifact_hashes_and_original_reservation':
            outer['package_manifest_sha256'] == sha(outer['package_manifest']) and
            outer['component_manifest_sha256'] == package['component_manifest_sha256'] ==
            sha(outer['component_manifest']) and component['reservation_bytes'] == 3145728 and
            component['remaining_reservation_bytes'] == 682868,
        'all_three_original_registry_paths_execute_native_generic_API_and_full_wrapper':
            all(len(oc['outer_original_' + n]['registry']) == 1 and
                all(oc['outer_original_' + n]['outer']['native_entries_executed'][hex(a)] > 0 for a in
                    [0x2d3166, 0x2d3380, 0x2d32de, 0xfea50, 0x31d09a, 0x31cf22,
                     0x1fde12, 0x31d2e0, 0x31cf5c, 0x31ce8c, 0x1fdaca, 0x31e3be, 0x1fdb8e])
                for n in ['Chinese_Big5_MeiLing', 'Chinese_GB_MeiLing', 'English_American_Jill']),
        'native_binding_readonly_fallback_busy_deferred_error_full_pool_controls':
            oc['native_bind_second_open_readonly_fallback']['native_status'] == 0 and
            [e['mode'] for e in oc['native_bind_second_open_readonly_fallback']['outer']['driver_open_close_events']
                if e['operation'] == 'driver_open_fixture'] == [0x23, 0x21] and
            oc['native_bind_existing_mapping_returns2']['native_status'] == 2 and
            oc['native_bind_deferred_missing_file_returns3']['native_status'] == 3 and
            oc['native_bind_deferred_missing_file_returns3']['state_before_unbind'][0] == 1 and
            oc['native_bind_failed_driver_opens_return1']['native_status'] == 1 and
            oc['native_bind_full32_pool_skips_open']['native_status'] == 1 and
            not oc['native_bind_full32_pool_skips_open']['outer']['driver_open_close_events'],
        'complete_outer_loader_return11_runtime40_exports_control_private12_INIT':
            len(loading) == 3 and all(r['loader_result'] == r['independent_control_result'] == 11 and
                r['original40_trampolines_and_runtime_match_control'] for r in loading) and
            oc['full_outer_preserving_component_selected_compatible']['selection']['runtime_bytes'] == 2462860 and
            oc['full_outer_preserving_component_selected_compatible']['selection'][
                'private12_initialized_without_workers_or_music_registration'],
        'matching_cached_voice_no_diagnostic_success_flag_empty_cache409_same_original_code':
            all(oc[name]['selection']['native_compatibility_result'] == 1 and
                oc[name]['selection']['original_success_path_enabled_byte'] == 1 and
                not oc[name]['selection']['selection_diagnostics'] for name in
                ['full_outer_original_selected_compatible', 'full_outer_preserving_component_selected_compatible']) and
            oc['full_outer_original_empty_cached_selection_diagnostic409']['selection']['native_compatibility_result'] == 0 and
            oc['full_outer_original_empty_cached_selection_diagnostic409']['selection']['selection_diagnostics'][0]['code'] == 409,
        '94_exact_original_requirement_records_MeiLing130_version_controls':
            len(compat['requirements']) == 94 and compat['requirements'][73]['volume_id'] == 'mei-lingb' and
            compat['requirements'][73]['version_text'] == '1.30' and
            hashlib.sha256(runtime.read(0x9bb86c, 0x24c * 94)).hexdigest() == compat['requirements_bytes_sha256'] and
            all(cc['known_meiling_version_' + v + '_original_compare_mode2']['native_result'] == expected
                for v, expected in [('0.99', 0), ('1.00', 0), ('1.29', 0), ('1.30', 1), ('1.99', 1), ('2.10', 1)]),
        'three_current_original_selection_accept_empty_unknown_TTS_reject_type_fallback':
            all(cc['matching_original_' + n]['native_result'] == 1 for n in
                ['Chinese_Big5_MeiLing', 'Chinese_GB_MeiLing', 'English_American_Jill']) and
            cc['empty_current_selection_cache']['native_result'] == 0 and
            cc['unknown_TTS_voice_ID_fallback_reject']['native_result'] == 0 and
            all(cc['unknown_ID_fallback_type' + str(k) + '_subtype' + str(t)]['native_result'] == expected
                for k, t, expected in [(0, 1, 1), (0, 2, 1), (0, 3, 0), (1, 1, 0)]),
        'resource_guards_closed_objects_and_only_synchronous_cleanup_not_safe_unload':
            all(c.get('original_code_heap_SP_all_outer_objects_released',
                c.get('selection', {}).get('original_code_registry_heap_SP_and_closed_objects_verified', False))
                for c in outer['cases']) and
            all(r['cleanup_only_after_synchronous_INIT_not_safe_worker_unload'] for r in loading) and
            all(c['original_code_unchanged_no_override_or_module_execution_SP_mutex_checked'] for c in compat['cases']),
        'native_task_mutex_TCB_and_compare_mode_assumptions_corrected':
            outer['original_current_task_helpers_are_mutex_not_IRQ_save_restore'] and
            outer['native_TCB_helper358D24_executed_not_timestamp_fixture'] and
            compat['native_version_comparison_mode_argument'] == 2 and
            compat['native_version_comparison_length_is_maximum_of_both_strings'] and
            not compat['complete_semantic_version_ordering_verified'],
        'actual_backend_settings_initializer_acceptance_App_phone_speaker_unverified':
            not outer['actual_filesystem_driver_table_board_storage_cache_settings_initializer_verified'] and
            not outer['real_modified_package_acceptance_or_signature_policy_verified'] and
            not outer['App_UI_phone_radio_speaker_or_worker_safe_unload_verified'] and
            not compat['settings_initializer_or_live_current_voice_recovered'] and
            all(r['current_selection_cache_is_fixture_not_live_preference'] for r in loading),
        'previous10_2_6_29_189_208_18_10_112_proofs_and19_snapshot_preserved':
            frozen == [10, 2, 6, 29, 189, 208, 18, 10, 112] and prior['all_passed'] and
            len(prior['scope_checks']) == 19 and prior['state_sha256'] == sha(s['last_goal_turn']['previous_state_snapshot']),
        'canonical_task_public_report_match31_percent33_details_Taiwan_times':
            public['deep_research'] == s and all(task[k] == s[k] for k in
                ['last_goal_turn', 'next_actions', 'attended_testing', 'ordered_priorities', 'latest_user_instruction']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 33 and
            all(re.search('<time id="' + ident + '" datetime="[^"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']),
        'new_report_scope_original12_15_tests_cache_and_driver_fixtures_visible':
            all(text in report for text in ['12 個外層流程案例', '15 個原廠相容性案例', '94 項原廠對照資料',
                '目前語音快取仍是測試資料', '真正設定初始化、磁碟驅動與實機接受尚未驗證',
                '此輪沒有安裝導航機', '不能把這項清理當作有工作／回呼時可以安全卸載']),
        'user_away_no_IO_call_sound_question_install_candidate_mic_cancelled_goal_active':
            s['attended_testing']['waiting_for_user_return'] and not s['attended_testing']['user_present'] and
            s['attended_testing']['no_pending_question'] and not s['last_goal_turn']['device_io'] and
            not s['last_goal_turn']['device_files_written'] and
            all(not p['device_io'] and not p['backup_modified'] and not p['device_install_candidate'] for p in [outer, compat]) and
            s['microphone_amplifier']['status'] == 'cancelled_by_user' and not s['microphone_amplifier']['next_actions'] and
            s['goal_status'] == 'active' and not s['goal_complete'] and s['required_work_remaining'] and
            s['latest_user_instruction']['goal_completion_forbidden_by_user'] and s['native_android_auto']['requested'] and
            s['google_maps']['research_deferred_by_user'] and not s['native_app_music']['native_app_running'] and
            not s['native_app_music']['direct_phone_music_verified'],
        'no_private_MAC_or_unit_ID_in_public_report':
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
    }
    assert all(checks.values()), [k for k, v in checks.items() if not v]
    path = 'evidence/firmware-analysis/native-voice-outer-checkpoint-audit.json'
    (ROOT / path).write_text(json.dumps({
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True, 'scope_checks': checks,
        'state_sha256': sha('evidence/deep-research-state.json'), 'report_sha256': sha('reports/nuvi2565RT.html'),
        'proof_sha256': {f[k]['evidence']: sha(f[k]['evidence']) for k in keys},
        'execution_dependencies': {k: len(p['source_sha256']) for k, p in zip(keys, [outer, compat])},
        'component_build_dependencies': len(component['source_sha256']),
        'previous_checkpoint_snapshot_sha256': sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'audit_script_sha256': sha(str(Path(__file__).relative_to(ROOT))), 'current_turn_device_IO': False,
        'device_install_candidate': False, 'goal_status': 'active', 'full_goal_complete': False,
    }, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scope_checks': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
