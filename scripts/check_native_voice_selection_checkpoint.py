#!/usr/bin/env python3
"""Validate the current offline package/registry/selection checkpoint."""
from datetime import datetime, timezone
import hashlib
import json
import re
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED
from analyze_tts_vpm import parse_image


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    state = read('evidence/deep-research-state.json')
    findings = state['native_app_music']['static_findings']
    keys = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection']
    proofs = {key: read(findings[key]['evidence']) for key in keys}
    for key, proof in proofs.items():
        assert sha(findings[key]['evidence']) == findings[key]['evidence_sha256'], key
        for path, digest in proof['source_sha256'].items():
            assert sha(path) == digest, path
    registry, reads, selection = [proofs[key] for key in keys]
    package = read(selection['package_manifest'])
    component = read(selection['component_manifest'])
    for manifest in [package, component]:
        for path, digest in manifest['source_sha256'].items():
            assert sha(path) == digest, path
    for pathkey, hashkey in [('combined_binary', 'combined_sha256'),
                             ('extension_flat', 'extension_flat_sha256'),
                             ('extension_elf', 'extension_elf_sha256')]:
        assert sha(component[pathkey]) == component[hashkey], pathkey
    assert sha(package['package']) == package['package_sha256']
    assert sha(package['original_package']) == package['original_package_sha256']
    original, _ = parse_image((ROOT / package['original_package']).read_bytes())
    changed, geometry = parse_image((ROOT / package['package']).read_bytes())
    assert set(original) == set(changed)
    oldstate = read(state['last_goal_turn']['previous_state_snapshot'])
    oldaudit = read(state['last_goal_turn']['previous_current_audit_snapshot'])
    preserved = []
    for key in ['native_music_endpoint', 'native_music_configuration_gate',
                'native_music_policy', 'native_music_dispatch', 'native_l2cap_send',
                'native_music_reply']:
        item = findings[key]
        assert item == oldstate['native_app_music']['static_findings'][key], key
        proof = read(item['evidence'])
        assert sha(item['evidence']) == item['evidence_sha256'], key
        for path, digest in proof['source_sha256'].items():
            assert sha(path) == digest, path
        preserved.append(proof['case_count'])
    rc = {c['name']: c for c in registry['cases']}
    pc = {c['name']: c for c in reads['cases']}
    sc = {c['name']: c for c in selection['cases']}
    loaded = [c for c in selection['cases'] if c['selection']['module_executed']]
    modified = [c for c in loaded if c['changed_package_local_fixture']]
    public = read('reports/findings.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    task = read('evidence/task-state.json')
    checks = {
        'fresh10_registry2_read6_selection_cases_all_pass':
            [proofs[k]['case_count'] for k in keys] == [10, 2, 6] and
            all(p['all_passed'] and len(p['cases']) == p['case_count'] and
                all(c['passed'] for c in p['cases']) for p in proofs.values()),
        'exact_Taiwan_MAIN_current_source_build_and_artifact_hashes':
            all(p['MAIN_sha256'] == EXPECTED for p in proofs.values()) and
            selection['component_manifest_sha256'] == package['component_manifest_sha256'] ==
            sha(selection['component_manifest']) and
            selection['package_manifest_sha256'] == sha(selection['package_manifest']),
        'native_registry_sort_and_duplicate_failure_controls':
            len(rc['all_three_original_sorted_native_registry']['result']['registry']) == 3 and
            len(rc['duplicate_volume_ID_skips_second_registration']['result']['registry']) == 1 and
            all(not rc[name]['result']['registry'] for name in
                ['missing_required_language', 'platform_predicate_rejects_type1',
                 'outer_region_binding_failure_skips_metadata']),
        'rejected_sparse_package_mismatch_preserved_not_executed':
            not pc['rejected_sparse_fixture']['native_matches_independent_extraction'] and
            pc['rejected_sparse_fixture']['first_difference_offset'] == 2295808 and
            pc['rejected_sparse_fixture']['modified_module_not_executed'] and
            sha(pc['rejected_sparse_fixture']['package']) == pc['rejected_sparse_fixture']['package_sha256'],
        'corrected2353068_byte_native_read_identical_before_execution':
            pc['corrected_contiguous_fixture']['native_matches_independent_extraction'] and
            pc['corrected_contiguous_fixture']['native_read_bytes'] == 2353068 and
            pc['corrected_contiguous_fixture']['native_read_sha256'] == package['module_sha256'] and
            all(c['selection']['native_file_readback_before_execution_matches_independent_extraction'] for c in loaded),
        'contiguous_DDL_relocation_preserves_all_other_member_payloads':
            package['checks']['DLL_blocks_contiguous'] and not geometry['allocation_overlap'] and
            changed['DLLIMG.BIN']['content'] == (ROOT / component['combined_binary']).read_bytes() and
            all(changed[k]['content'] == original[k]['content'] for k in original
                if k not in ['DLLIMG.BIN', 'DLLINFO.TXT']) and
            package['checks']['allocation_relocated_members'] == ['DLLIMG.SIG', 'IMGEND.TST'],
        'native_original_selector_loader_callbacks_return11_and_control_match':
            len(loaded) == 4 and all(c['selection']['INIT_calls'] == 1 and
                c['selection']['loader_result_captured_before_native_compare'] == 11 and
                c['selection']['matches_independent_direct_loader_control'] and
                all(c['selection']['original_loader_file_callback_visits'].values()) for c in loaded),
        'modified_component2462860_RAM_original_reservation40_exports12_private':
            len(modified) == 3 and component['reservation_bytes'] == 3145728 and
            component['remaining_reservation_bytes'] == 682868 and
            all(c['selection']['runtime_bytes'] == 2462860 and
                c['selection']['within_original_3MiB_reservation'] and
                c['selection']['original40_trampolines_identical'] and
                c['selection']['preserving_component_state'] == [1, 11, 0] and
                c['selection']['private12_API_table_points_to_reserved_component'] and
                c['selection']['private_API_or_audio_workers_not_called_by_this_test'] for c in modified),
        'bad_index_platform_control_skip_INIT_and_module':
            all(sc[name]['selection']['selected_index'] == 255 and
                not sc[name]['selection']['INIT_calls'] and
                not sc[name]['selection']['module_executed'] for name in
                ['out_of_range_index_skips_loader', 'platform_reject_leaves_no_voice_to_load']),
        'stale_sum_zero_SIG_only_fixture_path_not_signature_policy_proof':
            sc['preserving_component_stale_sum_original_SIG']['dll_byte_sum'] !=
            sc['preserving_component_stale_sum_original_SIG']['metadata_sum'] and
            sc['preserving_component_updated_sum_zero_SIG']['signature_sha256'] !=
            sc['preserving_component_updated_sum_original_SIG']['signature_sha256'] and
            not selection['global_signature_policy_absence_proven'] and
            not package['signature_acceptance_verified'],
        'unaltered_language_helper_diagnostic409_boundary_explicit':
            all(c['selection']['selection_diagnostics'] == [{'code': 409,
                'operation': 'diagnostic_UI_submission_fixture',
                'native_language_compatibility_helper_not_overridden': True}] and
                c['selection']['native_selector_lookup_mount_original_functions_executed']['0x222a34'] == 1
                for c in loaded),
        'stock_code_registry_heap_stack_guards_and_temporary_cleanup':
            all(c['result']['original_code_heap_and_stack_guards_intact'] and
                c['result']['temporary_objects_released_registry_nodes_retained'] for c in registry['cases']) and
            all(c['selection']['original_code_registry_heap_SP_guards_intact'] and
                c['selection']['temporary_handles_released_native_registry_retained'] for c in loaded),
        'outer_mount_live_platform_real_acceptance_UI_hardware_unverified':
            registry['outer_storage_and_activation_wrappers_are_fixtures'] and
            not registry['live_platform_predicate_or_real_outer_mount_verified'] and
            not selection['real_outer_storage_mount_and_live_platform_values_verified'] and
            not selection['device_package_acceptance_verified'] and
            not selection['native_App_menu_or_physical_audio_verified'] and
            not findings['native_voice_selection']['actual_private_API_audio_workers_UI_or_music_wire_component_binding_verified'],
        'previous29_189_208_18_10_112_proofs_unchanged_and_previous23_audit_matches_state':
            preserved == [29, 189, 208, 18, 10, 112] and oldaudit['all_passed'] and
            len(oldaudit['scope_checks']) == 23 and
            oldaudit['state_sha256'] == sha(state['last_goal_turn']['previous_state_snapshot']),
        'canonical_report_and_task_current_state_equal':
            public['deep_research'] == state and all(task[k] == state[k] for k in
                ['last_goal_turn', 'next_actions', 'latest_user_instruction', 'attended_testing', 'ordered_priorities']),
        'report31_percent31_details_Taiwan_time_and_loader_limits_visible':
            public['research_progress']['estimate_percent'] == 31 and
            len(public['research_progress']['completed']) == 31 and
            all(text in report for text in ['6 個選取／載入案例', '2,353,068 bytes',
                '封裝僅供離線研究', '代碼 409', '12 個私有介面', '尚未連入這個保留區']) and
            all(re.search('<time id="' + ident + '" datetime="[^"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']),
        'user_away_mic_canceled_no_hardware_IO_calls_or_install_candidate':
            state['attended_testing']['waiting_for_user_return'] and
            not state['attended_testing']['user_present'] and
            not state['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            state['attended_testing']['no_pending_question'] and
            state['microphone_amplifier']['status'] == 'cancelled_by_user' and
            not state['microphone_amplifier']['next_actions'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            all(not p['device_io'] and not p['device_install_candidate'] for p in proofs.values()) and
            not package['device_install_candidate'] and not package['backup_modified'],
        'full_goal_active_no_achieve_AA_later_Maps_deferred_native_music_incomplete':
            state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'],
        'no_private_unit_ID_or_MAC_in_public_report':
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
    }
    assert all(checks.values()), [k for k, value in checks.items() if not value]
    path = 'evidence/firmware-analysis/native-voice-selection-checkpoint-audit.json'
    (ROOT / path).write_text(json.dumps({
        'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True,
        'scope_checks': checks, 'state_sha256': sha('evidence/deep-research-state.json'),
        'report_sha256': sha('reports/nuvi2565RT.html'),
        'proof_sha256': {findings[k]['evidence']: sha(findings[k]['evidence']) for k in keys},
        'execution_dependencies': {k: len(p['source_sha256']) for k, p in proofs.items()},
        'component_build_dependencies': len(component['source_sha256']),
        'previous_checkpoint_snapshot_sha256': sha(state['last_goal_turn']['previous_current_audit_snapshot']),
        'audit_script_sha256': sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO': False, 'device_install_candidate': False,
        'goal_status': 'active', 'full_goal_complete': False,
    }, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scope_checks': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
