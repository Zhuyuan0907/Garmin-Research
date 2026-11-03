#!/usr/bin/env python3
"""Keep offline cable-state evidence distinct from real host/phone progress."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT/name).read_text())


def digest(name):
    return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()


def main():
    state = read('evidence/deep-research-state.json')
    aa = state['native_android_auto']
    current = aa['USB_transition_and_worker']
    emu_name, static_name = current['emulation_evidence'], current['static_evidence']
    emu, static = read(emu_name), read(static_name)
    for proof in (emu,static):
        for name, expected in proof['source_sha256'].items():
            assert digest(name) == expected, name
    cases = {c['name']:c for c in emu['transition_cases']}
    profiles = emu['original_callback_initializer']
    selectors, registers = emu['board_control_selector_cases'], emu['synthetic_softconnect_cases']
    functions = static['functions']
    switch_rows = [r for f in functions.values() for r in f['instructions'] if 'switch_targets' in r]
    fresh_usb_name = aa['latest_USB_reconnection']['evidence']
    fresh_usb = read(fresh_usb_name)
    for name, expected in fresh_usb['source_sha256'].items():
        assert digest(name) == expected, name
    prior_name = 'evidence/firmware-analysis/native-display-id-checkpoint-audit.json'
    prior = read(prior_name)
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    state_digest, report_digest = digest('evidence/deep-research-state.json'), digest('reports/nuvi2565RT.html')
    checks = {
        'exact1352_800_stock_inputs_match': (
            emu['exact_target'] == static['exact_target'] and
            emu['exact_target']['HWID'] == 1352 and emu['exact_target']['software'] == '8.00' and
            emu['exact_target']['stock_sha256'] == digest('evidence/firmware-analysis/main_02bd.bin')),
        'all13_emulation_and18_static_dependencies_match': (
            len(emu['source_sha256']) == 13 and len(static['source_sha256']) == 18),
        'all_current_proof_hash_references_match': (
            current['emulation_sha256'] == digest(emu_name) and current['static_sha256'] == digest(static_name) and
            aa['latest_USB_reconnection']['evidence_sha256'] == digest(fresh_usb_name)),
        'eight_fresh_transition_controls_execute_stock_code': (
            emu['all_passed'] and len(cases) == 8 and all(c['all_passed'] and
                c['native_transition_calls'] == len(c['snapshots']) and
                c['record_and_control_guards_intact'] and c['immutable_channel_registration_fields_unchanged']
                for c in cases.values())),
        'three_sample_debounce_and_churn_restart_match': (
            [s['debounce_counter'] for s in cases['TypeB_to_TypeA']['snapshots']] == [1,2,3] and
            [s['debounce_counter'] for s in cases['candidate_churn_restarts_debounce']['snapshots']] == [1,1,1,2,3]),
        'original_six_byte_messages_keep_predicate_order': (
            cases['TypeB_to_TypeA']['events'][0]['message_hex'] == '01000d000100' and
            cases['TypeA_to_TypeB']['events'][0]['message_hex'] == '0100000d0001' and
            static['type_one_message']['fields'] ==
                ['kind=1','channel','old_type','new_type','old_predicate','new_predicate']),
        'null_or_disabled_task_gate_rejects_acceptance': all(
            cases[name]['snapshots'][-1]['current_type_field'] == 13 and
            not any(e['boundary'] == 'queue_publication' for e in cases[name]['events'])
            for name in ('missing_task_handle','disabled_publication')),
        'queue_return_failure_ignored_is_not_delivery_success': (
            cases['publication_return_zero_is_ignored_by_wrapper']['events'][0]['fixture_return'] == 0 and
            cases['publication_return_zero_is_ignored_by_wrapper']['snapshots'][-1]['current_type_field'] == 0 and
            not static['task_link']['actual_kernel_scheduling_or_queue_delivery_verified']),
        'policy_bypass_and_invalid_channel_controls_pass': (
            cases['policy11_bypasses_publication']['native_message_builder_calls'] == 0 and
            cases['policy11_bypasses_publication']['snapshots'][-1]['current_type_field'] == 0 and
            not cases['unknown_channel_ignored']['events']),
        'function_fixtures_only_queue_notification_and_logger': (
            all(f['boundary'] in ('queue_publication','state_notification') for c in cases.values()
                for f in c['function_fixtures']) and
            all(f['boundary'] == 'diagnostic_logging' for f in profiles['function_fixtures']) and
            all(not c['function_fixtures'] for c in selectors+registers)),
        'original_initializer_builds56_profiles_with_ARM_clear': (
            profiles['all_passed'] and profiles['guard_intact'] and profiles['other_task_control_bytes_unchanged'] and
            len(profiles['records']) == 56 and profiles['profile_bytes'] == 0x4b40 and
            profiles['channel_stride'] == 0x12d0 and profiles['type_stride'] == 0x158),
        'TypeA_Audio_Ethernet_default_BX_LR_not_whole_firmware_absence': (
            profiles['default_callbacks_executed_and_returned'] and
            profiles['default_callbacks_exact_body'] == 'BX LR' and
            all(r['close_callback'] == '0x3230ff' and r['open_callback'] == '0x3230fd'
                for r in profiles['records'] if r['type'] in (0,5,6)) and
            static['callbacks']['default_table_does_not_prove_all_other_paths_lack_host_or_audio']),
        'harness_pointer_expectation_corrected_before_fresh_complete_run': (
            emu['verification_history']['initial_callback_table_expectation_rejected'] and
            emu['verification_history']['complete_fresh_run_after_correction']),
        '16_bounded_functions_keep_4_external_indirect_exits': (
            len(functions) == 16 and sum(not f['unresolved_exits'] for f in functions.values()) == 13 and
            sum(len(f['unresolved_exits']) for f in functions.values()) == 4 and
            all(not f['instruction_limit_reached'] for f in functions.values())),
        'four_byte_table_switches_and_task_worker_link_resolved': (
            sorted(len(r['switch_targets']) for r in switch_rows) == [5,9,9,14] and
            static['task_link']['descriptor_entry_word'] == '0x323a6b' and
            static['type_one_message']['worker_dispatch'] == '0x3236d4'),
        'three_board_control_selectors_are_not_a_proven_host_driver': (
            len(selectors) == 3 and [c['synthetic_selector'] for c in selectors] == [0,3,5] and
            all(c['all_passed'] and c['guard_intact'] and c['not_claimed_as_USB_host_driver_vector'] and
                not c['board_selector_actual_value_or_target_functions_executed'] for c in selectors)),
        'four_original_bit40_register_cases_use_synthetic_RAM_only': (
            len(registers) == 4 and [c['after'] for c in registers] == [0xe5,0xa5,0x40,0xbf] and
            all(c['all_passed'] and c['adjacent_register_bytes_unchanged'] and
                c['real_softconnect_VBUS_or_host_session_not_executed'] for c in registers)),
        'MUSB_primary_source_comparison_is_explicit_inference': (
            len(static['primary_sources']) == 2 and all(s['upstream_tag'] == 'v6.12' and
                digest(s['path']) == s['sha256'] for s in static['primary_sources']) and
            not static['register_comparison']['controller_model_or_live_register_identity_verified'] and
            current['MUSB_POWER_softconnect_offset1_bit40_comparison_is_inference']),
        'current_live_USB_identity_descriptors_and_no_device_writes': (
            fresh_usb['private_USB_hex_serial_matches_decimal_diagnostic_ESN'] and
            fresh_usb['backup_USB_identity_including_serial_matched'] and
            fresh_usb['matches_previous_live_and_original_builder'] and
            fresh_usb['logical_disk_bytes'] == 3879731200 and not fresh_usb['device_files_written'] and
            fresh_usb['observed_utc'] == state['execution_environment']['last_USB_observed_utc']),
        'offline_proofs_do_not_claim_device_host_phone_or_install': (
            emu['stock_code_mappings_write_protected'] and
            all(not p['device_io'] and not p['firmware_modified'] and not p['device_install_candidate']
                for p in (emu,static)) and not emu['USB_host_AOA_VBUS_or_phone_session_verified'] and
            not aa['native_receiver_running'] and not aa['phone_session_verified']),
        'current_task_report_and_prior20_scope_checkpoint_match': (
            read('evidence/task-state.json')['native_android_auto'] == aa and
            read('reports/findings.json')['deep_research'] == state and
            prior['all_passed'] and len(prior['scope_checks']) == 20 and
            prior['state_sha256'] == state_digest and prior['report_sha256'] == report_digest),
        'new_report_preserves_scope_and_active_full_goal': (
            'USB 主機研究：類型名稱之後的實際動作' in report and
            '實際板號選擇與底層 I/O 用途仍未知' in report and
            '這是來源比對的推論，尚未確認實機控制器型號' in report and
            state['last_goal_turn']['classification'] == 'progress' and
            state['goal_status'] == 'active' and not state['goal_complete'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['google_maps']['research_deferred_by_user'] and
            not state['native_app_music']['native_app_running'] and state['required_work_remaining']),
    }
    assert all(checks.values()), [name for name, ok in checks.items() if not ok]
    name = 'evidence/firmware-analysis/native-usb-transition-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({
        'updated_utc':datetime.now(timezone.utc).isoformat(), 'all_passed':True, 'scope_checks':checks,
        'state_sha256':state_digest,'report_sha256':report_digest,
        'evidence_sha256':{n:digest(n) for n in (emu_name,static_name,fresh_usb_name,prior_name)},
        'audit_script_sha256':digest(str(Path(__file__).relative_to(ROOT))),
        'offline_proof_device_io':False,'live_readonly_sysfs_observed':True,
        'device_files_written':False,'goal_status':'active','full_goal_complete':False,
    },indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))


if __name__ == '__main__':
    main()
