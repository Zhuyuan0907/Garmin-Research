#!/usr/bin/env python3
"""Audit diagnostic observations and the bounded native display/USB-ID proofs."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(name):
    return hashlib.sha256((ROOT / name).read_bytes()).hexdigest()


def main():
    state = read('evidence/deep-research-state.json')
    task = read('evidence/task-state.json')
    aa = state['native_android_auto']
    display_name = aa['display_path']['evidence']
    id_name = aa['USB_ID_classification']['evidence']
    display, usb_id = read(display_name), read(id_name)
    for proof in (display, usb_id):
        for name, expected in proof['source_sha256'].items():
            assert digest(name) == expected, name
    diagnostic_ref = aa['hardware_diagnostics']
    diag_name = diagnostic_ref['evidence']
    initial_name = diagnostic_ref['initial_observation']['evidence']
    diag, initial = read(diag_name), read(initial_name)
    reconnect_name = aa['latest_USB_reconnection']['evidence']
    reconnect = read(reconnect_name)
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    public_json = (ROOT / 'reports/findings.json').read_text()
    published = report + public_json
    surface = display['surface_descriptor_static_ABI']
    functions = display['functions']
    cases = usb_id['cases']
    prior_name = 'evidence/firmware-analysis/native-projection-io-checkpoint-audit.json'
    prior = read(prior_name)
    private_values = [diag['private_unit_ESN'], diag['private_flash_SN'], initial['private_unit_ESN']]
    checks = {
        'exact_HWID1352_800_and_original_stock_bytes': (
            display['exact_target'] == usb_id['exact_target'] and
            display['exact_target']['HWID'] == 1352 and
            display['exact_target']['software'] == '8.00' and
            display['exact_target']['stock_sha256'] == digest('evidence/firmware-analysis/main_02bd.bin')),
        'all_12_display_and_13_ID_dependencies_match': (
            len(display['source_sha256']) == 12 and len(usb_id['source_sha256']) == 13),
        'evidence_references_match_current_state': (
            aa['display_path']['evidence_sha256'] == digest(display_name) and
            aa['USB_ID_classification']['evidence_sha256'] == digest(id_name) and
            diagnostic_ref['evidence_sha256'] == digest(diag_name) and
            diagnostic_ref['initial_observation']['evidence_sha256'] == digest(initial_name) and
            aa['latest_USB_reconnection']['evidence_sha256'] == digest(reconnect_name)),
        'eleven_original_query_cases_and_no_function_fixtures': (
            usb_id['all_passed'] and len(cases) == 11 and all(
                c['all_passed'] and not c['function_fixtures'] and
                c['native_functions_executed']['0x33213e'] == 1 and
                c['native_functions_executed']['0x332124'] == 1 for c in cases)),
        'bounds_gaps_invalid_channel_and_policy_control_results': (
            [c['native_type_result'] for c in cases] == [0,0,14,1,12,14,13,13,14,14,10] and
            cases[9]['synthetic_channel'] == 4 and cases[10]['synthetic_policy_byte'] == 0),
        'stock_tables_not_physical_USB_driver_proof': (
            len(usb_id['stock_classification_windows']) == 11 and
            len(usb_id['stock_type_labels_and_predicates']) == 14 and
            usb_id['stock_type_labels_and_predicates'][0]['label'] == 'USB Type-A' and
            usb_id['stock_type_labels_and_predicates'][13]['label'] == 'USB Type-B' and
            not usb_id['USB_host_AOA_or_VBUS_drive_verified'] and
            not usb_id['observed_3_29V_conversion_to_classification_input_verified'] and
            not usb_id['live_policy_channel_registration_or_ADC_sample_verified']),
        'ID_queries_keep_record_guards_and_protected_code': (
            usb_id['stock_code_mappings_write_protected'] and all(
                c['registered_record_and_guard_unchanged'] and
                not c['actual_ADC_or_USB_role_change_executed'] for c in cases)),
        'eight_bounded_ARM_CFGs_with_one_explicit_external_tail': (
            len(functions) == 8 and all(not f['instruction_limit_reached'] for f in functions.values()) and
            sum(not f['unresolved_exits'] for f in functions.values()) == 7 and
            functions['0x44de780']['unresolved_exits'] == [
                {'target': '0x448c930', 'reason': 'Outside bounded local range'}]),
        'six_original_veneers_link_conditional_SGA_backend': (
            display['all_assertions_passed'] and len(display['ARM_veneers']) == 6 and
            display['conditional_display_backend']['SGA_submit'] == '0x6f63f4' and
            not display['conditional_display_backend']['live_conditional_activation_or_control_structure_read']),
        'surface_offsets_and_two_byte_format_are_static_only': (
            [surface[k] for k in ('primary_data_pointer_offset','secondary_data_pointer_offset',
                'width_u16_offset','height_u16_offset','stride_u16_offset','format_flags_u16_offset')]
                == [0,4,8,10,12,14] and surface['built_format_low3'] == 4 and
            surface['bpp_table_bytes'][4] == surface['format4_bytes_per_pixel'] == 2 and
            not surface['specific_RGB_layout_or_framebuffer_present_verified']),
        'stock_software_flag_fallback_is_not_working_renderer': (
            display['software_flag_branch_warning']['surface_flag_mask'] == '0x200' and
            display['software_flag_branch_warning']['exact_6f9054_body'] == 'BX LR' and
            display['software_flag_branch_warning']['is_not_evidence_of_working_software_blit'] and
            not display['SGA_submit_arguments']['real_SGA_operation_completion_or_pixel_output_verified']),
        'user_diagnostics_report_128MB_PCB3_USB_TypeB': (
            initial['private_unit_ESN_matches_backup_XML'] and
            initial['RAM_capacity_reported_MB'] == 128 and
            diagnostic_ref['RAM_label_displayed'] == '128MB' and
            diag['reported']['PCB_Version'] == 3 and diag['reported']['USB_Device'] == 'USB Type-B' and
            diag['reported']['USB_ID_Volts'] == 3.29),
        'Ready_Checking_and_Freq_are_not_success_or_CPU_measurement': (
            diag['reported']['RAM_Test'] == diag['reported']['ROM_Test'] == 'Ready' and
            all(diag['not_claimed'].values()) and
            not diagnostic_ref['RAM_ROM_test_passed_verified'] and
            not diagnostic_ref['CPU_clock_identified'] and not diagnostic_ref['free_heap_measured']),
        'private_observations_0600_and_serials_not_published': (
            all(stat.S_IMODE((ROOT / name).stat().st_mode) == 0o600 for name in (diag_name, initial_name)) and
            all(len(str(v)) >= 6 and str(v) not in published for v in private_values) and
            not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', published)),
        'USB_reconnection_identity_size_descriptor_and_timestamp_match': (
            reconnect['backup_USB_identity_including_serial_matched'] and
            reconnect['logical_disk_bytes'] == 3879731200 and
            reconnect['matches_previous_live_and_original_builder'] and
            reconnect['observed_utc'] == state['execution_environment']['last_USB_observed_utc'] ==
            task['device_connection_observed_utc']),
        'current_cable_works_OTG_adapter_presence_not_assumed': (
            'USB-A to microUSB' in diagnostic_ref['user_current_cable_description'] and
            not diagnostic_ref['separate_OTG_adapter_availability_confirmed'] and
            '現有 USB-A → microUSB' in report),
        'offline_proofs_and_live_observations_have_separate_scope': (
            not display['device_io'] and not usb_id['device_io'] and
            bool(aa['projection_io'].get('live_USB_verification')) and not reconnect['device_files_written'] and
            not reconnect['USB_host_AOA_or_framebuffer_RAM_read']),
        'task_state_report_and_prior25_checkpoint_are_current': (
            task['native_android_auto'] == aa and read('reports/findings.json')['deep_research'] == state and
            prior['all_passed'] and len(prior['scope_checks']) == 25 and
            prior['state_sha256'] == digest('evidence/deep-research-state.json') and
            prior['report_sha256'] == digest('reports/nuvi2565RT.html')),
        'report_includes_current_findings_and_explicit_limits': (
            '診斷頁與 USB／畫面介面的最新結果' in report and
            '4GB 128MB' in report and 'RGB 位元排列、實際畫面緩衝區與螢幕呈現尚未確認' in report and
            'USB 主機傳輸、VBUS 供電與 AOA 仍待驗證' in report),
        'goal_active_no_achieve_Maps_deferred_no_App_or_AA_claim': (
            state['goal_status'] == 'active' and not state['goal_complete'] and
            state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['google_maps']['research_deferred_by_user'] and
            not aa['native_receiver_running'] and not aa['phone_session_verified'] and
            not state['native_app_music']['native_app_running'] and
            all(not p['firmware_modified'] and not p['device_install_candidate'] for p in (display, usb_id))),
    }
    assert all(checks.values()), [name for name, ok in checks.items() if not ok]
    output_name = 'evidence/firmware-analysis/native-display-id-checkpoint-audit.json'
    evidence_names = (display_name, id_name, diag_name, initial_name, reconnect_name, prior_name)
    (ROOT / output_name).write_text(json.dumps({
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'all_passed': True, 'scope_checks': checks,
        'state_sha256': digest('evidence/deep-research-state.json'),
        'report_sha256': digest('reports/nuvi2565RT.html'),
        'evidence_sha256': {name: digest(name) for name in evidence_names},
        'audit_script_sha256': digest(str(Path(__file__).relative_to(ROOT))),
        'offline_proof_device_io': False, 'live_readonly_observations': True,
        'device_files_written': False, 'full_goal_complete': False, 'goal_status': 'active',
    }, indent=2) + '\n')
    print(json.dumps({'audit': output_name, 'all_passed': True, 'scope_checks': len(checks)}))


if __name__ == '__main__':
    main()
