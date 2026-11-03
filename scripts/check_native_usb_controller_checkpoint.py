#!/usr/bin/env python3
"""Audit native peripheral evidence without claiming a working host receiver."""
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
    current = aa['USB_controller_peripheral_path']
    emu_name, static_name = current['emulation_evidence'], current['static_evidence']
    emu, static = read(emu_name), read(static_name)
    for proof in (emu,static):
        for name, expected in proof['source_sha256'].items():
            assert digest(name)==expected,name
    ep, irq, setup, sizes = (emu[k] for k in ('endpoint_cases','reset_IRQ_cases','EP0_setup_cases','FIFO_size_cases'))
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    prior_name = 'evidence/firmware-analysis/native-usb-transition-checkpoint-audit.json'
    prior = read(prior_name)
    state_hash, report_hash = digest('evidence/deep-research-state.json'),digest('reports/nuvi2565RT.html')
    checks = {
        'exact_target_and_stock_sha':emu['exact_target']==static['exact_target'] and
            emu['exact_target']['HWID']==1352 and emu['exact_target']['software']=='8.00' and
            emu['exact_target']['stock_sha256']==digest('evidence/firmware-analysis/main_02bd.bin'),
        'source13_emulation20_static_dependencies_match':len(emu['source_sha256'])==13 and len(static['source_sha256'])==20,
        'current_state_proof_references_match':current['emulation_sha256']==digest(emu_name) and current['static_sha256']==digest(static_name),
        '22_fresh_offline_controls_pass':emu['all_passed'] and [len(c) for c in (ep,irq,setup,sizes)]==[2,5,7,8] and
            all(c['all_passed'] for group in (ep,irq,setup,sizes) for c in group),
        'two_speed_packet_words_and_original_ARM_CLZ':
            [c['native_packet_size_words'] for c in ep]==[[16,16,64],[64,512,512]] and
            all(c['original_ARM_CLZ_body_calls']==3 and not c['function_fixtures'] for c in ep),
        'FIFO_power_of_two_validation_controls':
            [c['input'] for c in sizes]==[0,8,16,64,512,4096,8192,24] and
            [c['returned'] for c in sizes]==[0,0,1,3,6,9,0,0] and
            all(c['original_ARM_CLZ_body_executed'] and not c['function_fixtures'] for c in sizes),
        'five_IRQ_controls_keep_ARM_masks_and_guards':all(c['IRQ_mask_bits_restored'] and
            c['original_ARM_IRQ_helpers_executed'] and c['workspace_guards_intact'] for c in irq),
        'only_IRQ_ack_and_optional_publication_function_fixtures':
            all(c['function_fixtures'][-1]['boundary']=='controller_IRQ_acknowledgement_only' for c in irq) and
            all(len(c['function_fixtures'])==1 for c in irq[:4]) and
            [f['boundary'] for f in irq[4]['function_fixtures']]==
                ['kernel_event_publication_only','controller_IRQ_acknowledgement_only'],
        'four_personality_speed_descriptors_preserve_complete_configs':
            all(len(bytes.fromhex(c['device_descriptor_hex']))==18 and
                len(bytes.fromhex(c['configuration_hex']))==c['configuration_capture_bytes']==
                int.from_bytes(bytes.fromhex(c['configuration_hex'])[2:4],'little') for c in irq),
        'three_valid_SET_ADDRESS_cases_delay_application':
            [bytes.fromhex(c['setup_packet_hex'])[2] for c in setup[:3]]==[1,42,127] and
            all(c['pending_address_applied_only_after_EP0_completion'] for c in setup[:3]),
        'GET_DESCRIPTOR_truncation_and_type6_stall_controls':
            [len(bytes.fromhex(c['FIFO_output_hex'])) for c in setup[3:6]]==[8,18,18] and
            setup[6]['name']=='unsupported_descriptor_type6_stalls' and setup[6]['unknown_descriptor_stall_case'],
        'setup_FIFO_is_explicit_data_fixture_original_reader_executes':
            all(c['FIFO_input_fixture_bytes']==8 and c['original_FIFO_reader_executed'] and
                c['FIFO_input_staged_before_original_LDRB']=='0x1bcc26' and
                not c['function_fixtures'] and c['workspace_guards_intact'] for c in setup),
        'no_actual_bus_status_banking_or_IRQ_claim':
            all(not c['USB_packet_ack_status_phase_or_actual_bus_transfer_verified'] for c in setup) and
            all(c['read_clear_interrupts_FIFO_endpoint_banking_or_physical_IRQ_not_emulated'] for c in irq) and
            all(c['indexed_register_side_effects_not_hardware_emulated'] for c in ep),
        '12_Thumb_three_ARM_local_CFGs_resolved':
            len(static['bounded_Thumb_functions'])==12 and len(static['bounded_ARM_functions'])==3 and
            all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for group in
                (static['bounded_Thumb_functions'],static['bounded_ARM_functions']) for f in group.values()),
        'six_descriptor_switch_cases_and_ARM_veneer_explicit':
            len(static['EP0_device_path']['descriptor_switch']['switch_targets'])==6 and
            static['ARM_FIFO_size_veneer']['unresolved_exits']==[
                {'target':'0x6e4724','reason':'Outside bounded local range'}],
        'literal_DEVCTL_address_used_for_FIFO_fields_only':
            static['register_comparison']['native_literal10200060_used_at_offsets2_3_4_6_not_DEVCTL'] and
            all(c['DEVCTL_offset60_not_accessed'] for c in ep) and
            static['register_comparison']['comparison_is_inference_not_physical_controller_identification'],
        'peripheral_request_receiver_not_AOA_host_backend':
            static['EP0_device_path']['receives_host_requests_not_issues_AOA_to_phone'] and
            current['receives_host_control_requests_not_a_phone_AOA_host_backend'] and
            not emu['USB_host_AOA_VBUS_or_phone_session_verified'],
        'failed_fixture_expectations_not_saved_as_success':all(emu['verification_history'].values()),
        'code_protected_no_device_writes_or_install_candidates':
            emu['stock_code_mappings_write_protected'] and all(not p['device_io'] and
                not p['firmware_modified'] and not p['device_install_candidate'] for p in (emu,static)) and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'],
        'task_report_prior22_checkpoint_current':
            read('evidence/task-state.json')['native_android_auto']==aa and
            read('reports/findings.json')['deep_research']==state and prior['all_passed'] and
            len(prior['scope_checks'])==22 and prior['state_sha256']==state_hash and prior['report_sha256']==report_hash,
        'new_report_separates_device_from_host_scope':
            '控制器與控制端點：已驗證的仍是 USB 裝置路徑' in report and
            '這條流程接收主機送給 Garmin 的控制請求' in report and
            '本輪沒有實機操作或改寫 Garmin' in report,
        'full_goal_active_no_achieve_Maps_deferred_App_phone_open':
            state['last_goal_turn']['classification']=='progress' and state['goal_status']=='active' and
            not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['google_maps']['research_deferred_by_user'] and not aa['native_receiver_running'] and
            not aa['phone_session_verified'] and not state['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name = 'evidence/firmware-analysis/native-usb-controller-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'state_sha256':state_hash,'report_sha256':report_hash,
        'evidence_sha256':{n:digest(n) for n in (emu_name,static_name,prior_name)},
        'audit_script_sha256':digest(str(Path(__file__).relative_to(ROOT))),
        'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))


if __name__=='__main__':
    main()
