#!/usr/bin/env python3
"""Audit USB/graphics projection leads against current state and prior proofs."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def read(path):return json.loads((ROOT/path).read_text())
def digest(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def main():
    emu_name='evidence/firmware-analysis/native-projection-io-emulation.json'
    static_name='evidence/firmware-analysis/native-projection-io-static.json'
    emu,static=read(emu_name),read(static_name)
    for proof in (emu,static):
        for source,expected in proof['source_sha256'].items():
            assert digest(source)==expected,source
    state=read('evidence/deep-research-state.json')
    new=state['native_android_auto']['projection_io']
    prior=read('evidence/firmware-analysis/native-android-auto-checkpoint-audit.json')
    usb=emu['USB_cases'];sga=emu['SGA_cases']
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    checks={
        'exact_HWID1352_800_input':emu['exact_target']['HWID']==1352 and emu['exact_target']==static['exact_target'],
        'source_dependencies_match':len(emu['source_sha256'])==12 and len(static['source_sha256'])==14,
        'three_runtime_descriptor_cases':len(usb['descriptors'])==3 and all(c['all_passed'] for c in usb['descriptors']),
        'vendor_and_MSC_device_personalities': [c['interface_class_subclass_protocol'] for c in usb['descriptors']]==[[255,255,255],[8,6,80],[8,6,80]],
        'MSC_PID_matches_historical_USB_identity':usb['descriptors'][1]['PID']=='0x2548' and usb['descriptors'][1]['VID']=='0x91e',
        'packet_sizes_only_synthetic':usb['descriptors'][2]['fixture_packet_sizes']['bulk']==512 and not static['USB_device_path']['USB_host_AOA_driver_board_VBUS_ID_or_transfer_completion_verified'],
        'CSW_original_copy_and_in_flight_rejection':len(usb['transmit'])==2 and [c['transfer_queued'] for c in usb['transmit']]==[True,False] and usb['transmit'][0]['original_ARM_copy_executed'] and not usb['transmit'][1]['original_ARM_copy_executed'],
        'sole_function_fixture_is_event_publication':len(usb['transmit'][0]['function_fixtures'])==1 and usb['transmit'][0]['function_fixtures'][0]['boundary']=='kernel_event_publication_only' and not usb['transmit'][1]['function_fixtures'],
        'two_receive_register_paths':len(usb['receive'])==2 and [c['synthetic_register_index'] for c in usb['receive']]==[1,165] and all(not c['function_fixtures'] for c in usb['receive']),
        'ten_native_translation_ID_controls':len(sga)==10 and [c['probe_status'] for c in sga]==[0]+[13]*8+[11],
        'six_mask_and_one_two_status_controls':len(sga[0]['native_register_controls'])==7 and sga[0]['native_register_controls'][-1]['returned']==[4660,22136],
        'graphics_has_no_function_fixtures':all(not c['function_fixtures'] for c in sga),
        'all_buffer_guards_and_write_protected_code':emu['stock_code_mappings_write_protected'] and all(c['buffer_guards_intact'] for cases in usb.values() for c in cases) and all(c['buffer_guards_intact'] for c in sga),
        '15_complete_Thumb_and6_complete_ARM_CFGs':len(static['bounded_Thumb_CFGs'])==15 and len(static['bounded_ARM_CFGs'])==6 and all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in static['bounded_Thumb_CFGs'].values()) and all(f['all_local_paths_resolved'] for f in static['bounded_ARM_CFGs'].values()),
        'two_GUI_classes_use_conditional_runtime_RTTI':len(static['conditional_GUI_classes'])==2 and all(c['conditional_startup_copy'] and not c['live_copy_flag_or_constructor_or_renderer_verified'] for c in static['conditional_GUI_classes']),
        'GUI_renderer_slots_are_leads_only':static['Image_renderer_dispatch']['renderer_virtual_slots']==[16,17,18] and not static['Image_renderer_dispatch']['actual_renderer_table_pixel_format_surface_present_or_UI_registration_verified'],
        'SD_MMC_host_info_not_USB_host':static['SD_MMC_false_host_lead']['not_used_as_USB_host_evidence'],
        'no_SGA_pixels_H264_full_init_or_hardware_ID_claim':static['SGA_driver']['full_init_allocation_semaphore_IRQ_and_real_ID_not_executed'] and static['SGA_driver']['display_framebuffer_or_H264_decoder_not_established'],
        'current_state_hashes_and_task_copy_match':new['emulation_sha256']==digest(emu_name) and new['static_sha256']==digest(static_name) and read('evidence/task-state.json')['native_android_auto']==state['native_android_auto'],
        'report_current_and_explicit_limits':read('reports/findings.json')['deep_research']==state and 'USB 裝置模式與圖形驅動的新證據' in report and 'USB 主機角色仍未證實' in report and '合成暫存器' in report,
        'prior26_AA_checkpoint_current':prior['all_passed'] and len(prior['scope_checks'])==26 and prior['state_sha256']==digest('evidence/deep-research-state.json') and prior['report_sha256']==digest('reports/nuvi2565RT.html'),
        'goal_stays_active_user_no_achieve_and_Maps_deferred':state['goal_status']=='active' and not state['goal_complete'] and state['latest_user_instruction']['goal_completion_forbidden_by_user'] and state['google_maps']['research_deferred_by_user'],
        'AA_App_phone_display_or_install_not_claimed':not state['native_android_auto']['native_receiver_running'] and not state['native_android_auto']['phone_session_verified'] and not state['native_app_music']['native_app_running'] and not new['display_pixels_or_AOA_host_verified'],
        'fresh_progress_and_offline_proofs_no_device_IO':state['last_goal_turn']['classification']=='progress' and not emu['device_io'] and not static['device_io'] and not emu['firmware_modified'] and not static['device_install_candidate'],
    }
    live_record=new.get('live_USB_verification')
    if live_record:
        live=read(live_record['evidence'])
        expected=usb['descriptors'][2]
        checks['live_USB_identity_descriptor_map_and_readonly_checks']= (
            digest(live_record['evidence'])==live_record['evidence_sha256'] and
            live['USB']['descriptors_hex']==expected['device_descriptor_hex']+expected['configuration_hex'] and
            live['backup_USB_identity_including_serial_matched'] and live['live_XML_identity_matched'] and
            live['host']['device_tree_model']=='Raspberry Pi 5 Model B Rev 1.0' and
            live['host']['previous_inference_other_host_from_hostname_was_incorrect'] and
            live['USB']['speed_Mbps']==480 and not live['USB']['USB_host_AOA_VBUS_ID_verified'] and
            live['installed_map']['matches_installed_evidence'] and live['filesystem_readonly_mount_verified'] and
            live['unmounted'] and not live['device_files_written'] and not live['firmware_modified'] and
            '實機核對：當前主機確實是 Raspberry Pi' in report)
    assert all(checks.values()),{k:v for k,v in checks.items() if not v}
    output=ROOT/'evidence/firmware-analysis/native-projection-io-checkpoint-audit.json'
    output.write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'source_dependency_counts':{
            'emulation':len(emu['source_sha256']),'static':len(static['source_sha256'])},
        'state_sha256':digest('evidence/deep-research-state.json'),
        'report_sha256':digest('reports/nuvi2565RT.html'),
        'evidence_sha256':{p:digest(p) for p in (emu_name,static_name)},
        'audit_script_sha256':digest(str(Path(__file__).relative_to(ROOT))),
        'goal_status':'active','full_goal_complete':False,
        'offline_proof_device_io':False,'live_readonly_device_io_observed':bool(live_record)},indent=2)+'\n')
    print(json.dumps({'audit':str(output.relative_to(ROOT)),'all_passed':True,
                      'scope_checks':len(checks),'live_readonly_device_io_observed':bool(live_record)}))


if __name__=='__main__':main()
