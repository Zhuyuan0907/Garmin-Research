#!/usr/bin/env python3
"""Check native projection evidence, current state/report and frozen inputs."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):return json.loads((ROOT/path).read_text())
def digest(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def main():
    name='evidence/firmware-analysis/native-android-auto-feasibility.json'
    touch_name='evidence/firmware-analysis/native-projection-touch-emulation.json'
    aa,touch=read(name),read(touch_name)
    for proof in (aa,touch):
        for source,expected in proof['source_sha256'].items():
            assert digest(source)==expected,source
    # Prior32-scope checker is rerun separately after state/report updates.
    checkpoint=read('evidence/firmware-analysis/native-voice-metadata-checkpoint-audit.json')
    state=read('evidence/deep-research-state.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    new=state['native_android_auto']
    counts={}
    for path in ['evidence/firmware-analysis/native-loaded-playback-emulation.json',
                 'evidence/firmware-analysis/native-voice-metadata-emulation.json',
                 'evidence/firmware-analysis/native-voice-predicate-emulation.json']:
        proof=read(path)
        for source,expected in proof['source_sha256'].items():assert digest(source)==expected,source
        counts[path]=len(proof['source_sha256'])
    checks={
        'exact_Taiwan1352_800_target':aa['exact_target']['HWID']==1352 and aa['exact_target']['software']=='8.00',
        '376_sources_verified_against_two_pinned_archives':aa['archive_files_verified']==376 and len(aa['source_snapshots']['sources'])==2,
        'legacy_source_current_Pixel_compatibility_unverified':aa['older_upstream_implementation_current_Pixel_compatibility_unverified'],
        '7_GUI_candidates_and10_bounded_CFGs':len(aa['original_GUI_candidates'])==7 and len(aa['original_bounded_function_CFGs'])==10,
        'bounded_CFGs_resolved_without_claiming_all_callees':all(not f['instruction_limit_reached'] and not f['unresolved_exits'] for f in aa['original_bounded_function_CFGs'].values()),
        '6_fresh_original_touch_cases_passed':len(touch['cases'])==6 and all(c['all_passed'] for c in touch['cases']),
        'four_press_drag_records_two_ignored': [c['records_appended'] for c in touch['cases']]==[1,1,1,1,0,0],
        'original_native_getter_placement_base_functions':all(c['native_functions_executed']['0x3766c4']==1 and c['native_functions_executed']['0x376bf6']==1 for c in touch['cases']),
        'native_event_code_and_buffer_guards_unchanged':len({c['original_code_sha256_before_after'] for c in touch['cases']})==1 and all(c['temporary_buffer_guards_intact'] for c in touch['cases']),
        'touch_release_input_driver_UI_and_scheduler_unverified':touch['release_action1_static_branch_identified_but_not_executed'] and all(not c['real_input_driver_or_registered_App_exercised'] for c in touch['cases']),
        'outside_coordinates_not_automatically_clamped':touch['cases'][3]['records'][0]['x']==-3 and touch['cases'][3]['records'][0]['y']==700,
        'USB_host_board_or_driver_not_claimed':not aa['transport']['actual_board_host_wiring_VBUS_ID_driver_verified'],
        'Bluetooth_only_wireless_projection_not_claimed':not aa['transport']['Bluetooth_only_projection_claimed'] and not aa['transport']['onboard_WiFi_confirmed'],
        'H264_decode_performance_and_clock_not_claimed':not aa['video']['actual_H264_hardware_or_software_decoder_identified'] and not aa['video']['actual_cpu_clock_RAM_video_performance_measured'],
        'legacy_resolution_not_global_phone_minimum':not aa['video']['direct_480x272_negotiation_with_current_phone_verified'],
        'AA_PCM_not_SBC_or_HFP_claim':not aa['audio']['SBC_decoder_required_for_this_PCM_media_channel'] and aa['audio']['prior_HFP_8kHz_success_does_not_verify_AA_audio'],
        'RAM_illustration_not_whole_board_limit':aa['memory_illustration']['not_a_decoder_requirement_or_whole_board_RAM_limit'] and aa['memory_illustration']['general_heap_allocation_headroom_unverified'],
        'state_evidence_hashes_current':new['evidence_sha256']==digest(name) and new['touch_evidence_sha256']==digest(touch_name),
        'report_and_current_state_match':read('reports/findings.json')['deep_research']==state and '目前主線：GarminOS 內建 Android Auto 接收端' in report,
        'user_no_achieve_instruction_persisted':state['latest_user_instruction']['goal_completion_forbidden_by_user'] and read('evidence/task-state.json')['latest_user_instruction']==state['latest_user_instruction'],
        'goal_active_and_Maps_deferred':state['goal_status']=='active' and not state['goal_complete'] and state['google_maps']['research_deferred_by_user'],
        'AA_is_mainline_with_real_work_remaining':new['research_priority']=='mainline' and state['required_work_remaining'] and len(new['remaining_work'])>=5,
        'actual_AA_App_and_direct_music_not_claimed':not new['native_receiver_running'] and not new['phone_session_verified'] and not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'],
        'no_device_IO_or_install_candidate':not aa['device_io'] and not touch['device_io'] and not aa['modified_VPM_or_firmware_saved'] and not aa['device_install_candidate'],
        'prior32_metadata_checkpoint_current':checkpoint['all_passed'] and len(checkpoint['scope_checks'])==32 and checkpoint['state_sha256']==digest('evidence/deep-research-state.json') and checkpoint['report_sha256']==digest('reports/nuvi2565RT.html'),
        'frozen_playback94_and_metadata17_dependencies_preserved':counts['evidence/firmware-analysis/native-loaded-playback-emulation.json']==94 and counts['evidence/firmware-analysis/native-voice-metadata-emulation.json']==17,
    }
    assert all(checks.values()),{key:value for key,value in checks.items() if not value}
    output=ROOT/'evidence/firmware-analysis/native-android-auto-checkpoint-audit.json'
    output.write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'source_dependency_counts':{
            'AA':len(aa['source_sha256']),'touch':len(touch['source_sha256']),**counts},
        'state_sha256':digest('evidence/deep-research-state.json'),
        'report_sha256':digest('reports/nuvi2565RT.html'),
        'evidence_sha256':{p:digest(p) for p in [name,touch_name]},
        'audit_script_sha256':digest(str(Path(__file__).relative_to(ROOT))),
        'goal_status':'active','full_goal_complete':False,'device_io':False},indent=2)+'\n')
    print(json.dumps({'audit':str(output.relative_to(ROOT)),'all_passed':True,
                      'scope_checks':len(checks),'AA_dependencies':len(aa['source_sha256'])}))


if __name__=='__main__':main()
