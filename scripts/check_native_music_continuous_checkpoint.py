#!/usr/bin/env python3
"""Audit persistent-source evidence, frozen history and publication limits."""
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED, NativeImage
from check_native_music_stream_checkpoint import read, sha, artifacts


def main():
    state=read('evidence/deep-research-state.json')
    findings=state['native_app_music']['static_findings']
    item=findings['native_music_continuous'];proof=read(item['evidence'])
    build=read(proof['build_manifest'])
    assert sha(item['evidence'])==item['evidence_sha256']
    assert sha(proof['build_manifest'])==proof['build_manifest_sha256']
    for path,h in proof['source_sha256'].items():assert sha(path)==h,path
    artifacts(build)
    previous=read('staging/native-music-continuous/previous-checkpoint.json')
    before=read(previous['state']);prior_audit=read(previous['audit'])
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
        'native_voice_outer','native_voice_compatibility','native_music_endpoint',
        'native_music_configuration_gate','native_music_policy','native_music_dispatch',
        'native_l2cap_send','native_music_reply','native_music_loaded','native_music_stream',
        'native_music_runtime','native_music_ready']
    counts=[]
    for name in names:
        assert findings[name]==before['native_app_music']['static_findings'][name],name
        old=read(findings[name]['evidence'])
        assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,h in old['source_sha256'].items():assert sha(path)==h,path
        if name in ['native_music_loaded','native_music_stream','native_music_runtime','native_music_ready']:
            assert sha(old['build_manifest'])==old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        counts.append(old['case_count'])
    cases={r['name']:r for r in proof['cases']}
    routes=[r for r in proof['cases'] if '_priority' in r['name']]
    controls=[r for r in proof['cases'] if '_cancel_resume' in r['name']]
    startup=cases['persistent_startup_cancel_resume']
    disconnect=cases['persistent_disconnect_cancel_resume']
    original=(ROOT/build['original_binary']).read_bytes()
    combined=(ROOT/build['combined_binary']).read_bytes()
    stock=NativeImage();public=read('reports/findings.json');task=read('evidence/task-state.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    checks={
        'fresh5_complete_cases137_sources_exact_MAIN_build':
            proof['all_passed'] and proof['case_count']==len(cases)==5 and
            len(proof['source_sha256'])==137 and proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and
            all(r['passed'] and all(r['checks'].values()) for r in proof['cases']),
        'same_VM_original_DLL_loader_kernel_RAM_retained':
            proof['original_loader_wire_kernel_mixer_source_cancel_same_VM'] and
            all(r['snapshot']['loaded']['same_vm_as_native_kernel'] and
                r['snapshot']['loaded']['original_initialized_data_not_recopied'] and
                r['snapshot']['loaded']['status']==11 for r in proof['cases']),
        'two_rate_priority_routes80_frames7180_PCM_bytes_reference':
            {r['name'] for r in routes}=={'persistent_44100_priority40','persistent_48000_priority28'} and
            sum(r['extra']['frames_reference_checked'] for r in proof['cases'])==proof['frames_reference_checked']==80 and
            sum(r['extra']['PCM_reference_bytes'] for r in proof['cases'])==proof['PCM_reference_checked_bytes']==7180 and
            all(r['snapshot']['continuous']['payload_bytes']==r['snapshot']['reference_cursor']==r['extra']['PCM_reference_bytes']
                for r in proof['cases']),
        'one_original_anchor17_valid_packets_each_CRC_failure_no_prefix':
            len(routes)==2 and all(r['snapshot']['coordinator']['starts']==r['snapshot']['coordinator']['remove_calls']==1 and
                r['snapshot']['continuous']['packets_consumed']==17 and r['snapshot']['owned'][9]==1 and
                r['checks']['CRC_failure_no_prefix_then_fresh_reference'] for r in routes),
        'four_PCM_held_fifth_compressed_capacity_posts_resume':
            all(r['extra']['held_before_reader_wakeup']=={'PCM':4,'compressed':1} and
                r['snapshot']['continuous']['capacity_posts']>0 and
                r['checks']['reader_capacity_event_resumed_fifth_packet'] for r in routes),
        'full_capacity_reader_payload_reference_silence_explicit_starvation':
            proof['temporary_underflow_silence_keeps_source_alive'] and
            all(r['snapshot']['continuous']['underflows']>0 and r['snapshot']['continuous']['silence_bytes']>0 and
                all(t['returned']==(t['capacity'] if t['running_before'] else 0) and
                    t['payload']+t['silence']==t['returned']
                    for t in r['snapshot']['reader_trace']) for r in proof['cases']),
        'both_streamed_music_prefixes_reach_original_virtual_stereo_output':
            all(r['checks']['all_music_writer_prefix_reached_virtual_output'] and
                r['checks']['virtual_stereo_reference_including_explicit_silence'] and
                r['extra']['virtual_output_bytes_before_stop']>2*r['extra']['PCM_reference_bytes'] for r in routes),
        'original_timer_expiry_with_declared70ms_input_not_hardware_clock':
            proof['original_timer_expiry_drives_capacity_waiting_mixer'] and
            proof['virtual_70ms_ticks_and_output_frames_are_explicit_fixtures'] and
            not proof['host_decoder_step_or_coordinator_pump_register_start_remove_release'] and
            not proof['long_duration_gapless_or_realtime_verified'],
        'Suspend_disconnect_stop_discard4_remove1_before_resume_fresh_reference':
            len(controls)==3 and all(r['checks']['four_held_packets_plus_pending_compressed_canceled'] and
                r['checks']['one_original_anchor_removal_for_cancel'] and
                r['checks']['fresh_PCM_reference_after_resume'] and
                r['snapshot']['coordinator']['discarded']==4 and
                r['snapshot']['coordinator']['starts']==r['snapshot']['coordinator']['remove_calls']==2 for r in controls) and
            disconnect['extra']['busy_reply']['new_sends'][0]['wire_hex']=='13030031' and
            cases['persistent_suspend_cancel_resume']['extra']['busy_reply']['new_sends'][0]['wire_hex']=='13070431',
        'unentered_initializer_configuration_closed_then_native_entry':
            startup['extra']['early_reply']['state']==1 and
            startup['extra']['early_reply']['new_sends'][0]['wire_hex']=='13030031' and
            all(r['snapshot']['runtime_state']['source_init_done']==1 and
                r['snapshot']['runtime_state']['source_init_result']==0 for r in proof['cases']),
        'original40_runtime_original_kernel_task_exit_pinned_lifetime':
            proof['original_TTS40_runtime_preserved'] and
            all(r['snapshot']['original_TTS40_runtime_preserved'] and
                r['snapshot']['source_native_tcb_state']==r['snapshot']['decoder_native_tcb_state']==0x80 and
                not r['snapshot']['coordinator']['ticket'] and not r['snapshot']['owned'][4] and
                not r['snapshot']['queue'][2] for r in proof['cases']),
        'guest11_sites64bytes_preflight_stock_no_postload_host_rewiring':
            len(build['patch_plan'])==11 and sum(r['length'] for r in build['patch_plan'])==build['VM_MAIN_patch_bytes']==64 and
            all(stock.read(r['address'],r['length']).hex()==r['before'] for r in build['patch_plan']) and
            all(r['snapshot']['guest_MAIN_write_bytes']==64 for r in proof['cases']),
        'original_payload64899_code2363919_file2462860_RAM_RX_RW':
            combined[12:len(original)]==original[12:] and build['extension_bytes']==64899 and
            len(combined)==build['combined_file_bytes']==2363919 and build['combined_ram_bytes']==2462860 and
            build['remaining_reservation_bytes']==682868 and build['BSS_bytes']==18224 and
            build['code_RX_data_RW_segments'] and not build['unresolved_symbols'] and
            not any(t in build['segments'] for t in ['RWE','INTERP','DYNAMIC']) and
            build['pcm_pages']==[build['symbols']['pcm'+str(i)]['address'] for i in range(4)],
        'contiguous_emulation_package_other_members_preserved_acceptance_unknown':
            build['package_checks']['DLL_blocks_contiguous'] and build['package_checks']['all_other_members_byte_identical'] and
            not build['package_checks']['signature_algorithm_or_enforcement_verified'] and
            not build['real_package_acceptance_verified'] and not proof['actual_package_acceptance_verified'] and
            'EMULATION-ONLY' in build['package'],
        'frozen15_proofs_and_exact_saved19_scope_state':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14] and prior_audit['all_passed'] and
            len(prior_audit['scope_checks'])==19 and prior_audit['state_sha256']==sha(previous['state']),
        'isolated214_emulator_independent_read_write_guard_faults':
            proof['emulator_binding_version']=='2.1.4' and proof['emulator_native_version']==[2,1,33621247] and
            len(proof['guard_fault_controls'])==2 and all(r['passed'] for r in proof['guard_fault_controls']),
        'canonical_task_public31percent39_details_Taiwan_times_method_and_limits':
            public['deep_research']==state and all(task[k]==state[k] for k in
                ['last_goal_turn','next_actions','attended_testing','ordered_priorities','latest_user_instruction']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==39 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)
                for ident in ['report-updated-time','research-updated-time']) and
            all(t in report for t in ['最新：同一原廠音訊來源可持續接收 PCM','5 個持續來源整合案例通過',
                '尚未證明長時間無縫音樂、實際延遲或音質','兩個持續播放案例中','70 毫秒',
                '這些離線測試怎麼做？','沒有模擬整台導航機','研究封裝沒有傳入導航機']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
        'attended_hardware_observations_distinct_from_offline_module_proof':
            state['attended_testing']['user_present'] and not state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and
            state['last_goal_turn']['device_io'] and state['last_goal_turn']['device_files_written'] and
            state['last_goal_turn']['attended_calls_or_sound'] and
            not state['last_goal_turn']['automatic_calls_or_sound_while_away'] and
            not state['last_goal_turn']['native_firmware_or_research_package_written'] and
            not proof['device_io'] and not build['device_io'] and
            not proof['device_install_candidate'] and not build['device_install_candidate'] and
            not proof['phone_speaker_navigation_verified'] and not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and
            state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'],
        'native16k_WAV_confirmed_44k_partial_no_stereo_claim_function_priority':
            len(state['audio']['native_WAV_tests'])==2 and
            state['audio']['native_WAV_tests'][0]['format']['sampling_hz']==16000 and
            state['audio']['native_WAV_tests'][0]['speaker_confirmed'] and
            state['audio']['native_WAV_tests'][0]['user_observation']=='有聽到五個音符' and
            state['audio']['native_WAV_tests'][1]['format']['sampling_hz']==44100 and
            state['audio']['native_WAV_tests'][1]['speaker_confirmed'] and
            not state['audio']['native_WAV_tests'][1]['all_test_segments_confirmed'] and
            not state['audio']['native_44100_both_segments_verified'] and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            all(sha(t['physical_evidence'])==t['physical_evidence_sha256'] and
                sha(t['installation_evidence'])==t['installation_evidence_sha256'] and
                read(t['installation_evidence'])['unmounted'] and
                read(t['installation_evidence'])['device_readback_sha256']==t['input_sha256']
                for t in state['audio']['native_WAV_tests']) and
            all(t in report for t in ['最新實機測試：車機直接播放自製 WAV',
                '不能宣稱雙聲道或 DAC 取樣率已驗證','聲道與音質精修不再列為目前優先']),
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    path='evidence/firmware-analysis/native-music-continuous-checkpoint-audit.json'
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':checks,
        'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':sha(item['evidence']),'build_manifest_sha256':sha(proof['build_manifest']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO':True,'offline_module_proof_device_IO':False,
        'device_install_candidate':False,'goal_status':'active','full_goal_complete':False}
    (ROOT/path).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'audit':path,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
