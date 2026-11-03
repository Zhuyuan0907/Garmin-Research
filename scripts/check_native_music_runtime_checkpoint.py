#!/usr/bin/env python3
"""Audit native-task/virtual-output evidence and preserve its physical limits."""
from datetime import datetime, timezone
import json
import re
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED, NativeImage
from check_native_music_stream_checkpoint import read, sha, artifacts


def main():
    state = read('evidence/deep-research-state.json')
    findings = state['native_app_music']['static_findings']
    item = findings['native_music_runtime']
    proof = read(item['evidence'])
    build = read(proof['build_manifest'])
    assert sha(item['evidence']) == item['evidence_sha256']
    assert sha(proof['build_manifest']) == proof['build_manifest_sha256']
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    artifacts(build)
    previous = read('staging/native-music-runtime/previous-checkpoint.json')
    before = read(previous['state'])
    prior_audit = read(previous['audit'])
    prior_names = ['native_voice_registry', 'native_voice_package_reads', 'native_voice_selection',
        'native_voice_outer', 'native_voice_compatibility', 'native_music_endpoint',
        'native_music_configuration_gate', 'native_music_policy', 'native_music_dispatch',
        'native_l2cap_send', 'native_music_reply', 'native_music_loaded', 'native_music_stream']
    counts = []
    for name in prior_names:
        assert findings[name] == before['native_app_music']['static_findings'][name], name
        old = read(findings[name]['evidence'])
        assert sha(findings[name]['evidence']) == findings[name]['evidence_sha256'], name
        for path, expected in old['source_sha256'].items():
            assert sha(path) == expected, path
        if name in ['native_music_loaded', 'native_music_stream']:
            assert sha(old['build_manifest']) == old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        counts.append(old['case_count'])
    cases = {r['name']: r for r in proof['cases']}
    routes = [r for r in proof['cases'] if r['name'].startswith('native_tasks_')]
    pause = cases['native_Suspend_busy_START_rejection_then_clean_resume']
    disconnect = cases['native_disconnect_busy_config_retirement_reused_LCID_new_session']
    crc = cases['native_worker_later_CRC_no_source_prefix_then_reset_recovery']
    original = (ROOT / build['original_binary']).read_bytes()
    combined = (ROOT / build['combined_binary']).read_bytes()
    stock = NativeImage()
    public = read('reports/findings.json')
    task = read('evidence/task-state.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    runtime = read(findings['native_music_stream']['emulator_runtime_evidence'])
    assert sha(runtime['successful_runtime']['native_library']) == runtime['successful_library_sha256']
    checks = {
        'fresh9_complete_cases_current118_sources_build_artifacts':
            proof['all_passed'] and proof['case_count'] == len(cases) == 9 and
            len(proof['source_sha256']) == 118 and
            all(r['passed'] and all(r['checks'].values()) for r in proof['cases']) and
            proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED,
        'same_VM_original_DLL_loader_live_kernel_RAM_not_reset':
            proof['original_loader_registered_wire_guard_native_tasks_source_virtual_output_same_VM'] and
            all(r['snapshot']['loaded']['same_vm_as_native_kernel'] and
                r['snapshot']['loaded']['original_initialized_data_not_recopied'] and
                r['snapshot']['loaded']['status'] == 11 for r in proof['cases']),
        'six_formats_priority_routes66_frames5986_PCM_bytes_reference':
            len(routes) == 6 and {(r['extra']['rate'], r['extra']['mode'], r['extra']['source_priority']) for r in routes} ==
                {(rate, mode, priority) for rate, mode in [(44100, 0), (44100, 3), (48000, 2)] for priority in [40, 28]} and
            sum(r['extra']['frames_reference_checked'] for r in proof['cases']) == proof['frames_reference_checked'] == 66 and
            sum(r['extra']['PCM_reference_bytes'] for r in proof['cases']) == proof['PCM_reference_checked_bytes'] == 5986 and
            all(r['checks']['native_PCM_reference'] and r['checks']['virtual_stereo_reference'] for r in routes),
        'original_events_capacity_wakeup_source_sync_wait_ACK_no_host_pump':
            not proof['host_decoder_step_or_coordinator_pump_notify_register_start_remove_release'] and
            all(r['checks']['capacity_wakeup_finishes_fifth_packet'] and
                len(r['snapshot']['original_synchronous_start_returns']) == 5 and
                r['checks']['higher_source_priority_publication_during_sync_start'] for r in routes),
        'native_Suspend_busy_START_reject_and_same_session_clean_resume':
            all(pause['checks'].values()) and pause['extra']['busy_reply']['state'] == 4 and
            pause['extra']['busy_reply']['new_sends'][0]['wire_hex'] == '13070431',
        'disconnect_retains_old_sources_rejects_config_then_reused_LCID_new_session':
            all(disconnect['checks'].values()) and disconnect['extra']['busy_reply']['state'] == 1 and
            disconnect['extra']['busy_reply']['new_sends'][0]['wire_hex'] == '13030031',
        'later_CRC_no_source_prefix_reset_reference_without_task_restart':all(crc['checks'].values()),
        'guest11_sites64bytes_original_preflight_no_postload_host_rewiring':
            len(build['patch_plan']) == 11 and sum(r['length'] for r in build['patch_plan']) == build['VM_MAIN_patch_bytes'] == 64 and
            all(stock.read(r['address'], r['length']).hex() == r['before'] for r in build['patch_plan']) and
            all(r['snapshot']['guest_MAIN_write_bytes'] == 64 for r in proof['cases']) and
            proof['guest_installs11_MAIN_sites64bytes_no_host_postload_dispatch_or_audio_hook_patches'],
        'original40_voice_runtime_task_exit_assertions_pinned_not_safe_unload':
            proof['original_voice40_and_full_runtime_preserved'] and
            proof['modules_TCB_stacks_remain_pinned_after_exit'] and
            all(r['snapshot']['original_TTS40_runtime_preserved'] and
                r['snapshot']['source_worker']['finished_on_stack'] == r['snapshot']['decoder_worker'][6] == 1
                for r in proof['cases']),
        'original_payload63923_code_2462860_RAM_RX_RW_inside_reservation':
            combined[12:len(original)] == original[12:] and build['extension_bytes'] == 63923 and
            len(combined) == build['combined_file_bytes'] == 2362943 and
            build['combined_ram_bytes'] == 2462860 and build['remaining_reservation_bytes'] == 682868 and
            build['code_RX_data_RW_segments'] and not build['unresolved_symbols'] and
            not any(t in build['segments'] for t in ['RWE', 'INTERP', 'DYNAMIC']),
        'contiguous_emulation_package_other_members_unchanged_no_acceptance':
            build['package_checks']['DLL_blocks_contiguous'] and build['package_checks']['all_other_members_byte_identical'] and
            not build['package_checks']['signature_algorithm_or_enforcement_verified'] and
            not build['real_package_acceptance_verified'] and not proof['actual_package_acceptance_verified'] and
            'EMULATION-ONLY' in build['package'],
        'frozen13_proofs_and_saved15_scope_prior_state_full_outer_not_relabeled':
            counts == [10, 2, 6, 12, 15, 29, 189, 208, 18, 10, 112, 8, 21] and
            prior_audit['all_passed'] and len(prior_audit['scope_checks']) == 15 and
            prior_audit['state_sha256'] == sha(previous['state']) and
            not proof['original_outer_filesystem_exercised_this_stage'],
        'isolated214_emulator_and_independent_read_write_fault_controls':
            proof['emulator_binding_version'] == '2.1.4' and proof['emulator_native_version'] == [2, 1, 33621247] and
            len(proof['guard_fault_controls']) == 2 and all(r['passed'] for r in proof['guard_fault_controls']),
        'canonical_task_public31_percent36_details_taiwan_times':
            public['deep_research'] == state and all(task[k] == state[k] for k in
                ['last_goal_turn', 'next_actions', 'attended_testing', 'ordered_priorities', 'latest_user_instruction']) and
            public['research_progress']['estimate_percent'] == 31 and len(public['research_progress']['completed']) == 36 and
            all(re.search('<time id="' + ident + '" datetime="[^\"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']),
        'public_virtual_finite_scope_remaining_startup_full_outer_install_no_identifiers':
            all(t in report for t in ['最新：原生藍牙端點、原廠排程與虛擬音訊輸出已接通',
                '9 個排程／輸出整合案例通過', '沒有原機喇叭或可安裝 App 的證據',
                '外層載入與音訊排程尚未合成一次測試', '仍以每個封包建立有限音訊',
                '工作初始化失敗／完成就緒', '研究封裝沒有傳入導航機']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
        'away_no_device_IO_calls_mic_canceled_goal_active_AA_later_Maps_deferred':
            state['attended_testing']['waiting_for_user_return'] and not state['attended_testing']['user_present'] and
            state['attended_testing']['no_pending_question'] and not state['last_goal_turn']['device_io'] and
            not state['last_goal_turn']['device_files_written'] and not state['last_goal_turn']['automatic_calls_or_sound'] and
            not proof['device_io'] and not build['device_io'] and not proof['device_install_candidate'] and
            not build['device_install_candidate'] and not proof['real_phone_speaker_navigation_verified'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status'] == 'cancelled_by_user' and not state['microphone_amplifier']['next_actions'] and
            state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'],
    }
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    path = 'evidence/firmware-analysis/native-music-runtime-checkpoint-audit.json'
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True,
        'scope_checks': checks, 'state_sha256': sha('evidence/deep-research-state.json'),
        'report_sha256': sha('reports/nuvi2565RT.html'), 'proof_sha256': sha(item['evidence']),
        'build_manifest_sha256': sha(proof['build_manifest']),
        'audit_script_sha256': sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO': False, 'device_install_candidate': False,
        'goal_status': 'active', 'full_goal_complete': False}
    (ROOT / path).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scope_checks': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
