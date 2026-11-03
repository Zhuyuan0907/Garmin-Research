#!/usr/bin/env python3
"""Audit the loaded stream proof, frozen evidence and published limits."""
from datetime import datetime, timezone
import hashlib
import json
import re
import struct
from pathlib import Path
from analyze_native_sections import ROOT, EXPECTED, NativeImage


def read(path):
    return json.loads((ROOT / path).read_text())


def sha(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def artifacts(build):
    for file_key, hash_key in [('combined_binary', 'combined_sha256'),
                              ('extension_flat', 'extension_flat_sha256'),
                              ('extension_elf', 'extension_elf_sha256'),
                              ('package', 'package_sha256')]:
        assert sha(build[file_key]) == build[hash_key], build[file_key]
    for path, expected in build['source_sha256'].items():
        assert sha(path) == expected, path


def main():
    state = read('evidence/deep-research-state.json')
    findings = state['native_app_music']['static_findings']
    item = findings['native_music_stream']
    proof = read(item['evidence'])
    build = read(proof['build_manifest'])
    assert sha(item['evidence']) == item['evidence_sha256']
    assert sha(proof['build_manifest']) == proof['build_manifest_sha256']
    for path, expected in proof['source_sha256'].items():
        assert sha(path) == expected, path
    artifacts(build)
    previous = read('staging/native-music-stream/previous-checkpoint.json')
    before = read(previous['state'])
    audit = read(previous['audit'])
    prior_names = ['native_voice_registry', 'native_voice_package_reads',
                   'native_voice_selection', 'native_voice_outer', 'native_voice_compatibility',
                   'native_music_endpoint', 'native_music_configuration_gate',
                   'native_music_policy', 'native_music_dispatch', 'native_l2cap_send',
                   'native_music_reply', 'native_music_loaded']
    counts = []
    for key in prior_names:
        assert findings[key] == before['native_app_music']['static_findings'][key], key
        old = read(findings[key]['evidence'])
        assert sha(findings[key]['evidence']) == findings[key]['evidence_sha256'], key
        for path, expected in old['source_sha256'].items():
            assert sha(path) == expected, path
        counts.append(old['case_count'])
    old_loaded = read(findings['native_music_loaded']['evidence'])
    artifacts(read(old_loaded['build_manifest']))
    assert sha(old_loaded['build_manifest']) == old_loaded['build_manifest_sha256']
    runtime = read(item['emulator_runtime_evidence'])
    assert sha(item['emulator_runtime_evidence']) == item['emulator_runtime_evidence_sha256']
    assert sha(runtime['successful_runtime']['native_library']) == runtime['successful_library_sha256']
    assert sha(runtime['successful_runtime']['binding_file']) == runtime['successful_binding_sha256']
    assert sha(runtime['system_runtime_unchanged']['library']) == runtime['system_runtime_unchanged']['library_sha256']
    failure = read(runtime['historical_failure_evidence'])
    assert sha(runtime['historical_failure_evidence']) == runtime['historical_failure_sha256']
    assert sha(failure['host_debugger_log']) == runtime['historical_debugger_log_sha256']
    assert sha(failure['source_at_failure']) == runtime['historical_crash_source_sha256']
    assert sha(failure['source_at_failure']) == failure['source_sha256']['scripts/emulate_native_music_stream.py']
    cases = {row['name']: row for row in proof['cases']}
    control_names = [name for name in cases if not name.startswith('negotiated_')]
    reference = proof['codec_formats']
    loader = proof['loader']
    public = read('reports/findings.json')
    task = read('evidence/task-state.json')
    report = (ROOT / 'reports/nuvi2565RT.html').read_text()
    original = (ROOT / build['original_binary']).read_bytes()
    combined = (ROOT / build['combined_binary']).read_bytes()
    stock = NativeImage()
    checks = {
        'current21_cases_sources_artifacts_complete':
            proof['all_passed'] and len(cases) == proof['case_count'] == 21 and
            all(row['passed'] and all(row['checks'].values()) for row in proof['cases']) and
            proof['MAIN_sha256'] == build['MAIN_sha256'] == EXPECTED,
        'same_VM_original_outer_loader_registered_endpoint_guarded_native_callback':
            proof['original_outer_load_registered_endpoint_wire_guard_queue_decoder_same_VM'] and
            loader['INIT_calls'] == 1 and loader['loader_result'] == 11 and
            loader['native_full_readback_sha256'] == build['combined_sha256'] and
            loader['original40_and_full_original_runtime_preserved'] and
            loader['private12_and_music12_linked_and_initialized'] and
            proof['original40_voice_runtime_preserved_during_stream_tests'],
        'captured_session_coherent_state_local_receiveMTU_RTP_all_frame_checks':
            proof['captured_session_native_view_local_receiveMTU_RTP_all_frame_checks_integrated'] and
            all(cases[n]['passed'] for n in ['coherent_native_pending_local_receiveMTU_channel_flags_guards',
                'local_receive_limit_distinct_from_peer_transmit_limit',
                'captured_slot_session_checked_at_consumer_not_inferred_from_LCID',
                'consumer_rechecks_native_state_after_enqueue_before_decode']),
        'eight_formats24_packets48_frames4280_bytes_independent_reference':
            proof['format_count'] == len(reference) == 8 and
            {(r['frequency'], r['mode']) for r in reference} ==
                {(rate, mode) for rate in [44100, 48000] for mode in range(4)} and
            sum(r['frames'] for r in reference) == proof['frames_reference_checked'] == 48 and
            sum(r['packets'] for r in reference) == proof['packets_reference_checked'] == 24 and
            sum(r['PCM_bytes'] for r in reference) == proof['PCM_reference_checked_bytes'] == 4280 and
            all(r['byte_identical_to_upstream_SBC_and_independent_FIR'] and
                all(p['state'] == 'READY_never_published' for p in r['private_PCM']) for r in reference),
        'thirteen_control_cases_copy_bounds_old_sessions_CRC_reset_pause_retention':
            len(control_names) == proof['guard_and_failure_case_count'] == 13 and
            all(all(cases[n]['checks'].values()) for n in control_names),
        'independent_second_access_read_write_unmapped_fault_controls':
            len(proof['guard_fault_controls']) == 2 and
            all(r['passed'] and r['first_access_mapped'] and
                r['second_access_unmapped_fault'] == {'read': 6, 'write': 7}[r['kind']]
                for r in proof['guard_fault_controls']),
        'original_payload_RX_RW_and_code_RAM_inside_existing_reservation':
            combined[12:len(original)] == original[12:] and
            struct.unpack_from('<2I', combined, 4) == (build['combined_ram_bytes'], len(combined)) and
            build['extension_bytes'] == 62827 and build['combined_file_bytes'] == len(combined) == 2361847 and
            build['combined_ram_bytes'] == 2462860 and build['remaining_reservation_bytes'] == 682868 and
            build['code_RX_data_RW_segments'] and not build['unresolved_symbols'] and
            not any(t in build['segments'] for t in ['RWE', 'INTERP', 'DYNAMIC']),
        'package_contiguous_other_members_unchanged_not_accepted_device_candidate':
            build['package_checks']['DLL_blocks_contiguous'] and
            build['package_checks']['all_other_members_byte_identical'] and
            not build['package_checks']['signature_algorithm_or_enforcement_verified'] and
            'EMULATION-ONLY' in build['package'] and not build['real_package_acceptance_verified'],
        'eight_guest_MAIN_sites40_bytes_match_exact_stock_preflight':
            len(build['patch_plan']) == 8 and sum(r['length'] for r in build['patch_plan']) == 40 and
            build['VM_MAIN_patch_bytes'] == loader['guest_MAIN_write_bytes'] == 40 and
            all(stock.read(r['address'], r['length']).hex() == r['before'] for r in build['patch_plan']),
        'twelve_prior_proofs_sources_and_saved14_scope_state_preserved':
            counts == [10, 2, 6, 12, 15, 29, 189, 208, 18, 10, 112, 8] and
            audit['all_passed'] and len(audit['scope_checks']) == 14 and
            audit['state_sha256'] == sha(previous['state']),
        'isolated214_runtime_host_failure_retained_root_cause_not_claimed':
            proof['emulator'] == runtime['successful_runtime'] and
            proof['emulator']['distribution_version'] == '2.1.4' and
            proof['emulator']['native_version'] == [2, 1, 33621247] and
            runtime['runtime_isolated_from_system_and_audio_services'] and
            failure['observed_exit_code'] == 139 and failure['authoritative_full_proof_not_generated'] and
            not runtime['specific_host_crash_root_cause_identified'],
        'private_cooperative_PCM_not_OS_actor_DAC_phone_App_install':
            proof['queue_consumer_cooperatively_called_not_booted_OS_worker'] and
            proof['READY_PCM_inspected_then_canceled_not_DAC_output'] and
            proof['radio_kernel_storage_cache_writability_fixtures'] and
            not proof['native_OS_output_actor_speaker_navigation_coexistence_verified'] and
            not proof['actual_package_acceptance_verified'] and
            not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'],
        'canonical_task_public31_percent35_details_taiwan_timestamps':
            public['deep_research'] == state and
            all(task[k] == state[k] for k in ['last_goal_turn', 'next_actions', 'attended_testing',
                                             'ordered_priorities', 'latest_user_instruction']) and
            public['research_progress']['estimate_percent'] == 31 and
            len(public['research_progress']['completed']) == 35 and
            all(re.search('<time id="' + ident + '" datetime="[^\"]+\\+08:00"', report)
                for ident in ['report-updated-time', 'research-updated-time']),
        'public_current_stage_limits_and_version_unknown_cause_no_identifiers':
            all(t in report for t in ['最新：原生藍牙端點到封包檢查、解碼佇列與 PCM 已接通',
                '21 個串流整合案例通過', '沒有喇叭播放證據', '解碼佇列由測試逐步呼叫',
                '沒有運行中的音訊輸出程序', '具體崩潰原因尚未確認', '研究封裝沒有傳入導航機']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', report),
        'away_no_calls_sound_device_IO_mic_canceled_goal_active_no_achieve':
            state['attended_testing']['waiting_for_user_return'] and not state['attended_testing']['user_present'] and
            state['attended_testing']['no_pending_question'] and not state['last_goal_turn']['device_io'] and
            not state['last_goal_turn']['device_files_written'] and not state['last_goal_turn']['automatic_calls_or_sound'] and
            not proof['device_io'] and not build['device_io'] and
            not proof['device_install_candidate'] and not build['device_install_candidate'] and
            state['microphone_amplifier']['status'] == 'cancelled_by_user' and
            not state['microphone_amplifier']['next_actions'] and
            state['goal_status'] == 'active' and not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'],
    }
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    path = 'evidence/firmware-analysis/native-music-stream-checkpoint-audit.json'
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'all_passed': True,
              'scope_checks': checks, 'state_sha256': sha('evidence/deep-research-state.json'),
              'report_sha256': sha('reports/nuvi2565RT.html'), 'proof_sha256': sha(item['evidence']),
              'build_manifest_sha256': sha(proof['build_manifest']),
              'emulator_runtime_evidence_sha256': sha(item['emulator_runtime_evidence']),
              'audit_script_sha256': sha(str(Path(__file__).relative_to(ROOT))),
              'current_turn_device_IO': False, 'device_install_candidate': False,
              'goal_status': 'active', 'full_goal_complete': False}
    (ROOT / path).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'audit': path, 'scope_checks': len(checks), 'all_passed': True}))


if __name__ == '__main__':
    main()
