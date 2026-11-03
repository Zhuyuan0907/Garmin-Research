#!/usr/bin/env python3
"""Audit published progress without rerunning guests or historical checkpoints."""
from datetime import datetime, timezone
import hashlib
import json
import re
import subprocess
import urllib.request
from publish_native_decoder_scope_state import (
    ROOT, BASE, RUNTIME, PREFIX, PARTIAL, IMAGE, CONTRACT, PACKAGE, PEER,
    EXTRAS, read, registry, sha, write,
)


def main():
    previous = read(BASE + 'previous-audit.json')
    before = read(BASE + 'previous-state.json')
    prior_public = read(BASE + 'previous-public.json')
    for row in read(BASE + 'previous-checkpoint.json')['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    protected, native_deps, fragment_deps = {}, {}, {}
    registry(previous['protected_sources'], protected)
    assert previous['all_passed'] and len(previous['scope_checks']) == 35
    assert len(protected) == 892
    suites = list(previous['selected_frozen_suites'])
    assert len(suites) == 43
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and doc['case_count'] == suite['case_count']
        assert all(case['passed'] for case in doc['cases'])
        registry(doc['source_sha256'], native_deps)
    assert len(native_deps) == 785
    fragments = list(previous['selected_original_fragment_suites'])
    for suite in fragments:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and doc['original_fragment_controls']
        assert not doc['complete_cold_boot_or_Dispatcher_integration_scenario']
        registry(doc['source_sha256'], fragment_deps)
    docs = {path: read(path) for path in (PREFIX, PARTIAL, IMAGE, CONTRACT, PACKAGE, PEER, *EXTRAS)}
    for path, doc in docs.items():
        registry(doc['source_sha256'], protected)
        for field in ('artifacts_sha256', 'verified_protected_sources',
                      'verified_runtime_source_dependencies', 'verified_run_input_source_dependencies'):
            if field in doc:
                registry(doc[field], protected)
        protected[path] = sha(path)
    prefix, partial, image, contract, package, peer = [docs[p] for p in (PREFIX, PARTIAL, IMAGE, CONTRACT, PACKAGE, PEER)]
    registry(prefix['source_sha256'], native_deps)
    suites.append(dict(path=PREFIX, sha256=sha(PREFIX), case_count=1,
        scope='Complete cold component prefix only; later original Dispatcher/MainMenu body stopped at settings2CABFA.'))
    meta, probe, receipt = [read(RUNTIME + p) for p in (
        'terminal-metadata.json', 'terminal-probe.json', 'terminal-tool-receipt.json')]
    registry(meta['source_sha256'], protected)
    for key in ('runner', 'runner_snapshot', 'inputs', 'probe', 'FP_helper', 'GUI_observer', 'sealer', 'cold_prefix'):
        assert sha(meta[key]) == meta[key + '_sha256'], key
        protected[meta[key]] = sha(meta[key])
    image_cold = read(image['cold_loader_proof']['path'])
    assert sha(image['cold_loader_proof']['path']) == image['cold_loader_proof']['sha256']
    registry(image_cold['source_sha256'], protected)
    registry(image_cold['artifacts_sha256'], protected)
    image_manifest = read(image['build_manifest']['path'])
    assert sha(image['build_manifest']['path']) == image['build_manifest']['sha256']
    registry(image_manifest['source_sha256'], protected)
    registry(image_manifest['artifacts_sha256'], protected)
    for attempt in image['failed_attempt_history']:
        for key in ('record', 'tool_receipt', 'source', 'source_snapshot'):
            digest_key = 'sha256' if key == 'record' else key + '_sha256'
            assert sha(attempt[key]) == attempt[digest_key], key
    state, task, public = [read(p) for p in (
        'evidence/deep-research-state.json', 'evidence/task-state.json', 'reports/findings.json')]
    app = state['native_app_music']
    old_findings = before['native_app_music']['static_findings']
    findings = app['static_findings']
    for key, value in old_findings.items():
        assert findings[key] == value, key
    for key in set(findings) - set(old_findings):
        assert sha(findings[key]['evidence']) == findings[key]['evidence_sha256'], key
    progress = public['research_progress']
    report_bytes = (ROOT / 'reports/nuvi2565RT.html').read_bytes()
    report = report_bytes.decode()
    times = [re.search(r'<time id="' + name + r'" datetime="([^"]+)"', report)[1]
             for name in ('report-updated-time', 'research-updated-time')]
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control', '')
    result = subprocess.run(['systemctl', 'show', 'garmin-report-web.service',
        '--property=MainPID,ActiveState,SubState,UnitFileState'], capture_output=True, text=True, check=True)
    service = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    prior_web = read(BASE + 'previous-web.json')
    row = probe['original_lazy_handler_rows'][0]
    page_entry_stores = [event for zone in probe['partial_body_zone_verification']
                         for event in zone['stores'] if event['PC'] == '0x40434c']
    checks = {
        'prior35_scope_checkpoint_and892_protected_files_preserved': len(old_findings) == 141 and all(previous['scope_checks'].values()),
        'prior43_complete_native_prefix_suites785_dependencies_preserved': len(previous['selected_frozen_suites']) == 43 and previous['native_unique_exact_dependencies'] == 785,
        '5_original_FP_fragment_controls_kept_separate': len(fragments) == 1 and fragments[0]['case_count'] == 5,
        'authoritative44634_exit1_actual_tool_receipt_preserved': meta['session_id'] == receipt['session_id'] == 44634 and meta['terminal_exit_code'] == receipt['actual_exec_result']['exit_code'] == 1 and receipt['actual_exec_result']['chunk_id'] == '66f1d6' and 'session_id' not in receipt['actual_exec_result'] and meta['authoritative_terminal_result_received_from_exec'],
        'exact_runner_and_at_run_snapshot_match': meta['runner_sha256'] == meta['runner_snapshot_sha256'] == 'a9deadbbeb89b8cf5ca3550164736f852abb16c522a953c6e6dc84009ddc644e',
        'complete_cold_prefix_positive_separate_from_body_failure': prefix['all_passed'] and meta['cold_prefix_full_guards_passed'] and prefix['subsequent_body_terminal_exit_code'] == 1 and not prefix['subsequent_Dispatcher_body_or_multiowner_scheduling_or_foreground_verified'],
        'all11_helpers_and5_boot22_component_zones_verified': len(prefix['independent_cold_boot_zone_replays']) == 5 and len(prefix['independent_component_zone_replays']) == 22 and prefix['cases'][0]['native_helpers_returned'] == 11,
        'current356835_cache_events112_raw_inputs_exact_final_cache': prefix['native_cache_CPU_store_events'] == 356835 and prefix['exact_raw_backup_input_chunks'] == 112 and prefix['whole_cache_replay_sha256'] == '5eb8c4f79003fc8bb7d7b7fba66277286fc4de54235969d7ab23c7b29df958e3' and prefix['cache_event_count_independently_derived_per_run'],
        'pure_host_decoder_contract10_cases_is_not_guest_proof': contract['pure_host_controls']['passed'] and contract['pure_host_controls']['count'] == 10 and not contract['guest_execution'] and not contract['runtime_validation_performed'],
        'original_queued_Dispatcher_entered_not_direct_host_callback': probe['callback_entry_seen'] and probe['callback_entry_reached'] and bool(probe['independent_signal']),
        'only_first_C_to_D_FP_save_no_later_exchange_claim': len(probe['original_lazy_handler_rows']) == 1 and row['save_complete'] and not row['restore_complete'] and row['original_opcode_retry_reached'] and len(probe['native_FP_allocations']) == 1,
        'FP148_request152_advance_actual16_VSTM_stores': probe['native_FP_allocations'][0]['request'] == 148 and probe['native_FP_allocations'][0]['advance'] == 152 and len(row['VSTM_callbacks']) == 16 and all(event['size'] == 8 for event in row['VSTM_callbacks']),
        'body6_FP8_inherited22_partial_zone_checks_only': len(probe['partial_body_zone_verification']) == 6 and all(zone['whole_zone_replayed'] for zone in probe['partial_body_zone_verification']) and len(probe['partial_FP_zone_verification']) == 8 and all(zone['whole_zone_replayed'] for zone in probe['partial_FP_zone_verification']) and len(probe['partial_inherited_zone_verification']) == 22 and all(zone['whole_net_zone_matches_original_stores'] for zone in probe['partial_inherited_zone_verification']),
        'runtime_bank_check_recorded_without_claiming_independent_file_replay': probe['partial_initialized_bank_verification']['whole_bank_matches_original_CPU_write_history'] and not probe['partial_initialized_bank_verification']['host_unrecorded_mutation'],
        'file_backed_decoder_partial6_zones3_ranges_replayed': partial['all_passed'] and len(partial['independently_replayed_root_whole_zones']) == 6 and len(partial['derived_exact_decoder_slot_callback_ranges']) == 3 and not partial['guest_execution_by_this_verifier'],
        'four_native_raw_locks_released_and_actual_callers_returned': len(partial['native_raw_operations']) == 4 and all(op['native_body_returned'] and op['actual_caller_continuation_seen'] and op['semaphore_fields_written_by_original_only'] for op in partial['native_raw_operations']),
        'six_original_decoder_functions_returned_not_host_success_stubs': len(partial['exact_native_function_returns']) == 6 and all(op['returned'] for op in partial['exact_native_function_returns']),
        'two_original_slot_status_stores_observed': len(partial['native_slot_status_writes']) == 2 and [op['value'] for op in partial['native_slot_status_writes']] == [1, 0],
        'cold_zero_absent_driver_input_explicit_no_hardware_ctor_claim': not probe['decoder_inputs_after_cold_prefix']['native_decoder_ctor_observed'] and not probe['decoder_inputs_after_cold_prefix']['host_seeded_or_reset_bytes'] and not partial['foreground_or_App_or_hardware_driver_verified'] and 'returned8' in partial['cold_zero_driver_qualification'],
        'original_MainMenu_ctor_entry7_push_stores_not_return_or_foreground': len(page_entry_stores) == 7 and all(op['opcode_hex'] == 'f3b5' for op in page_entry_stores) and state['last_goal_turn']['native_MainMenu_constructor_entry_verified'] and not state['last_goal_turn']['native_MainMenu_constructor_return_verified'],
        'new_settings_boundary_preserved_actual_D_pointer_caller_SP': probe['registers']['r0'] == '0x148e6cc' and probe['registers']['lr'] == '0x2cabfb' and probe['registers']['sp'] == '0x8804018' and meta['error'] == 'Native raw mutex pointer/actor/storage differs' and not docs[EXTRAS[0]]['guest_execution'],
        'callback_return_fullbody_and_foreground_remain_false': not meta['callback_return_seen'] and not meta['body_full_guards_passed'] and not state['last_goal_turn']['complete_native_Dispatcher_FP_integration_verified'] and not state['last_goal_turn']['native_foreground_or_multiowner_FP_verified'],
        'fresh_full_ARMv6_ET_EXEC_image_zero_unresolved_symbols': image['all_passed'] and image['actual_ARM_ELF']['type'] == 'ET_EXEC' and image['actual_ARM_ELF']['machine'] == 'EM_ARM' and image['actual_ARM_ELF']['ARM1176_ARMv6_soft_float'] and not image['actual_ARM_ELF']['undefined_symbols'],
        'image139_source122_artifact_ledger_entries_preserved': len(image['source_sha256']) == 139 and len(image['artifacts_sha256']) == 122,
        'all12_REL_boundaries_resolved_in_fresh_compilation': len(image['actual_ARM_ELF']['actual_12_REL_boundaries_resolved']) == 12 and image['actual_ARM_ELF']['two_pass_symbol_maps_identical'] and not image['actual_ARM_ELF']['frozen_absolute_extension_map_used_as_binding'],
        '11_bounded_loader_ARM_assertions_not11_native_suites': image_cold['all_passed'] and len(image_cold['controls']) == image['bounded_ARM_controls']['count'] == 11 and len(image_cold['direct_ARM_controls']) == 4 and image['bounded_ARM_controls']['synthetic_file_cache_strcmp_RAM_permissions_fixture'],
        'original40_TTS_interfaces_and_RAM_preserved': image['bounded_ARM_controls']['original_TTS40_imports_trampolines_RAM_preserved'] and image_cold['controls']['whole_original_RAM_after_header_identical'],
        'single_bootstrap_guard_and24576_actual_zero_stores': image['once_guard']['actual_original_common_entries'] == image['once_guard']['actual_original_TTS_entries'] == 1 and image['once_guard']['zero_span_words'] == 24576 and image['once_guard']['zero_store_PC'] == '0x2f7d0c0' and image['once_guard']['resident_entry_repeat_returns_pinned_no_module_write_or_common_TTS_entry'],
        'same_LOCAL_anchor_getter_without_exclusive_channel_claim': image['owned_anchor']['STB_LOCAL_size2'] and image['owned_anchor']['ARM_getter_executed_and_returned_this_object'] and not image['owned_anchor']['registration_execution_or_channel_exclusivity_proven'],
        '8_host_groups_ASan_UBSan_mock_owners_not_native_audio_GUI': image['host_tests']['group_count'] == 8 and image['host_tests']['complete_host_scenarios'] == 1 and image['host_tests']['ASan_UBSan'] and image['host_tests']['explicit_mock_ownership_and_session_contracts'] and not image['host_tests']['native_IRQ_audio_GUI_executed'],
        'two_failed_image_harness_attempts_retained': len(image['failed_attempt_history']) == 2,
        'no_device_image_candidate_or_native_session_integration_claim': not image['combined_raw_image']['VPM_or_SIG_created'] and not image['combined_raw_image']['device_install_candidate'] and not image['limits']['native_kernel_GUI_audio_integrated'],
        'native_package_acceptance_boundary_static_only_unknown_SIG': package['all_exact_assertions_passed'] and package['static_only'] and not package['policy_and_scope_claims']['native_SIG_requester_identified'] and not package['policy_and_scope_claims']['modified_code_accepted_on_device'],
        'independent_peer_review_available_and_frozen': sha(PEER) == findings['native_decoder_query_partial_and_MainMenu_entry']['independent_peer_review_sha256'] and peer['all_passed'] and len(peer['assertions']) == 20 and all(peer['assertions'].values()),
        'canonical_public_task_consistent146_findings118_details': len(findings) == 146 and len(progress['completed']) == 118 and public['deep_research'] == state and task['last_goal_turn'] == state['last_goal_turn'],
        'all141_findings113_prior_progress_details_unchanged': all(findings[key] == value for key, value in old_findings.items()) and progress['completed'][:113] == prior_public['research_progress']['completed'],
        'weighted33_App20_remains_milestone_estimate': progress['estimate_percent'] == 33 and progress['weighted_estimate_percent'] == 33.0 and sum(phase['weight'] * phase['estimate_percent'] / 100 for phase in progress['phases']) == 33 and progress['phases'][4]['estimate_percent'] == 20,
        'two_matching_Taiwan_timestamps_and_progress_bar': times[0] == times[1] and times[0].endswith('+08:00') and 'value="33"' in report,
        'updated_success_and_remaining_limits_visible': '播放器整體編譯完成，首頁建立流程前進' in report and '尚未完成前景顯示、觸控或實機 App 安裝' in report and '沒有證明音訊硬體已啟動' in report,
        'fresh_LAN_HTTP200_exact_latest_report_no_store': status == 200 and served == report_bytes and 'no-store' in cache,
        'enabled_active_report_service_same_PID': service['ActiveState'] == 'active' and service['UnitFileState'] == 'enabled' and service['MainPID'] == prior_web['service']['MainPID'] == '357833',
        'public_report_without_private_MAC_or_ESN': not re.search(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', report) and 'REDACTED_PRIVATE_ID' not in report,
        'no_new_device_writes_calls_or_sound': not meta['device_io'] and not meta['sounds_emitted'] and not probe['device_io'] and not probe['sounds_emitted'] and not state['last_goal_turn']['device_files_written'],
        'App_icon_direct_phone_music_unverified_goal_active_remaining': not app['native_app_running'] and not app['menu_icon_visible_on_device'] and not app['direct_phone_music_verified'] and state['required_work_remaining'] and not state['goal_complete'] and state['goal_status'] == 'active',
    }
    assert all(checks.values()), [name for name, passed in checks.items() if not passed]
    for path in (ROOT / BASE).rglob('*'):
        if path.is_file() and '__pycache__' not in path.parts:
            relative = str(path.relative_to(ROOT))
            protected[relative] = sha(relative)
    for path in ('scripts/probe_native_dispatcher_decoder.py', 'scripts/seal_native_decoder_attempt.py',
                 'scripts/verify_native_decoder_cold_prefix.py', 'scripts/publish_native_decoder_scope_state.py',
                 'scripts/check_native_decoder_scope_checkpoint.py', PREFIX,
                 'evidence/firmware-analysis/native-dispatcher-body-checkpoint-audit.json'):
        protected[path] = sha(path)
    out = 'evidence/firmware-analysis/native-decoder-scope-checkpoint-audit.json'
    audit = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True,
        scope_checks=checks, previous_checkpoint_scopes=35, selected_frozen_suites=suites,
        native_unique_exact_dependencies=len(native_deps), selected_original_fragment_suites=fragments,
        fragment_unique_exact_dependencies=len(fragment_deps),
        selected_native_partial_exchange_proofs=previous['selected_native_partial_exchange_proofs'],
        selected_partial_decoder_proofs=[dict(path=PARTIAL, sha256=sha(PARTIAL),
            scope='Cold-zero absent-driver native query with4 raw operations; partial body only, later settings failure retained.')],
        selected_full_linked_image_controls=dict(path=IMAGE, sha256=sha(IMAGE),
            bounded_ARM_assertions=11, original_loader_sessions=2, direct_ARM_calls=4,
            host_groups=8, complete_host_scenarios=1, native_GUI_audio_owner_integration=False),
        protected_sources=protected, state_sha256=sha('evidence/deep-research-state.json'),
        report_sha256=sha('reports/nuvi2565RT.html'), first_native_C_to_D_FP_exchange_verified=True,
        complete_native_Dispatcher_FP_integration_verified=False, latest_body_terminal_exit_code=1,
        cold_prefix_all_guards_passed=True, native_MainMenu_constructor_entry_verified=True,
        native_MainMenu_constructor_return_verified=False, foreground_or_device_App_verified=False,
        bank_replay_scope='Runtime-recorded whole-bank match; before bytes absent from file proof, no independent file-only bank replay claim.',
        inherited_journal_scope='Includes original MAIN and frozen ARM companion stores; not labeled entirely original MAIN.')
    write(out, audit)
    latest['historical_offline_checkpoint_audits']['prior_native_Dispatcher_body_checkpoint'] = dict(
        audit=BASE + 'previous-audit.json', audit_sha256=sha(BASE + 'previous-audit.json'),
        state_snapshot=BASE + 'previous-state.json', state_snapshot_sha256=sha(BASE + 'previous-state.json'),
        fresh_revalidation_scopes=35, all_passed=True)
    latest.pop('current_native_Dispatcher_body_checkpoint', None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(), HTTP_status=status,
        served_latest_report=True, local_report_sha256=sha('reports/nuvi2565RT.html'),
        served_report_sha256=hashlib.sha256(served).hexdigest(), report_bytes=len(served),
        service=service, service_not_restarted=True, cache_control=cache,
        current_native_decoder_scope_checkpoint=out, checkpoint_sha256={out: sha(out)},
        goal_status='active', full_goal_complete=False, current_physical_test_requested=False)
    latest['complete_current_offline_run'] = dict(checkpoint_all_scope_checks_passed=True,
        checkpoint_scope_count=len(checks), previous_checkpoint_scope_count=35,
        native_frozen_suites_revalidated=len(suites), native_unique_exact_dependencies=len(native_deps),
        original_fragment_suites=1, original_fragment_controls=5,
        partial_native_exchange_proofs=1, partial_decoder_query_proofs=1,
        compiled_image_bounded_ARM_assertions=11, compiled_image_host_control_groups=8,
        protected_source_count=len(protected), native_MainMenu_constructor_entry_verified=True,
        native_MainMenu_constructor_return_verified=False, latest_body_terminal_exit_code=1,
        cold_prefix_all_guards_passed=True, physical_App_verified=False,
        device_io=False, sounds_emitted=False,
        scope='44 preserved complete/native-prefix suites; separate5 FP fragments and partial exchange/query proofs. Full-linked image11 bounded assertions and8 host groups are separate from native suites. No full body/foreground/device proof.')
    latest['progress_display_verified'].update(estimate_percent=33, completed_items=118,
        report_updated_time=times[0], research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,
        visual_browser_render_not_performed=True, current_success_and_body_failure_separated_visible=True)
    write('evidence/report-web-latest.json', latest)
    print(json.dumps(dict(all_passed=True, scopes=len(checks), findings=146,
        native_suites=len(suites), native_deps=len(native_deps), fragment_controls=5,
        partial_native_exchange_proofs=1, partial_decoder_query_proofs=1,
        compiled_image_bounded_ARM_assertions=11, protected_sources=len(protected),
        url=latest['url'], HTTP_status=status, report_bytes=len(served), service_PID=service['MainPID'])))


if __name__ == '__main__':
    main()
