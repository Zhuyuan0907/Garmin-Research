#!/usr/bin/env python3
"""Check immutable component evidence, scoped static results and live LAN report."""
from pathlib import Path
from datetime import datetime, timezone
from functools import lru_cache
import hashlib, importlib.util, json, re, subprocess, sys, urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from publish_native_cache_declared_state import BASE, RUNTIME, PROOF, STATIC, SUPPLEMENT

def read(path): return json.loads((ROOT/path).read_text())
@lru_cache(None)
def sha(path): return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def registry(values, target):
    for path, digest in values.items():
        assert sha(path) == digest, path
        assert path not in target or target[path] == digest, path
        target[path] = digest

def main():
    snapshots = read(BASE+'previous-checkpoint.json')
    for row in snapshots['snapshots']: assert sha(row['snapshot']) == row['sha256']
    prior, before = read(BASE+'previous-audit.json'), read(BASE+'previous-state.json')
    protected, native_deps = {}, {}
    registry(prior['protected_sources'], protected)
    assert prior['all_passed'] and len(prior['scope_checks']) == 30 and len(protected) == 665
    suites = list(prior['selected_frozen_suites'])
    assert len(suites) == 40
    for suite in suites:
        assert sha(suite['path']) == suite['sha256']
        doc = read(suite['path'])
        assert doc['all_passed'] and doc['case_count'] == suite['case_count'] and all(c['passed'] for c in doc['cases'])
        registry(doc['source_sha256'], native_deps)
    assert len(native_deps) == 437
    proof, meta = read(PROOF), read(RUNTIME+'terminal-metadata.json')
    registry(proof['source_sha256'], native_deps); registry(proof['source_sha256'], protected)
    registry(proof['artifacts_sha256'], protected); registry(meta['source_sha256'], protected)
    assert proof['all_passed'] and proof['case_count'] == 1 and proof['cases'][0]['passed']
    suites.append(dict(path=PROOF, sha256=sha(PROOF), case_count=1))
    for key in ['runner', 'runner_snapshot', 'inner_observer', 'inner_snapshot', 'driver', 'driver_snapshot',
                'outer_inputs', 'inner_inputs', 'driver_inputs', 'probe', 'actual_observer_state',
                'declared_cache_state', 'peer_review', 'previous_checkpoint', 'previous_audit', 'sealer']:
        assert sha(meta[key]) == meta[key+'_sha256'], key
        protected[meta[key]] = sha(meta[key])
    probe, actual, declared = [read(meta[k]) for k in ['probe', 'actual_observer_state', 'declared_cache_state']]
    assert meta['session_id'] == 14246 and meta['terminal_exit_code'] == 0 and meta['authoritative_terminal_result_received_from_exec']
    assert meta['completed'] and meta['full_scoped_final_guards_passed'] and probe['completed'] and probe['full_scoped_final_guards_passed']
    assert len(probe['component_calls']) == 11 and all(row['returned'] for row in probe['component_calls'])
    assert probe['component_return'] == '0x1' and probe['component_result20'][2:4] == [0x2ffc, 1]
    memory = probe['memory']
    assert memory['all_scoped_memory_guards_passed'] and memory['whole_original_shared_font_cache_replayed']
    assert len(proof['independent_whole_zone_replays']) == 19 and all(r['independently_replayed'] for r in proof['independent_whole_zone_replays'])
    assert len(actual['native_cache_allocations']) == 280 and sum(r['freed'] for r in actual['native_cache_allocations']) == 59
    assert actual['native_cache_CPU_store_count'] == meta['native_cache_CPU_store_count'] == 356833
    assert len(actual['native_cache_read_bindings']) == proof['cache_raw_input_chunks'] == 112
    assert all(r['actual_caller_return_observed'] for r in actual['native_cache_allocations']+actual['native_cache_read_bindings'])
    assert not any(actual[k] for k in ['native_cache_alloc_pending','native_cache_free_pending','native_cache_returns_pending','native_cache_read_pending'])
    assert actual['native_cache_reader_route_pending'] is None
    assert declared['whole_declared_cache_zero_sha256'] == hashlib.sha256(bytes(786432)).hexdigest()
    assert not declared['cache_observer_UcErrors'] and not declared['unexpected_emulation_UcErrors']
    assert len(memory['resident_font_streams']) == 8 and len(memory['actual_font_inventory']) == 13 and memory['all_SQL_statements_closed']
    for row in memory['actual_font_inventory']:
        active = row['index'] not in [6, 11]
        assert row['metadata_flags'][1] == int(active) and row['context_error'] == ('0x0' if active else '0x66')
    documents = {}
    for key, path in STATIC.items():
        doc = read(path); registry(doc['source_sha256'], protected)
        for field in ['verified_protected_sources', 'rechecked_existing_source_registry']:
            if field in doc: registry(doc[field], protected)
        documents[key] = doc; protected[path] = sha(path)
    supplement = read(SUPPLEMENT); registry(supplement['source_sha256'], protected); protected[SUPPLEMENT] = sha(SUPPLEMENT)
    review = documents['native_controller_GIR_cache_declared_review']
    fp = documents['native_multiowner_FP_cold_boot_exchange_recipe']
    sig = documents['native_voice_SIG_OpenPGP_format']
    assert review['protected_registry']['count'] == 665 and not review['protected_registry']['changed_or_missing']
    assert review['reviewed_source_sha256'] == meta['runner_sha256']
    assert review['static_only'] and not review['new_emulator_execution']
    assert fp['static_only'] and not fp['emulator_guest_executed'] and fp['assertions_passed']
    assert supplement['static_only'] and not supplement['emulator_guest_executed'] and supplement['assertions_passed']
    assert supplement['preserved_terminal']['session'] == 14246 and supplement['preserved_terminal']['full_scoped_final_guards_passed']
    assert sig['limits']['static_only'] and not sig['limits']['native_code_executed'] and not sig['limits']['modified_package_written']
    controls, associations = sig['pure_host_parser_controls'], sig['original_document_association_controls']
    assert controls['all_passed'] and controls['case_count'] == 16 and all(r['passed'] for r in controls['cases'])
    assert associations['all_passed'] and associations['case_count'] == 9 and all(r['passed'] for r in associations['cases'])
    assert associations['left16_bits_only'] and not associations['full_public_key_DSA_authentication']
    rows = sig['TTS_signature_analysis']; assert len(rows) == 3
    for row in rows:
        assert sha(row['package']) == row['package_sha256']
        packet, digest = row['parsed_signature'], row['candidate_BIN_digest_association']
        assert row['signature_member']['bytes'] == packet['complete_packet_bytes'] == 72
        assert packet['packet_tag'] == 2 and packet['version']['value'] == 4 and packet['signature_type']['value'] == 0
        assert packet['public_key_algorithm']['value'] == 17 and packet['hash_algorithm']['value'] == 2
        assert digest['left16_matches'] and digest['compared_digest_bits'] == 16 and not digest['full_DSA_or_trust_verification']
    gate = sig['acceptance_gate_status']
    assert gate['signature_file_format_identified'] and not any(gate[k] for k in ['public_key_identified','full_DSA_verification',
        'native_SIG_reader','native_SIG_verifier_algorithm_or_enforcement','native_policy_absence_proven','physical_modified_DLL_code_accepted'])
    state, task, public = [read(p) for p in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    app = state['native_app_music']; findings = app['static_findings']
    for key, value in before['native_app_music']['static_findings'].items(): assert findings[key] == value, key
    for key in set(findings)-set(before['native_app_music']['static_findings']):
        assert sha(findings[key]['evidence']) == findings[key]['evidence_sha256']
    assert len(findings) == 128
    report_bytes = (ROOT/'reports/nuvi2565RT.html').read_bytes(); report = report_bytes.decode()
    progress = public['research_progress']
    times = [re.search(r'<time id="'+name+r'" datetime="([^"]+)"', report)[1] for name in ['report-updated-time','research-updated-time']]
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'], timeout=10) as response:
        served, status, cache = response.read(), response.status, response.headers.get('Cache-Control','')
    service_out = subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],
        capture_output=True, text=True, check=True).stdout
    service = dict(line.split('=',1) for line in service_out.splitlines() if '=' in line)
    checks = {
        'prior30_scopes124_findings665_protected_sources_preserved':len(before['native_app_music']['static_findings']) == 124 and all(prior['scope_checks'].values()),
        '40_prior_native_suites437_dependencies_and_one_new_full_scenario':len(suites) == 41 and proof['case_count'] == 1,
        'terminal14246_exit0_authoritative_not_status_file_liveness':meta['authoritative_terminal_result_received_from_exec'],
        'outer_inner_driver_snapshots_separate_exact_hashes':len({meta['runner_sha256'],meta['inner_observer_sha256'],meta['driver_sha256']}) == 3,
        'all11_original_helpers_return_and_component_status1':meta['component_native_original_helpers_returned'] == 11,
        'full_scoped_endpoint_guards_and19_independent_zone_replays':memory['all_scoped_memory_guards_passed'] and len(proof['independent_whole_zone_replays']) == 19,
        'whole786432_byte_cache_comparison_and_replay_witness':memory['whole_original_cache_bytes'] == 786432 and proof['actual_runtime_full_cache_read_comparison_witness'],
        '356833_native_CPU_events_and112_exact_backup_input_chunks':actual['native_cache_CPU_store_count'] == 356833 and proof['cache_raw_input_chunks'] == 112,
        '280_native_allocations59_frees221_resident_payloads':sum(not r['freed'] for r in actual['native_cache_allocations']) == 221,
        'all_native_return_bindings_complete_no_pending_cache_operations':actual['native_cache_reader_route_pending'] is None,
        'original_startup_zero_input_not_host_font_decode_results':declared['whole_declared_cache_zero_sha256'] == hashlib.sha256(bytes(786432)).hexdigest(),
        'UcErrors_empty_in_new_run_old85428_errno_still_uncaptured':not meta['cache_observer_UcErrors'] and before['native_app_music']['static_findings']['native_font_cache_allocation_span_contract']['original85428_cause_is_inference'],
        '13_font_descriptors8_resident_streams2_actual_missing_inputs':len(memory['actual_font_inventory']) == 13 and len(memory['resident_font_streams']) == 8,
        'all_SQL_statements_closed_distinct_from_resident_font_streams':memory['all_SQL_statements_closed'],
        'five_native_TCB108_four_resident_frames_preserved':len(probe['native_endpoint']['native_inventory']['tasks']) == 5 and len(probe['native_endpoint']['resident_four_frames']) == 4,
        'no_native_fatal_or_invalid_access':not probe['native_fatal_entries'] and not probe['invalid_accesses'],
        '665_source_peer_review_static_only_matches_executed_outer_source':review['reviewed_source_sha256'] == meta['runner_sha256'] and not review['new_emulator_execution'],
        'cold_metadata_FP_boot_exchange_recipe_static_not_execution':fp['static_only'] and not fp['emulator_guest_executed'],
        'live_FPowner_metadata_zero_requires_new_cold_source':supplement['static_only'] and 'TCB+28=0' in supplement['current_live_constraint'],
        '3_original_SIG72_OpenPGP_v4_DSA_SHA1_format_identified':len(rows) == 3 and gate['signature_file_format_identified'],
        '16_host_parser_controls_and9_document_cross_associations':controls['case_count'] == 16 and associations['case_count'] == 9,
        '16bit_digest_prefix_not_full_DSA_or_trust_authentication':associations['left16_bits_only'] and not gate['full_DSA_verification'],
        'native_SIG_requester_enforcement_and_modified_code_acceptance_unknown':not gate['native_SIG_reader'] and not gate['native_SIG_verifier_algorithm_or_enforcement'] and not gate['physical_modified_DLL_code_accepted'],
        'bounded17_CFG_not_global_callgraph_or_policy_closure':sig['bounded_CFG_count'] == 17 and not gate['native_policy_absence_proven'],
        '124_historical_findings_identical4_added128_total':len(findings) == 128,
        'canonical_task_public_synced_goal_active_remaining_required':public['deep_research'] == state and all(task[k] == state[k] for k in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']) and state['goal_status'] == 'active' and not state['goal_complete'] and bool(state['required_work_remaining']),
        '33_weighted_percent100_details_App20_time_and_bar':progress['estimate_percent'] == progress['weighted_estimate_percent'] == 33 and len(progress['completed']) == 100 and sum(p['weight']*p['estimate_percent']/100 for p in progress['phases']) == 33 and progress['phases'][4]['estimate_percent'] == 20 and times[0] == times[1] and times[0].endswith('+08:00') and 'value="33"' in report,
        'report_latest_full_endpoint_and_installation_limits_visible':all(t in report for t in ['新增元件完成原廠資源與字型準備','目前還沒有能安裝到車機的整合 App','手機直接藍牙音樂','前 16 位','公鑰驗證']),
        'public_HTML_has_no_private_MAC_or_ESN':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
        'fresh_HTTP200_no_store_exactbytes':status == 200 and served == report_bytes and 'no-store' in cache,
        'fresh_enabled_active_service_same_PID_without_restart':service['ActiveState'] == 'active' and service['SubState'] == 'running' and service['UnitFileState'] == 'enabled' and service['MainPID'] == read(BASE+'previous-web.json')['service']['MainPID'],
        'no_device_IO_installs_calls_or_sounds':not meta['device_io'] and not meta['sounds_emitted'] and not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['automatic_calls_or_sound'],
        'App_menu_icon_direct_phone_music_and_multiowner_FP_still_unproven':not app['native_app_running'] and not app['menu_icon_visible_on_device'] and not app['direct_phone_music_verified'] and not state['last_goal_turn']['native_foreground_or_multiowner_FP_verified'],
    }
    assert all(checks.values()), [k for k,v in checks.items() if not v]
    protected[PROOF] = sha(PROOF)
    for base in [BASE, RUNTIME]:
        for path in (ROOT/base).rglob('*'):
            if path.is_file() and '__pycache__' not in path.parts:
                rel = str(path.relative_to(ROOT)); protected[rel] = sha(rel)
    for path in ['scripts/publish_native_cache_declared_state.py','scripts/check_native_cache_declared_checkpoint.py',
                 'scripts/verify_native_controller_gir_cache_declared.py','evidence/firmware-analysis/native-controller-gir-checkpoint-audit.json']:
        protected[path] = sha(path)
    audit_path = 'evidence/firmware-analysis/native-cache-declared-checkpoint-audit.json'
    audit = dict(updated_utc=datetime.now(timezone.utc).isoformat(), all_passed=True, scope_checks=checks,
        previous_checkpoint_scopes=30, state_sha256=sha('evidence/deep-research-state.json'), report_sha256=sha('reports/nuvi2565RT.html'),
        selected_frozen_suites=suites, native_unique_exact_dependencies=len(native_deps), protected_sources=protected,
        latest_component_session=14246, latest_component_terminal_exit_code=0, latest_component_full_scoped_guards_passed=True,
        independent_component_scenarios=1, whole_cache_bytes=786432, native_cache_CPU_store_events=356833,
        physical_App_or_menu_or_direct_phone_music_verified=False, native_SIG_enforcement_verified=False)
    (ROOT/audit_path).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_controller_gir_checkpoint'] = dict(audit=BASE+'previous-audit.json',
        audit_sha256=sha(BASE+'previous-audit.json'),state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),
        fresh_revalidation_scopes=30,all_passed=True)
    latest.pop('current_native_controller_gir_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(served).hexdigest(),
        report_bytes=len(served),service=service,service_not_restarted=True,cache_control=cache,
        current_native_cache_declared_checkpoint=audit_path,checkpoint_sha256={audit_path:sha(audit_path)},
        goal_status='active',full_goal_complete=False,current_physical_test_requested=False)
    latest['complete_current_offline_run'] = dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=30,native_frozen_suites_revalidated=41,native_unique_exact_dependencies=len(native_deps),
        protected_source_count=len(protected),latest_component_session=14246,terminal_exit_code=0,full_scoped_guards_passed=True,
        physical_App_verified=False,scope='One complete native preparation scenario; no foreground, multiowner FP, accepted modified-code package or physical music claim.',device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=33,completed_items=100,report_updated_time=times[0],research_updated_time=times[1],
        native_component_and_remaining_device_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scope_count=len(checks),findings=len(findings),protected_sources=len(protected),
        native_suites=len(suites),native_exact_dependencies=len(native_deps),estimate_percent=33,App_estimate_percent=20,
        url=latest['url'],HTTP_status=status,report_bytes=len(served),service_PID=service['MainPID'])))

if __name__ == '__main__': main()
