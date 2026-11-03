#!/usr/bin/env python3
"""Check sealed native settings evidence separately from static/device claims."""
from datetime import datetime, timezone
from pathlib import Path
from functools import lru_cache
import hashlib, json, re, subprocess, sys, urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
BASE = 'staging/native-player-settings-vfp-context/'

def read(path):
    return json.loads((ROOT/path).read_text())

@lru_cache(None)
def sha(path):
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

def registry(values, target):
    for path, digest in values.items():
        assert sha(path) == digest, path
        assert path not in target or target[path] == digest, path
        target[path] = digest

def main():
    checkpoint = read(BASE+'previous-checkpoint.json')
    for row in checkpoint['snapshots']:
        assert sha(row['snapshot']) == row['sha256']
    before, prior = read(BASE+'previous-state.json'), read(BASE+'previous-audit.json')
    assert prior['all_passed'] and len(prior['scope_checks']) == 27
    assert prior['state_sha256'] == sha(BASE+'previous-state.json')
    protected = {}
    registry(prior['protected_sources'], protected)
    assert len(protected) == 535
    suites = list(prior['selected_frozen_suites'])
    assert len(suites) == 39 and prior['native_unique_exact_dependencies'] == 430
    meta = read(BASE+'runtime-v2/terminal-metadata.json')
    for key in ['runner', 'runner_snapshot', 'driver', 'inputs', 'probe',
                'lazy_evidence', 'peer_review', 'sealer', 'positive_native_proof']:
        assert sha(meta[key]) == meta[key+'_sha256'], key
        protected[meta[key]] = sha(meta[key])
    inputs, probe, lazy = [read(meta[key]) for key in ['inputs', 'probe', 'lazy_evidence']]
    registry(inputs['source_sha256'], protected)
    registry(meta['source_sha256'], protected)
    assert len(inputs['source_sha256']) == 544
    positive = read(meta['positive_native_proof'])
    suites.append(dict(path=meta['positive_native_proof'], sha256=sha(meta['positive_native_proof']), case_count=4))
    native_deps = {}
    for row in suites:
        assert sha(row['path']) == row['sha256'], row['path']
        doc = read(row['path'])
        assert doc['all_passed'] and doc['case_count'] == row['case_count']
        assert all(case['passed'] for case in doc['cases'])
        registry(doc['source_sha256'], native_deps)
        registry(doc['source_sha256'], protected)
        protected[row['path']] = row['sha256']
    assert len(suites) == 40 and len(native_deps) == 437
    assert len(positive['source_sha256']) == 115
    micro = read(BASE+'micro/original-lazy-vfp-micro-probe.json')
    fp_path = 'staging/native-player-heap-settings-boot/vfp-static/native-vfp-context-preflight.json'
    fp = read(fp_path)
    registry(fp['source_sha256'], protected)
    tcb = read(BASE+'tcb-fp-static/native-tcb-fp-metadata-preflight.json')
    registry(tcb['source_sha256'], protected)
    gui = read(BASE+'gui-static/controller-gir-native-integration-contract.json')
    registry(gui['source_sha256'], protected)
    registry(gui['verified_frozen_previous_source_hashes'], protected)
    policy = read(BASE+'acceptance-static/acceptance-policy-provenance.json')
    registry(policy['source_sha256'], protected)
    registry(policy['protected_checkpoint']['registry'], protected)
    assert sha(policy['functions_artifact']['path']) == policy['functions_artifact']['sha256']
    assert policy['protected_checkpoint']['sha256'] == sha(policy['protected_checkpoint']['path'])
    ctor = read(BASE+'runtime/constructor-terminal.json')
    assert sha(ctor['source']) == sha(ctor['source_snapshot']) == ctor['source_snapshot_sha256']
    mapping = read(BASE+'runtime/declared-mapping-preflight-v2.json')
    regions = mapping['memory_regions']
    def overlaps(address):
        return [row for row in regions if int(row['low'],16) <= address+4095 and address <= int(row['high'],16)]
    assert overlaps(0xEC00000) == mapping['previous_stack_overlaps']
    assert overlaps(0x18400000) == mapping['earlier_candidate_overlaps']
    assert overlaps(0x18310000) == mapping['selected_stack_overlaps'] == []
    peer = read(meta['peer_review'])
    assert peer['reviewed_runner_sha256'] == meta['runner_sha256'] and peer['assertions_passed']
    assert peer['mapping_review']['selected_page_overlaps_recomputed'] == []
    stock = NativeImage()
    replays = []
    for zone in probe['extra_zones']:
        expected = bytearray.fromhex(zone['before_hex'])
        assert len(expected) == zone['bytes']
        for store in zone['stores']:
            offset = int(store['address'],16)-int(zone['start'],16)
            size = store['size']
            assert 0 <= offset and offset+size <= len(expected)
            assert expected[offset:offset+size].hex() == store['before_hex']
            opcode = bytes.fromhex(store['opcode_hex'])
            assert stock.read(int(store['PC'],16), len(opcode)) == opcode
            expected[offset:offset+size] = int(store['value']).to_bytes(size,'little')
        assert zone['whole_net_zone_matches_original_stores']
        assert hashlib.sha256(expected).hexdigest() == zone['after_sha256']
        replays.append(dict(start=zone['start'],bytes=zone['bytes'],original_stores=len(zone['stores']),replayed=True))
    assert len(replays) == 16 and replays == meta['independent_whole_zone_journal_replays']
    assert replays == positive['independent_whole_zone_journal_replays']
    journal = probe['initialized_data_journal']
    for store in journal['stores']:
        opcode = bytes.fromhex(store['original_opcode_hex'])
        assert stock.read(int(store['PC'],16),len(opcode)) == opcode
    for row in lazy['original_lazy_handler_rows']:
        initial, final = row['before'], row['after_native_handler']
        assert initial['PC'] == final['PC'] == '0x3404dc'
        assert initial['FPEXC'] == '0x0' and final['FPEXC'] == '0x40000000'
        assert final['FPowner'] == initial['current_TCB'] == '0x9503f90'
        assert len(initial['GP15']) == 15 and len(initial['D16']) == 16
        for key in ['CPSR','GP15','D16','FPSCR','CPACR']:
            assert initial[key] == final[key], key
        assert row['original_handler_entered'] and row['original_exception_return_seen'] and row['original_opcode_retry_reached']
        assert row['undefined_entry_is_explicit_architectural_fixture'] and not row['host_wrote_FP_enable_or_context']
    endpoint = probe['settings_native_endpoint']
    inventory = endpoint['native_inventory']
    assert len(inventory['tasks']) == 5 and all(len(bytes.fromhex(row['raw108_hex'])) == 108 for row in inventory['tasks'])
    assert len(endpoint['resident_four_frames']) == 4 and all(len(row['raw13']) == 13 for row in endpoint['resident_four_frames'])
    assert len(bytes.fromhex(endpoint['timed_thread']['raw20_hex'])) == 20
    fonts = gui['font_input_table']['descriptors']
    for font in fonts:
        if font.get('present'):
            assert sha(font['readonly_backup']) == font['backup_sha256']
    old_failure = read('staging/native-player-heap-settings-boot/terminal-metadata.json')
    state,task,public = [read(path) for path in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    findings = state['native_app_music']['static_findings']
    for key,value in before['native_app_music']['static_findings'].items():
        assert findings[key] == value, key
    newkeys = ['native_settings_lazy_vfp_runtime','native_first_owner_lazy_vfp_micro',
               'native_controller_GIR_integration_contract','native_voice_mount_policy_provenance']
    for key in newkeys:
        assert sha(findings[key]['evidence']) == findings[key]['evidence_sha256']
    for path in [fp_path, BASE+'previous-checkpoint.json', 'scripts/publish_native_settings_vfp_state.py',
                 'scripts/check_native_settings_vfp_checkpoint.py', 'evidence/firmware-analysis/native-heap-settings-checkpoint-audit.json']:
        protected[path] = sha(path)
    for path in (ROOT/BASE).rglob('*'):
        if path.is_file() and path.suffix in ['.json','.py','.html'] and '__pycache__' not in path.parts:
            rel = str(path.relative_to(ROOT))
            protected[rel] = sha(rel)
    report = (ROOT/'reports/nuvi2565RT.html').read_text()
    progress = public['research_progress']
    times = [re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1] for name in ['report-updated-time','research-updated-time']]
    latest = read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10) as response:
        content,status,cache = response.read(),response.status,response.headers.get('Cache-Control','')
    service_output = subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True).stdout
    service = dict(line.split('=',1) for line in service_output.splitlines() if '=' in line)
    checks = {
        'previous27_scopes113_findings_and535_sources_preserved':all(prior['scope_checks'].values()) and len(before['native_app_music']['static_findings'])==113,
        '40_selected_successful_native_suites437_exact_dependencies':len(suites)==40 and len(native_deps)==437,
        'four_new_findings117_total_old113_unchanged':len(findings)==117,
        'terminal20619_exit0_runner_snapshot_driver_separately_attributed':meta['session_id']==20619 and meta['terminal_exit_code']==0 and sha(meta['runner'])==sha(meta['runner_snapshot']) and probe['source_sha256_before_run']==meta['driver_sha256'] and lazy['runner_sha256']==meta['runner_sha256'],
        'all544_input_dependencies_match_previous_protection':len(inputs['source_sha256'])==544,
        'constructor_failure_kept_before_load_not_native_pipeline_failure':ctor['terminal_exit_code']==1 and not ctor['stock_pipeline_load_reached'] and not ctor['full_scoped_final_guards_passed'],
        'mapping_correction35_regions_new18310000_page_free':len(regions)==35 and mapping['earlier_artifact_empty_candidate_overlaps_was_incorrect'] and bool(overlaps(0x18400000)),
        'static_peer_review_exact_new_runner_preserves_first_owner_scope':peer['static_peer_review'] and not peer['new_guest_execution'] and peer['exact_delta']['all_function_bodies_and_existing_push_journal_guards_unchanged'],
        'original_heap_lists_and_two_listener_registrations_return':probe['heap_return']=='0x0' and probe['heap_inventory']['whole_cold_workspace_recipe_checked'] and probe['heap_after_settings']['whole_extent_matches_original_recipe'] and len(probe['list_constructors'])==2 and all(row['original_constructor_returned'] for row in probe['list_constructors']) and len(probe['heap_inventory']['listener_registration_returns'])==2,
        'original_settings_initializer_complete_all_scoped_guards':probe['completed'] and probe['settings_initializer_returned'] and probe['settings_native_final_inventory_verified'] and probe['settings_return']=='0x0' and probe['full_scoped_final_guards_passed'],
        'one_original_lazy_handler_exact_gp15_d16_cpsr_restored_retry':len(lazy['original_lazy_handler_rows'])==1 and lazy['active_handler'] is None,
        'native_owner_and_UND_push_stores_independently_replayed':any(row['start']=='0x3ab1000' and row['original_stores']==1 for row in replays) and any(row['start']=='0x18310020' and row['original_stores']==8 for row in replays),
        '16_whole_zones_original_opcode_and_value_journals_match':len(replays)==16,
        'whole_initialized_bank22_original_CPU_writes_no_host_repair':journal['CPU_store_count']==22 and journal['whole_bank_matches_original_CPU_write_history'] and not journal['host_unrecorded_mutation'],
        'five108_TCB_four52_frames_timed20node_resident_guarded':endpoint['whole_TCB108_compared_with_exact_native_deltas'] and endpoint['timed_thread']['virtual_clock_is_fixture'],
        'native_Timer_condition_token_transfer_no_ret0_lock':endpoint['native_Timer_transfer']['owner_matches_timer'] and not endpoint['inherited_settings_ret0_lock_used'] and not probe['pending_raw_ops'],
        'no_native_fatal_invalid_access_or_foreground_claim':not probe['native_fatal_entries'] and not probe['invalid_accesses'] and not probe['foreground_or_device_App_verified'],
        'three_original_micro_controls_explicit_architectural_fixtures':micro['all_passed'] and micro['case_count']==3 and all(row['passed'] for row in micro['cases']) and micro['TCBs_and_exception_entry_are_explicit_fixtures'],
        'first_same_owner_only_no_FPboot_or_multiactor_FP_claim':lazy['virtual_inputs']['first_or_same_task_only'] and lazy['virtual_inputs']['multi_task_FP_context_exchange_not_admitted'] and lazy['virtual_inputs']['original_FP_boot20ED68_not_executed'] and not positive['physical_App_or_full_boot_or_multi_owner_FP_or_accepted_package_verified'],
        'original_TCB_metadata_provenance14_CFG_static_only':tcb['assertions_passed'] and tcb['static_only'] and len(tcb['bounded_CFGs'])==14 and not tcb['new_guest_execution'] and tcb['central_result']['descriptor_flags_do_not_allocate_metadata'],
        'old46928_failure_not_reinterpreted_as_captured_FP_evidence':old_failure['session_id']==46928 and old_failure['terminal_exit_code']==1 and not old_failure['full_scoped_final_guards_passed'] and fp['frozen_terminal']['CPSR_FPEXC_CPACR_FPSCR_FP_bank_at_fault_not_captured'],
        'GUI_contract14_CFG928_opcodes38_sources_static_only':gui['exact_copied_bounded_local_CFG_count']==14 and gui['exact_MAIN_instruction_bytes_checked']==928 and gui['direct_dependency_count']==38 and not gui['new_ARM_emulation_executed'],
        '13_stock_font_descriptors_three_embedded_eight_present_two_missing':len(fonts)==13 and sum(row['kind']==2 for row in fonts)==3 and sum(row.get('present') is True for row in fonts)==8 and sum(row.get('present') is False for row in fonts)==2,
        'policy64_CFG74_assertions_all535_protected_static_only':policy['bounded_CFG_count']==64 and len(policy['instruction_assertions'])==74 and policy['all_exact_assertions_passed'] and policy['static_only'] and policy['protected_checkpoint']['source_count']==535,
        'mount_premark_is_not_success_formal_publication_unobserved':not policy['mount_success_witnesses']['generic_FAT']['physical_success_observed'] and bool(policy['mount_success_witnesses']['generic_FAT']['partition_marker_alone_is_not_success']),
        'SIG_algorithm_enforcement_and_modified_install_still_unknown':not policy['UNL_policy_distinct_from_DLLIMG_SIG']['SIG_reader_algorithm_or_enforcement_identified'] and not policy['modified_package_accepted_on_device'] and not policy['device_install_candidate'],
        'canonical_task_public_equal_active_goal_required_work':public['deep_research']==state and all(task[key]==state[key] for key in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']) and state['goal_status']=='active' and not state['goal_complete'] and bool(state['required_work_remaining']),
        '32_weighted_percent91_details_App10_bar_Taiwan_time':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and len(progress['completed'])==91 and sum(row['weight']*row['estimate_percent']/100 for row in progress['phases'])==32 and progress['phases'][4]['estimate_percent']==10 and times[0]==times[1] and times[0].endswith('+08:00') and 'value="32"' in report,
        'report_complete_settings_and_remaining_device_limits_visible':all(text in report for text in ['原廠浮點例外流程與設定初始化','原廠設定初始化已完整返回','目前還沒有能安裝到車機的整合 App','尚未完成跨執行緒浮點保存']),
        'no_private_identifiers_in_public_HTML':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
        'fresh_HTTP200_no_store_exact_current_report':status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store' in cache,
        'fresh_enabled_running_report_service_same_PID_not_restarted':service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled' and int(service['MainPID'])>0 and service['MainPID']==read(BASE+'previous-web.json')['service']['MainPID'],
        'no_device_IO_install_call_or_sound_this_round':not meta['device_io'] and not probe['sounds_emitted'] and not policy['device_service_IO'] and not gui['device_io'] and not micro['device_io'],
        'native_App_direct_phone_music_menu_icon_still_unproven':not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and not state['native_app_music']['menu_icon_visible_on_device'],
    }
    assert all(checks.values()), [key for key,value in checks.items() if not value]
    auditpath = 'evidence/firmware-analysis/native-settings-vfp-checkpoint-audit.json'
    audit = dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        previous_checkpoint_scopes=27,state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        selected_frozen_suites=suites,native_unique_exact_dependencies=len(native_deps),protected_sources=protected,
        native_settings_session20619_full_scoped_guards_passed=True,original_lazy_handler_count=1,
        separate_GUI_contract_static_only=True,native_device_App_not_proven=True)
    (ROOT/auditpath).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest['historical_offline_checkpoint_audits']['prior_native_heap_settings_checkpoint'] = dict(
        audit=BASE+'previous-audit.json',audit_sha256=sha(BASE+'previous-audit.json'),state_snapshot=BASE+'previous-state.json',
        state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=27,all_passed=True)
    latest.pop('current_native_heap_settings_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),report_bytes=len(content),
        service=service,service_not_restarted=True,cache_control=cache,current_native_settings_vfp_checkpoint=auditpath,
        checkpoint_sha256={auditpath:sha(auditpath)},goal_status='active',full_goal_complete=False,current_physical_test_requested=False)
    latest['complete_current_offline_run'] = dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=27,native_frozen_suites_revalidated=40,native_unique_exact_dependencies=len(native_deps),
        protected_source_count=len(protected),native_settings_runtime_session=20619,terminal_exit_code=0,full_scoped_guards_passed=True,
        original_lazy_handler_count=1,separate_GIR_native_runtime_verified=False,physical_App_verified=False,
        scope='Original heap/list/settings initialization and first-controller lazy-FP retry completed on declared inputs. Static GUI integration and package policy remain separate. No full boot, multi-owner FP, visible App, direct phone music or installation proof.',device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=91,report_updated_time=times[0],research_updated_time=times[1],
        native_settings_success_and_static_device_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scope_count=len(checks),findings=117,protected_sources=len(protected),native_suites=40,
        native_exact_dependencies=len(native_deps),native_settings_final_guards_passed=True,url=latest['url'],HTTP_status=status,report_bytes=len(content))))

if __name__ == '__main__':
    main()
