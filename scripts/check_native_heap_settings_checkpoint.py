#!/usr/bin/env python3
"""Verify preserved checkpoints and distinct runtime/static/host scopes."""
from datetime import datetime,timezone
from pathlib import Path
from functools import lru_cache
import hashlib,json,re,struct,subprocess,urllib.request

ROOT=Path(__file__).resolve().parents[1]
BASE='staging/native-player-heap-settings-boot/'
def read(path):return json.loads((ROOT/path).read_text())
@lru_cache(None)
def sha(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
def registry(values):
    for path,digest in values.items():assert sha(path)==digest,path

def main():
    previous=read(BASE+'previous-checkpoint.json')
    for row in previous['snapshots']:assert sha(row['snapshot'])==row['sha256']
    before=read(BASE+'previous-state.json');prior=read(BASE+'previous-audit.json')
    assert prior['all_passed'] and len(prior['scope_checks'])==29
    registry(prior['protected_sources']);protected=dict(prior['protected_sources'])
    suites=prior['selected_frozen_suites']
    for row in suites:
        assert sha(row['path'])==row['sha256'];doc=read(row['path'])
        assert doc['all_passed'] and doc['case_count']==row['case_count'];registry(doc['source_sha256'])
    state,task,public=[read(path) for path in ['evidence/deep-research-state.json','evidence/task-state.json','reports/findings.json']]
    findings=state['native_app_music']['static_findings']
    for key,value in before['native_app_music']['static_findings'].items():assert findings[key]==value,key
    newkeys=['native_heap_settings_boot_development','native_heap_settings_endpoint_peer_guard_static',
        'native_vpm_acceptance_preflight','native_controller_gir_prep_prototype']
    for key in newkeys:assert sha(findings[key]['evidence'])==findings[key]['evidence_sha256']
    meta=read(BASE+'terminal-metadata.json');probe=read(meta['probe']);inputs=read(meta['inputs'])
    assert sha(meta['inputs'])==meta['inputs_sha256'] and sha(meta['probe'])==meta['probe_sha256']
    for key in ['runner','runner_snapshot','sealer','peer_review']:assert sha(meta[key])==meta[key+'_sha256']
    registry(inputs['source_sha256']);registry(meta['source_sha256'])
    peer=read(meta['peer_review']);registry(peer['inputs_sha256'])
    fields=read(BASE+'static/peer-heap-settings-guard-fields.json');registry(fields['source_sha256']);registry(fields['verified_frozen_dependency_hashes'])
    package=read(findings[newkeys[2]]['evidence']);registry(package['source_sha256']);registry(package['protected_checkpoint']['registry'])
    cfg=package['bounded_functions_artifact'];assert sha(cfg['path'])==cfg['sha256']
    gui=read(findings[newkeys[3]]['evidence']);registry(gui['source_sha256']);registry(gui['verified_protected_previous_source_hashes'])
    first=read('staging/controller-gir-prep/verification.json');registry(first['source_sha256'])
    for doc in [first,gui]:
        for key in ['ELF','flat_binary']:assert sha(doc[key])==doc[key+'_sha256']
    for values in [inputs['source_sha256'],peer['inputs_sha256'],fields['source_sha256'],package['source_sha256'],
                   gui['source_sha256'],gui['verified_protected_previous_source_hashes'],first['source_sha256']]:
        for path,digest in values.items():assert path not in protected or protected[path]==digest;protected[path]=digest
    for path in [BASE+'runner-at-run.py',BASE+'terminal-metadata.json',BASE+'heap-settings-terminal-probe.json',
                 BASE+'inputs-before-run.json',meta['peer_review'],BASE+'static/peer-heap-settings-guard-fields.json',
                 findings[newkeys[2]]['evidence'],findings[newkeys[3]]['evidence'],cfg['path'],
                 gui['ELF'],gui['flat_binary'],'scripts/seal_native_heap_settings_boot.py',
                 'scripts/publish_native_heap_settings_state.py','scripts/check_native_heap_settings_checkpoint.py']:
        protected[path]=sha(path)
    assert meta['terminal_exit_code']==1 and not meta['completed'] and meta['phase']=='settings'
    assert not meta['full_scoped_final_guards_passed'] and probe['source_sha256_before_run']==meta['runner_sha256']
    expected=bytearray(96)
    for offset,value in [(4,0x18302000),(0x18,0x18301000),(0x2c,0x388d00),(0x50,8192),(0x54,4096),(0x58,4096)]:
        struct.pack_into('<I',expected,offset,value)
    heap=probe['heap_inventory'];assert bytes.fromhex(heap['workspace96_hex'])==bytes(expected)
    assert len(heap['listener_registration_returns'])==2 and all(row['result']==0 for row in heap['listener_registration_returns'])
    assert [row['pointer'] for row in heap['listeners']]==[0x3a7f150,0x3a7f160]
    assert heap['listeners'][0]['words']==['0x3a7f160','0x1000000','0x388b57','0x0']
    assert heap['listeners'][1]['words']==['0x0','0x3000000','0x388b37','0x0']
    lists=probe['list_constructors']
    assert len(lists)==2 and {row['pointer'] for row in lists}=={'0x2d226b4','0x148e680'}
    assert all(row['native_initializer_observed'] and row['original_constructor_returned'] and not row['host_seeded_tag_or_head'] for row in lists)
    initializers=[row for row in probe['backend_initializations'] if row['native_caller'] in ['0x388bd0','0x3cc58a']]
    assert len(initializers)==3 and all(row['original_body_executed'] and len(row['native_zero_writes'])==6 for row in initializers)
    report=(ROOT/'reports/nuvi2565RT.html').read_text();progress=public['research_progress']
    times=[re.search(r'<time id="'+name+r'" datetime="([^"]+)"',report)[1] for name in ['report-updated-time','research-updated-time']]
    checks={
        'fresh_previous29_scope109_finding_snapshot_preserved':prior['state_sha256']==sha(BASE+'previous-state.json') and all(prior['scope_checks'].values()),
        '109_previous_findings_unchanged_four_new_records':len(before['native_app_music']['static_findings'])==109 and len(findings)==113,
        '465_previous_protected_sources_unchanged':len(prior['protected_sources'])==465,
        '39_previous_successful_native_suites_remain_separate':len(suites)==39 and prior['native_unique_exact_dependencies']==430,
        'actual_terminal46928_exit1_exact_runner_snapshot_and_inputs':meta['session_id']==46928 and sha(meta['runner'])==sha(meta['runner_snapshot']),
        'stock_heap_constructor_returned_exact_cold96_recipe':heap['whole_cold_workspace_recipe_checked'] and probe['heap_return'] is not None,
        'whole8192_native_prefix_and_free_header_recipe_guarded':heap['whole_extent_matches_original_recipe'] and heap['declared_extent']==['0x18301000',8192],
        'two_original_listener_registration_ret0_and_exact_nodes':len(heap['listener_registration_returns'])==2,
        'exit_and_settings_list_native_constructors_both_returned':len(lists)==2,
        'three_heap_list_backend_bodies_six_zero_stores_observed':len(initializers)==3,
        'settings_failure_at_original_ARM_VFP_not_full_guard_proof':probe['registers']['pc']=='0x3404dc' and probe['registers']['lr']=='0x2cc247' and probe['error']=='Invalid instruction (UC_ERR_INSN_INVALID)' and not probe.get('settings_initializer_returned',False),
        'partial_runtime_not_upgraded_to_foreground_or_hardware_boot':not meta['full_scoped_final_guards_passed'] and not meta['native_mainmenu_foreground_or_physical_App_or_accepted_package_verified'],
        'exact_failure_FPEXC_not_captured_cause_remains_unconfirmed':findings[newkeys[0]]['FPEXC_at_failure_not_captured_and_exact_cause_not_verified'],
        'peer_guard_review_exact_runner_not_runtime_success':peer['reviewed_source_sha256']==meta['runner_sha256'] and not peer['concrete_blocking_error_found'] and peer['static_only'],
        'native_TCB36_stale_links_resident_frames_guard_sources_preserved':fields['assertions_passed'] and fields['candidate_runtime_not_executed_or_claimed_by_peer'],
        '60_bounded_VPM_CFG65_instruction_checks_static_only':package['bounded_CFG_count']==60 and len(package['exact_instruction_assertions'])==65 and package['all_static_assertions_passed'] and package['static_only'],
        '13_backup_voices_three_TTS_still_exact':package['voice_count']==13 and package['TTS_count']==3,
        'SIG_reader_algorithm_modified_package_acceptance_unknown':not package['SIG_verifier_identified'] and not package['modified_VPM_accepted_on_device'] and not package['device_install_candidate'],
        'corrected_GIR_component_ARMv6_2412bytes_zero_undefined':gui['flat_binary_bytes']==2412 and not gui['undefined_symbols'] and 'v6KZ' in gui['attributes'],
        '29_actual_stock_length_and_range_host_controls_pass':gui['host_logic_control_count']==29 and all(row['passed'] for row in gui['host_logic_controls']),
        'first_admission_candidate_preserved_v2_distinct_native_unverified':first['load_base']!=gui['load_base'] and not gui['new_ARM_emulation_executed'] and not gui['install_candidate'],
        'canonical_public_task_equal_goal_active_and_required_work':public['deep_research']==state and all(task[key]==state[key] for key in ['updated_utc','current_priority','next_actions','last_goal_turn','parallel_research']) and state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining'],
        '32_weighted_milestone87_details_App10_time_and_bar':progress['estimate_percent']==progress['weighted_estimate_percent']==32 and len(progress['completed'])==87 and sum(row['weight']*row['estimate_percent']/100 for row in progress['phases'])==32 and progress['phases'][4]['estimate_percent']==10 and times[0]==times[1] and 'value="32"' in report,
        'report_partial_initialization_and_host_static_limits_visible':all(text in report for text in ['App 啟動前置與程式包載入條件','完整最終檢查尚未通過','目前還沒有能安裝到車機的整合 App','二十九組主機控制']),
        'report_no_private_identifiers':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
        'no_device_install_sound_or_calls_this_round':not meta['device_io'] and not probe['sounds_emitted'] and not package['device_service_IO'] and not gui['device_io'] and not gui['sounds_emitted'],
        'native_App_direct_phone_music_menu_touch_still_unproven':not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and not state['native_app_music']['menu_icon_visible_on_device'],
    }
    assert all(checks.values()),[key for key,value in checks.items() if not value]
    auditpath='evidence/firmware-analysis/native-heap-settings-checkpoint-audit.json'
    audit=dict(updated_utc=datetime.now(timezone.utc).isoformat(),all_passed=True,scope_checks=checks,
        previous_checkpoint_scopes=29,state_sha256=sha('evidence/deep-research-state.json'),report_sha256=sha('reports/nuvi2565RT.html'),
        selected_frozen_suites=suites,native_unique_exact_dependencies=430,protected_sources=protected,
        heap_settings_terminal46928_full_scoped_guards_passed=False,runtime_is_partial_development=True,
        separate_GIR_component_host_groups=29,native_device_App_not_proven=True)
    (ROOT/auditpath).write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
    latest=read('evidence/report-web-latest.json')
    with urllib.request.urlopen(latest['url'],timeout=10) as response:
        content=response.read();status=response.status;cache=response.headers.get('Cache-Control','')
    assert status==200 and content==(ROOT/'reports/nuvi2565RT.html').read_bytes() and 'no-store' in cache
    run=subprocess.run(['systemctl','show','garmin-report-web.service','--property=MainPID,ActiveState,SubState,UnitFileState'],capture_output=True,text=True,check=True)
    service=dict(line.split('=',1) for line in run.stdout.splitlines() if '=' in line)
    assert service['ActiveState']=='active' and service['SubState']=='running' and service['UnitFileState']=='enabled'
    assert int(service['MainPID'])>0 and service['MainPID']==read(BASE+'previous-web.json')['service']['MainPID']
    latest['historical_offline_checkpoint_audits']['prior_mainmenu_native_prep_checkpoint']=dict(
        audit=BASE+'previous-audit.json',audit_sha256=sha(BASE+'previous-audit.json'),
        state_snapshot=BASE+'previous-state.json',state_snapshot_sha256=sha(BASE+'previous-state.json'),fresh_revalidation_scopes=29,all_passed=True)
    latest.pop('current_native_mainmenu_prep_checkpoint',None)
    latest.update(updated_utc=datetime.now(timezone.utc).isoformat(),HTTP_status=status,served_latest_report=True,
        local_report_sha256=sha('reports/nuvi2565RT.html'),served_report_sha256=hashlib.sha256(content).hexdigest(),report_bytes=len(content),
        service=service,service_not_restarted=True,cache_control=cache,current_native_heap_settings_checkpoint=auditpath,
        checkpoint_sha256={auditpath:hashlib.sha256((ROOT/auditpath).read_bytes()).hexdigest()},goal_status='active',full_goal_complete=False,
        current_physical_test_requested=False)
    latest['complete_current_offline_run']=dict(checkpoint_all_scope_checks_passed=True,checkpoint_scope_count=len(checks),
        previous_checkpoint_scope_count=29,native_frozen_suites_revalidated=39,native_unique_exact_dependencies=430,
        protected_source_count=len(protected),heap_settings_runtime_session=46928,terminal_exit_code=1,
        full_scoped_guards_passed=False,separate_GIR_host_groups=29,separate_GIR_native_runtime_verified=False,
        scope='Original heap/list initialization returns; settings stops at an original VFP instruction. Exact guarded partial development, static acceptance and compiled controller host tests remain separate.',
        device_io=False,sounds_emitted=False)
    latest['progress_display_verified'].update(estimate_percent=32,completed_items=87,report_updated_time=times[0],research_updated_time=times[1],
        partial_heap_settings_failure_and_host_static_limits_visible=True,visual_browser_render_not_performed=True)
    (ROOT/'evidence/report-web-latest.json').write_text(json.dumps(latest,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(dict(all_passed=True,scope_count=len(checks),findings=113,protected_sources=len(protected),
        GIR_host_groups=29,native_settings_final_guards_passed=False,url=latest['url'],HTTP_status=status,report_bytes=len(content))))

if __name__=='__main__':main()
