#!/usr/bin/env python3
"""Audit loader-to-private-catalog evidence and preserve wider goal limits."""
from datetime import datetime,timezone
import json
from pathlib import Path
import re
from analyze_native_sections import ROOT, EXPECTED
from check_native_music_stream_checkpoint import read,sha,artifacts

def main():
    state=read('evidence/deep-research-state.json');task=read('evidence/task-state.json')
    public=read('reports/findings.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=state['native_app_music']['static_findings']
    item=findings['native_player_menu_loaded'];proof=read(item['evidence']);build=read(proof['build_manifest'])
    for path,h in proof['source_sha256'].items():assert sha(path)==h,path
    for path,h in build['source_sha256'].items():assert sha(path)==h,path
    artifacts(build)
    previous=read('staging/native-player-menu-loaded/previous-checkpoint.json')
    before=read(previous['state']);prior=read(previous['audit'])
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
        'native_voice_outer','native_voice_compatibility','native_music_endpoint',
        'native_music_configuration_gate','native_music_policy','native_music_dispatch',
        'native_l2cap_send','native_music_reply','native_music_loaded','native_music_stream',
        'native_music_runtime','native_music_ready','native_music_continuous','native_player_menu']
    counts=[]
    for name in names:
        assert findings[name]==before['native_app_music']['static_findings'][name],name
        old=read(findings[name]['evidence'])
        assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,h in old['source_sha256'].items():assert sha(path)==h,path
        if name in ['native_music_loaded','native_music_stream','native_music_runtime',
                    'native_music_ready','native_music_continuous']:
            assert sha(old['build_manifest'])==old['build_manifest_sha256'];artifacts(read(old['build_manifest']))
        if name=='native_player_menu':
            b=read(old['build_manifest']);assert sha(old['build_manifest'])==old['build_sha256']
            assert sha(b['elf'])==b['elf_sha256'] and sha(b['flat_binary'])==b['flat_binary_sha256']
        counts.append(old['case_count'])
    cases={c['name']:c for c in proof['cases']}
    empty=cases['original_loader_auto_registers_resident_player']
    growth=cases['original_loader_preserves_existing_catalog_and_grows']
    duplicate=cases['duplicate_player_ID_retains_existing_callback_and_voice']
    rows=[empty,growth,duplicate]
    original=(ROOT/build['original_binary']).read_bytes();combined=(ROOT/build['combined_binary']).read_bytes()
    checks={
        'three_complete_cases74_source_artifact_hashes_exact_MAIN':
            proof['all_passed'] and proof['case_count']==len(cases)==3 and len(proof['source_sha256'])==74 and
            proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and all(c['passed'] for c in rows) and
            sha(item['evidence'])==item['evidence_sha256'] and
            sha(proof['build_manifest'])==proof['build_manifest_sha256'],
        'original_outer_readback_selector_loader_and_menu_share_VM':
            proof['original_outer_loader_and_catalog_same_VM'] and
            all(c['load']['native_readback_bytes']==build['combined_file_bytes'] and
                c['load']['native_readback_sha256']==build['combined_sha256'] and
                c['load']['original_loader_result']==c['load']['original_control_result']==11 and
                all(c['load']['native_file_callback_entries'].values()) and
                c['snapshot']['outer']['generic_API_binding_activation_region_read_unhooked'] for c in rows),
        'automatic_compiled_entry_registration_no_host_installer_call':
            proof['automatic_registration_from_loaded_entry'] and
            all(not c['host_calls_menu_installer'] and len(c['load']['entry_events'])==1 and
                c['load']['entry_events'][0]['from_original_loader'] and len(c['load']['install_callers'])==1 and
                c['load']['install_callers'][0]['inside_loaded_component'] and
                c['snapshot']['original_entry_visits']['0x23c3c4']==1 for c in rows),
        'forty_voice_exports_full_original_runtime_and_private_tables_preserved':
            all(c['load']['original40_and_original_runtime_preserved'] and
                c['load']['native_private12_and_player2_tables_match'] and
                c['load']['original_compatibility_result']==1 and
                c['load']['current_voice_cache_is_fixture'] for c in rows) and
            combined[12:len(original)]==original[12:],
        'loaded_original_reservation_callback_and_WAV_boundary_not_standalone_address':
            proof['stock_WAV_request_from_callback_in_original_reservation'] and
            all(c['snapshot']['state']['registration_result']==0 and
                c['snapshot']['native_menu_state']==[1,1,1,0x13528000,1,1] and
                c['snapshot']['catalog'][-1]['caption']=='Pi 播放器' and
                c['snapshot']['catalog'][-1]['launch']==hex(build['symbols']['native_player_menu_activate']['address']) and
                c['snapshot']['original_entry_visits']['0x6acf3a']==c['snapshot']['original_entry_visits']['0x31649a']==1 and
                c['snapshot']['audio_API_boundary_requests'][0]['registers']==[9,22,11] and
                c['snapshot']['audio_API_boundary_requests'][0]['stack']==[38,0,0] and
                c['snapshot']['audio_API_boundary_requests'][1]['arguments']==[9,0] for c in [empty,growth]),
        'existing_control_entries_preserved_through_native_catalog_growth':
            growth['existing_entries_are_explicit_control_fixtures'] and
            len(growth['catalog_before'])==2 and len(growth['snapshot']['catalog'])==3 and
            growth['snapshot']['catalog'][:2]==growth['catalog_before'] and
            growth['snapshot']['original_entry_visits']['0x6a4d66']==2 and
            growth['snapshot']['original_entry_visits']['0x31592a']==3,
        'duplicate_ID_preserves_original_owner_no_new_audio_or_registration':
            duplicate['snapshot']['state']['registration_result']==2 and
            duplicate['snapshot']['state']['original_result']==11 and
            duplicate['snapshot']['catalog']==duplicate['catalog_before'] and
            duplicate['snapshot']['native_menu_state']==[1,0,0,0,0,0] and
            not duplicate['snapshot']['audio_API_boundary_requests'],
        '54894_code2353914_file2462860_RAM18036_BSS_in_original3MiB_RX_RW':
            build['extension_bytes']==54894 and len(combined)==build['combined_file_bytes']==2353914 and
            build['combined_ram_bytes']==2462860 and build['BSS_bytes']==18036 and
            build['remaining_reservation_bytes']==682868 and
            all(c['load']['original_3MiB_reservation_retained'] for c in rows) and
            not build['unresolved_symbols'] and build['code_RX_data_RW_segments'] and
            not any(t in build['segments'] for t in ['RWE','INTERP','DYNAMIC']),
        'no_MAIN_patch_only_declared_initial_platform_byte_and_guarded_resident_code':
            not build['patch_plan'] and build['VM_MAIN_patch_bytes']==proof['MAIN_patch_bytes']==0 and
            all(c['snapshot']['stock_and_loaded_code_unchanged'] and
                c['snapshot']['all_allocation_guards_intact'] and
                c['snapshot']['declared_platform_fixture_changes']==[{
                    'address':'0x05400000','before':'0x0','fixture':1,
                    'purpose':'Inherited platform active-byte fixture'}] and
                c['snapshot']['outer_files_and_temporary_handles_closed'] and
                c['snapshot']['loaded_module_and_callback_remain_resident'] for c in rows),
        'container_other_members_preserved_SIG_acceptance_unknown':
            build['package_checks']['DLL_blocks_contiguous'] and
            build['package_checks']['all_other_members_byte_identical'] and
            build['package_checks']['changed_members']==['DLLIMG.BIN','DLLINFO.TXT'] and
            not build['package_checks']['signature_algorithm_or_enforcement_verified'] and
            not build['real_package_acceptance_verified'] and not proof['actual_package_acceptance_verified'] and
            'EMULATION-ONLY' in build['package'],
        'frozen17_suites_and_saved_prior14_scope_exact_state':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5,4] and
            prior['all_passed'] and len(prior['scope_checks'])==14 and prior['state_sha256']==sha(previous['state']),
        'isolated214_guard_faults_and_unverified_UI_speaker_physical_App':
            proof['emulator_binding_version']=='2.1.4' and proof['emulator_native_version']==[2,1,33621247] and
            len(proof['guard_fault_controls'])==2 and all(c['passed'] for c in proof['guard_fault_controls']) and
            all(not c['snapshot']['full_Widget_SQL_touch_rendering_executed'] and
                not c['snapshot']['speaker_or_DAC_executed'] and not c['snapshot']['UI_thread_timing_proven'] for c in rows),
        'canonical_task_public31_percent41_details_Taiwan_time_privacy_scope':
            public['deep_research']==state and all(task[k]==state[k] for k in
                ['last_goal_turn','next_actions','attended_testing','latest_user_instruction','ordered_priorities']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==41 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)
                for ident in ['report-updated-time','research-updated-time']) and
            all(t in report for t in ['最新離線進展：原廠載入器接上播放器功能清單','3 個載入整合案例通過',
                '自動登錄功能記錄尚未證明一般菜單已顯示新 App','合成控制資料','這版不改 MAIN',
                '圖示資源目前是空白占位','實機修改包／SIG 接受']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
        'offline_sleeping_scope_physical_observations_and_full_goal_preserved':
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests'] and
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and
            not proof['device_io'] and not proof['sounds_emitted'] and not build['device_install_candidate'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining'],
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':checks,
        'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':sha(item['evidence']),'build_manifest_sha256':sha(proof['build_manifest']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False}
    path='evidence/firmware-analysis/native-player-menu-loaded-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'audit':path,'scopes':len(checks),'all_passed':True}))

if __name__=='__main__':main()
