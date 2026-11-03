#!/usr/bin/env python3
"""Audit the new private-menu proof without rerunning frozen audio suites."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re

from analyze_native_sections import ROOT, EXPECTED
from check_native_music_stream_checkpoint import read, sha, artifacts

def main():
    state=read('evidence/deep-research-state.json')
    task=read('evidence/task-state.json')
    public=read('reports/findings.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=state['native_app_music']['static_findings']
    item=findings['native_player_menu'];proof=read(item['evidence'])
    build=read(proof['build_manifest'])
    for path,h in proof['source_sha256'].items(): assert sha(path)==h,path
    for path,h in build['source_sha256'].items(): assert sha(path)==h,path
    previous=read('staging/native-player-menu/previous-checkpoint.json')
    before=read(previous['state']);prior=read(previous['audit'])
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
        'native_voice_outer','native_voice_compatibility','native_music_endpoint',
        'native_music_configuration_gate','native_music_policy','native_music_dispatch',
        'native_l2cap_send','native_music_reply','native_music_loaded','native_music_stream',
        'native_music_runtime','native_music_ready','native_music_continuous']
    counts=[]
    for name in names:
        assert findings[name]==before['native_app_music']['static_findings'][name],name
        old=read(findings[name]['evidence'])
        assert sha(findings[name]['evidence'])==findings[name]['evidence_sha256'],name
        for path,h in old['source_sha256'].items(): assert sha(path)==h,path
        if name in ['native_music_loaded','native_music_stream','native_music_runtime',
                    'native_music_ready','native_music_continuous']:
            assert sha(old['build_manifest'])==old['build_manifest_sha256']
            artifacts(read(old['build_manifest']))
        counts.append(old['case_count'])
    cases={c['name']:c for c in proof['cases']}
    first=cases['original_registry_copy_and_click']
    growth=cases['original_vector_growth_keeps_callbacks']
    reject=cases['wrapper_rejects_duplicate_and_malformed_input']
    bind=cases['original_button_member_bind_copy_and_consumer']
    rows=[first,growth,reject,bind]
    checks={
        'four_complete_cases21_hashed_dependencies_exact_MAIN':
            proof['all_passed'] and proof['case_count']==len(cases)==4 and
            len(proof['source_sha256'])==21 and
            proof['MAIN_sha256']==build['MAIN_sha256']==EXPECTED and all(c['passed'] for c in rows) and
            sha(item['evidence'])==item['evidence_sha256'] and
            sha(proof['build_manifest'])==proof['build_sha256'],
        'freestanding1236_byte_ARMv6_RX_RW_no_dynamic_or_undefined_symbols':
            build['flat_binary_bytes']==(ROOT/build['flat_binary']).stat().st_size==1236 and
            sha(build['flat_binary'])==build['flat_binary_sha256'] and
            sha(build['elf'])==build['elf_sha256'] and not build['undefined_symbols'] and
            'Tag_CPU_arch: v6' in build['attributes'] and ' R E ' in build['segments'] and
            ' RW ' in build['segments'] and not any(t in build['segments'] for t in ['RWE','INTERP','DYNAMIC']),
        'private12_bounded_functions_original_three_instruction_click_ABI':
            len(proof['functions'])==12 and
            all(not f['unresolved_exits'] and not f['instruction_limit_reached']
                for f in proof['functions'].values()) and
            [i['instruction'] for i in proof['functions']['0x31649a']['instructions']]==
                ['ldr r0, [r1, #0x58]','ldr r1, [r1, #0x54]','bx r1'] and
            proof['private_ABI']['record_bytes']==100 and proof['private_ABI']['registry_bytes']==44 and
            proof['private_ABI']['record_launch_offset']==84 and proof['private_ABI']['record_context_offset']==88,
        'original_singleton_record_string_copy_Ch_label_retained':
            first['record']['caption']=='Pi 播放器' and first['caption_survives_input_overwrite'] and
            first['stock_entries_executed']['0x31590a']==1 and
            first['stock_entries_executed']['0x3158c8']==1 and
            first['stock_entries_executed']['0x44f6702']==1 and
            first['stock_entries_executed']['0x31592a']==1 and
            first['record']['launch']==hex(build['symbols']['native_player_menu_activate']['address']) and
            first['native_state']==[1,1,1,0x13528000,1,1],
        'twelve_original_records_five_growths_three_contexts_dispatched':
            growth['records']==12 and growth['activated_indices']==[0,5,11] and
            growth['stock_entries_executed']['0x31592a']==12 and
            growth['stock_entries_executed']['0x6a4d66']==5 and
            growth['native_state']==[12,12,3,0xabc00b,3,3],
        'duplicate_invalid_catalog_wrapper_rejected_without_stock_append':
            reject['no_extra_stock_appends'] and reject['duplicate_result']==2 and
            reject['invalid_result']==1 and reject['native_state']==[7,1,0,0,0,0] and
            reject['stock_entries_executed']['0x31592a']==1 and not reject['audio_requests'],
        'original112_byte_button_member_copy_destroy_and_consumer':
            bind['bind_bytes']==112 and bind['binding_destroyed_catalog_retained'] and
            not bind['full_Widget_touch_chain_executed'] and
            bind['stock_entries_executed']['0x31649a']==1 and
            bind['native_state']==[1,1,1,0x55aa,1,1],
        'five_compiled_activations_reach_explicit_WAV_API_boundaries':
            sum(c['native_state'][2] for c in rows)==5 and
            sum(len(c['audio_requests']) for c in rows)==10 and
            all(all(r['operation']=='register' and r['registers']==[9,22,11] and
                    r['stack']==[38,0,0] and r['path']=='0:/Garmin/test.wav'
                    for r in c['audio_requests'][::2]) and
                all(r['operation']=='start' and r['arguments']==[9,0]
                    for r in c['audio_requests'][1::2]) for c in rows),
        'allocation_guards_original_ROM_and_RX_unchanged_fixtures_declared':
            all(c['all_allocation_guards_intact'] and c['RX_code_unchanged'] and
                c['all_original_code_regions_unchanged'] and
                c['allocation_services_are_fixtures'] and c['audio_API_boundaries_are_fixtures'] for c in rows) and
            [c['live_resident_allocations'] for c in rows]==[3,14,3,3],
        'isolated214_emulator_independent_guard_read_write_faults':
            proof['emulator_binding_version']=='2.1.4' and
            proof['emulator_native_version']==[2,1,33621247] and
            len(proof['guard_fault_controls'])==2 and all(c['passed'] for c in proof['guard_fault_controls']),
        'frozen16_suites_and_exact_prior_attended19_scope_state':
            counts==[10,2,6,12,15,29,189,208,18,10,112,8,21,9,14,5] and
            prior['all_passed'] and len(prior['scope_checks'])==19 and
            prior['state_sha256']==sha(previous['state']) and
            before['attended_testing']['user_present'] and before['last_goal_turn']['device_io'],
        'physical_WAV_observations_preserved_separate_from_new_offline_unit':
            state['audio']['native_WAV_tests']==before['audio']['native_WAV_tests'] and
            state['audio']['native_WAV_tests'][0]['speaker_confirmed'] and
            not state['audio']['native_WAV_tests'][1]['all_test_segments_confirmed'] and
            all(sha(t['physical_evidence'])==t['physical_evidence_sha256'] and
                sha(t['installation_evidence'])==t['installation_evidence_sha256']
                for t in state['audio']['native_WAV_tests']),
        'canonical_task_public31_percent40_items_times_privacy_scope':
            public['deep_research']==state and all(task[k]==state[k] for k in
                ['last_goal_turn','next_actions','attended_testing','latest_user_instruction',
                 'ordered_priorities','current_priority']) and
            public['research_progress']['estimate_percent']==31 and len(public['research_progress']['completed'])==40 and
            all(re.search('<time id="'+ident+'" datetime="[^\"]+\\+08:00"',report)
                for ident in ['report-updated-time','research-updated-time']) and
            all(t in report for t in ['最新離線進展：自製播放器的菜單回呼已接通','4 個菜單入口案例通過',
                '實機一般菜單顯示、觸控及 App 載入仍待完成','圖示資源是空白占位',
                '沒有執行 WAV 解碼、DAC 或喇叭','使用者目前不在現場','聲道與音質精修擱置']) and
            'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
        'sleeping_user_no_device_io_sound_or_install_goals_unchanged':
            not state['attended_testing']['user_present'] and state['attended_testing']['waiting_for_user_return'] and
            state['attended_testing']['no_pending_question'] and state['user_resting'] and task['user_away'] and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'] and
            not state['last_goal_turn']['automatic_calls_or_sound'] and not proof['sounds_emitted'] and
            not proof['device_io'] and not build['device_io'] and not proof['native_App_installed'] and
            not proof['rendered_or_touchable_menu_icon'] and not proof['accepted_module_loading'] and
            not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['latest_user_instruction']['stereo_or_fidelity_tuning_deprioritized'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            state['goal_status']=='active' and not state['goal_complete'] and state['required_work_remaining'],
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    path='evidence/firmware-analysis/native-player-menu-checkpoint-audit.json'
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,
        'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),'proof_sha256':sha(item['evidence']),
        'build_manifest_sha256':sha(proof['build_manifest']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False}
    (ROOT/path).write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'audit':path,'scope_checks':len(checks),'all_passed':True}))

if __name__=='__main__':main()
