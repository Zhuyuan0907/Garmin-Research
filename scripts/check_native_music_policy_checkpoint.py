#!/usr/bin/env python3
"""Check compiled policy evidence, canonical scope and previous checkpoint."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']['native_music_policy']
    p=read(f['evidence']);build=read(f['manifest']);cases={r['name']:r for r in p['cases']}
    for name,h in {**build['source_sha256'],**p['source_sha256']}.items():assert sha(name)==h,name
    assert p['build_source_sha256']==build['source_sha256']
    assert sha(build['flat'])==build['flat_sha256'] and sha(build['elf'])==build['elf_sha256']
    before=read(s['last_goal_turn']['previous_state_snapshot']);prior=read(s['last_goal_turn']['previous_current_audit_snapshot'])
    task=read('evidence/task-state.json');public=read('reports/findings.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    normal=cases['real_stock_lifecycle_view_allows_registered_fixture_stream']
    fenced=cases['compiled_gate_rejects_stock_success_media_with_pending_Open']
    checks={
        'proof_and_build_hash_dependencies_current':sha(f['evidence'])==f['evidence_sha256'],
        'compiled_ARMv6_softfloat_no_unresolved_Linux_runtime':build['flat_bytes']==p['compiled_policy_code_bytes']==2151 and
            not build['unresolved_symbols'] and not build['Linux_runtime_dependencies'] and 'Tag_CPU_arch: v6' in build['attributes'],
        '208_fresh_executable_cases_passed':p['all_passed'] and len(cases)==p['case_count']==208 and
            all(c['passed'] and c['actual_return']==c['expected_return'] for c in cases.values()),
        '128_supported_configuration_matrix_and_36_20_48_ABI':p['valid_SBC_configuration_matrix']==128 and
            len([k for k in cases if k.startswith('valid_') and k!='valid_service_order_reversed'])==128 and
            p['config_guard_view_bytes']==[36,20,48],
        'unsupported_codec_missing_or_ambiguous_configuration_fenced':all(cases[k]['actual_return']<0 and
            cases[k]['rejection_leaves_output_unchanged'] and cases[k]['stock_accept_handler_not_called'] for k in
            ['transport_only','AAC_ID_with_SBC_bytes','duplicate_codec','multiple_frequencies','content_protection_unsupported']),
        'normal_stock_ready_view_and_early_Start_success_callback_distinguished':normal['actual_return']==0 and
            normal['native_view'][:2]==[8,0] and fenced['actual_return']==-17 and
            fenced['native_view'][:2]==[8,2] and fenced['stock_steps'][-1]['callbacks'][0]['status']==0,
        'local_receive_MTU_not_peer_receive_MTU':cases['local_receive_MTU_boundary_672']['actual_return']==0 and
            all(cases['local_receive_MTU_boundary_'+str(n)]['actual_return']==-19 for n in [673,1008]) and
            cases['local_receive_MTU_boundary_1008']['peer_receive_MTU']==1008 and
            cases['local_receive_MTU_boundary_1008']['local_receive_MTU']==672,
        'captured_sessions_inactive_wrap_and_LCID_reconnect_checked':all(k in cases for k in
            ['session_binding_busy_stale_and_monotonic_rebind','session_exhaustion_no_wrap_to1',
             'inactive_guard_rejects_otherwise_ready_stock_view','same_LCID_reconnect_new_session_rejects_captured_old_epoch',
             'stale_session_frame_rejected']),
        'frame_format_length_and_narrow_bitpool_bounds_checked':cases['narrow_negotiated_bitpool_19']['actual_return']==-14 and
            cases['narrow_negotiated_bitpool_31']['actual_return']==-14 and
            cases['narrow_negotiated_bitpool_20']['actual_return']>0 and cases['narrow_negotiated_bitpool_30']['actual_return']>0 and
            cases['SBC_frame_truncated_frame']['actual_return']==-19,
        'immutable_code_inputs_metadata_guards_stack_all_calls':all(call['code_input_metadata_guards_and_stack_intact']
            for row in cases.values() for call in row['policy_calls']),
        'prototype_driver_not_native_hook_or_CRC_decoder':p['prevalidation_fixture_driver_not_real_native_hook'] and
            not p['native_preaccept_hook_or_real_SDP_SEP_registration_verified'] and
            not p['CRC_RTP_fragment_jitter_decoder_integration_verified'] and not p['physical_decoder_speaker_UI_or_phone_verified'],
        'previous_19_scope_progress_state_snapshot_preserved':prior['all_passed'] and len(prior['scope_checks'])==19 and
            prior['state_sha256']==sha(s['last_goal_turn']['previous_state_snapshot']) and before['last_goal_turn']['classification']=='progress',
        'no_device_IO_modification_or_install_candidate':not p['device_io'] and not p['firmware_modified'] and
            not p['device_install_candidate'] and not build['device_install_candidate'] and
            not s['last_goal_turn']['device_io'] and not s['last_goal_turn']['device_files_written'],
        'canonical_findings_task_plan_match':public['deep_research']==s and all(task[k]==s[k] for k in
            ['last_goal_turn','next_actions','latest_user_instruction','attended_testing','ordered_priorities']),
        'user_away_offline_wait_and_mic_cancelled':s['attended_testing']['waiting_for_user_return'] and
            not s['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            s['microphone_amplifier']['status']=='cancelled_by_user' and not s['microphone_amplifier']['next_actions'],
        'progress31_23_details_and_prototype_limits_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])>=23 and all(t in report for t in
            ['208 個離線案例','128 種支援','2151 bytes','本機接收上限','仍須由解碼器驗證 CRC','尚未掛入原廠設定接受入口']),
        'no_private_MAC_or_ESN_in_report':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
        'full_goal_active_no_achieve_music_App_AA_Maps_scope_retained':s['goal_status']=='active' and not s['goal_complete'] and
            s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
            not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
    }
    assert all(checks.values()),[k for k,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-music-policy-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),'proof_sha256':{f['evidence']:sha(f['evidence'])},
        'execution_dependencies':len(p['source_sha256']),'build_dependencies':len(build['source_sha256']),
        'previous_checkpoint_snapshot_sha256':sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False,
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'all_passed':True,'scope_checks':len(checks)}))


if __name__=='__main__':main()
