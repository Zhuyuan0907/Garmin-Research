#!/usr/bin/env python3
"""Current lifecycle/menu research integrity and scope checks."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    state=read('evidence/deep-research-state.json')
    findings=state['native_app_music']['static_findings']
    proofs={k:read(findings[k]['evidence']) for k in ['avdtp_lifecycle','native_music_menu_action']}
    for key,proof in proofs.items():
        assert sha(findings[key]['evidence'])==findings[key]['evidence_sha256']
        for name,value in proof['source_sha256'].items():assert sha(name)==value,name
    lifecycle=proofs['avdtp_lifecycle'];menu=proofs['native_music_menu_action']
    cases={r['name']:r for r in lifecycle['cases']}
    chain=cases['complete_stock_configure_Open_L2CAP_ready_Start_media_chain']['steps']
    ready=next(r for r in chain if r['step']=='local_configuration_confirmation')
    unsafe=cases['rejected_early_Start_can_deliver_media_with_pending_Open']['steps'][-1]
    before=read(state['last_goal_turn']['previous_state_snapshot'])
    prior=read(state['last_goal_turn']['previous_current_audit_snapshot'])
    task=read('evidence/task-state.json');public=read('reports/findings.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    checks={
        'new_source_and_proof_hashes_current':True,
        '16_lifecycle_cases_passed':lifecycle['all_passed'] and lifecycle['case_count']==len(cases)==16 and
            all(r['passed'] and all(r['checks'].values()) for r in cases.values()),
        'stock_ready_store_observed_then_same_VM_streams':ready['state']==4 and ready['pending']==0 and
            any(w['instruction']=='0x524ea4' and w['value']==4 for w in ready['native_SEP_state_writes']) and
            chain[-1]['state']==8 and chain[-1]['pending']==0 and chain[-1]['callbacks'][0]['event']==0xf1,
        'native_resume_reset_retry_duplicate_failure_controls':all(k in cases for k in [
            'Suspend_and_Start_reuse_completed_channel','Disconnect_resets_SEP_then_same_VM_reconnects',
            'remote_configuration_reply_failure_waits_then_retry_completes',
            'connection_reply_send_failure_runs_stock_cleanup','local_configuration_request_send_failure_resets',
            'local_configuration_error_confirmation_resets','duplicate_incoming_media_connection_rejected',
            'duplicate_confirmation_requests_disconnect_then_notification_resets']),
        'unsafe_early_Start_does_not_become_acceptance_proof':unsafe['state']==8 and unsafe['pending']==2 and
            unsafe['callbacks'][0]['status']==0 and bytes.fromhex(unsafe['media_channel_hex'])[5]==2 and
            lifecycle['application_must_fence_pending_channel_readiness_and_session_epoch'],
        'stock_code_globals_RAM_input_guards_retained':all(
            step.get('code_globals_input_RAM_guards_and_stack_intact',step.get('original_code_input_and_RAM_guards_intact',False))
            for row in lifecycle['cases'] for step in row['steps']),
        'registration_and_physical_transport_remain_unproven':
            not lifecycle['actual_SEP_SDP_registration_verified'] and not lifecycle['real_L2CAP_transport_executed'] and
            not lifecycle['phone_speaker_native_App_or_decoder_integration_verified'],
        '7_menu_binding_dispatch_and_ownership_cases_passed':menu['all_passed'] and menu['case_count']==len(menu['cases'])==7 and
            all(row['passed'] and all(row['checks'].values()) for row in menu['cases']),
        'real_member_dispatch_to_slot60_action_with_boundaries':menu['button_binding']['member_pointer_words']==[240,1] and
            menu['button_binding']['virtual_slot']==60 and menu['real_closure_binding_member_dispatch_and_action_executed_offline'] and
            not menu['real_mixer_constructor_or_page_publication_executed'],
        'menu_code_child_RAM_and_stack_guards':all(step['code_and_unallocated_child_storage_unchanged'] and
            step['RAM_guards_and_SP_intact'] for row in menu['cases'] for step in row['steps']),
        'native_widget_event_screen_App_install_not_claimed':not menu['button_binding']['stock_widget_constructor_executed'] and
            not menu['button_binding']['stock_event_queue_executed'] and
            not menu['actual_UI_dispatch_or_screen_execution_verified'] and
            not menu['generic_App_registration_or_install_API_identified'],
        'previous_18_scope_progress_snapshot_preserved':prior['all_passed'] and len(prior['scope_checks'])==18 and
            prior['state_sha256']==sha(state['last_goal_turn']['previous_state_snapshot']) and
            before['last_goal_turn']['classification']=='progress' and not before['last_goal_turn']['device_io'],
        'local_only_no_device_write_or_install_candidate':all(not p['device_io'] and not p['firmware_modified'] and
            not p['device_install_candidate'] for p in proofs.values()) and
            not state['last_goal_turn']['device_io'] and not state['last_goal_turn']['device_files_written'],
        'away_wait_no_autonomous_calls_or_mic_work':state['attended_testing']['waiting_for_user_return'] and
            not state['attended_testing']['user_present'] and
            not state['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            state['microphone_amplifier']['status']=='cancelled_by_user' and not state['microphone_amplifier']['next_actions'],
        'canonical_report_and_task_plan_match':public['deep_research']==state and all(task[k]==state[k] for k in
            ['last_goal_turn','next_actions','ordered_priorities','attended_testing','latest_user_instruction','execution_environment']),
        'progress31_with22_details_and_latest_scope_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])>=22 and all(word in report for word in
            ['16 個離線案例','7 個案例','沒有手動把端點狀態改成就緒','待完成操作與連線世代',
             '按鈕事件佇列和螢幕尚未執行','尚未找到任意自製 App','使用者暫時外出']),
        'priority_music_App_before_AA_and_no_stale_mainline':state['ordered_priorities'][1].startswith('原生音訊') and
            '播放器' in state['ordered_priorities'][2] and 'Android Auto' in state['ordered_priorities'][3] and
            '主線改為 GarminOS 原生 Android Auto' not in report,
        'public_report_no_private_MAC_ESN':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and
            'REDACTED_PRIVATE_ID' not in report,
        'full_goal_active_no_achieve_and_remaining_scope_retained':state['goal_status']=='active' and
            not state['goal_complete'] and state['required_work_remaining'] and
            state['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            state['native_android_auto']['requested'] and state['google_maps']['research_deferred_by_user'] and
            not state['native_app_music']['native_app_running'] and not state['native_app_music']['direct_phone_music_verified'],
    }
    assert all(checks.values()),[k for k,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-lifecycle-menu-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':{findings[k]['evidence']:sha(findings[k]['evidence']) for k in proofs},
        'source_dependency_counts':[len(p['source_sha256']) for p in proofs.values()],
        'previous_checkpoint_snapshot_sha256':sha(state['last_goal_turn']['previous_current_audit_snapshot']),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False,
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'all_passed':True,'scope_checks':len(checks)}))


if __name__=='__main__':main()
