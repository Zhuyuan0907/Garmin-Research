#!/usr/bin/env python3
"""Audit current AVDTP controls/UI mapping without claiming native installation."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
from analyze_native_sections import NativeImage

ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']
    c=read(f['avdtp_control']['evidence']);u=read(f['native_music_ui']['evidence'])
    cap=read(f['avdtp_capabilities']['evidence'])
    for proof in (c,u,cap):
        for p,want in proof['source_sha256'].items():assert sha(p)==want,p
    cases={r['name']:r for r in c['cases']}
    image=NativeImage()
    for table in u['full_vtables']:
        for row in table['slots']:
            assert image.runtime_to_load(int(row['pointer'],16)&~1,2)==int(row['load_address'],16)
    prior=s['last_goal_turn']['previous_current_audit_snapshot'];p=read(prior)
    state_snapshot=s['last_goal_turn']['previous_state_snapshot'];before=read(state_snapshot)
    findings=read('reports/findings.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    config=cases['configure_SBC_uses_original_parser_and_channel_reservation']
    pending=cases['Open_accepts_then_waits_for_real_L2CAP_completion']
    rejected=cases['rejected_Start_still_updates_state_after_successful_send']
    failed=cases['Start_send_failure_does_not_transition']
    checks={
      'new_proof_hashes_and_exact_source_dependencies':all(f[k]['evidence_sha256']==sha(f[k]['evidence'])
          for k in ['avdtp_control','native_music_ui','avdtp_capabilities']),
      '17_fresh_controls_immutable_code_input_guards_stack':c['all_passed'] and len(cases)==c['case_count']==17 and
          all(r['passed'] and r['original_code_input_and_RAM_guards_intact'] and r['stack_and_mutex_restored'] for r in cases.values()),
      'real_stock_parser_and_channel_reservation_offline':config['original_parser_executed'] and
          config['original_channel_reservation_executed'] and config['state']==2 and
          config['native_media_channel_index']==1 and config['negotiated_codec_hex']=='21150235',
      'Open_wait_not_faked_full_connection':pending['state']==2 and pending['pending']==2 and not pending['callbacks'] and
          not c['real_L2CAP_connection_completion_executed'],
      'separate_synthetic_ready_Start_Suspend_cases':cases['Start_from_synthetic_ready_state']['state']==8 and
          cases['Suspend_returns_to_ready_state']['state']==4 and
          cases['Start_from_synthetic_ready_state']['pending']==0,
      'rejected_Start_still_transitions_and_notifies_control':rejected['replies'][0]['wire_hex']=='13070431' and
          rejected['state']==8 and rejected['pending']==2 and rejected['callbacks'][0]['event']==17 and
          rejected['callbacks'][0]['pending_during_callback']==6,
      'send_error_gate_prevents_state_transition':failed['state']==4 and not failed['callbacks'],
      'config_accept_precedes_callback_error_return_not_reject_API':config['event_order']==['send','unlock','callback','lock'] and
          cases['callback_return_error_does_not_reject_already_accepted_config']['callbacks'][0]['callback_return_fixture']==0xdead and
          cases['callback_return_error_does_not_reject_already_accepted_config']['replies'][0]['wire_hex']=='1203',
      'missing_codec_and_other_ID_not_decoder_support':cases['transport_only_config_has_no_codec_but_core_accepts']['state']==2 and
          cases['codec_ID_without_local_decoder_validation_control']['state']==2 and
          not c['native_App_or_physical_phone_or_speaker_verified'],
      'complete_66_57_vtables_and_ten_conditional_code_pointers':
          [t['slot_count'] for t in u['full_vtables']]==[66,57] and
          sum(r['requires_conditional_startup_copy'] for t in u['full_vtables'] for r in t['slots'])==10 and
          all(t['end_has_next_zero_offset_to_top_and_RTTI'] for t in u['full_vtables']),
      'eight_complete_local_CFGs_and_slot60_action':u['bounded_function_count']==8 and
          all(not a['instruction_limit_reached'] and not a['unresolved_exits'] for a in u['functions'].values()) and
          u['audio_settings_action']['vtable_slot']==60 and u['audio_settings_action']['allocation_bytes']==0x258c,
      'UI_static_does_not_claim_live_page_or_generic_App_API':not u['new_App_or_generic_plugin_install_API_identified'] and
          not u['actual_UI_dispatch_or_screen_execution_verified'] and not u['live_conditional_copy_flag_verified'],
      'previous_progress_revalidated_and_attended_IO_historical':p['all_passed'] and len(p['scope_checks'])==14 and
          p['state_sha256']==sha(state_snapshot) and before['last_goal_turn']['device_io'] and
          s['last_goal_turn']['previous_goal_turn_classification']=='progress',
      'current_local_only_no_device_write_install':all(not r['device_io'] and not r['firmware_modified'] and
          not r['device_install_candidate'] for r in [c,u]) and not s['last_goal_turn']['device_io'] and
          not s['last_goal_turn']['device_files_written'],
      'canonical_task_findings_match_plan_mic_cancelled':findings['deep_research']==s and
          read('evidence/task-state.json')['last_goal_turn']==s['last_goal_turn'] and
          read('evidence/task-state.json')['next_actions']==s['next_actions'] and
          s['microphone_amplifier']['status']=='cancelled_by_user' and
          all('microphone' not in a.lower() and '麥克風' not in a for a in s['ordered_priorities']),
      'progress31_twenty_details_report_scope_visible':findings['research_progress']['estimate_percent']==31 and
          len(findings['research_progress']['completed'])>=20 and
          all(t in report for t in ['17 個離線案例','66／57','等待媒體連線','slot 60','尚未找到任意自製 App']),
      'no_private_device_IDs_in_report':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
      'full_scope_retained_active_no_achieve':s['goal_status']=='active' and not s['goal_complete'] and
          s['latest_user_instruction']['goal_completion_forbidden_by_user'] and s['required_work_remaining'] and
          s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
          not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-avdtp-control-ui-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),'source_dependency_counts':[len(x['source_sha256']) for x in (c,u,cap)],
        'proof_sha256':{p:sha(p) for p in [f[k]['evidence'] for k in ['avdtp_control','native_music_ui','avdtp_capabilities']]},
        'previous_validated_checkpoint_snapshot_sha256':sha(prior),'current_turn_device_IO':False,
        'goal_status':'active','full_goal_complete':False,'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'all_passed':True,'scope_checks':len(checks)}))


if __name__=='__main__':main()
