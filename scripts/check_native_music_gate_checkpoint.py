#!/usr/bin/env python3
"""Verify fresh gate proof, frozen prior policy, public scope and active goal."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json')
    f=s['native_app_music']['static_findings']['native_music_configuration_gate']
    p=read(f['evidence']);b=read(f['manifest']);cases={r['name']:r for r in p['cases']}
    for path,h in {**b['source_sha256'],**p['source_sha256']}.items():assert sha(path)==h,path
    assert p['build_source_sha256']==b['source_sha256']
    old=s['native_app_music']['static_findings']['native_music_policy']
    op=read(old['evidence']);ob=read(old['manifest'])
    for path,h in {**ob['source_sha256'],**op['source_sha256']}.items():assert sha(path)==h,path
    before=read(s['last_goal_turn']['previous_state_snapshot'])
    prior=read(s['last_goal_turn']['previous_current_audit_snapshot'])
    task=read('evidence/task-state.json');public=read('reports/findings.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    partial=cases['stock_accept_send_failure_leaves_configured_state_not_rolled_back']['gate_calls'][-1]
    lifecycle=cases['compiled_preaccept_wrapper_full_stock_lifecycle_then_idle_release']
    reference=read('sources/music-policy-reference/manifest.json')
    checks={
        'current_build_proof_and_all_source_hashes_match':sha(f['evidence'])==f['evidence_sha256'] and
            sha(b['flat'])==b['flat_sha256'] and sha(b['elf'])==b['elf_sha256'],
        'ARMv6_softfloat_freestanding3527_RX_code_separate12_RW_BSS':b['flat_bytes']==p['compiled_code_bytes']==3527 and
            b['binding_bytes']==p['binding_bytes']==12 and b['code_RX_BSS_RW_separate_pages'] and
            'Tag_CPU_arch: v6' in b['attributes'] and 'RWE' not in b['segments'] and
            not b['unresolved_symbols'] and not b['Linux_runtime_dependencies'],
        '189_fresh_cases_and128_supported_formats_passed':p['all_passed'] and p['case_count']==len(cases)==189 and
            p['valid_SBC_matrix']==len([k for k in cases if re.fullmatch('supported_[0-9a-f]{2}_[0-9a-f]{2}',k)])==128 and
            all(r['passed'] and all(r['checks'].values()) for r in cases.values()),
        'native_reject_before_accept_or_stock_state_allocation':all(cases[k]['checks']['no_callbacks_channel_reservation_or_SEP_state_change'] and
            cases[k]['gate_calls'][-1]['original_reply_helper_executed'] and
            not cases[k]['gate_calls'][-1]['original_config_handler_executed'] for k in
            ['AAC_ID_rejected_before_stock_accept','transport_only_rejected_before_stock_accept',
             'duplicate_codec','truncated_codec','ambiguous_frequency','advertised_frequency_subset_enforced',
             'advertised_bitpool_subset_enforced']),
        'exact_original_handler_and_reply_five_argument_ABI':b['stock_configuration_handler']==0x574acc and
            b['stock_reply_helper']==0x5756ac and
            cases['native_reject_transaction15_exact_five_argument_ABI']['gate_calls'][-1]['native_entry_ABI']==
                [{'entry':'0x5756ac','args':[0,15,3,7,0x29]}] and
            cases['service_order_and_transaction15_preserved']['gate_calls'][-1]['replies'][0]['wire_hex']=='f203',
        'normal_unclaimed_SEP_and_Reconfigure_match_stock':all(all(cases[k]['checks'].values()) for k in
            ['unclaimed_second_SEP_preserves_normal_stock_behavior',
             'unclaimed_Reconfigure_preserves_stock_accept_and_callback21',
             'unclaimed_codec_keeps_stock_policy_not_global_replacement']),
        'same_VM_compiled_gate_native_completion_stream_reset_release':all(lifecycle['checks'].values()) and
            any(r.get('original_ready_helper_executed') for r in lifecycle['stock_steps']) and
            any(r.get('original_reset_executed') for r in lifecycle['stock_steps']),
        'ownership_role_busy_and_idle_claim_release_checked':all(k in cases for k in
            ['changed_callback_owner_drops_without_foreign_callback','changed_descriptor_role_drops_claimed_configuration',
             'claim_rejects_source_role','claim_rejects_null_capability','claim_rejects_nonidle',
             'claim_rejects_pending','double_claim_wrong_release_and_idle_release']),
        'stock_accept_send_failure_partial_state_not_hidden_as_success':partial['state']==2 and
            partial['return_value']==0 and not partial['callbacks'] and not partial['stock_pool_unchanged'] and
            p['original_accept_send_failure_can_leave_state2_without_callback_and_return0'],
        'reject_send_failure_does_not_modify_stock_pool':cases['reject_send_failure_propagates_without_state_change']['gate_calls'][-1]['return_value']==0x2930 and
            cases['reject_send_failure_propagates_without_state_change']['gate_calls'][-1]['stock_pool_unchanged'],
        'all_gate_calls_code_inputs_caps_BSS_stack_register_guards':all(call[
            'compiled_gate_stock_code_inputs_capabilities_BSS_guards_stack_and_saved_registers_intact']
            for row in cases.values() for call in row['gate_calls']),
        'claimed_Reconfigure_unsupported_and_real_bindings_unproven':p['claimed_Reconfigure_deliberately_unsupported'] and
            p['compiled_wrapper_invoked_by_fixture_not_installed_dispatcher'] and
            not p['real_SEP_SDP_registration_or_pointer_allocator_verified'] and
            not p['real_mutex_scheduling_module_pin_unload_or_media_hook_verified'] and
            b['pointer_allocation_lifetime_lock_and_ownership_are_caller_obligations'],
        'frozen208_policy_proof_source_and_artifacts_preserved':old==before['native_app_music']['static_findings']['native_music_policy'] and
            sha(old['evidence'])==old['evidence_sha256'] and op['case_count']==208 and
            sha(ob['flat'])==ob['flat_sha256'] and sha(ob['elf'])==ob['elf_sha256'],
        'previous18_scope_progress_checkpoint_and_state_saved':prior['all_passed'] and len(prior['scope_checks'])==18 and
            prior['state_sha256']==sha(s['last_goal_turn']['previous_state_snapshot']) and
            before['last_goal_turn']['classification']=='progress',
        'official_constants_source_pinned_and_not_Garmin_registration_assumption':reference['commit']=='665f35180ff20ceb994f857bd11f1b31742faf80' and
            reference['sha256']==sha('sources/music-policy-reference/bluez-avdtp.h') and
            reference['commit'] in report,
        'canonical_state_findings_and_task_plan_synchronized':public['deep_research']==s and all(task[k]==s[k] for k in
            ['last_goal_turn','next_actions','latest_user_instruction','attended_testing','ordered_priorities']),
        '31_percent24_details_Taiwan_times_and_limits_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])==24 and
            all(t in report for t in ['189 個離線案例','3527 bytes','尚未安裝原生派送掛接','沒有回呼','Reconfigure']) and
            all(re.search('<time id="'+id+'" datetime="[^"]+\\+08:00"',report) for id in
                ['report-updated-time','research-updated-time']),
        'user_away_no_pending_physical_test_mic_cancelled':s['attended_testing']['waiting_for_user_return'] and
            not s['attended_testing']['user_present'] and not s['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            s['attended_testing']['next_attended_test_not_requested_yet'] and
            s['microphone_amplifier']['status']=='cancelled_by_user' and not s['microphone_amplifier']['next_actions'],
        'no_device_IO_install_phone_App_or_new_speaker_claim':not p['device_io'] and not p['firmware_modified'] and
            not p['device_install_candidate'] and not b['device_install_candidate'] and
            not p['phone_speaker_DAC_native_App_or_UI_verified'] and not s['last_goal_turn']['device_io'] and
            not s['last_goal_turn']['device_files_written'],
        'full_goal_active_no_achieve_AA_and_deferred_Maps_retained':s['goal_status']=='active' and not s['goal_complete'] and
            s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
            not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
        'public_report_no_private_device_MAC_or_ESN':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and
            'REDACTED_PRIVATE_ID' not in report,
    }
    assert all(checks.values()),[k for k,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-music-gate-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
        'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),'proof_sha256':{f['evidence']:sha(f['evidence']),old['evidence']:sha(old['evidence'])},
        'execution_dependencies':len(p['source_sha256']),'build_dependencies':len(b['source_sha256']),
        'previous_checkpoint_snapshot_sha256':sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False,
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
