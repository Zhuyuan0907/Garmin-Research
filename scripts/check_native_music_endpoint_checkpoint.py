#!/usr/bin/env python3
"""Audit compiled endpoint evidence and distinguish it from installation."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']['native_music_endpoint']
    p=read(f['evidence']);b=read(f['manifest']);cases={r['name']:r for r in p['cases']}
    for path,h in {**b['source_sha256'],**p['source_sha256']}.items():assert sha(path)==h,path
    assert b['source_sha256']==p['build_source_sha256']
    prior=read(s['last_goal_turn']['previous_current_audit_snapshot'])
    before=read(s['last_goal_turn']['previous_state_snapshot'])
    previous=[]
    for key in ['native_music_configuration_gate','native_music_policy']:
        old=s['native_app_music']['static_findings'][key]
        assert old==before['native_app_music']['static_findings'][key]
        op=read(old['evidence']);ob=read(old['manifest'])
        assert sha(old['evidence'])==old['evidence_sha256']
        assert sha(ob['flat'])==ob['flat_sha256'] and sha(ob['elf'])==ob['elf_sha256']
        for path,h in {**ob['source_sha256'],**op['source_sha256']}.items():assert sha(path)==h,path
        previous.append(op['case_count'])
    first=cases['original_boot_compiled_endpoint_stock_SDP_Discover_and_capabilities']
    life=cases['compiled_registration_gate_original_media_lifecycle_and_reconfiguration']
    unlock=cases['SDP_unlock_failure_records_uncertain_publication_no_rollback']['calls'][-1]
    prepare_unlock=cases['prepare_unlock_failure_keeps_endpoint_and_owner_pinned']['calls'][-1]
    public=read('reports/findings.json');task=read('evidence/task-state.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    checks={
        'current_all_dependencies_and_artifacts_hashes_match':sha(f['evidence'])==f['evidence_sha256'] and
            sha(b['flat'])==b['flat_sha256'] and sha(b['elf'])==b['elf_sha256'],
        'compiled_ARMv6_softfloat5075_RX_code28_RW_BSS_no_Linux_imports':b['flat_bytes']==p['compiled_code_bytes']==5075 and
            b['BSS_bytes']==p['BSS_bytes']==28 and b['code_RX_BSS_RW_separate_pages'] and
            'Tag_CPU_arch: v6' in b['attributes'] and not b['unresolved_symbols'] and not b['Linux_runtime_dependencies'],
        '29_fresh_executable_cases_passed':p['all_passed'] and p['case_count']==len(cases)==29 and
            all(r['passed'] and all(r['checks'].values()) for r in cases.values()),
        'original_boot_without_registered_SEP_then_compiled_creation':first['checks']['boot_has_no_registered_SEP'] and
            first['checks']['compiled_provider_creates_SEID1'] and
            all(r['boot_steps'][1]['state']==0 for r in cases.values()) and
            p['SEP_descriptors_created_by_compiled_provider_not_registered_SEP_starting_fixture'],
        'stock_SDP_activate_and_actual_attribute_read_return_AudioSink':first['checks']['original_SDP_enable_only_at_publication'] and
            first['checks']['inactive_SDP_query_fails_before_publication'] and
            first['calls'][-1]['attribute_bytes']=='350319110b' and first['calls'][-1]['return_value']==0,
        'stock_Discover_and_caps_consume_compiled_module_data':first['checks']['stock_Discover_consumes_created_endpoint'] and
            first['checks']['stock_capabilities_read_module_static_SBC'],
        'stock_fixed_HeaderCompression_offer_removed_only_for_owned_SEP':first['checks'][
            'fixed_stock_HeaderCompression_offer_removed_only_for_owned_endpoint'] and
            p['owned_capability_dispatch_removes_fixed_stock_HeaderCompression_offer'] and
            cases['normal_unowned_GetCapabilities_keeps_original_policy_and_wire']['checks']['unchanged_original_offer'] and
            cases['owned_GetConfiguration_delegates_selected_codec_to_stock']['checks']['stock_handler_and_selected_bytes'],
        'exact_stock_serializer_six_argument_ABI_third_SEP_transaction15':cases[
            'third_owned_endpoint_transaction15_and_six_argument_serializer_ABI']['calls'][-1][
                'native_serializer_six_argument_ABI']==[[15,2,0x11,0,2,0]],
        'created_endpoint_gate_original_ready_media_disconnect_reconfigure':all(life['checks'].values()) and
            any(r.get('original_ready_helper_executed') for r in life['stock_lifecycle']) and
            any(r.get('original_reset_executed') for r in life['stock_lifecycle']) and
            cases['compiled_registration_already_claims_preaccept_gate']['checks']['reject_before_original_config'],
        'foreign_entries_full_pool_duplicate_and_claim_rollback_checked':all(k in cases for k in
            ['three_compiled_endpoints_and_full_pool','foreign_active_endpoint_preserved_choose_next_slot',
             'foreign_descriptor_pointer_not_overwritten','duplicate_callback_owner_not_allocated_twice',
             'gate_claim_failure_restores_complete_prior_endpoint_and_descriptor']),
        'lock_failures_unmodified_retry_and_no_nested_locks':first['checks']['provider_publication_does_not_nest_mutexes'] and
            all(cases[k]['checks'][n] for k,n in [
                ('prepare_lock_failure_no_registration','fails_without_writes'),
                ('SDP_lock_failure_keeps_prepared_endpoint_then_retry_publishes','retry_after_lock_failure')]),
        'unlock_failure_retains_registration_or_enabled_record_and_uncertainty':unlock['return_value']==0x2504 and
            unlock['SDP_audio_sink_active']==1 and unlock['publication_state']==2 and unlock['mutex_held_on_return'] and
            prepare_unlock['return_value']==-38 and prepare_unlock['state']==1 and prepare_unlock['mutex_held_on_return'],
        'capability_invalid_owner_length_reserved_state_allocation_rejected':all(k in cases for k in
            ['stale_owned_capability_callback_fails_closed','stale_owned_capability_descriptor_fails_closed',
             'owned_capability_length2_native_reject','owned_capability_reserved_bits_native_reject',
             'owned_capability_inactive_state_rejected','owned_capability_allocator_failure_native_reject']),
        'code_data_input_BSS_heap_RAM_SDP_guards_SP_saved_registers_all_calls':all(call[
            'compiled_stock_code_initialized_data_input_BSS_heap_core_SDP_guards_SP_saved_registers_intact']
            for row in cases.values() for call in row['calls']),
        'custom_provider_not_recovered_API_installed_dispatcher_kernel_radio_or_App':not p['original_endpoint_registration_API_recovered'] and
            not p['dispatcher_installed_or_real_radio_endpoint_verified'] and
            not p['actual_kernel_mutex_PSM_registration_or_signaling_connection_verified'] and
            not p['App_menu_loader_module_unload_decoder_DAC_phone_speaker_verified'],
        'previous189_gate208_policy_artifacts_proofs_and_sources_preserved':previous==[189,208],
        'previous21_scope_checkpoint_and_progress_state_saved':prior['all_passed'] and len(prior['scope_checks'])==21 and
            prior['state_sha256']==sha(s['last_goal_turn']['previous_state_snapshot']) and before['last_goal_turn']['classification']=='progress',
        'state_task_findings_and_plan_match':public['deep_research']==s and all(task[k]==s[k] for k in
            ['last_goal_turn','next_actions','latest_user_instruction','attended_testing','ordered_priorities']),
        'report31_25_details_time_and_prototype_limits_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])==25 and all(t in report for t in
            ['29 個離線案例','5075 bytes','28 bytes','HeaderCompression','未裝到 Garmin','目前沒有卸載／取消註冊流程']) and
            all(re.search('<time id="'+id+'" datetime="[^"]+\\+08:00"',report) for id in
                ['report-updated-time','research-updated-time']),
        'user_away_mic_cancelled_no_device_IO_or_pending_test':s['attended_testing']['waiting_for_user_return'] and
            not s['attended_testing']['user_present'] and not s['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            s['attended_testing']['next_attended_test_not_requested_yet'] and s['microphone_amplifier']['status']=='cancelled_by_user' and
            not s['microphone_amplifier']['next_actions'] and not p['device_io'] and not p['firmware_modified'] and
            not p['device_install_candidate'] and not s['last_goal_turn']['device_io'] and not s['last_goal_turn']['device_files_written'],
        'full_goal_active_no_achieve_AA_retained_and_Maps_deferred':s['goal_status']=='active' and not s['goal_complete'] and
            s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
            not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
        'no_private_device_MAC_or_ESN_in_public_report':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
    }
    assert all(checks.values()),[k for k,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-music-endpoint-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,
        'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':{f['evidence']:sha(f['evidence'])},'execution_dependencies':len(p['source_sha256']),
        'build_dependencies':len(b['source_sha256']),'previous_checkpoint_snapshot_sha256':sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'current_turn_device_IO':False,'goal_status':'active','full_goal_complete':False,
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
