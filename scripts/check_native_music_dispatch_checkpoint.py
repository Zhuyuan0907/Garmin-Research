#!/usr/bin/env python3
"""Check wire-driven native dispatch proof and explicitly VM-only scope."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']['native_music_dispatch']
    p=read(f['evidence']);build=read(f['component_manifest']);plan=read(f['patch_plan'])
    cases={r['name']:r for r in p['cases']}
    for path,h in {**build['source_sha256'],**p['source_sha256']}.items():assert sha(path)==h,path
    assert p['build_source_sha256']==build['source_sha256']
    before=read(s['last_goal_turn']['previous_state_snapshot']);prior=read(s['last_goal_turn']['previous_current_audit_snapshot'])
    previous=[]
    for key in ['native_music_endpoint','native_music_configuration_gate','native_music_policy']:
        old=s['native_app_music']['static_findings'][key];assert old==before['native_app_music']['static_findings'][key]
        op=read(old['evidence']);ob=read(old['manifest']);assert sha(old['evidence'])==old['evidence_sha256']
        assert sha(ob['flat'])==ob['flat_sha256'] and sha(ob['elf'])==ob['elf_sha256']
        for path,h in {**ob['source_sha256'],**op['source_sha256']}.items():assert sha(path)==h,path
        previous.append(op['case_count'])
    cap=cases['native_received_capability_routes_through_bound_ARM_entry']
    cfg=cases['full_length_patch_fences_native_uint8_prefix_acceptance']
    invalid=cases['range_patch_rejects_signal11_before_ASCII_table_overread']
    public=read('reports/findings.json');task=read('evidence/task-state.json');report=(ROOT/'reports/nuvi2565RT.html').read_text()
    reference=read('sources/music-policy-reference/avdtp-message-reference.json')
    checks={
        'proof_build_source_dependencies_and_artifacts_current':sha(f['evidence'])==f['evidence_sha256'] and
            sha(build['flat'])==build['flat_sha256'] and sha(build['elf'])==build['elf_sha256'],
        '18_fresh_cases_all_passed':p['all_passed'] and p['case_count']==len(cases)==18 and
            all(row['passed'] and all(row['checks'].values()) for row in cases.values()),
        'original_L2CAP_parser_native_BX_select_compiled_entries':cap['checks']['original_receive_dispatch_and_BX_all_execute'] and
            p['native_L2CAP_wire_parser_fragment_reassembly_and_indirect_dispatch_executed'] and
            p['bound_entries_selected_by_native_table_not_per_message_Python'],
        'native_received_caps_and_bad_codec_baselines_change_behavior':cap['checks']['stock_offer_contains_HeaderCompression'] and
            cap['checks']['bound_entry_offer_supported_subset_only'] and
            cases['native_received_AAC_ID_rejects_before_original_config_accept']['checks']['baseline_core_accept'] and
            cases['native_received_AAC_ID_rejects_before_original_config_accept']['checks']['patched_table_reject'],
        'same_VM_wire_Config_Open_Start_suspend_disconnect_reconfigure':all(cases[
            'native_wire_config_Open_Start_suspend_reconnect_same_VM']['checks'].values()),
        'stock_uint8_length12_from268_then_full268_reject_verified':cfg['extra']['table_only_control'][
            'native_compiled_dispatch_entries'][0]['args'][-1]==12 and cfg['calls'][-1][
            'native_compiled_dispatch_entries'][0]['args'][-1]==268 and
            cfg['calls'][-1]['state']==1 and not cfg['calls'][-1]['callbacks'],
        'capability257_wrap1_and_full_length_rejection_verified':all(cases[
            'full_length_patch_fences_capability_uint8_prefix_acceptance']['checks'].values()),
        'native_fragment_reassembly_gate_borrowed_callback_heap_freed':all(cases[
            'stock_two_fragment_reassembly_invokes_bound_configuration_gate']['checks'].values()) and
            cases['stock_two_fragment_reassembly_invokes_bound_configuration_gate']['calls'][-1]['callbacks'][0][
                'payload_backing']=='native_signaling_reassembly_heap',
        'transaction_mismatch_short_packet_and_transaction15_checked':all(k in cases for k in
            ['fragment_transaction_mismatch_rejected_by_original_parser','one_byte_packet_dropped_before_handler_payload_read',
             'wire_transaction15_capability_preserved']) and
            cases['fragment_transaction_mismatch_rejected_by_original_parser']['calls'][-1]['replies'][0]['wire_hex']=='23030001',
        'signal11_ASCII5046485B_stopped_before_BX_range_variant_prevents_read':invalid['extra']['stock_invalid_branch']==
            {'veneer':'0x427588','target':'0x5046485b','PC_before_branch':'0x427588'} and
            invalid['checks']['patched_never_reads_outside_table'] and invalid['extra']['stock_table_entries']==10,
        'six_declared_sites22bytes_vm_only_patch_recipe':len(plan['patches'])==6 and
            sum(len(bytes.fromhex(r['replacement'])) for r in plan['patches'])==22 and plan['patch_fields_bytes']==22 and
            {r['address']:r['replacement'] for r in plan['patches'] if r['address'].startswith('0x524')}==
                {'0x5249f8':'0200c046','0x5248fc':'0a28'},
        'expected_variant_immutable_globals_inputs_BSS_RAM_heap_SDP_stack_guards':all(call[
            'compiled_stock_code_initialized_data_input_BSS_heap_core_SDP_guards_SP_saved_registers_intact']
            for row in cases.values() for call in row['calls']),
        '484_byte_CB179C_vector_source_is_not_free_code_gap':p['vector_load_span_not_free_insertion_gap']['load_start']==0xcb179c and
            p['vector_load_span_not_free_insertion_gap']['runtime_start']==0xffff0000 and
            p['vector_load_span_not_free_insertion_gap']['size']==484,
        'unknown_reply1000_modern_format_and_send_path_explicitly_unresolved':p[
            'stock_unknown_reply_1000_captured_modern_reject_format_unresolved'] and
            invalid['calls'][-1]['replies'][0]['wire_hex']=='1000' and
            reference['sha256']==sha('sources/music-policy-reference/bluez-avdtp.c') and reference['commit'] in report,
        'no_real_allocator_loader_App_media_policy_or_full_legacy_regression_claim':p[
            'component_link_address_is_synthetic_no_device_allocation'] and p['media_policy_decoder_callback_still_unbound'] and
            p['all_legacy_handlers_large_body_regression_not_verified'] and
            not p['accepted_loader_real_scheduling_UI_phone_or_speaker_verified'],
        'previous29_endpoint189_gate208_policy_proofs_artifacts_preserved':previous==[29,189,208],
        'previous22_scope_checkpoint_state_snapshot_preserved':prior['all_passed'] and len(prior['scope_checks'])==22 and
            prior['state_sha256']==sha(s['last_goal_turn']['previous_state_snapshot']) and before['last_goal_turn']['classification']=='progress',
        'canonical_findings_task_plan_match':public['deep_research']==s and all(task[k]==s[k] for k in
            ['last_goal_turn','next_actions','latest_user_instruction','attended_testing','ordered_priorities']),
        'report31_26_details_time_and_VM_limits_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])==26 and all(t in report for t in
                ['18 個離線案例','22 bytes','8 位元','256 bytes','484 bytes','不是可刷入版本','1000']) and
            all(re.search('<time id="'+id+'" datetime="[^"]+\\+08:00"',report) for id in
                ['report-updated-time','research-updated-time']),
        'user_away_no_hardware_IO_or_physical_question_mic_cancelled':s['attended_testing']['waiting_for_user_return'] and
            not s['attended_testing']['user_present'] and not s['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            s['attended_testing']['next_attended_test_not_requested_yet'] and
            s['microphone_amplifier']['status']=='cancelled_by_user' and not s['microphone_amplifier']['next_actions'] and
            not p['device_io'] and not s['last_goal_turn']['device_io'] and not s['last_goal_turn']['device_files_written'],
        'VM_variant_modified_but_backup_device_unchanged_no_install_candidate':p['VM_firmware_copy_modified'] and
            not p['backup_firmware_modified'] and not p['device_firmware_modified'] and not p['device_install_candidate'] and
            not plan['device_install_candidate'] and plan['component_link_address_is_synthetic'],
        'full_goal_active_AA_scope_Maps_deferred_no_achieve':s['goal_status']=='active' and not s['goal_complete'] and
            s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
            not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
        'no_private_MAC_or_ESN_in_report':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
    }
    assert all(checks.values()),[k for k,ok in checks.items() if not ok]
    target='evidence/firmware-analysis/native-music-dispatch-checkpoint-audit.json'
    (ROOT/target).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,
        'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':{f['evidence']:sha(f['evidence'])},'execution_dependencies':len(p['source_sha256']),
        'previous_checkpoint_snapshot_sha256':sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'current_turn_device_IO':False,'VM_firmware_copy_modified':True,'device_firmware_modified':False,
        'goal_status':'active','full_goal_complete':False,'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT)))},indent=2)+'\n')
    print(json.dumps({'audit':target,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
