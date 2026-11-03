#!/usr/bin/env python3
"""Check current send/reply research against executable proofs and scope."""
from datetime import datetime,timezone
import hashlib,json,re
from pathlib import Path
from analyze_native_sections import NativeImage,ROOT,EXPECTED
def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']
    send=read(f['native_l2cap_send']['evidence']);p=read(f['native_music_reply']['evidence'])
    build=read(f['native_music_reply']['manifest']);endpoint=read(f['native_l2cap_send']['manifest'])
    for proof in [send,p]:
        for path,h in proof['source_sha256'].items():assert sha(path)==h,path
    for b in [build,endpoint]:
        for path,h in b['source_sha256'].items():assert sha(path)==h,path
        assert sha(b['flat'])==b['flat_sha256'] and sha(b['elf'])==b['elf_sha256']
    assert p['build_source_sha256']==build['source_sha256']
    assert p['component_manifest_sha256']==sha(f['native_music_reply']['manifest'])
    assert p['endpoint_manifest_sha256']==send['component_manifest_sha256']==sha(f['native_l2cap_send']['manifest'])
    reference=read('sources/music-policy-reference/avdtp-message-reference.json')
    assert reference['sha256']==sha('sources/music-policy-reference/bluez-avdtp.c')
    cases={r['name']:r for r in p['cases']};sc={r['name']:r for r in send['cases']}
    before=read(s['last_goal_turn']['previous_state_snapshot']);prior=read(s['last_goal_turn']['previous_current_audit_snapshot'])
    preserved=[]
    for key in ['native_music_endpoint','native_music_configuration_gate','native_music_policy','native_music_dispatch']:
        item=f[key];assert item==before['native_app_music']['static_findings'][key]
        old=read(item['evidence']);assert sha(item['evidence'])==item['evidence_sha256']
        for path,h in old['source_sha256'].items():assert sha(path)==h,path
        preserved.append(old['case_count'])
    report=(ROOT/'reports/nuvi2565RT.html').read_text();public=read('reports/findings.json');task=read('evidence/task-state.json')
    stock=NativeImage();code=(ROOT/build['flat']).read_bytes();offset=build['symbols']['stock_reply_relocated']-build['base']
    patches=p['all_VM_patch_plan'];new=p['additional_patch_plan']
    checks={
        'fresh112_reply_cases_and10_send_cases_passed':p['all_passed'] and send['all_passed'] and
            p['case_count']==len(cases)==112 and send['case_count']==len(sc)==10 and
            all(row['passed'] and all(row['checks'].values()) for row in p['cases']+send['cases']),
        'current_execution_build_and_artifact_hashes':all(sha(f[k]['evidence'])==f[k]['evidence_sha256'] for k in
            ['native_l2cap_send','native_music_reply']) and p['MAIN_sha256']==send['MAIN_sha256']==EXPECTED,
        'unknown5_signals_all16_transactions_native_queued_type1_original_signal':all(
            cases['unknown_'+str(signal)+'_transaction_'+str(tx)+'_native_general_reject']['result']['TX_queue'][0]['wire_hex']==
            bytes([(tx<<4)|1,signal]).hex() for signal in [0,11,12,13,63] for tx in range(16)),
        'known10_accept_reject_baselines_exact_with_original_relocated_body':all(all(cases[
            'known_signal_'+str(signal)+'_error_'+str(error)+'_relocated_original_reply_identical']['checks'].values())
            for signal in range(1,11) for error in [0,1]),
        'normal_capabilities_bad_codec_accept_and_short_configuration_wire_unchanged':all(all(cases[
            name+'_wire_dispatch_unchanged']['checks'].values()) for name in
            ['owned_caps','AAC_preaccept_reject','valid_config_accept','short_known_config_reject']),
        'same_VM_unknown_then_caps_config_GetConfiguration_preserves_four_copies':all(cases[
            'unknown_then_capabilities_configuration_and_GetConfiguration_same_VM']['checks'].values()),
        'fragment_mismatch_known_error_and_one_byte_drop_retained':all(cases[
            'fragment_transaction_mismatch_known_signal_reject_retained']['checks'].values()) and
            all(cases['one_byte_input_original_drop_retained']['checks'].values()),
        'lock_failure_not_ready_and_invalid_envelope_do_not_queue':all(all(cases[name]['checks'].values()) for name in
            ['unknown_reply_native_lock_failure_not_delivery','unknown_reply_native_channel_not_ready_no_queue',
             'channel12_unknown_wrapper_rejects_before_lookup_send','transaction16_unknown_wrapper_rejects_before_lookup_send',
             'signal64_unknown_wrapper_rejects_before_lookup_send']),
        'original1000_proved_after_native_send_allocation_copy_and_link':send[
            'unknown_reply_1000_survives_native_send_allocation_copy_and_queue'] and all(sc[
            'unknown_'+str(signal)+'_unchanged_in_actual_native_queue']['result']['TX_queue'][0]['wire_hex']=='1000'
            for signal in [0,11,12,13,63]),
        'native_two_record_queue_and_single_pending_scheduler_submission':all(sc[
            'two_replies_link_actual_native_queue_and_copy_after_stack_reuse']['checks'].values()),
        'exact16_byte_stock_prologue_relocated_register_args_SP_preserved':code[offset:offset+16]==stock.read(0x5756ac,16) and
            new[1]['first_instructions']==['push {r3}','ldr r3, [pc, #8]','mov ip, r3','pop {r3}','bx ip'],
        '18_new_and40_aggregate_fields_at8_declared_VM_sites':len(new)==2 and len(patches)==8 and
            sum(len(bytes.fromhex(r['replacement'])) for r in new)==p['additional_patch_fields_bytes']==18 and
            sum(len(bytes.fromhex(r['replacement'])) for r in patches)==p['all_VM_patch_fields_bytes']==40 and
            all(stock.read(int(row['address'],16),len(bytes.fromhex(row['original']))).hex()==row['original'] for row in patches),
        'freestanding208_byte_ARMv6_no_BSS_or_unresolved_dependencies':build['flat_bytes']==p['reply_component_bytes']==208 and
            not build['BSS_bytes'] and not build['unresolved_symbols'] and not build['Linux_runtime_dependencies'] and
            'Tag_CPU_arch: v6' in build['attributes'],
        'code_globals_inputs_pool_guards_stack_and_saved_registers':all(row['result'][
            'compiled_stock_code_initialized_data_input_BSS_heap_core_SDP_guards_SP_saved_registers_intact'] for row in p['cases']),
        'previous29_endpoint189_gate208_policy18_dispatch_evidence_preserved':preserved==[29,189,208,18],
        'previous23_scope_audit_matches_saved_previous_state':prior['all_passed'] and len(prior['scope_checks'])==23 and
            prior['state_sha256']==sha(s['last_goal_turn']['previous_state_snapshot']) and before['last_goal_turn']['classification']=='progress',
        'canonical_public_and_task_state_match':public['deep_research']==s and all(task[k]==s[k] for k in
            ['last_goal_turn','next_actions','latest_user_instruction','attended_testing','ordered_priorities']),
        'report31_28_details_Taiwan_times_and_prototype_limits_visible':public['research_progress']['estimate_percent']==31 and
            len(public['research_progress']['completed'])==28 and all(t in report for t in
                ['112 個案例','208 bytes','40 bytes','GeneralReject','不是可載入或可刷入版本','484 bytes']) and
            all(re.search('<time id="'+id+'" datetime="[^"]+\\+08:00"',report) for id in
                ['report-updated-time','research-updated-time']),
        'pinned_primary_reference_used_without_Garmin_BlueZ_assumption':p['bluez_reference_manifest_sha256']==
            sha('sources/music-policy-reference/avdtp-message-reference.json') and reference['commit'] in report and
            '並未假設 Garmin 使用 BlueZ' in report,
        'synthetic_VM_only_no_actual_loader_radio_App_policy_binding':p['VM_firmware_copy_modified'] and
            not p['firmware_modified_on_device'] and not p['device_install_candidate'] and
            not p['actual_radio_phone_speaker_or_accepted_loader_verified'] and p['media_policy_decoder_callback_still_unbound'] and
            p['original_inbound_GeneralReject_processing_not_fixed_or_tested'] and
            build['synthetic_link_address_not_device_allocation'] and not send['actual_radio_delivery_or_phone_behavior_verified'],
        'user_away_no_device_IO_physical_question_or_microphone_work':s['attended_testing']['waiting_for_user_return'] and
            not s['attended_testing']['user_present'] and not s['attended_testing']['automatic_calls_or_sound_allowed_while_away'] and
            s['attended_testing']['no_pending_question'] and not p['device_io'] and not send['device_io'] and
            not s['last_goal_turn']['device_io'] and not s['last_goal_turn']['device_files_written'] and
            s['microphone_amplifier']['status']=='cancelled_by_user' and not s['microphone_amplifier']['next_actions'],
        'full_goal_active_no_achieve_AA_retained_Maps_deferred':s['goal_status']=='active' and not s['goal_complete'] and
            s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
            s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'] and
            not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
        'no_private_MAC_or_unit_ESN_in_report':not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report) and 'REDACTED_PRIVATE_ID' not in report,
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    path='evidence/firmware-analysis/native-music-reply-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,
        'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
        'report_sha256':sha('reports/nuvi2565RT.html'),
        'proof_sha256':{f[k]['evidence']:sha(f[k]['evidence']) for k in ['native_l2cap_send','native_music_reply']},
        'execution_dependencies':{k:len(v['source_sha256']) for k,v in [('send',send),('reply',p)]},
        'previous_checkpoint_snapshot_sha256':sha(s['last_goal_turn']['previous_current_audit_snapshot']),
        'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),'current_turn_device_IO':False,
        'VM_firmware_copy_modified':True,'device_firmware_modified':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':path,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
