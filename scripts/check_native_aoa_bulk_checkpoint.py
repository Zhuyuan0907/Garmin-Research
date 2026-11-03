#!/usr/bin/env python3
"""Audit owned bulk evidence and report scope; no controller or phone actions."""
from datetime import datetime,timezone
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
def main():
    s=read('evidence/deep-research-state.json');aa=s['native_android_auto'];a=aa['AOA_bulk_prototype']
    m=read(a['build_manifest']);p=read(a['emulation_evidence'])
    for proof in (m,p):
        for name,want in proof['source_sha256'].items():assert sha(name)==want,name
    names={c['name'] for c in p['cases']};report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=read('reports/findings.json');progress=findings['research_progress']
    prior_name='evidence/firmware-analysis/native-aoa-config-checkpoint-audit.json';prior=read(prior_name)
    checks={
      'seven_build27_execution_dependencies':len(m['source_sha256'])==a['build_dependencies']==7 and
         len(p['source_sha256'])==a['emulation_dependencies']==27,
      'state_and_artifact_hashes_current':a['build_manifest_sha256']==sha(a['build_manifest']) and
         a['emulation_sha256']==sha(a['emulation_evidence']) and m['flat_sha256']==sha(m['flat']) and
         m['elf_sha256']==sha(m['elf']),
      'ARMv6_freestanding_no_imports':p['compiled_ARMv6_code_executed'] and 'Tag_CPU_arch: v6' in m['attributes'] and
         not m['unresolved_symbols'] and not m['Linux_runtime_dependencies'],
      '35_fresh_cases_guarded_protected':p['case_count']==len(p['cases'])==a['offline_cases_passed']==35 and
         p['all_passed'] and all(c['all_passed'] and c['guards_and_all_three_code_images_intact'] for c in p['cases']),
      'bounded_footprints_current':a['code_bytes']==m['flat_bytes']==p['code_bytes']==1532 and
         a['context_bytes']==p['context_bytes']==8284 and a['request_bytes']==28 and
         a['RX_TX_buffer_bytes_each']==p['RX_TX_buffer_bytes_each']==4096,
      'both_simultaneous_completion_orders_and_preserved_parents':{'full_chain_duplex_IN_first',
         'full_chain_duplex_OUT_first'}<=names and p['simultaneous_RX_TX_borrows_verified_offline'] and
         p['old_handshake_and_config_artifacts_unchanged'],
      'partial_OUT_exact_reconstruction_and_owned_TX':len([n for n in names if n.startswith('partial_success_OUT_')])==3 and
         all(c.get('exact_original_bytes_sent_without_duplication') for c in p['cases'] if c['name'].startswith('partial_success_OUT_')) and
         'TX_capacity_gates_replacement' in names,
      'short_zero_IN_backpressure_and_unambiguous_two_byte_count':{f'valid_short_or_zero_IN_{n}' for n in
         (0,1,511,512,1023,4096)}<=names and 'consumer_copies_across_small_reads_while_RX_reuse_blocked' in names and
         a['pending_RX_read_uses_negative_error_distinct_from_two_byte_count'],
      'stale_session_direction_duplicate_and_sequence_exhaustion':{'stale_direction_session_duplicate_callback_guards',
         'sequence_exhaustion_keeps_existing_RX_borrow'}<=names,
      'cancel_disconnect_both_terminal_orders_and_borrow_retention':{f'stop_{d}_terminal_order_{o}' for d in (0,1)
         for o in (0,1)}<=names and a['cancel_disconnect_error_timeout_preserve_each_borrow_until_terminal'],
      'paired_deadlines_wrap_and_terminal_ownership':{'timeout_retains_both_borrows_until_terminal_callbacks',
         'IN_completion_observes_expired_OUT_deadline_without_prior_poll',
         'OUT_completion_observes_expired_IN_deadline_without_prior_poll','bulk_deadline_32bit_wrap'}<=names,
      'argument_and_parent_rejection_controls':{f'invalid_RX_packet_multiple_or_bound_{n}' for n in (0,1,511,4097)}<=names and
         {'invalid_TX_RX_output_and_stop_arguments','unconfigured_parent_rejected_without_output_change',
          'borrowed_config_parent_rejected'}<=names,
      'synthetic_not_real_USB_DMA_cache_framing_phone_AA':m['synthetic_link_address_not_device_allocation'] and
         p['terminal_completion_controller_writes_and_events_are_fixtures'] and
         not p['real_controller_USB_cache_ZLP_framing_TLS_phone_or_AA_verified'] and
         not a['GarminOS_loaded_execution_or_native_UI_verified'],
      'no_device_operations_or_install_candidate':all(not x['device_io'] and not x['firmware_modified'] and
         not x['device_install_candidate'] for x in (m,p,a)) and not s['last_goal_turn']['device_io'] and
         not s['last_goal_turn']['device_files_written'],
      'previous19_checkpoint_state_report_current':prior['all_passed'] and len(prior['scope_checks'])==19 and
         prior['state_sha256']==sha('evidence/deep-research-state.json') and prior['report_sha256']==sha('reports/nuvi2565RT.html'),
      'task_findings_state_current':read('evidence/task-state.json')['native_android_auto']==aa and findings['deep_research']==s,
      '31_progress_estimate_full_scope_and14_details':progress['estimate_percent']==31 and
         progress['includes_deferred_Google_Maps'] and len(progress['completed'])>=14 and not progress['goal_completed'] and
         '雙向傳輸原型：35 個離線案例' in '\n'.join(progress['completed']),
      'report_scope_disclosed':all(text in report for text in ['雙向傳輸原型',
         '35 個新鮮離線案例通過','1532 bytes','8284 bytes','尚未傳送真正的 USB 資料','目前只有模擬器中的資料傳輸']),
      'goal_active_original_scopes_open_no_achieve':s['goal_status']=='active' and not s['goal_complete'] and
         s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
         s['google_maps']['research_deferred_by_user'] and not aa['native_receiver_running'] and
         not aa['phone_session_verified'] and not s['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-aoa-bulk-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'evidence_sha256':{n:sha(n) for n in
        (a['build_manifest'],a['emulation_evidence'],prior_name)},
      'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))
if __name__=='__main__':main()
