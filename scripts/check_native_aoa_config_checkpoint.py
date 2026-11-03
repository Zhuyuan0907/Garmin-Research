#!/usr/bin/env python3
"""Audit descriptor/configuration scope without claiming a real bulk connection."""
from datetime import datetime,timezone
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
def main():
    s=read('evidence/deep-research-state.json');aa=s['native_android_auto'];a=aa['AOA_configuration_prototype']
    m=read(a['build_manifest']);p=read(a['emulation_evidence']);h=read(a['host_search_evidence'])
    for proof in (m,p,h):
        for name,want in proof['source_sha256'].items():assert sha(name)==want,name
    names={c['name'] for c in p['cases']};report=(ROOT/'reports/nuvi2565RT.html').read_text()
    prior_name='evidence/firmware-analysis/native-aoa-checkpoint-audit.json';prior=read(prior_name)
    findings=read('reports/findings.json');progress=findings['research_progress']
    checks={
      'nine_build19_execution_five_host_search_dependencies':len(m['source_sha256'])==9 and len(p['source_sha256'])==19 and len(h['source_sha256'])==5,
      'state_proof_hashes_current':a['build_manifest_sha256']==sha(a['build_manifest']) and
         a['emulation_sha256']==sha(a['emulation_evidence']) and a['host_search_sha256']==sha(a['host_search_evidence']),
      'ARMv6_freestanding_no_imports':p['compiled_ARMv6_code_executed'] and 'Tag_CPU_arch: v6' in m['attributes'] and
         not m['unresolved_symbols'] and not m['Linux_runtime_dependencies'],
      '62_cases_guarded_protected':p['case_count']==len(p['cases'])==62 and p['all_passed'] and
         p['code_protected_and_guard_pages_used'] and all(c['all_passed'] and c['guards_and_code_intact'] for c in p['cases']),
      'footprints_current':a['code_bytes']==m['flat_bytes']==p['code_bytes']==2184 and
         a['context_bytes']==p['context_bytes']==64 and p['plan_bytes']==24,
      'nonfirst_accessory_ADB_audio_alt_exclusion_controls':{'accessory_after_ADB_fixture','OUT_before_IN',
         'audio_interfaces_and_alt_are_ignored','alternate_not_selected','ADB_only_fixture',
         'accessory_nondefault_alt_only','ambiguous_accessory_interfaces'}<=names,
      'bounds_and_wrong_descriptor_controls':{'1024byte_configuration_boundary','64_interface_alt_pairs_boundary',
         '65_alt_pairs_over_bound','descriptor_overrun','wrong_total_high','duplicate_endpoint',
         'global_active_endpoint_collision','partial_descriptor_trailer'}<=names,
      'copied_plan_correct_configuration_value_and_whole_chain':{'full_handshake_reenum_parse_SET_CONFIGURATION_chain',
         'configuration_value7_owned_plan_not_constant1'}<=names and
         next(c for c in p['cases'] if c['name']=='full_handshake_reenum_parse_SET_CONFIGURATION_chain')['setup_hex']=='0009010000000000' and
         next(c for c in p['cases'] if c['name']=='configuration_value7_owned_plan_not_constant1')['setup_hex']=='0009070000000000',
      'timeout_cancel_wrap_sequence_and_parent_borrow':{'timeout_retains_setup_borrow_until_terminal_completion',
         'cancel_ack_requires_failed_state_and_matching_token','configuration_timeout_32bit_clock_wrap',
         'configuration_sequence_exhaustion','borrowed_parent_rejected'}<=names,
      'old_handshake_frozen_parent_code_not_replaced':p['handshake_core_original_artifacts_unchanged'] and
         aa['AOA_negotiation_prototype']['emulation_sha256']==sha(aa['AOA_negotiation_prototype']['emulation_evidence']),
      'specific15_anchor_host_search_not_whole_absence':h['anchor_count']==len(h['candidates'])==15 and
         len(h['scanned_startup_backed_regions'])==3 and not h['actual_host_driver_registration_VBUS_or_AOA_verified'],
      'false_MMIO_pointer_positively_excluded':h['excluded_raw_word_candidate']['address']=='0x6f058c' and
         h['excluded_raw_word_candidate']['raw_word']=='0x10200080' and
         h['excluded_raw_word_candidate']['bounded_original_instructions'][1]['instruction']=='eorne r0, r0, r0, lsl #1',
      'no_real_bulk_host_phone_or_AA_claim':p['configuration_interface_bulk_endpoint_selection_implemented'] and
         not p['actual_bulk_data_transfer_or_interface_claim_implemented'] and
         not p['host_controller_VBUS_real_phone_TLS_or_AA_verified'] and p['descriptor_and_controller_events_are_fixtures'],
      'no_device_writes_or_install_candidate':all(not x['device_io'] and not x['firmware_modified'] and
         not x['device_install_candidate'] for x in (m,p,h)) and not s['last_goal_turn']['device_io'] and
         not s['last_goal_turn']['device_files_written'],
      'prior16_checkpoint_state_report_current':prior['all_passed'] and len(prior['scope_checks'])==16 and
         prior['state_sha256']==sha('evidence/deep-research-state.json') and prior['report_sha256']==sha('reports/nuvi2565RT.html'),
      'task_findings_state_consistent':read('evidence/task-state.json')['native_android_auto']==aa and findings['deep_research']==s,
      'progress31_weighted_full_scope_retained':progress['estimate_percent']==31 and
         progress['includes_deferred_Google_Maps'] and len(progress['completed'])>=13 and not progress['goal_completed'],
      'report_scope_current':all(text in report for text in ['手機 USB 介面與配置','62 個新鮮離線案例通過',
         '尚未傳送真正的 bulk 資料','不是 USB 暫存器指標']),
      'full_goal_active_no_achieve_original_scopes_open':s['goal_status']=='active' and not s['goal_complete'] and
         s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
         s['google_maps']['research_deferred_by_user'] and not aa['native_receiver_running'] and
         not aa['phone_session_verified'] and not s['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-aoa-config-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'evidence_sha256':{n:sha(n) for n in
        (a['build_manifest'],a['emulation_evidence'],a['host_search_evidence'],prior_name)},
      'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))
if __name__=='__main__':main()
