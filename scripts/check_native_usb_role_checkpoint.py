#!/usr/bin/env python3
"""Audit stock helper evidence without claiming a host port or live execution."""
from datetime import datetime,timezone
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
def main():
    s=read('evidence/deep-research-state.json');aa=s['native_android_auto'];a=aa['USB_role_helper_analysis']
    p=read(a['emulation_evidence']);st=read(a['static_evidence'])
    for proof in (p,st):
        for name,want in proof['source_sha256'].items():assert sha(name)==want,name
    names={c['name'] for c in p['cases']};report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=read('reports/findings.json');progress=findings['research_progress']
    prior_name='evidence/firmware-analysis/native-aoa-bulk-checkpoint-audit.json';prior=read(prior_name)
    flows=st['bounded_Thumb_functions'];scan=st['literal_search'];test=st['electrical_test'];probe=st['temporary_sample_probe']
    checks={
      'sixteen_execution23_static_dependencies':len(p['source_sha256'])==a['emulation_dependencies']==16 and
         len(st['source_sha256'])==a['static_dependencies']==23,
      'state_proof_hashes_current':a['emulation_sha256']==sha(a['emulation_evidence']) and
         a['static_sha256']==sha(a['static_evidence']),
      '53_original_code_cases_protected_no_function_replacements':p['case_count']==len(p['cases'])==a['offline_cases_passed']==53 and
         p['all_passed'] and p['stock_code_mappings_write_protected'] and
         all(c['all_passed'] and c['original_code_intact'] and not c['function_fixtures'] for c in p['cases']),
      '24_enable_three_disable_field_preservation_cases':len([n for n in names if n.startswith('extension_enable_')])==24 and
         len([n for n in names if n.startswith('extension_disable_')])==3 and
         all(c['only_bit14_cleared'] and c['separate_gate_not_cleared'] for c in p['cases'] if c['name'].startswith('extension_disable_')),
      '18_probe_cases_restore_IRQ_mask_not_all_extension_fields':len([n for n in names if n.startswith('sample_probe_')])==18 and
         all(c['IRQ_mask_restored'] for c in p['cases'] if c['name'].startswith('sample_probe_')) and
         probe['previous_extension_control_not_fully_restored'] and probe['probe_not_ready_to_call_on_hardware'],
      'unsupported_probe_banks_fail_before_register_access':{'unsupported_probe_bank_2','unsupported_probe_bank_4'}<=names and
         all(not c['synthetic_register_writes'] for c in p['cases'] if c['name'].startswith('unsupported_probe_bank_')),
      'electrical_test_selector_controls_not_force_host':{f'electrical_test_selector_{v}' for v in (0,1,2,3,4,128)}<=names and
         test['selector_to_TESTMODE']=={'1':2,'2':4,'3':1,'4':8} and test['force_host_bit80_not_set_by_helper'],
      'exact53byte_primary_test_pattern_not_AOA_setup':test['packet_bytes']==a['test_packet_bytes']==53 and
         test['test_packet_sha256']==p['test_packet_sha256']==a['test_packet_sha256'] and
         test['exact_primary_test_pattern_match'] and test['same_numeric_host_setup_mask_does_not_prove_host'] and
         next(c for c in p['cases'] if c['name']=='electrical_test_selector_4')['test_FIFO_bytes']==53,
      '13_bounded_flows_no_unresolved_local_exits':len(flows)==a['bounded_Thumb_CFGs']==13 and
         all(not f['unresolved_exits'] and not f['instruction_limit_reached'] for f in flows.values()),
      'ten_confirmed_literals17_unvalidated_words_no_global_absence':len(scan['Thumb_PC_relative_candidates'])==a['confirmed_literal_references']==10 and
         all(r['confirmed_in_bounded_reachable_Thumb_CFG'] for r in scan['Thumb_PC_relative_candidates']) and
         len(scan['raw_aligned_words_unvalidated'])==a['raw_unvalidated_address_words']==17 and
         not scan['strict_ARM_PC_relative_candidates'] and not a['global_firmware_host_absence_proven'],
      'only_three_of_five_call_scan_candidates_CFG_confirmed':len(st['direct_call_scan_candidates'])==5 and
         sum(c['confirmed_in_local_CFG'] for c in st['direct_call_scan_candidates'])==3,
      'unknown_extension_register_not_assumed_DMA_ADC_UART_VBUS':st['extension_control']['width_bytes']==4 and
         st['extension_control']['physical_register_role_UART_mux_ADC_DMA_or_VBUS_unidentified'] and
         st['extension_control']['not_equated_to_standard_MUSB_DMA_control'] and
         not a['extension_control_register_physical_meaning_verified'],
      'synthetic_timer_status_unbounded_local_waits_disclosed':p['timer_and_status_loads_are_fixtures'] and
         probe['timer_loops_have_no_software_iteration_limit_in_local_CFG'] and
         not p['physical_chip_identity_USB_host_UART_ADC_VBUS_or_phone_verified'],
      'no_physical_operations_or_install_candidate':all(not x['device_io'] and not x['firmware_modified'] and
         not x['device_install_candidate'] for x in (p,st,a)) and not s['last_goal_turn']['device_io'] and
         not s['last_goal_turn']['device_files_written'],
      'prior19_checkpoint_state_report_current':prior['all_passed'] and len(prior['scope_checks'])==19 and
         prior['state_sha256']==sha('evidence/deep-research-state.json') and prior['report_sha256']==sha('reports/nuvi2565RT.html'),
      'task_findings_state_and_progress_current':read('evidence/task-state.json')['native_android_auto']==aa and findings['deep_research']==s and
         progress['estimate_percent']==31 and progress['includes_deferred_Google_Maps'] and
         len(progress['completed'])>=15 and not progress['goal_completed'],
      'report_scope_disclosed':all(text in report for text in ['USB 主機入口查找','53 個新鮮離線案例驗證',
         '不會完整還原先前擴充設定','沒有局部次數上限','不能推論整台沒有 USB 主機功能']),
      'goal_active_full_original_scopes_open_no_achieve':s['goal_status']=='active' and not s['goal_complete'] and
         s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
         s['google_maps']['research_deferred_by_user'] and not aa['USB_host_board_wiring_or_driver_verified'] and
         not aa['native_receiver_running'] and not aa['phone_session_verified'] and
         not s['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-usb-role-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'evidence_sha256':{n:sha(n) for n in
        (a['emulation_evidence'],a['static_evidence'],prior_name)},
      'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))
if __name__=='__main__':main()
