#!/usr/bin/env python3
"""Keep the compiled negotiation proof distinct from a live Android Auto link."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(name):return json.loads((ROOT/name).read_text())
def sha(name):return hashlib.sha256((ROOT/name).read_bytes()).hexdigest()

def main():
    s=read('evidence/deep-research-state.json');aa=s['native_android_auto']
    a=aa['AOA_negotiation_prototype'];m=read(a['build_manifest']);p=read(a['emulation_evidence'])
    for proof in (m,p):
        for name,want in proof['source_sha256'].items():assert sha(name)==want,name
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    prior='evidence/firmware-analysis/native-usb-controller-checkpoint-audit.json';old=read(prior)
    checks={
      'source_and_binary_dependencies_match':len(m['source_sha256'])==4 and len(p['source_sha256'])==8,
      'ARMv6_freestanding_no_imports':p['ARM_architecture']=='ARMv6/ARM1176/soft-float' and
         'Tag_CPU_arch: v6' in m['attributes'] and not m['unresolved_symbols'] and not m['Linux_runtime_dependencies'],
      '50_fresh_compiled_code_cases':p['new_compiled_code_executed'] and p['all_passed'] and
         p['case_count']==len(p['cases'])==50 and all(c['all_passed'] for c in p['cases']),
      'protocol_request_byte_vectors':all(c['setup_hex'][0]=='c033000000000200' and
         c['setup_hex'][-1]=='4035000000000000' and len(c['setup_hex'])==8 for c in p['cases'][:2]),
      'code_and_context_footprint_current':a['code_bytes']==m['flat_bytes']==p['code_bytes'] and p['code_bytes']>0 and
         a['context_bytes']==p['context_bytes']==1604,
      'timeout_cancel_ownership_tests_present':{'timeout_retains_borrow_until_terminal_callback',
         'cancel_requires_controller_ack_before_release','terminal_completion_after_cancel_releases_borrow',
         '32bit_millisecond_wrap_timeout'}<={c['name'] for c in p['cases']},
      'guard_pages_canaries_code_protected':p['code_mappings_write_protected'] and
         all(c['guard_pages_and_canaries_intact'] for c in p['cases']),
      'controller_events_are_explicit_fixtures':p['controller_completions_and_enumeration_are_fixtures'] and
         p['session_ID_uniqueness_same_port_binding_and_single_actor_are_caller_contracts'],
      'recognition_not_bulk_or_full_AA':not p['configuration_interface_or_bulk_endpoint_selection_implemented'] and
         not p['host_controller_VBUS_or_real_phone_session_verified'] and not aa['native_receiver_running'] and
         not aa['phone_session_verified'],
      'no_hardware_or_install_candidate':all(not q['device_io'] and not q['firmware_modified'] and
         not q['device_install_candidate'] for q in (m,p)) and m['synthetic_link_address_not_device_allocation'] and
         not s['last_goal_turn']['device_io'] and not s['last_goal_turn']['device_files_written'],
      'current_state_proof_hashes':a['build_manifest_sha256']==sha(a['build_manifest']) and
         a['emulation_sha256']==sha(a['emulation_evidence']),
      'state_task_report_consistent':read('evidence/task-state.json')['native_android_auto']==aa and
         read('reports/findings.json')['deep_research']==s,
      'prior_22scope_checkpoint_current':old['all_passed'] and len(old['scope_checks'])==22 and
         old['state_sha256']==sha('evidence/deep-research-state.json') and old['report_sha256']==sha('reports/nuvi2565RT.html'),
      'user_cable_clarification_retained':aa['hardware_diagnostics']['user_current_cable_description']==
         'USB-A to microUSB data cable between Pi and Garmin' and not aa['hardware_diagnostics']['separate_OTG_adapter_availability_confirmed'],
      'public_report_scope':all(t in report for t in ['原生 AOA 握手原型','50 個測試通過',
         '尚未接上 Garmin 的 USB 主機驅動','目前不需使用者更動接線']),
      'whole_goal_still_active_no_achieve':s['goal_status']=='active' and not s['goal_complete'] and
         s['required_work_remaining'] and s['last_goal_turn']['classification']=='progress' and
         s['latest_user_instruction']['goal_completion_forbidden_by_user'] and s['google_maps']['research_deferred_by_user'] and
         not s['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[name for name,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-aoa-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'evidence_sha256':{n:sha(n) for n in
        (a['build_manifest'],a['emulation_evidence'],prior)},
      'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))
if __name__=='__main__':main()
