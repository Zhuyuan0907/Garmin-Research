#!/usr/bin/env python3
"""Audit wire framing evidence, preserving TLS/phone/device scope boundaries."""
from datetime import datetime,timezone
import hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def read(n):return json.loads((ROOT/n).read_text())
def sha(n):return hashlib.sha256((ROOT/n).read_bytes()).hexdigest()
def main():
    s=read('evidence/deep-research-state.json');aa=s['native_android_auto'];a=aa['framing_prototype']
    m=read(a['build_manifest']);p=read(a['emulation_evidence'])
    for proof in (m,p):
        for path,want in proof['source_sha256'].items():assert sha(path)==want,path
    names={c['name'] for c in p['cases']};report=(ROOT/'reports/nuvi2565RT.html').read_text()
    findings=read('reports/findings.json');progress=findings['research_progress']
    prior_name='evidence/firmware-analysis/native-usb-role-checkpoint-audit.json';prior=read(prior_name)
    provenance=read('native/aa-framing/provenance.json')
    checks={
      '17_build47_execution_dependencies_current':len(m['source_sha256'])==a['build_dependencies']==17 and
         len(p['source_sha256'])==a['emulation_dependencies']==47,
      'state_and_binaries_hashes_current':a['build_manifest_sha256']==sha(a['build_manifest']) and
         a['emulation_sha256']==sha(a['emulation_evidence']) and m['flat_sha256']==sha(m['flat']) and m['elf_sha256']==sha(m['elf']),
      'ARMv6_freestanding_no_imports':p['compiled_ARMv6_code_executed'] and 'Tag_CPU_arch: v6' in m['attributes'] and
         not m['unresolved_symbols'] and not m['Linux_runtime_dependencies'],
      '70_fresh_execution_cases_guarded_four_code_images':p['case_count']==len(p['cases'])==a['offline_cases_passed']==70 and
         p['all_passed'] and all(c['all_passed'] and c['guard_pages_canaries_and_four_code_images_intact'] for c in p['cases']),
      'footprints_and_caller_workspaces_current':a['code_bytes']==m['flat_bytes']==p['code_bytes']==2196 and
         a['frame_context_bytes']==p['frame_context_bytes']==52 and a['message_context_bytes']==p['message_context_bytes']==52 and
         a['frame_view_bytes']==p['frame_view_bytes']==28 and a['message_view_bytes']==p['message_view_bytes']==24 and
         a['tested_frame_pool_bytes']==p['tested_frame_pool_capacity']==65535 and
         a['tested_message_pool_bytes']==p['tested_message_pool_capacity']==262144,
      'six_literal_wire_vectors_and21_split_positions':len([n for n in names if n.startswith('independent_literal_wire_vector_')])==6 and
         {f'all_header_payload_two_call_split_{i}' for i in range(21)}<=names,
      'empty_last_16KiB_and256KiB_plain_messages':{'bounded_message_16384','bounded_message_262144'}<=names and
         next(c for c in p['cases'] if c['name']=='bounded_message_16384')['empty_last_supported_at_exact_upstream_fragment_size'],
      'full_wire_length_extended_boundary_and_byte_ownership':{'full_uint16_wire_payload_boundary_unaligned_frame_pool',
         'largest_extended_wire_frame_keeps_ciphertext_opaque','input_and_frame_pool_reuse_do_not_change_copied_message',
         'coalesced_input_exact_consumption_and_frame_message_backpressure'}<=names,
      'ciphertext_opaque_no_fake_decrypt_TLS':{'opaque_ciphertext_length_not_plain_total_and_no_fake_decryption'}<=names and
         p['ciphertext_not_delivered_as_plaintext_no_fake_TLS'] and not a['actual_TLS_crypto_authentication_implemented_or_verified'],
      'malformed_order_channels_type_totals_and_reserved_flags':{'reject_interleaved_channel','reject_changed_control_flag',
         'reject_second_first','reject_short_last','reject_payload_over_declared_total','reject_total_uint32_over_capacity',
         'reserved_flags_lock_stream_128','non_FIRST_extended_total_metadata_rejected'}<=names,
      'stale_sequence_and_empty_fragment_limit':{'frame_sequence_exhaustion_no_reused_token','message_sequence_exhaustion_no_wrap',
         'duplicate_fragment_locks_message','bounded_empty_fragment_count'}<=names,
      'cancel_retains_complete_borrows_and_hides_partial_data':{'cancel_holds_ready_frame_until_release',
         'cancel_partial_extended_header_no_partial_delivery','cancel_holds_ready_message_until_release'}<=names,
      'same_VM_chain_is_fixture_dispatch_not_live_receiver':{'same_VM_handshake_config_bulk_and_framing_chain'}<=names and
         p['preserved_negotiation_configuration_bulk_artifacts_unchanged'] and
         p['controller_events_and_dispatch_driver_are_fixtures'] and
         not a['automatic_native_outbound_fragmentation_or_dispatch_loop_implemented'],
      'GPL3_attribution_full_license_ten_frozen_primary_files':m['license']==provenance['license']=='GPL-3.0-or-later' and
         len(provenance['upstream_sources'])==10 and 'GNU GENERAL PUBLIC LICENSE' in (ROOT/'native/aa-framing/COPYING').read_text() and
         provenance['upstream_commit']=='046b3b381595509d0939fa84b14a90978f46ff63',
      'synthetic_allocation_old_model_current_phone_unverified':m['synthetic_link_address_not_device_allocation'] and
         a['compiled_memory_addresses_and_pools_are_synthetic_not_Garmin_allocations'] and
         not a['current_Pixel_compatibility_or_official_wire_spec_verified'] and
         not p['real_TLS_crypto_auth_current_phone_host_Garmin_RAM_UI_or_AA_verified'],
      'no_physical_device_operations_or_install_candidate':all(not x['device_io'] and not x['firmware_modified'] and
         not x['device_install_candidate'] for x in (m,p,a)) and not s['last_goal_turn']['device_io'] and
         not s['last_goal_turn']['device_files_written'],
      'prior18_checkpoint_state_report_current':prior['all_passed'] and len(prior['scope_checks'])==18 and
         prior['state_sha256']==sha('evidence/deep-research-state.json') and prior['report_sha256']==sha('reports/nuvi2565RT.html'),
      'task_findings_progress_current_full_scope_retained':read('evidence/task-state.json')['native_android_auto']==aa and findings['deep_research']==s and
         progress['estimate_percent']==31 and progress['includes_deferred_Google_Maps'] and len(progress['completed'])>=16 and not progress['goal_completed'],
      'report_scope_current':all(v in report for v in ['原生封包與明文重組','70 個新鮮離線案例通過','2196 bytes',
         '沒有 TLS 解密或認證','目前尚無原生連續派送迴圈','Android Auto 尚未在 GarminOS 執行']),
      'full_goal_active_no_achieve_original_scopes_open':s['goal_status']=='active' and not s['goal_complete'] and
         s['required_work_remaining'] and s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
         s['google_maps']['research_deferred_by_user'] and not aa['native_receiver_running'] and
         not aa['phone_session_verified'] and not s['native_app_music']['native_app_running'],
    }
    assert all(checks.values()),[n for n,ok in checks.items() if not ok]
    name='evidence/firmware-analysis/native-aa-framing-checkpoint-audit.json'
    (ROOT/name).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'evidence_sha256':{n:sha(n) for n in
        (a['build_manifest'],a['emulation_evidence'],prior_name)},
      'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'device_io_this_turn':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':name,'all_passed':True,'scope_checks':len(checks)}))
if __name__=='__main__':main()
