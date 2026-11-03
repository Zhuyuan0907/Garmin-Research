#!/usr/bin/env python3
"""Audit loaded music proof/artifacts, previous evidence and public scope."""
from datetime import datetime,timezone
import hashlib,json,re,struct
from pathlib import Path
from analyze_native_sections import ROOT,EXPECTED,NativeImage


def read(p):return json.loads((ROOT/p).read_text())
def sha(p):return hashlib.sha256((ROOT/p).read_bytes()).hexdigest()


def main():
    s=read('evidence/deep-research-state.json');f=s['native_app_music']['static_findings']
    item=f['native_music_loaded'];p=read(item['evidence']);b=read(p['build_manifest'])
    previous=read('staging/native-music-loaded/previous-checkpoint.json')
    before=read(previous['state']);audit=read(previous['audit'])
    for d in [p,b]:
        for path,h in d['source_sha256'].items():assert sha(path)==h,path
    assert sha(item['evidence'])==item['evidence_sha256']
    for path,h in [('combined_binary','combined_sha256'),('extension_flat','extension_flat_sha256'),
                   ('extension_elf','extension_elf_sha256'),('package','package_sha256')]:
        assert sha(b[path])==b[h],path
    assert p['build_manifest_sha256']==sha(p['build_manifest'])
    names=['native_voice_registry','native_voice_package_reads','native_voice_selection',
      'native_voice_outer','native_voice_compatibility','native_music_endpoint','native_music_configuration_gate',
      'native_music_policy','native_music_dispatch','native_l2cap_send','native_music_reply']
    frozen=[]
    for key in names:
        assert f[key]==before['native_app_music']['static_findings'][key],key
        old=read(f[key]['evidence']);assert sha(f[key]['evidence'])==f[key]['evidence_sha256'],key
        for path,h in old['source_sha256'].items():assert sha(path)==h,path
        frozen.append(old['case_count'])
    c={row['name']:row for row in p['cases']}
    chain=c['native_outer_load_bootstrap_owned_wire_lifecycle_and_TX_same_VM']
    public=read('reports/findings.json');task=read('evidence/task-state.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text();stock=NativeImage()
    original=(ROOT/b['original_binary']).read_bytes();combined=(ROOT/b['combined_binary']).read_bytes()
    checks={
      'fresh8_loaded_cases_current_sources_artifacts_all_pass':p['all_passed'] and p['case_count']==len(c)==8 and
          all(row['passed'] for row in p['cases']) and p['MAIN_sha256']==b['MAIN_sha256']==EXPECTED,
      'relinked_music_inside_original_reservation_original_bytes_retained':
          combined[12:len(original)]==original[12:] and struct.unpack_from('<2I',combined,4)==
          (b['combined_ram_bytes'],len(combined)) and b['combined_ram_bytes']==2462860 and
          b['remaining_reservation_bytes']==682868 and b['extension_bytes']==59987 and
          b['code_RX_data_RW_segments'] and all(x not in b['segments'] for x in ['RWE','INTERP','DYNAMIC']),
      'package_contiguous_capacity_original_other_members_preserved_emulation_only':
          b['package_checks']['DLL_blocks_contiguous'] and b['package_checks']['all_other_members_byte_identical'] and
          not b['package_checks']['signature_algorithm_or_enforcement_verified'] and 'EMULATION-ONLY' in b['package'],
      'loaded_original40_runtime_private12_music12_match':chain['load']['original40_and_full_original_runtime_preserved'] and
          chain['load']['private12_and_music12_linked_and_initialized'] and chain['load']['INIT_calls']==1 and
          chain['load']['loader_result']==11 and chain['load']['native_full_readback_sha256']==b['combined_sha256'],
      'eight_exact_guest_MAIN_changes40bytes_original_preflight_fixture':
          len(b['patch_plan'])==8 and b['VM_MAIN_patch_bytes']==40 and
          all(stock.read(x['address'],x['length']).hex()==x['before'] for x in b['patch_plan']) and
          chain['load']['guest_MAIN_write_bytes']==40 and p['guest_installs_MAIN_sites_no_host_dispatch_rewiring'],
      'same_VM_original_loader_bootstrap_native_wire_TX_lifecycle_loaded_callback':
          p['original_outer_loader_and_native_bootstrap_wire_TX_same_VM'] and all(chain['checks'].values()) and
          chain['load']['state']['published']==1 and chain['load']['state']['bootstrap_result']==0,
      'no_SDP_boot_no_patches_deferred_same_module_start':
          all(c[n]['checks'].values() for n in ['load_without_completed_SDP_boot_preserves_voice_and_MAIN',
              'same_loaded_module_start_after_native_boot_without_reload']),
      'last_site_preflight_rejects_without_partial_changes_busy_lock_active_controls':
          all(all(c[n]['checks'].values()) for n in ['last_site_mismatch_preflight_makes_no_partial_MAIN_changes',
              'occupied_SEP_slots_do_not_publish_or_overwrite','AVDTP_lock_failure_does_not_create_endpoint',
              'foreign_active_AudioSink_does_not_claim_publication']),
      'RX_control_fault_and_physical_cache_MMU_not_inferred':
          'UC_ERR_WRITE_PROT' in c['RX_MAIN_guest_write_fault_control']['error'] and
          p['MAIN_writability_cache_kernel_radio_storage_are_fixtures'],
      'callback_media_dropped_no_real_phone_speaker_App_menu_acceptance':
          p['native_callback_executes_but_media_is_explicitly_dropped'] and
          not p['native_phone_or_speaker_playback_verified'] and not p['real_package_acceptance_verified'] and
          not s['native_app_music']['native_app_running'] and not s['native_app_music']['direct_phone_music_verified'],
      'previous11_proofs_and16_scope_state_snapshot_preserved':
          frozen==[10,2,6,12,15,29,189,208,18,10,112] and audit['all_passed'] and
          len(audit['scope_checks'])==16 and audit['state_sha256']==sha(previous['state']),
      'canonical_task_public_scope31_percent34_details_taiwan_times':public['deep_research']==s and
          all(task[k]==s[k] for k in ['last_goal_turn','next_actions','attended_testing','ordered_priorities',
                                   'latest_user_instruction']) and public['research_progress']['estimate_percent']==31 and
          len(public['research_progress']['completed'])==34 and all(re.search('<time id="'+ident+
            '" datetime="[^\"]+\\+08:00"',report) for ident in ['report-updated-time','research-updated-time']),
      'public_new_stage_limits_visible_no_private_identifiers':
          all(t in report for t in ['8 個載入整合案例通過','最新：原生音樂元件與原廠載入流程已離線整合',
             '目前明確丟棄','可寫權限及快取同步由模擬環境提供','新語音封裝僅供離線研究']) and
          'REDACTED_PRIVATE_ID' not in report and not re.search(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',report),
      'away_no_device_IO_calls_sound_mic_canceled_goal_active_no_achieve':
          s['attended_testing']['waiting_for_user_return'] and not s['attended_testing']['user_present'] and
          s['attended_testing']['no_pending_question'] and not s['last_goal_turn']['device_io'] and
          not s['last_goal_turn']['device_files_written'] and not p['device_io'] and
          not p['device_install_candidate'] and not b['device_install_candidate'] and
          s['microphone_amplifier']['status']=='cancelled_by_user' and not s['microphone_amplifier']['next_actions'] and
          s['goal_status']=='active' and not s['goal_complete'] and s['required_work_remaining'] and
          s['latest_user_instruction']['goal_completion_forbidden_by_user'] and
          s['native_android_auto']['requested'] and s['google_maps']['research_deferred_by_user'],
    }
    assert all(checks.values()),[k for k,v in checks.items() if not v]
    path='evidence/firmware-analysis/native-music-loaded-checkpoint-audit.json'
    (ROOT/path).write_text(json.dumps({'updated_utc':datetime.now(timezone.utc).isoformat(),
      'all_passed':True,'scope_checks':checks,'state_sha256':sha('evidence/deep-research-state.json'),
      'report_sha256':sha('reports/nuvi2565RT.html'),'proof_sha256':sha(item['evidence']),
      'build_manifest_sha256':sha(p['build_manifest']),'audit_script_sha256':sha(str(Path(__file__).relative_to(ROOT))),
      'current_turn_device_IO':False,'device_install_candidate':False,'goal_status':'active','full_goal_complete':False},indent=2)+'\n')
    print(json.dumps({'audit':path,'scope_checks':len(checks),'all_passed':True}))


if __name__=='__main__':main()
