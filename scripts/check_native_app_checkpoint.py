#!/usr/bin/env python3
"""Audit the saved combined-component checkpoint and frozen predecessor proof."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from analyze_native_sections import ROOT
from emulate_native_memory_notice import check_manifest


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    def read(name):
        return json.loads((ROOT/name).read_text())
    app_name='evidence/firmware-analysis/native-app-component-emulation.json'
    mount_name='evidence/firmware-analysis/native-voice-mount-static.json'
    app,mount=read(app_name),read(mount_name)
    for obj in (app,mount):
        for p,expected in obj['source_sha256'].items():
            assert sha(ROOT/p)==expected,p
    old_name='evidence/firmware-analysis/native-source-worker-emulation.json'
    old=read(old_name)
    assert sha(ROOT/'scripts/emulate_native_source_worker.py')==old['script_sha256']
    for p,expected in old['dependency_sha256'].items():
        assert sha(ROOT/p)==expected,p
    previous=read('evidence/firmware-analysis/native-source-worker-checkpoint-audit.json')
    assert sha(ROOT/old_name)==previous['evidence_sha256']
    compiled={}
    for directory,expected in previous['compiled_manifests'].items():
        m=check_manifest(ROOT/'staging'/directory/'manifest.json')
        assert m['elf_sha256']==expected,directory
        compiled[directory]=expected
    for voice in app['voices']:
        m=read(voice['manifest'])
        for field,hash_field in (('extension_elf','extension_elf_sha256'),
          ('extension_flat','extension_flat_sha256'),('combined_binary','combined_sha256')):
            assert sha(ROOT/m[field])==m[hash_field],m[field]
        for p,expected in m['source_sha256'].items():
            assert sha(ROOT/p)==expected,p
        assert m['combined_ram_bytes']<=m['reservation_bytes']==0x300000
    state=read('evidence/deep-research-state.json')
    findings=read('reports/findings.json')
    assert findings['deep_research']==state
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    f=state['native_app_music']['static_findings']['native_app_component']
    checks={
      'three_voices':app['all_passed'] and app['voice_count']==3,
      'decoder_frames':app['decoded_frames']==18,
      'original_exports':all(v['original_40_exports_and_trampolines_identical'] for v in app['voices']),
      'original_tail':all(v['original_bss_tail_difference_count']==0 for v in app['voices']),
      'private_api':all(v['private_api_pointers_verified']==12 for v in app['voices']),
      'reserved_storage':all(v['all_storage_within_original_3MiB_reservation'] for v in app['voices']),
      'original_api_query':sum(len(v['original_query_calls']) for v in app['voices'])==6,
      'voice_id_units':mount['voice_record_fields']['volume_id']['maximum_copied_bytes']==40,
      'full_relocated_pipeline_gap':not f['full_relocated_workers_and_hooks_executed'] and
         '只執行載入入口、解碼器和該查詢' in report,
      'signature_acceptance_gap':not f['signature_acceptance_verified'] and
         not mount['signature_enforcement_verified'],
      'original_worker_proof_retained':old['all_passed'] and len(old['routes'])==6,
      'report_current':str(f['appended_code_bytes']) in report and str(f['decoded_frames']) in report,
      'no_device_io':not app['device_io'] and not mount['device_io'],
      'not_installed_app':not app['device_install_candidate'] and
         not state['native_app_music']['native_app_running'] and
         not state['native_app_music']['direct_phone_music_verified'],
      'full_goal_and_maps_status':state['goal_status']=='active' and not state['goal_complete']
         and state['google_maps']['research_deferred_by_user'],
      'saved_evidence_hash_current':f['evidence_sha256']==sha(ROOT/app_name)
    }
    assert all(checks.values()),checks
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'scope_checks':checks,
      'all_passed':True,'app_evidence_sha256':sha(ROOT/app_name),
      'mount_evidence_sha256':sha(ROOT/mount_name),'state_sha256':sha(ROOT/'evidence/deep-research-state.json'),
      'report_sha256':sha(ROOT/'reports/nuvi2565RT.html'),
      'new_dependencies_checked':len(app['source_sha256']),
      'previous_dependencies_checked':len(old['dependency_sha256']),
      'unchanged_compiled_manifests':compiled,'combined_manifests_checked':3,
      'physical_goal_complete':False,'device_io':False,'goal_status':'active',
      'audit_script_sha256':sha(Path(__file__))}
    path=ROOT/'evidence/firmware-analysis/native-app-component-checkpoint-audit.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'audit':str(path.relative_to(ROOT)),'all_passed':True,
                     'scope_checks':len(checks),'new_dependencies':len(app['source_sha256']),
                     'old_dependencies':len(old['dependency_sha256'])}))


if __name__=='__main__':main()
