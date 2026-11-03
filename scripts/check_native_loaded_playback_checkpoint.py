#!/usr/bin/env python3
"""Audit full loaded-playback evidence, preserved builds and report scope."""
from datetime import datetime,timezone
import json
from pathlib import Path
from analyze_native_sections import ROOT
from emulate_native_audio_registration import sha
from emulate_native_memory_notice import check_manifest
from emulate_native_sbc import Reference


def read(name):return json.loads((ROOT/name).read_text())
def digest(name):return sha((ROOT/name).read_bytes())


def main():
    proof_name='evidence/firmware-analysis/native-loaded-playback-emulation.json'
    static_name='evidence/firmware-analysis/native-voice-acceptance-static.json'
    proof,static=read(proof_name),read(static_name)
    for name in (proof_name,static_name,'evidence/firmware-analysis/native-app-component-emulation.json'):
        for path,expected in read(name)['source_sha256'].items():
            assert digest(path)==expected,path
    previous=read('evidence/firmware-analysis/native-source-worker-checkpoint-audit.json')
    builds={}
    for name,expected in previous['compiled_manifests'].items():
        m=check_manifest(ROOT/'staging'/name/'manifest.json');assert m['elf_sha256']==expected,name
        builds[name]=expected
    combined=[]
    for path in sorted((ROOT/'staging/native-app-component-emulation').glob('*/manifest.json')):
        m=json.loads(path.read_text())
        for key,h in (('extension_elf','extension_elf_sha256'),('extension_flat','extension_flat_sha256'),
                      ('combined_binary','combined_sha256')):
            assert digest(m[key])==m[h],m[key]
        for name,h in m['source_sha256'].items():assert digest(name)==h,name
        combined.append(str(path.relative_to(ROOT)))
    converter=check_manifest(ROOT/'staging/native-pcm-converter/manifest.json')
    assert digest(converter['coefficient_table'])==converter['coefficient_table_sha256']
    reference=Reference()
    recorded_inputs={'staging/native-pcm-converter/manifest.json':digest('staging/native-pcm-converter/manifest.json'),
        converter['coefficient_table']:digest(converter['coefficient_table']),
        str(reference.library_path):sha(reference.library_path.read_bytes())}
    state=read('evidence/deep-research-state.json');assert read('reports/findings.json')['deep_research']==state
    report=(ROOT/'reports/nuvi2565RT.html').read_text();s=state['native_app_music']['static_findings']
    latest=s['native_loaded_playback'];all_cases=proof['routes']+proof['cancellation']
    scope={
      'six_rotating_streams':len(proof['routes'])==6 and proof['test_matrix_is_rotating_formats_not_full18_cross_product'],
      'three_voice_placements':len({c['component']['manifest'] for c in all_cases})==3,
      'three_cancel_cases':len(proof['cancellation'])==3,
      'stream_sixty_frames':proof['decoded_stream_frames']==60,
      'source_and_virtual_pcm':proof['source_pcm_bytes']==8688 and proof['virtual_stereo_bytes']==17376,
      'guarded_reads':sum(r['guarded_reads'] for r in proof['routes'])==60,
      'real_ack_checks':sum(len(r['native_synchronous_start_returns']) for r in proof['routes'])==30,
      'publication_during_wait':sum(r['publication_during_synchronous_start'] for r in proof['routes'])==12,
      'twelve_cancelled_buffers':sum(r['coordinator']['discarded'] for r in proof['cancellation'])==12,
      'nine_unplayed_buffers':sum(r['unplayed_ready_sources_cancelled_without_reads'] for r in proof['cancellation'])==9,
      'no_host_pump_or_notify':all(not c['host_coordinator_pump_or_notify'] for c in all_cases),
      'same_vm_loader_and_playback':all(c['component']['component_loaded_and_played_in_same_vm'] and
         c['component']['loaded_report']['same_vm_as_native_kernel'] for c in all_cases),
      'legacy_code_excluded':all(not c['component']['legacy_custom_code_used_after_load'] for c in all_cases),
      'original_voice_preserved':all(c['component']['original_voice_runtime_and40_api_pointers_preserved'] for c in all_cases),
      'retained_tasks_not_safe_unload':all(not c['component']['safe_unload_verified'] for c in all_cases),
      'metadata_13_cases_resolved':len(static['metadata_postprocess']['cases'])==13,
      'driver_acceptance_still_unknown':not static['generic_file_open']['actual_voice_drive_ops_or_mount_initialization_identified'],
      'latest_evidence_current':latest['evidence_sha256']==digest(proof_name) and
         s['native_voice_acceptance']['evidence_sha256']==digest(static_name),
      'report_scope_current':'同一個模擬系統中串接原廠載入器與完整播放' in report and
         '沒有測完全部十八種組合' in report and '三個語音版本各通過取消測試' in report and
         '尚未重跑移動後的工作／事件／播放流程' not in report,
      'real_app_and_phone_incomplete':not state['native_app_music']['native_app_running'] and
         not state['native_app_music']['direct_phone_music_verified'] and
         '原生 App 與手機直接音樂播放尚未達成' in report,
      'full_goal_and_maps_defer':state['goal_status']=='active' and not state['goal_complete'] and
         state['google_maps']['research_deferred_by_user'],
      'no_device_io_or_install_candidate':not proof['device_io'] and not proof['device_install_candidate'],
      'all_evidence_cases_passed':proof['all_passed'] and all(c['passed'] for c in all_cases)
    }
    assert all(scope.values()),scope
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':scope,
      'evidence_sha256':digest(proof_name),'static_sha256':digest(static_name),
      'state_sha256':digest('evidence/deep-research-state.json'),'report_sha256':digest('reports/nuvi2565RT.html'),
      'recorded_execution_dependencies_checked':len(proof['source_sha256']),
      'additional_reference_inputs_hashes_audited_after_run':recorded_inputs,
      'reference_version':reference.version,'unchanged_old_compiled_manifests':builds,
      'combined_manifests_checked':combined,'audit_script_sha256':sha(Path(__file__).read_bytes()),
      'physical_goal_complete':False,'device_io':False,'goal_status':'active'}
    path=ROOT/'evidence/firmware-analysis/native-loaded-playback-checkpoint-audit.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'audit':str(path.relative_to(ROOT)),'all_passed':True,'scope_checks':len(scope),
                     'execution_dependencies':len(proof['source_sha256']),'unchanged_old_builds':len(builds)}))


if __name__=='__main__':main()
