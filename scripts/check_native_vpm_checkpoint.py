#!/usr/bin/env python3
"""Audit the DSK filesystem proof, frozen playback and current stated scope."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
from analyze_native_sections import ROOT,NativeImage
from emulate_native_memory_notice import check_manifest


def read(path):return json.loads((ROOT/path).read_text())
def digest(path):return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()


def main():
    stock=NativeImage()
    proof_name='evidence/firmware-analysis/native-vpm-filesystem-emulation.json'
    static_name='evidence/firmware-analysis/native-vpm-filesystem-static.json'
    proof,static=read(proof_name),read(static_name)
    previous=read('evidence/firmware-analysis/native-loaded-playback-emulation.json')
    dependency_counts={}
    for name in (proof_name,static_name,
                 'evidence/firmware-analysis/native-loaded-playback-emulation.json',
                 'evidence/firmware-analysis/native-app-component-emulation.json'):
        deps=read(name)['source_sha256']
        for path,expected in deps.items():assert digest(path)==expected,path
        dependency_counts[name]=len(deps)
    old=read('evidence/firmware-analysis/native-source-worker-checkpoint-audit.json')
    unchanged={}
    for name,expected in old['compiled_manifests'].items():
        m=check_manifest(ROOT/'staging'/name/'manifest.json')
        assert m['elf_sha256']==expected,name
        unchanged[name]=expected
    combined=[]
    for path in sorted((ROOT/'staging/native-app-component-emulation').glob('*/manifest.json')):
        m=json.loads(path.read_text())
        for filekey,hashkey in (('extension_elf','extension_elf_sha256'),
                               ('extension_flat','extension_flat_sha256'),
                               ('combined_binary','combined_sha256')):
            assert digest(m[filekey])==m[hashkey],m[filekey]
        for name,expected in m['source_sha256'].items():assert digest(name)==expected,name
        combined.append(str(path.relative_to(ROOT)))
    backup=read('evidence/firmware-analysis/tts-vpm-containers.json')
    packages=[r for r in backup['containers'] if r['native_module_container']]
    for row in packages:assert digest(row['file'])==row['sha256'],row['file']
    reference_inputs=read('evidence/firmware-analysis/native-loaded-playback-checkpoint-audit.json')[
        'additional_reference_inputs_hashes_audited_after_run']
    for path,expected in reference_inputs.items():assert digest(path)==expected,path
    state=read('evidence/deep-research-state.json')
    report=(ROOT/'reports/nuvi2565RT.html').read_text()
    latest=state['native_app_music']['static_findings']['native_vpm_filesystem']
    cases=proof['cases'];changes=proof['memory_only_content_controls'];rejects=proof['header_rejection_controls']
    scope={
        'three_original_packages':len(cases)==3 and
            {r['voice'] for r in cases}=={Path(r['file']).name for r in packages},
        'full_original_lengths':[r['dll_bytes'] for r in cases]==[2295424,2400048,1858024],
        'original_modules_match_backup':all(r['dll_sha256']==p['files']['DLLIMG.BIN']['sha256']
            and r['package_sha256']==p['sha256'] for r,p in zip(cases,packages)),
        'original_native_loader_returns11':all(r['original_loader']['status']==11 for r in cases),
        'all5_original_file_callbacks_executed':all(
            len(r['original_loader']['file_callback_entries_executed_during_load'])==5 and
            all(r['original_loader']['file_callback_entries_executed_during_load'].values()) for r in cases),
        'callback_bytes_unchanged':all(r['original_loader']['stock_callback_block_unchanged_before_after_sha256']==
            hashlib.sha256(stock.read(0x1fb2f8,0xf0)).hexdigest() for r in cases),
        'runtime_and40_trampolines_match_control':all(
            r['original_loader']['matches_independent_original_loader_control'] and
            r['original_loader']['original40_trampolines_match'] for r in cases),
        'native_DSK_and_allocation_paths_executed':all(all(r['original_functions_executed'][hex(a)]>0
            for a in (0x1e86ce,0x1e8046,0x2fb988,0x123f6c,0x11d678,0x123920,0x3324b8))
            for r in cases+changes),
        'native_files_closed_and_missing_rejected':all(r['all_native_file_objects_closed'] and
            r['missing_file_rejected'] for r in cases+changes),
        'two_memory_content_controls':len(changes)==2,
        'checksum_mismatch_readable':changes[0]['kind']=='dll_payload_changed_metadata_sum_stale' and
            not changes[0]['metadata_byte_sum_matches'] and changes[0]['dll_sha256']!=cases[0]['dll_sha256'],
        'zero_SIG_readable':changes[1]['kind']=='signature_content_zeroed' and
            changes[1]['signature_bytes']==72 and
            changes[1]['signature_sha256']==hashlib.sha256(bytes(72)).hexdigest() and
            changes[1]['dll_sha256']==cases[0]['dll_sha256'],
        'modified_contents_never_executed':all(r['original_loader'] is None and
            not r['modified_instructions_executed'] and not r['file_read_output_executed_as_code'] and
            r['original_functions_executed']['0x23c3c4']==0 for r in changes),
        'four_header_controls_rejected':len(rejects)==4 and
            {r['kind'] for r in rejects}=={'bad_image_magic','bad_vendor_magic','invalid_sector_size','short_initial_sector'} and
            all(not r['active_volume'] and r['original_remount_and_parser_executed'] for r in rejects),
        'all_native_cases_passed':proof['all_passed'] and all(r['all_passed'] for r in cases+changes+rejects),
        '26_complete_static_CFGs':len(static['functions'])==26 and all(not f['instruction_limit_reached'] and
            not f['unresolved_exits'] for f in static['functions'].values()),
        'outer_FAT_and_inner_DSK_distinct':static['generic_outer_filesystem']['type1_file_open']=='0x3a1318' and
            static['embedded_container_filesystem']['parser']=='0x1e8046' and
            static['mapped_region_clarification']['earlier_2D3166_mount_label_was_only_mapped_file_setup'],
        'evidence_state_hashes_current':latest['evidence_sha256']==digest(proof_name) and
            latest['static_evidence_sha256']==digest(static_name),
        'report_state_current':read('reports/findings.json')['deep_research']==state,
        'report_scope_current':'最新已識別外層 FAT 驅動註冊與內層 DSKIMG 解析器' in report and
            '兩個只存在記憶體的控制組' in report and '不能推論高層語音選取不檢查簽章' in report,
        'legacy_playback_proof_preserved':previous['all_passed'] and len(previous['routes'])==6 and
            len(previous['cancellation'])==3 and not previous['old_compiled_artifacts_changed'],
        'filesystem_not_misclaimed_as_combined_playback':not latest['test_and_loaded_playback_integrated_in_same_VM'],
        'no_actual_App_phone_speaker_goal_completion':not state['native_app_music']['native_app_running'] and
            not state['native_app_music']['direct_phone_music_verified'] and not state['goal_complete'],
        'goal_active_and_Maps_deferred':state['goal_status']=='active' and
            state['google_maps']['research_deferred_by_user'] and state['required_work_remaining'],
        'high_level_acceptance_not_proven':not proof['signature_enforcement_verified'] and
            not latest['higher_signature_policy_or_modified_package_acceptance_verified'],
        'no_device_IO_or_install_candidate':not proof['device_io'] and not static['device_io'] and
            not proof['device_install_candidate'] and not static['device_install_candidate'],
        'three_combined_and_six_old_builds_preserved':len(combined)==3 and len(unchanged)==6,
        'progress_after_previous_status_turn':state['last_goal_turn']['classification']=='progress' and
            state['last_goal_turn']['previous_goal_turn_classification']=='no_progress'
    }
    assert all(scope.values()),{k:v for k,v in scope.items() if not v}
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'all_passed':True,'scope_checks':scope,
         'evidence_sha256':digest(proof_name),'static_sha256':digest(static_name),
         'state_sha256':digest('evidence/deep-research-state.json'),
         'report_sha256':digest('reports/nuvi2565RT.html'),'dependency_counts_checked':dependency_counts,
         'legacy_reference_inputs_preserved':reference_inputs,
         'unchanged_old_builds':unchanged,'unchanged_combined_manifests':combined,
         'audit_script_sha256':digest(str(Path(__file__).relative_to(ROOT))),
         'goal_status':'active','full_goal_complete':False,'device_io':False}
    path=ROOT/'evidence/firmware-analysis/native-vpm-filesystem-checkpoint-audit.json'
    path.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps({'audit':str(path.relative_to(ROOT)),'all_passed':True,'scope_checks':len(scope),
                     'filesystem_dependencies':len(proof['source_sha256']),
                     'frozen_playback_dependencies':len(previous['source_sha256'])}))


if __name__=='__main__':main()
