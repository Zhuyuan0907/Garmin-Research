#!/usr/bin/env python3
"""New-only ARM REL/glue host compile; no prior builder/emulator imports.

All writes stay in this exclusive directory. Old781/source manifests are
read and checked only. A REL artifact is not a combined DLL/VPM or runtime.
"""
import sys
sys.dont_write_bytecode = True
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess

OUT=Path(__file__).resolve().parent
ROOT=OUT.parents[2]
BUILD=OUT/'arm1176-rel-v1'
REPORT=OUT/'verification.json'
AUDIT=ROOT/'staging/native-player-dispatcher-native-body/previous-audit.json'
CONTINUOUS=ROOT/'staging/native-music-continuous/manifest.json'
PLAYER=ROOT/'staging/native-player-resources/manifest.json'
ADAPTER=ROOT/'staging/ui-music-native-adapter/verification.json'
CONTROL=ROOT/'staging/ui-music-control-prototype/verification.json'
SOURCE9=ROOT/'staging/native-player-task-runtime-full/source9-lifecycle-preflight.json'
PLAN=ROOT/'staging/native-player-task-runtime-full/single-bootstrap-ui-music-implementation-plan.json'
SDP=ROOT/'evidence/firmware-analysis/sdp-activation.json'

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def rel(path): return str(path.relative_to(ROOT))
def write_new(path,value):
    with path.open('x') as f: json.dump(value,f,ensure_ascii=False,indent=2); f.write('\n')
def check(reg):
    for name,digest in reg.items():
        if sha(ROOT/name)!=digest: raise ValueError('Changed source '+name)
def run(command):
    p=subprocess.run(command,cwd=ROOT,capture_output=True,text=True,timeout=60)
    return {'command':command,'exit_code':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

def main():
    if REPORT.exists() or BUILD.exists(): raise ValueError('Exclusive output already exists')
    audit=json.loads(AUDIT.read_text()); protected=audit['protected_sources']
    assert len(protected)==781; check(protected)
    prior={rel(p):json.loads(p.read_text()) for p in [CONTINUOUS,PLAYER,ADAPTER,CONTROL,SOURCE9]}
    dependency={}
    for record in prior.values():
        check(record['source_sha256'])
        for name,digest in record['source_sha256'].items():
            assert name not in dependency or dependency[name]==digest
            dependency[name]=digest
    BUILD.mkdir()
    common=['-std=c11','-Wall','-Wextra','-Werror','-Wshadow','-Wstrict-prototypes']
    arm=['-Os','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-ffreestanding',
         '-fno-builtin','-fno-pic','-fno-pie','-fdata-sections','-ffunction-sections',
         '-fno-unwind-tables','-fno-asynchronous-unwind-tables']
    sources=[ROOT/'native/ui-music-control-prototype/ui_music_control.c',
             ROOT/'native/ui-music-native-adapter/native_adapter.c',
             OUT/'ui_music_single.c',OUT/'ui_music_linked_bindings.c',OUT/'ui_music_menu.c']
    commands=[];objects=[]
    for n,source in enumerate(sources):
        obj=BUILD/(str(n)+'-'+source.stem+'.o'); objects.append(obj)
        commands.append(['arm-linux-gnueabi-gcc',*common,*arm,'-c',str(source),'-o',str(obj)])
    assembly=ROOT/'native/ui-music-native-adapter/cleanup_bridge.S'
    bridge=BUILD/'cleanup-bridge.o'; objects.append(bridge)
    commands.append(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft','-c',str(assembly),'-o',str(bridge)])
    elf=BUILD/'ui-music-single-bootstrap-relocatable.elf'
    commands.append(['arm-linux-gnueabi-gcc','-mcpu=arm1176jzf-s','-marm','-mfloat-abi=soft',
                     '-nostdlib','-no-pie','-r','-Wl,--build-id=none',*[str(p) for p in objects],'-o',str(elf)])
    host=BUILD/'host-single-controls-sanitized'
    commands.append(['gcc',*common,'-O2','-fsanitize=address,undefined','-fno-omit-frame-pointer',
                     str(sources[0]),str(sources[1]),str(OUT/'ui_music_single.c'),
                     str(OUT/'host_single_controls.c'),'-o',str(host)])
    executed=[]
    for n,cmd in enumerate(commands+[[str(host)]]):
        result=run(cmd); executed.append(result)
        write_new(BUILD/('command-'+str(n)+'.json'),result)
        if result['exit_code']:
            write_new(BUILD/'failed-attempt.json',{'updated_utc':datetime.now(timezone.utc).isoformat(),
                'command_index':n,'result':result,'source_sha256':{rel(p):sha(p) for p in OUT.glob('*') if p.is_file()},
                'old_sources_not_modified':True})
            raise RuntimeError('New-only compilation/control failed; preserved '+rel(BUILD/'failed-attempt.json'))
    host_results=json.loads(executed[-1]['stdout'])
    assert host_results['all_passed'] and host_results['group_count']==8 and host_results['complete_host_scenarios']==1
    assert not executed[-1]['stderr']
    queries={
        'ELF_header_attributes':['arm-linux-gnueabi-readelf','-h','-A',str(elf)],
        'ELF_sections':['arm-linux-gnueabi-readelf','-SW',str(elf)],
        'ELF_symbols':['arm-linux-gnueabi-readelf','-sW',str(elf)],
        'ELF_relocations':['arm-linux-gnueabi-readelf','-rW',str(elf)],
        'ELF_defined':['arm-linux-gnueabi-nm','-g','--defined-only',str(elf)],
        'ELF_undefined':['arm-linux-gnueabi-nm','-u',str(elf)],
        'ELF_size':['arm-linux-gnueabi-size',str(elf)],
        'entry_and_cleanup_disassembly':['arm-linux-gnueabi-objdump','-dr',str(objects[2]),str(bridge)]}
    output={}
    for name,cmd in queries.items():
        result=run(cmd); assert result['exit_code']==0; output[name]=result['stdout']
        with (BUILD/(name+'.txt')).open('x') as f: f.write(result['stdout'])
    attrs=output['ELF_header_attributes']; sections=output['ELF_sections']; undefined=output['ELF_undefined']
    assert 'Machine:                           ARM' in attrs and 'Type:                              REL' in attrs
    assert 'Tag_CPU_arch: v6' in attrs and 'Tag_ABI_VFP_args' not in attrs
    assert all(x not in sections for x in ['.interp','.dynamic','.dynsym'])
    assert '.data.native_ui_music_entry_phase' in sections and '.bss.native_ui_music_resident' in sections
    guard=BUILD/'entry-guard-initialized-data.bin'
    result=run(['arm-linux-gnueabi-objcopy','--dump-section','.data.native_ui_music_entry_phase='+str(guard),str(elf)])
    assert result['exit_code']==0 and guard.read_bytes()==bytes.fromhex('31534955')
    names=sorted(line.split()[-1] for line in undefined.splitlines() if line.strip())
    expected=sorted(['anchor_zero','coordinator_state','media_queue_control','media_worker_state',
        'memory_output_control','memory_output_slots','music_runtime_cancel','music_runtime_state',
        'native_app_component_entry','owned_media_control','source_worker_completed','source_worker_state'])
    assert names==expected,(names,expected)
    assert 'native_music_component_entry' not in output['ELF_defined']+undefined
    assert 'native_player_component_entry' not in output['ELF_defined']+undefined
    assert 'umcn_fill_exact_continuous_bindings' not in output['ELF_defined']+undefined
    assert '003b9e07' in output['entry_and_cleanup_disassembly']
    size_line=output['ELF_size'].splitlines()[1].split(); text_bytes,data_bytes,bss_bytes=map(int,size_line[:3])
    continuous=prior[rel(CONTINUOUS)]; player=prior[rel(PLAYER)]; source9=prior[rel(SOURCE9)]
    sdp=json.loads(SDP.read_text())
    requirements={
        'sole_bootstrap': {'resolved_candidate_symbol':'native_ui_music_single_entry','unresolved_common_symbol':'native_app_component_entry',
            'calls_common_once':True,'guard_initialized_data_hex':guard.read_bytes().hex(),
            'required_final_layout':'Keep .data.native_ui_music_entry_phase outside __app_zero_start/end; include all NEW BSS in common zero-span; preserve original TTS40; original loader serialization/pinning/no reload still required.',
            'old_entries_not_linked_or_called':['native_music_component_entry','native_player_component_entry']},
        'GUI': {'candidate_install':'native_ui_music_menu_install','registry_original_getter':'0x31590b',
            'Grid_record_bytes':100,'launch_offset':84,'context_offset':88,'appearance_offset':96,
            'icon_id':'0x7f135201','context':'0x13528000','borrowed_icon_hash':'0x08a56eac',
            'original_helpers':{'string_ctor':'0x39274f','grid_ctor':'0x498fc4','append':'0x31592b','grid_dtor':'0x399088','string_dtor':'0x392773'},
            'required_owner_input':'actual live GUI/Dispatcher TCB; must separately observe original native queued launch, resource/font/SQL/render/frame lifetimes',
            'duplicate_known_id_returns':2,'already_registered_old_player_record_replaced':False,
            'integration_change':'A new sole entry/deferred GUI registration must use this installer before legacy player ID exists. Existing immutable menu record is not patched live.',
            'page_or_two_button_ABI_invented':False,'native_GUI_constructor_or_touch_executed_by_this_test':False},
        'runtime_boot': {'actual_existing_API':'music_runtime_boot(uint32_t channel,uint32_t decoder_priority,uint32_t source_priority)',
            'candidate_first_route_args':[8,36,40],'auto_called_by_candidate':False,
            'deferred_guard':'Original radio/SDP/driver and exclusive channel inventory complete; source init full return owner/result and both entered persistent actors required before umcn_owner_ready.',
            'known_continuous_radio_fixture_entries':['0x4ccfb4','0x4ccc3c','0x5d7588'],
            'physical_radio_or_HFP_boot_recovered':False,
            'stock_Handsfree_static_activation':[r for r in sdp['resolved_direct_activation_paths'] if r['service']=='Handsfree'],
            'HFP_preservation':'Existing stock Handsfree90005 connection/service must remain owned by stock. Do not rerun generic SDP initializer after live profiles as it initializes only SDP active. Three fixture radio entries are not a full HFP or physical stack boot contract.',
            'endpoint_API':'native_music_start() installs11 exact patch sites/publishes Sink90007 after prerequisites; existing current variant VM MAIN patch64 bytes, not unchanged-MAIN integration.'},
        'same_image_symbols': {name:{'role':'original-TTS common bootstrap' if name=='native_app_component_entry' else 'same relinked continuous module symbol',
            'old_continuous_address_inherited':False} for name in names},
        'missing_native_ownership': {'required_callback':'umcn_bindings.ownership_snapshot',
            'must_supply':'Serialized generation/cookie/source token/channel8/owner TCB/epoch and actual exclusion of independent writers plus future borrowing callbacks; no cookie/IRQ/count0 substitute.',
            'provided':False},
        'missing_session': {'required_callback':'umcn_bindings.prepare_session','must_supply':'Characterized AV-mutex coherent session/queue epoch resume or await actual remote START; cannot fabricate SEP state/event17/packet.', 'provided':False},
        'source_loop': {'service':'native_ui_music_service_owner','ready':'native_ui_music_owner_ready',
            'event':'0x80000','call_site_installed':False,
            'required_change':'NEW copy of source_worker_entry lines44-75 must consume controller pending on same source TCB; call owner_ready only after full coordinator initializer; service before pump/cancel as characterized and again after native return. Frozen loop currently consumes pending and only pump/cancel, so link alone does not service new control.'},
        'publication': {'candidate':'native_ui_music_note_publication','call_site_installed':False,
            'boundary':'Original owned registration returned, coordinator/output/slot true token, before native36B721 START; no supplied fake handle.'},
        'iteration': {'candidate':'native_ui_music_after_iteration','call_site_installed':False,
            'boundary':'Only after actual source cancel/pump returns and source_worker lines71-72 clear cancel_requested; pass unchanged actualresult. Real counters/remove/release/FIFO return barriers required.'},
        'cleanup': {'candidate':'umcn_cleanup_bridge','native_site':'0x3b9dfc','resume':'0x3b9e07','signature':'single-r0 source record; preserved r4-r8/LR and original result;64-byte frame/aligned8',
            'site_installed':False,'whole_callback_until_full_original_return':True,
            'binding_rule':'Use exactly one replacement instead of old source_completion_hook; forward unchanged source_worker_completed; never run both original cleanups.'},
        'admission': {'candidate':'native_ui_music_admission','call_sites_installed':False,
            'required_sites':{'configuration':'music_stream_configuration_gate','remote_START':'music_runtime_start_gate','event17':'music_stream_callback event0x17','F1':'music_stream_callback event0xf1','consumer':'music_stream_consume'},
            'additional_lease_calls':['native_ui_music_media_begin','native_ui_music_media_current','native_ui_music_media_end'],
            'scope':'Admission gate alone is insufficient; actual media/selected consumer references must span use and recheck generation/session; preserve original policy/syntax/locks/queue epochs.'},
        'source9': {'candidate_support':'UNSUPPORTED_ROUTE/fail closed','actual_mapping':source9['source9_mapping'],
            'register':'525F14 ARM veneer→27058B:9,22,11,path,38,0,0; clears existingqueue before registration, so foreign occupancy must reject before call',
            'START':'36B721 original synchronous class2/opcode1; not stop/refresh',
            'STOP':'36AF75 original asynchronous class2/opcode3;30EDD4 ignores sendresult and returns0; no STOP_DONE',
            'clear':'270537 only after independently proven native quiescence and owned node consistency',
            'heap_callback':'388746 pre-core callback when descriptor flag&6==6; callback outside heapmutex while source/list locks mayremain held',
            'release':'388676 mutates allocator/zeros caller opaquehandle aftercallback; notaudio stop/unload and not guessed structlayout',
            'missing':'Route9 owned node/provider/native stop completion and original clear/callback/core-release returned witnesses; current channel8 source completion filter does not handle9',
            'no_direct_clear_release_or_WAV_registration_called_by_candidate':True},
        'minimal_next_test_boundaries':['First relink sole entry/common/newBSS/data guard and calculate complete symbol/import/hook map in NEW layout; verify40 exports and repeated-entry refusal without any worker/UI boot.',
            'On actual original GUI actor, register known one ID before legacy entry, observe native registry callback copy, appearance/font/SQL/resource guards and queued launch; no hostdirect callback as touchproof.',
            'In a separate NEW native runtime, supply actual ownership/session bindings and wire same-source loop/publication/fullcleanup/iteration/media admission; execute START→STOP→delayedcallback→completion→restart through original kernel queue. Current REL does not prove that integration.',
            'Route9 remains separate until exact owned WAV lifecycle witnessed; do not use diagnosticWAV/hardware success as App/directphone proof.']}
    required=OUT/'required-native-adapters.json'; write_new(required,requirements)
    for p in [AUDIT,CONTINUOUS,PLAYER,ADAPTER,CONTROL,SOURCE9,PLAN,SDP,
              ROOT/'scripts/emulate_native_music_ready.py', ROOT/'native/music-continuous/entry.c',
              ROOT/'native/music-continuous/runtime.c',ROOT/'native/music-continuous/stream.c',
              ROOT/'native/sbc-prototype/source_worker.c',ROOT/'native/sbc-prototype/app_component_entry.c',
              ROOT/'native/player-menu-loaded/entry.c',ROOT/'native/player-resources/player_menu.c',required]:
        dependency[rel(p)]=sha(p)
    for p in OUT.iterdir():
        if p.is_file(): dependency[rel(p)]=sha(p)
    artifacts={rel(p):sha(p) for p in BUILD.iterdir() if p.is_file()}
    check(protected);check(dependency)
    report={
        'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','MAIN_sha256':'10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'},
        'all_passed':True,'source_sha256':dict(sorted(dependency.items())),
        'protected_registry':{'snapshot':rel(AUDIT),'sha256':sha(AUDIT),'count':781,'checked_all_before_and_after':True,'unchanged':True},
        'compiled_new_sources':[rel(p) for p in sources if p.parent==OUT],
        'compiled_frozen_readonly_sources':[rel(p) for p in sources if p.parent!=OUT]+[rel(assembly)],
        'compiled_existing_build_objects_used':False,'original_imports_old_absolute_map_compiled':False,
        'ARM_artifact':{'path':rel(elf),'sha256':sha(elf),'machine':'ARM','type':'REL','CPU':'ARM1176/ARMv6','soft_float':True,
            'text_bytes':text_bytes,'data_bytes':data_bytes,'BSS_bytes':bss_bytes,'undefined_symbols':names,
            'Linux_or_dynamic_loader_dependency':False,'executable_loader_image':False,'combined_DLL_or_VPM_generated':False,
            'initialized_once_guard':{'path':rel(guard),'bytes_hex':guard.read_bytes().hex(),'ELF_section':'.data.native_ui_music_entry_phase',
                                     'final_zero_span_exclusion_still_requires_relink':True}},
        'actual_symbol_and_relocation_artifacts':{k:rel(BUILD/(k+'.txt')) for k in queries},
        'required_native_adapters_manifest':{'path':rel(required),'sha256':sha(required)},
        'compilation':executed[:-1],'host_tests':host_results,'host_execution':executed[-1],
        'host_ASan_UBSan':True,'host_tests_are_not_native_IRQ_audio_GUI_or_ownership_proof':True,
        'layout_constraints':{'same_extension_base':continuous['extension_base'],'current_continuous_code_bytes':continuous['extension_bytes'],
            'current_code64KiB_free_bytes':65536-continuous['extension_bytes'],'new_REL_text_bytes':text_bytes,
            'current_player_code_bytes':player['extension_bytes'],'current_player_MAIN_patch_bytes':player['VM_MAIN_patch_bytes'],
            'current_continuous_MAIN_patch_bytes':continuous['VM_MAIN_patch_bytes'],
            'remaining_original3MiB_reservation_bytes':continuous['remaining_reservation_bytes'],
            'REL_section_sum_is_not_final_link_size':True,'at_least_larger_than_current64KiB_required':text_bytes>65536-continuous['extension_bytes'],
            'future128KiB_code_layout_is_candidate_not_verified_executable_or_accepted_space':True,
            'requires_recalculated':['all namedstate pointers','source/playback generated imports','AVDTP11-site targets','BSS/PCM/queue/stack/commonzero boundaries'],
            'old_GUI_and_continuous_entries_share_base_and_must_not_be_loaded_over_each_other':True},
        'artifacts_sha256':artifacts,
        'missing_binding_or_runtime_flags':{'native_channel8_exclusivity':True,'AV_locked_session_prepare':True,'source_loop_callsite':True,
            'publication_iteration_callsite':True,'full_cleanup_MAIN_hook_install':True,'five_admission_and_media_lease_calls':True,
            'physical_radio_or_HFP_boot':True,'source9_owned_stop_clear_release':True,'native_GUI_launch_render_touch':True,
            'final_single_image_relink':True,'physical_modified_package_or_code_acceptance':True},
        'limits':{'guest_or_emulator_executed':False,'device_service_IO':False,'sounds_emitted':False,
            'existing_sources_builds_manifests_proofs_canonical_report_modified':False,
            'runtime_781_snapshot_integrity_verified':True,'single_bootstrap_resident_no_reset_unload_free_design':True,
            'integrated_native_kernel_GUI_audio_proven':False,'physical_App_direct_A2DP_completed':False,
            'package_SIG_publickey_enforcement_and_modified_code_acceptance':'unknown; unchanged by compile-only result',
            'device_install_candidate':False,'goal_active':True,'AA_Maps':'deferred'}
    }
    write_new(REPORT,report)
    print(json.dumps({'report':rel(REPORT),'sha256':sha(REPORT),'ARM_REL':rel(elf),'ARM_REL_sha256':sha(elf),
        'source_sha256_count':len(dependency),'undefined_symbols':names,'host_groups':8,'host_scenarios':1,'protected_unchanged':781,
        'text_bytes':text_bytes,'data_bytes':data_bytes,'BSS_bytes':bss_bytes,'native_execution':False}))

if __name__=='__main__':main()
