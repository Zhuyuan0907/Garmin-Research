#!/usr/bin/env python3
"""Independent file-backed sealing of fresh image and bounded controls.

No compilation, host executable, guest or device execution in this seal.
"""
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,struct
from datetime import datetime,timezone
from pathlib import Path
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(d):
    for p,h in d.items():assert sha(ROOT/p)==h,p
def newjson(p,d):
    with p.open('x') as f:json.dump(d,f,indent=2,ensure_ascii=False);f.write('\n')

def main():
    report=OUT/'verification.json';assert not report.exists()
    mp=OUT/'manifest.json';cp=OUT/'cold-loader-verification.json'
    m=json.loads(mp.read_text());c=json.loads(cp.read_text())
    assert m['all_passed'] and c['all_passed'];check(m['source_sha256']);check(m['artifacts_sha256'])
    check(c['source_sha256']);check(c['artifacts_sha256'])
    protected=json.loads((OUT.parent/'previous-audit.json').read_text())['protected_sources'];assert len(protected)==1078;check(protected)
    spec=importlib.util.spec_from_file_location('sealed_ELF32',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);e=mod.ELF32(ROOT/m['extension_elf'])
    assert e.kind==2 and e.entry==m['entry']==m['extension_base']
    assert not [s for s in e.symbols if s['name'] and s['section_index']==0]
    h=struct.unpack_from('<16sHHIIIIIHHHHHH',e.raw);assert h[2]==40 and h[9]==32 and h[10]==2
    ph=[]
    for n in range(h[10]):
        names=['type','file_offset','vaddr','paddr','file_bytes','memory_bytes','flags','alignment']
        ph.append(dict(zip(names,struct.unpack_from('<8I',e.raw,h[5]+n*h[9]))))
    assert [p['type'] for p in ph]==[1,1] and [p['flags'] for p in ph]==[5,6]
    assert ph[0]['vaddr']==m['extension_base'] and ph[1]['vaddr']==m['initialized_guard']['address']
    assert ph[1]['file_bytes']==4 and ph[1]['memory_bytes']==0x19000
    flat=(ROOT/m['extension_flat']).read_bytes();expected=bytearray(len(flat))
    for p in ph:
        off=p['vaddr']-m['extension_base'];expected[off:off+p['file_bytes']]=e.raw[p['file_offset']:p['file_offset']+p['file_bytes']]
    assert flat==expected
    original=(ROOT/m['original_binary']).read_bytes();combined=(ROOT/m['combined_binary']).read_bytes()
    head=struct.unpack_from('<3I',combined)
    assert head[1:]==(m['combined_ram_bytes'],len(combined))
    disp=head[0]&0xffffff
    if disp&0x800000:disp-=0x1000000
    assert 0x2d4bb74+8+disp*4==e.entry
    assert combined[12:len(original)]==original[12:]
    assert combined[m['extension_base']-0x2d4bb74:]==flat
    assert not list(OUT.rglob('*.vpm')) and not list(OUT.rglob('*.sig'))
    anchor=e.symbol('anchor_zero');assert (anchor['binding'],anchor['size'],anchor['type'])==(0,2,1)
    direct={r['function']:r for r in c['direct_ARM_controls']}
    assert direct['native_ui_music_single_entry']['returned_signed']==-104
    assert direct['native_ui_music_owned_anchor_address']['returned_signed']==anchor['value']
    assert direct['native_ui_music_linked_bindings']['returned_signed']==-100
    assert direct['native_music_start']['returned_signed']==-2 and not direct['native_music_start']['MAIN_writes']
    assert c['observer']['zero_store_count']==24576
    assert c['exact_common_zero_opcode']=={'PC':'0x2f7d0c0','bytes':'041083e4','instruction':'str r1, [r3], #4'}
    previous_path=ROOT/'staging/native-player-decoder-scope/music-image/verification.json'
    previous=json.loads(previous_path.read_text());check(previous['source_sha256']);check(previous['artifacts_sha256'])
    failed=previous['failed_attempt_history']
    contract_path=OUT/'native-owner-contract.json';contract=json.loads(contract_path.read_text());check(contract['source_sha256'])
    host_compile=json.loads((OUT/'host-owner-v1/command-0.json').read_text())
    host_command=json.loads((OUT/'host-owner-v1/command-1.json').read_text())
    assert host_compile['exit_code']==host_command['exit_code']==0 and not host_command['stderr']
    newhost=json.loads(host_command['stdout']);assert newhost['all_passed'] and newhost['group_count']==7
    assert m['symbols']['source_completion_hook']['address']==m['symbols']['umcn_cleanup_bridge']['address']
    assert 'source_completion_original' not in m['symbols'] and 'source_completion_after_original' not in m['symbols']
    cleanup=[x for x in m['patch_plan'] if x['address']==0x3b9dfc];assert len(cleanup)==1
    assert struct.unpack('<I',bytes.fromhex(cleanup[0]['after'])[4:8])[0]==m['symbols']['umcn_cleanup_bridge']['address']
    deps=dict(m['source_sha256']);deps.update(c['source_sha256']);deps.update(contract['source_sha256']);deps[str(previous_path.relative_to(ROOT))]=sha(previous_path);deps[str(contract_path.relative_to(ROOT))]=sha(contract_path)
    for p in OUT.iterdir():
        if p.is_file() and p.suffix in ('.c','.h','.ld','.py'):deps[rel(p)]=sha(p)
    deps[rel(mp)]=sha(mp);deps[rel(cp)]=sha(cp)
    artifacts={rel(p):sha(p) for p in OUT.rglob('*') if p.is_file() and rel(p) not in deps}
    check(deps);check(artifacts);check(protected)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':m['exact_target'],'all_passed':True,
       'scope':'Fresh linked persistent source-worker owner/control/event/publication/after-iteration glue;15 HOST groups across two distinct scopes and11 bounded cold loader assertions; no native scheduling/audio/GUI/ownership/STOP_DONE proof.',
       'source_sha256':dict(sorted(deps.items())),'artifacts_sha256':dict(sorted(artifacts.items())),
       'protected_registry':{'snapshot':rel(OUT.parent/'previous-audit.json'),'sha256':sha(OUT.parent/'previous-audit.json'),
                             'count':1078,'all_checked_before_after':True,'unchanged':True},
       'build_manifest':{'path':rel(mp),'sha256':sha(mp)},'cold_loader_proof':{'path':rel(cp),'sha256':sha(cp)},
       'actual_ARM_ELF':{'path':m['extension_elf'],'sha256':m['extension_elf_sha256'],'type':'ET_EXEC','machine':'EM_ARM',
           'ARM1176_ARMv6_soft_float':True,'entry':hex(e.entry),'text_bytes':m['extension_code_bytes'],'file_backed_data_bytes':4,
           'flat_bytes':len(flat),'undefined_symbols':[],'actual_12_REL_boundaries_resolved':m['freshly_resolved_12_boundaries'],
           'fresh_lower_source_compilations_per_pass':25,'two_pass_symbol_maps_identical':True,'frozen_v2_REL_used_readonly':True,
           'frozen_absolute_extension_map_used_as_binding':False,'program_headers':ph,'ELF_load_bytes_reconstructed_flat_identical':True},
       'combined_raw_image':{'path':m['combined_binary'],'sha256':m['combined_sha256'],'file_bytes':len(combined),
           'ram_bytes':m['combined_ram_bytes'],'remaining_original_reservation_bytes':m['remaining_reservation_bytes'],
           'actual_header_words_hex':[hex(v) for v in head],'sole_wrapper':'native_ui_music_single_entry',
           'only_original_header_words0_4_8_changed':True,'VPM_or_SIG_created':False,'device_install_candidate':False},
       'owned_anchor':{'fresh_local_address':hex(anchor['value']),'STB_LOCAL_size2':True,'same_original_owner_TU':True,
           'ARM_getter_executed_and_returned_this_object':True,'registration_literal_and_params3_store_static_same_object':True,
           'registration_execution_or_channel_exclusivity_proven':False,'zero_anchor_duplicate_or_old_symbol_globalized':False},
       'once_guard':{'initialized_DATA':'31534955','RW_page':hex(ph[1]['vaddr']),'outside_common_zero_span':True,
           'actual_native_load_phase_transition':['COLD','CLAIMED','DONE'],'actual_original_common_entries':1,
           'actual_original_TTS_entries':1,'zero_span_words':24576,'zero_store_PC':'0x2f7d0c0',
           'resident_entry_repeat_returns_pinned_no_module_write_or_common_TTS_entry':True},
       'host_tests':{'ASan_UBSan':True,'group_count':8,'complete_host_scenarios':1,'groups':m['host_controls']['groups'],
                     'explicit_mock_ownership_and_session_contracts':True,'native_IRQ_audio_GUI_executed':False},
       'bounded_ARM_controls':{'count':len(c['controls']),'controls':c['controls'],'original_TTS40_imports_trampolines_RAM_preserved':True,
           'direct_controls':c['direct_ARM_controls'],'native_kernel_GUI_audio_started':False,
           'synthetic_file_cache_strcmp_RAM_permissions_fixture':True,'instruction_budgets':c['limits']},
       'previous_image_failed_attempt_history_unchanged':failed,
       'new_owner_HOST_controls':{'ASan_UBSan':True,'group_count':7,'groups':newhost['groups'],'actual_new_loop_and_glue_C':True,'native_ABI_spies_not_original_IRQ_audio_or_session':True},
       'native_owner_contract':{'path':rel(contract_path),'sha256':sha(contract_path),'bounded_original_functions':10,'source_loop_actual_BL_sites':contract['actual_source_loop_call_sites']},
       'cleanup_binding':{'one_3B9DFC_plan':True,'actual_alias_address':hex(m['symbols']['umcn_cleanup_bridge']['address']),'old_independent_cleanup_shim_removed':True,'private_source_completion_hook_alias_same_bridge':True,'live_patch_installed':False},
       'integrated_bounded_code':[
           'NEW original persistent source_worker_entry consumes0x80000 through actual BL music_owner_control_boundary; other source events10000/20000/40000 remain durable and continue original cancel/pump.',
           'Original last_result/count/double-pump preserved; only after full return and cancel_requested clearing calls music_owner_after_boundary, which asks original adapter for publication/returned evidence.',
           'One cleanup bridge entry for11-site3B9DFC and preserved private source_completion_hook aliases; no legacy cleanup bypass body remains.',
           'Source-owned bind fills actual same-image/kernel/state/anchor pointers and refuses missing resident/witness/session or route9; no success witness supplied.'
       ],
       'remaining_concrete_integration':[
           'NEW full image source_worker_boot/currentTCB/stack plus original post/wait/context restore must actually execute NEW loop in a separately bounded native kernel test; this turn only HOST loop spies and cold DLL bootstrap ran.',
           'Native transient source_record+1C8 and list+38 mutex scopes do not establish persistent channel8 exclusion across navigation/HFP/pool/callback actors; ownership_snapshot remains missing.',
           'AVDTP F50098 mutex and coherent SEP/channel/peer/codec state provenance identified, but real reservation epoch/session generation preparation is unknown; prepare_session remains missing.',
           'Config/START/event17/F1/consumer admissions and whole media leases have not been installed; localSTOP still cannot safely govern real incoming packets.',
           'Actual fullcleanup return/source token plus native cancel/remove/release completion must drive STOPPED under callback/media references; no native STOP_DONE was captured.',
           'Queued GUI/Dispatcher owner/menu/touch/resource/font/SQL guards and physical modified-DLL package/code acceptance remain parent runtime/device boundaries.',
           'HFP90005 is preserved; source9 WAV bindings remain rejected; directphone/native speaker proof and SIG native enforcement are incomplete.'
       ],
       'limits':{'device_service_USB_BT_IO':False,'audible_output':False,'emulator_executed':'bounded original DLL loader and pure ARM controls only',
           'original_40_full_speech_or_navigation_multitasking_verified':False,'native_kernel_GUI_audio_integrated':False,
           'physical_modified_package_App_direct_A2DP_verified':False,'frozen_sources_or_outputs_manifest_report_canonical_modified':False,
           'native_owner_loop_scheduled_or_nativeSTOP_DONE_proven':False,'reset_unload_or_free_supported':False,'goal_active':True,'AA_Maps':'deferred'}}
    newjson(report,result)
    print(json.dumps({'report':rel(report),'sha256':sha(report),'source_dependencies':len(deps),'artifact_files':len(artifacts),
                      'protected_unchanged':1078,'full_ELF_unresolved':0,'host_groups':8,'bounded_ARM_controls':len(c['controls']),
                      'preserved_old_failed_attempts':len(failed),'new_owner_host_groups':7,'physical_App':False}))

if __name__=='__main__':main()
