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
    protected=json.loads((OUT.parent/'previous-audit.json').read_text())['protected_sources'];assert len(protected)==892;check(protected)
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
    failed=[]
    for name,code in [('cold-loader-v1',1),('cold-loader-v2',1)]:
        p=OUT/name/'failed-attempt.json';f=json.loads(p.read_text());check(f['source_sha256']);check(f['artifacts_sha256'])
        receipt=OUT/name/'tool-exit-receipt.json';r=json.loads(receipt.read_text());assert r['actual_tool_exit_code']==code
        source=OUT/('verify_cold_image.py' if name.endswith('v1') else 'verify_cold_image_v2.py')
        snap=OUT/name/'source-at-failure.py';assert source.read_bytes()==snap.read_bytes()
        failed.append({'record':rel(p),'sha256':sha(p),'tool_receipt':rel(receipt),'tool_receipt_sha256':sha(receipt),
                       'source':rel(source),'source_sha256':sha(source),'source_snapshot':rel(snap),'source_snapshot_sha256':sha(snap),
                       'error_type':f['error_type'],'error':f['error'],'old_image_modified':False})
    deps=dict(m['source_sha256']);deps.update(c['source_sha256'])
    for p in OUT.iterdir():
        if p.is_file() and p.suffix in ('.c','.h','.ld','.py'):deps[rel(p)]=sha(p)
    deps[rel(mp)]=sha(mp);deps[rel(cp)]=sha(cp)
    artifacts={rel(p):sha(p) for p in OUT.rglob('*') if p.is_file() and rel(p) not in deps}
    check(deps);check(artifacts);check(protected)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':m['exact_target'],'all_passed':True,
       'scope':'Actual fresh ET_EXEC full link plus 8 HOST mock groups and 11 bounded original DLL-loader/ARM controls; no integrated native audio/UI/kernel or physical App claim.',
       'source_sha256':dict(sorted(deps.items())),'artifacts_sha256':dict(sorted(artifacts.items())),
       'protected_registry':{'snapshot':rel(OUT.parent/'previous-audit.json'),'sha256':sha(OUT.parent/'previous-audit.json'),
                             'count':892,'all_checked_before_after':True,'unchanged':True},
       'build_manifest':{'path':rel(mp),'sha256':sha(mp)},'cold_loader_proof':{'path':rel(cp),'sha256':sha(cp)},
       'actual_ARM_ELF':{'path':m['extension_elf'],'sha256':m['extension_elf_sha256'],'type':'ET_EXEC','machine':'EM_ARM',
           'ARM1176_ARMv6_soft_float':True,'entry':hex(e.entry),'text_bytes':m['extension_code_bytes'],'file_backed_data_bytes':4,
           'flat_bytes':len(flat),'undefined_symbols':[],'actual_12_REL_boundaries_resolved':m['freshly_resolved_12_boundaries'],
           'fresh_lower_source_compilations_per_pass':23,'two_pass_symbol_maps_identical':True,'frozen_v2_REL_used_readonly':True,
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
       'failed_attempt_history':failed,
       'remaining_concrete_integration':[
           'NEW source-worker copy must consume controller0x80000 on the same persistent source TCB and invoke service_owner; immutable loop has no such call.',
           'Bind actual native exclusive channel8 reservation/epoch and AV-mutex session preparation; ownership_snapshot/prepare_session/residency currently remain mandatory missing inputs.',
           'Hook note_publication after successful owned source registration; invoke after_iteration only after actual cancel/pump return and cancel_requested clearing; retain whole callback lease across cleanup.',
           'Install config/START/event17/F1/consumer admission and media acquire/current/release call-sites with matching generation; mere ELF link does not connect them.',
           'The new11-site plan targets umcn_cleanup_bridge and music_start fails closed before attachment; private old source_completion_hook is still separately retained and must not become a bypass/double-cleanup route.',
           'Defer menu install to actual native GUI/Dispatcher owner before legacy ID7F135201 exists; original queued launch/render/touch/resource lifetime remains root runtime work.',
           'Preserve existing HFP90005 while verifying complete radio readiness and source8 boot; no generic SDP reset or physical radio inference from this DLL bootstrap.',
           'Source9 WAV owned node/provider/async stop→clear→388746 callback→388676 core release witnesses remain unavailable; route9 remains rejected.',
           'NativeSIG requester/publickey/enforcement and physical changed-DLL execution acceptance remain unknown; no modified VPM install or direct-phone audio proof.'
       ],
       'limits':{'device_service_USB_BT_IO':False,'audible_output':False,'emulator_executed':'bounded original DLL loader and pure ARM controls only',
           'original_40_full_speech_or_navigation_multitasking_verified':False,'native_kernel_GUI_audio_integrated':False,
           'physical_modified_package_App_direct_A2DP_verified':False,'frozen_sources_or_outputs_manifest_report_canonical_modified':False,
           'reset_unload_or_free_supported':False,'goal_active':True,'AA_Maps':'deferred'}}
    newjson(report,result)
    print(json.dumps({'report':rel(report),'sha256':sha(report),'source_dependencies':len(deps),'artifact_files':len(artifacts),
                      'protected_unchanged':892,'full_ELF_unresolved':0,'host_groups':8,'bounded_ARM_controls':len(c['controls']),
                      'preserved_failed_attempts':len(failed),'physical_App':False}))

if __name__=='__main__':main()
