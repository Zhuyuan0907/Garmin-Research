#!/usr/bin/env python3
"""Read exact MAIN/fresh ELF only; original lock scope is not reservation."""
import sys
sys.dont_write_bytecode=True
import hashlib,importlib.util,json,struct
from pathlib import Path
from datetime import datetime,timezone
OUT=Path(__file__).resolve().parent;ROOT=OUT.parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
from analyze_sdp_activation import trace
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def check(d):
    for p,h in d.items():assert sha(ROOT/p)==h,p
def main():
    output=OUT/'native-owner-contract.json';assert not output.exists()
    mp=OUT/'manifest.json';m=json.loads(mp.read_text());check(m['source_sha256']);check(m['artifacts_sha256'])
    protected=json.loads((OUT.parent/'previous-audit.json').read_text())['protected_sources'];assert len(protected)==1078;check(protected)
    im=NativeImage();functions={}
    for a in (0x270458,0x277c6a,0x277b38,0x277674,0x5523c4,0x5523de,0x5523e2,0x5523fc,0x50bbc0,0x36af74):
        t=trace(im,a,250)
        for row in t['instructions']:
            pc=int(row['address'],16);ins=next(im.md.disasm(im.read(pc,4),pc,count=1));row['bytes']=ins.bytes.hex()
            if 'literal_address' in row:row['literal_bytes']=im.read(int(row['literal_address'],16),4).hex()
        functions[hex(a)]=t
    kernels={}
    for a,n,mode in [(0x21b6cc,0x20,CS_MODE_ARM),(0x358d24,0x16,CS_MODE_THUMB),(0x2fcf44,0xa0,CS_MODE_ARM),(0x2fd034,0x88,CS_MODE_THUMB)]:
        md=Cs(CS_ARCH_ARM,mode);raw=im.read(a,n)
        kernels[hex(a)]=[{'PC':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(raw,a)]
    # The saved Thumb windows below are decoded independently of CFG closure.
    windows={}
    for name,a,b in [('source_record_lock_and_indirect_queue',0x270484,0x2704bc),
                     ('list_insert_lock',0x277c90,0x277ca8),('list_remove_lock',0x277674,0x277694),
                     ('AV_unlock_before_media_callback',0x50bc5a,0x50bc96)]:
        windows[name]=[{'PC':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str}
                       for i in im.instructions(a,b)]
    spec=importlib.util.spec_from_file_location('owner_ELF',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);e=mod.ELF32(ROOT/m['extension_elf'])
    s={k:v['address'] for k,v in m['symbols'].items()};md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
    fresh={}
    for name in ['source_worker_entry','music_owner_control_boundary','music_owner_after_boundary','music_owner_bind_on_source',
                 'music_owner_current','music_owner_post','umcn_cleanup_bridge','native_ui_music_linked_bindings']:
        symbol=e.symbol(name);raw,offset,section=e.at(symbol['value'],symbol['size'])
        fresh[name]={'symbol':symbol,'section':section,'ELF_offset':hex(offset),'bytes_sha256':hashlib.sha256(raw).hexdigest(),
                     'instructions':[{'PC':hex(i.address),'bytes':i.bytes.hex(),'instruction':i.mnemonic+' '+i.op_str} for i in md.disasm(raw,symbol['value'])]}
    entry=fresh['source_worker_entry']['instructions']
    actual_calls={name:[row for row in entry if row['instruction']=='bl #'+hex(s[name])]
                  for name in ['music_owner_initialized','music_owner_control_boundary','music_owner_after_boundary']}
    assert all(len(v)==1 for v in actual_calls.values())
    assert s['source_completion_hook']==s['umcn_cleanup_bridge']
    assert not any(n in s for n in ['source_completion_original','source_completion_after_original'])
    p=[x for x in m['patch_plan'] if x['address']==0x3b9dfc];assert len(p)==1
    assert struct.unpack('<I',bytes.fromhex(p[0]['after'])[4:8])[0]==s['umcn_cleanup_bridge']
    no_init_call=[r for f in fresh.values() for r in f['instructions'] if r['instruction'] in ('bl #0x5d7588','blx #0x5d7588')]
    assert not no_init_call
    deps=dict(m['source_sha256'])
    for p in [Path(__file__).resolve(),mp,ROOT/m['extension_elf'],ROOT/'scripts/analyze_native_sections.py',
              ROOT/'scripts/analyze_sdp_activation.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',
              ROOT/'evidence/firmware-analysis/native-audio-registration-emulation.json',
              ROOT/'native/ui-music-native-adapter/native_adapter.c',ROOT/'native/music-continuous/stream.c']:
        deps[rel(p)]=sha(p)
    check(deps);check(protected)
    result={'updated_utc':datetime.now(timezone.utc).isoformat(),'exact_target':{'HWID':1352,'software':'8.00','MAIN_sha256':EXPECTED},
      'source_sha256':dict(sorted(deps.items())),'protected_1078_unchanged':True,
      'bounded_original_functions':functions,'raw_kernel_windows':kernels,'exact_argument_windows':windows,
      'fresh_ELF_functions':fresh,'actual_source_loop_call_sites':actual_calls,
      'native_lock_provenance':{
        'source_record_transient':{'call':'0x270496','mutex':'source_table034E6F08 + channel*520 +1C8',
          'derivation':'channel*65*8 at270484..27048C; FF+C9 at270490/492;3009A0 lock270496;3008B0 unlock2704B8',
          'queue_call':'2704B2 BLX r6 loaded from record+160 at2704A0..A4; r0=record+1A8',
          'actual_live_function_pointer_captured_in_this_task':False},
        'list_transient':{'insert_lock':'277C96: r0=list+38','insert_unlock':'277D1C','remove_lock':'27767E: r0=list+38',
          'remove_full_call':'277686→277596','remove_unlock':'27768E','if_list_is_record_plus1A8_mutex_offset':'1E0'},
        'AVDTP':{'holder_pointer_storage':'F50098','lock_call':'50BBCC→5523DE:ldr r0,[r0]→5523C4',
          'unlock_call':'50BC60→5523FC:ldr r0,[r0]→5523E2','media_callback_after_unlock':'50BC92→42758E',
          'same_native_lock_used_in_frozen_stream_source':True},
        'scope_limit':'These serialize their individual operations. No bounded instruction here establishes a persistent reservation spanning source selection, pool allocation, driver callbacks, navigation/HFP or future borrowers. No exclusive witness is synthesized.'},
      'session_preparation_provenance':{
        'known_native_handle_bytes':'stock callback initializes handle4..11;0..3 uninitialized',
        'coherent_view_fields':'localSEP03A88EF0 stride32;context+11/state+12/pending+13/channel+F;channel03A88F50 stride8;peer03A88EB8 contextstride28+16',
        'known_frozen_AV_locked_path':'stream.snapshot/configure require owned callback,context<2,SEID/peer/type/LCID/MTU/codec;guard_session andqueue_epoch private counters',
        'prepare_session_binding':'not implemented; a mutex acquisition or matchingcurrentLCID is not the native reservation epoch promised to umcn_adapter_prepare',
        'native_channel8_exclusive_witness':'not established','future_borrowing_callbacks_exclusion':'not established'},
      'integrated_bounded_pieces':{'persistent_worker_loop_replaced_in_full_image':True,'control_event':'00080000',
        'durable_original_events':['00010000 publication','00020000 completion','00040000 cancel'],
        'service_on_original_source_TCB':True,'after_iteration_after_last_result_and_cancel_flag_clear':True,
        'publication_after_actual_coordinator_registration_return':True,'runtime_native_execution_of_this_loop_captured':False,
        'cleanup_single_address_alias_and_one3B9DFC_target':True,'HFP90005_or_SDP_initializer_changed':False,
        'source9_missing_binding_rejected':True},
      'remaining_native_test_boundaries':['original source-worker boot/currentTCB+stack,post/wait/context restore executing NEW loop',
         'real native exclusive reservation/witness epoch and AV locked session preparation',
         'generation admission config/START/event17/F1/consumer and whole media lease calls',
         'fulloriginalcleanup→notification→actualcancel/remove/release returned barrier→STOPPED',
         'native queued GUI launch/touch and physical modified-code acceptance/direct phone'],
      'limits':{'static_CFG_is_bounded_not_global_closure':True,'indirect_function_pointer_or_runtime_values_unknown_preserved':True,
                'no_emulator_device_or_compilation_in_this_analyzer':True,'no_package_SIG_or_canonical_modified':True}}
    with output.open('x') as f:json.dump(result,f,indent=2,ensure_ascii=False);f.write('\n')
    print(json.dumps({'contract':rel(output),'sha256':sha(output),'source_dependencies':len(deps),'bounded_original_functions':len(functions),
                      'same_native_cleanup_address':hex(s['umcn_cleanup_bridge']),'native_reservation_verified':False}))
if __name__=='__main__':main()
