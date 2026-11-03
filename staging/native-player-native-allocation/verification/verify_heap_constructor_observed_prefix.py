#!/usr/bin/env python3
"""Independently replay original native public heap ctor and its whole stack."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct
from file_verifier_common import *
OUT=BASE+'verification/native-heap-constructor-observed-prefix.json'

def main():
    meta,probe,prefix=seal_inputs();r=Replay();s=probe['body_actor_observations']['native_allocation_observer']
    require(s['prepared']and s['cold_init_returned']and s['cold_recipe_verified'],'Native public constructor prefix missing')
    require(probe['native_heap_init_arguments']==[0x09701020,1,0x1830B020,1],'Exact root first private/public API argument list')
    ctor=s['cold_frame'];stack=s['constructor_stack']
    require(ctor['entry']=='0x388b6c'and ctor['SP']==0x9503F90 and ctor['LR']==0x10001
      and ctor['arguments']==probe['native_heap_init_arguments'],'Actual live controller constructor entry/arguments/SP/LR')
    require(ctor['returned']and ctor['actual_return_SP']=='0x9503f90'and ctor['actual_return_r0']==1
      and ctor['epilogue_return_branch_seen']and not ctor['host_context_or_return_supplied'],
      'Native constructor actual original epilogue/caller return missing')
    require(r.stock.read(0x388DF0,2).hex()=='1847'and r.stock.read(0x388B6C,2).hex()=='ffb5',
      'Original constructor PUSH9/BXr3 bytes')
    require(stack['start']=='0x9500000'and stack['bytes']==16384 and not stack['active']
      and not stack['old_five_cold_boot_zones_restarted']and stack['whole_net_zone_matches_original_stores']
      and stack['seal_after_original_constructor_return'],'New constructor stack journal was not sealed at genuine native RETURN')
    stack_bytes,stackproof=r.replay(stack)
    require(len(stack['stores'])==57,'Actual V1 constructor stack57 CPU stores')
    pushes=[]
    coldframes=s['frame_history'];require(len(coldframes)==8,'V1 has only actual original eight ctor/helper frames')
    for f in coldframes:
        require(f['actual_task']=='0x9503f90'and f['returned']and f['original_push_verified']
          and f['actual_return_SP']==hex(f['SP'])and not f['host_context_or_return_supplied'],
          'Actual cold helper return/prologue missing')
        entry=int(f['entry'],16);require(r.stock.read(entry,len(bytes.fromhex(f['original_entry_opcode']))).hex()==f['original_entry_opcode'],
          'Original containing function entry bytes')
        if f['push_bytes']:
            events=f['actual_push_events'];require(len(events)==f['push_bytes']//4,'Native helper PUSH size')
            before=bytearray.fromhex(f['actual_frame_before_hex']);o=f['local_bytes'];low=f['SP']-f['push_bytes']
            for i,e in enumerate(events):
                require(e in stack['stores']and e['PC']==f['push_writer']and e['Thumb']==f['Thumb']
                  and(int(e['address'],16),e['size'],e['value'])==(low+4*i,4,f['push_values'][i])
                  and e['before_hex']==before[o+4*i:o+4*i+4].hex(),'Genuine original native helper PUSH registers/beforeimage')
                before[o+4*i:o+4*i+4]=e['value'].to_bytes(4,'little')
            pushes.append(dict(entry=f['entry'],actual_SP=hex(f['SP']),PUSH_CPU_stores=len(events),
              actual_original_caller_return=f['actual_return_SP'],native_return_r0=hex(f['actual_return_r0'])))
    require(prefix['cold_boot']['whole_boot_zones']==probe['cold_boot_zones'],'Old five boot journals gained no later ctor/body writes')
    private=next(z for z in prefix['extra_zones']if z['start']=='0x18301000')
    work=next(z for z in prefix['extra_zones']if z['start']=='0x3a7f150')
    require(bytes.fromhex(private['before_hex'])==b'\xcc'*8192,'Actual initial private pool CC fixture beforeimage')
    initial_work=bytes.fromhex(s['input']['original_WORK96_actual_before_hex']);require(initial_work==bytes(96),'Actual original WORK96 before first ctor is zero')
    heap=bytearray.fromhex(private['before_hex']);workspace=bytearray(initial_work)
    coldwrites=s['heap_writes'];require(coldwrites and all(e['phase']=='heap_ctor'and e['actual_task']=='0x9503f90'for e in coldwrites),
      'V1 native allocator was not entered; only ctor heap writes may be present')
    for e in coldwrites:
        r.store(e);addr=int(e['address'],16);n=e['size']
        if 0x18301000<=addr and addr+n<=0x18303000:raw=heap;off=addr-0x18301000
        else:require(0x3A7F170<=addr and addr+n<=0x3A7F1D0,'Ctor heap writer crossed exact WORK/private spans');raw=workspace;off=addr-0x3A7F170
        require(raw[off:off+n].hex()==e['before_hex'],'Cold heap observer chronological original beforeimage');raw[off:off+n]=e['value'].to_bytes(n,'little')
    # Independent structural expectations; every remaining byte is protected by
    # original CPU replay and recorded actual whole-zone after SHA.
    H0,H1,H2=0x18302FD8,0x18302FC0,0x18302FA8
    W=struct.unpack('<24I',workspace)
    require(W[1:4]==(0,0,H2)and W[4:7]==(H0,H1,0x18301000)and W[11]==0x388D00
      and W[20:23]==(8192,8192,8192),'Native WORK/privateused/publichead/free descriptor fields')
    require(workspace.hex()==prefix['cold_heap']['workspace96_hex'],'Actual ctor WORK snapshot differs from independent CPU replay')
    require(struct.unpack_from('<I',heap,0)[0]==27 and struct.unpack_from('<I',heap,4)[0]==1024
      and struct.unpack_from('<I',heap,0x30)[0]==1 and struct.unpack_from('<I',heap,0x57C)[0]==H0,
      'Original public free bin directory/bitmaps')
    require(struct.unpack_from('<6I',heap,H0-0x18301000)==(0,0x18305001,H1,0xCCCCCCCC,0x1830157D,0),
      'Original whole24 first public free descriptor')
    require(struct.unpack_from('<6I',heap,H1-0x18301000)==(H0,0x18309002,0,0xCCCCCCCC,0xCCCCCCCC,H2),
      'Original whole24 public end descriptor and untouched fields')
    require(heap[-16:]==b'\xcc'*16,'Original170x24 descriptor pool tail16 retained')
    private_after,privateproof=r.replay(private);require(private_after==heap,'Native private cold heap recipe differs from actual prefix whole pool')
    backend_ops=[e for e in probe['cold_heap']['native_initializer']['native_zero_writes']]
    require(len(backend_ops)==6 and probe['cold_heap']['native_initializer']['original_body_executed'],'Original native semaphore six stores missing')
    six=[e for e in coldwrites if 0x3008A2<=int(e['PC'],16)<=0x3008AC]
    require(len(six)==6 and [(int(e['address'],16),e['size'],e['value'])for e in six]==[(0x3A7F18C+4*i,4,0)for i in range(6)],
      'Original initializer six exact fields/stores')
    tag=[e for e in coldwrites if e['PC']=='0x388bd2'];require(len(tag)==1 and(int(tag[0]['address'],16),tag[0]['size'],tag[0]['value'])==(0x3A7F19C,4,0x388D00),
      'Original heap native tag retag writer')
    require(probe['cold_heap']['listener_registration_returns']==[{'native_return':'0x388be6','result':0,'node':'0x3a7f150'},
      {'native_return':'0x388bf8','result':0,'node':'0x3a7f160'}],'Original listener return provenance')
    public_replay=[]
    guards=probe['terminal_native_public_heap_guards'];require(guards['all_passed']and guards['guard_pages_unchanged']and guards['descriptor_page_unchanged'],'Public actual terminal whole guards missing')
    for low,n in [(0x18304000,24576),(0x1830B000,4096)]:
        z=probe['journal_zones'][str(low)];actual=next(e['after_sha256']for e in guards['whole_zones']if int(e['start'],16)==low)
        raw,proof=r.replay(z,after_sha256=actual);public_replay.append(proof)
        expected=bytearray(b'\xa5'*n)
        if low==0x18304000:expected[4096:4096+16384]=b'\xcc'*16384
        else:struct.pack_into('<2I',expected,32,0x18305000,16384)
        require(raw==expected and not z['stores'],'Actual native ctor leaves public payload/descriptor input/guards unchanged')
    here=str(Path(__file__).resolve().relative_to(ROOT))
    doc=dict(all_passed=True,source_sha256=sources(meta,here),verified_runtime_dependencies=meta['source_sha256'],**fields(meta),
      native_heap_constructor_return_verified=True,native_public_free_bin_initialization_verified=True,
      original_private_page_and_descriptor_build_CPU_stores=len(coldwrites),independent_constructor_stack_replay=stackproof,
      actual_constructor_stack_CPU_stores=57,actual_reviewed_constructor_frames=8,actual_reviewed_frame_PUSH_stores=sum(e['PUSH_CPU_stores']for e in pushes),
      actual_helper_pushes_and_returns=pushes,private_heap_whole_replay=privateproof,
      native_WORK96_after_ctor_sha256=hashlib.sha256(workspace).hexdigest(),
      actual_public_boundary_descriptors24=[dict(pointer=hex(h),bytes24_hex=heap[h-0x18301000:h-0x18301000+24].hex())for h in [H0,H1]],
      public_guarded_envelope_and_descriptor_terminal_replays=public_replay,
      cold_five_boot_journals_unchanged=True,original_48_or8_native_allocator_success_verified=False,
      allocator_attempt_intercepted_by_inherited_host_provider=True,actual_native_allocator_raw_operations=0,
      full_inherited_terminal_zone_replay_verified=False,inherited_terminal_scope_failure=probe['partial_inherited_zone_verification'],
      scope='Native original388B6C initializes declared private/public fixture extents once, allocates descriptor page and inserts original free bin, then returns on actual controller. Separate16K stack CPU history and public terminal guards replay independently. Public RAM availability on hardware and native48/8 malloc remain unproven.')
    dump(OUT,doc);print(json.dumps({k:doc[k]for k in ['all_passed','native_heap_constructor_return_verified','native_public_free_bin_initialization_verified','actual_constructor_stack_CPU_stores','actual_native_allocator_raw_operations']}))
if __name__=='__main__':main()
