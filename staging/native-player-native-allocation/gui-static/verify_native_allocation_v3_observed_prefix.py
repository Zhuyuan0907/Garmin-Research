#!/usr/bin/env python3
"""Independent file replay of V3 native malloc progress, not allocation success."""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,json,struct
ROOT=Path(__file__).resolve().parents[3];BASE='staging/native-player-native-allocation/'
sys.path.insert(0,str(ROOT/BASE/'verification'))
from file_verifier_common import Replay,require,sha,read,dump
RUNTIME=BASE+'runtime-v3/'
OUT=BASE+'gui-static/native-allocation-v3-observed-native-prefix-review.json'
CONTRACT=BASE+'gui-static/native-allocation-v3-next-private-page-contract.json'
def word(raw,off):return struct.unpack_from('<I',raw,off)[0]
def signature(e):
 return tuple(e[k]for k in ['PC','address','size','value','before_hex'])
def main():
 meta=read(RUNTIME+'terminal-metadata.json');j=read(meta['probe']);prefix=read(meta['cold_prefix'])
 require(meta['authoritative_terminal_result_received_from_exec']and(meta['session_id'],meta['actual_exec_chunk'],meta['terminal_exit_code'])==(27241,'61dabd',1),
   'Exact authoritative frozen V3 terminal identity')
 receipt=read(BASE+'terminal-v3-receipt.json');actual=receipt['tool_result']
 require(receipt['observed_session_id']==27241 and actual['chunk_id']=='61dabd'and actual['exit_code']==1 and 'session_id'not in actual,
   'Actual final V3 exec receipt')
 for k in ['runner','runner_snapshot','inputs','probe','FP_helper','GUI_observer','sealer','cold_prefix','terminal_tool_receipt']:
  require(sha(meta[k])==meta[k+'_sha256'],'Frozen V3 file hash '+k)
 for p,h in meta['source_sha256'].items():require(sha(p)==h,'Frozen V3 protected source '+p)
 require(meta['GUI_observer_sha256']=='e96b0ca0fcb2d6b55e0d58f022fd08b0538aef69b30f07de1f86f0df64358931',
   'Exact V3 provider guard source')
 require(not j['completed']and not j['body_full_guards_passed']and j['cold_prefix_full_guards_passed']
   and prefix['cold_prefix_full_guards_passed']and len(prefix['component_calls'])==11
   and all(e['returned']for e in prefix['component_calls']), 'Preserve complete cold / incomplete body distinction')
 require(j['registers']=={'r0':'0x395535','r1':'0x18306000','r2':'0x18305000','r3':'0x38835f',
   'lr':'0x3883b3','pc':'0x38806c','sp':'0x8803f50'},'Actual V3 page-pop boundary ABI')
 require(j['error'].endswith('Native malloc reached unreviewed page/provider/invalid descriptor branch 0x38806c'),
   'Exact original observer admission stop')
 r=Replay();inherited=j['partial_inherited_zone_verification'];body=j['partial_body_zone_verification'];fp=j['partial_FP_zone_verification']
 require(isinstance(inherited,list)and len(inherited)==24 and len(body)==7 and len(fp)==8,'Actual V3 whole terminal journals')
 finals={};inheritedproof=[]
 for z in inherited:
  raw,p=r.replay(z);finals[int(z['start'],16)]=raw;inheritedproof.append(p)
 bodyproof=[r.replay(z)[1]for z in body];fpproof=[r.replay(z)[1]for z in fp]
 bank=j['partial_initialized_bank_verification'];_,bankproof=r.replay(bank,j['mutable_bank_initial_before_hex'])
 require(bankproof['bytes']==467532,'Whole initialized-bank actual replay')
 s=j['body_actor_observations']['native_allocation_observer'];a=s['pending'];shape=a['shape']
 require(s['cold_init_returned']and s['cold_recipe_verified']and len(s['allocations'])==1
   and not any(a[k]for k in ['lower_return_seen','query_return_seen','prefix_store_seen','actual_original_caller_return_seen'])
   and a['native_handle']is None and a['native_pointer']is None and not a['TCB_stores'],
   'No native malloc success/handle/ownership-prefix exists yet')
 gates=j['body_actor_observations']['native_allocator_provider_gate_observer']['entries']
 require(len(gates)==1 and gates[0]['entry']=='0x2dc954'and gates[0]['actual_arguments']==['0x30','0x0','0x8','0x395535'],
   'Actual strict original2DC954 provider bypass entry')
 nativeframes=[f for f in s['frame_history']if f['actual_task']=='0x8804fb8'];require(len(nativeframes)==7,'Exact V3 native body helper frame count')
 require([f['entry']for f in nativeframes]==['0x2dc954','0x38850a','0x3881bc','0x21210c','0x21210c','0x21210c','0x388df2'],
   'Exact native malloc helper progression')
 require([f['returned']for f in nativeframes]==[False,False,False,True,True,True,True],
   'Native helper returned versus still resident frames')
 dstack=next(z for z in body if z['start']=='0x8801024');pushes=[]
 for f in nativeframes:
  require(f['original_push_verified']and not f['host_context_or_return_supplied'],'Actual original frame PUSH/context provenance')
  opcode=bytes.fromhex(f['original_entry_opcode']);require(r.stock.read(int(f['entry'],16),len(opcode))==opcode,'Native containing-function original opcode')
  if not f['push_bytes']:continue
  events=f['actual_push_events'];require(len(events)==f['push_bytes']//4,'Actual native frame PUSH register count')
  before=bytes.fromhex(f['actual_frame_before_hex']);off=f['local_bytes']
  for i,e in enumerate(events):
   require(e in dstack['stores']and e['PC']==f['push_writer']and e['Thumb']==f['Thumb']
     and(int(e['address'],16),e['size'],e['value'])==(f['SP']-f['push_bytes']+4*i,4,f['push_values'][i])
     and e['before_hex']==before[off+4*i:off+4*i+4].hex(), 'Actual native original PUSH register/address/before binding')
  pushes.append(dict(entry=f['entry'],actual_SP=hex(f['SP']),PUSH_stores=len(events),actual_return_seen=f['returned']))
 require(sum(p['PUSH_stores']for p in pushes)==21,'Four native frames /21 genuine PUSH stores')
 writes=a['heap_stores'];require(len(writes)==13 and all(e['actual_task']=='0x8804fb8'for e in writes),'Exact13 allocator/native mutex original stores')
 privatezone=next(z for z in prefix['extra_zones']if z['start']=='0x18301000')
 private,_=r.replay(privatezone);private=bytearray(private);workspace=bytearray.fromhex(a['WORK96_before_hex'])
 for e in writes:
  r.store(e);addr=int(e['address'],16);n=e['size']
  if 0x18301000<=addr and addr+n<=0x18303000:raw=private;off=addr-0x18301000
  else:require(0x3A7F170<=addr and addr+n<=0x3A7F1D0,'Original malloc write crossed exact WORK/private spans');raw=workspace;off=addr-0x3A7F170
  require(raw[off:off+n].hex()==e['before_hex'],'Original13 chronological split/native backend beforeimage')
  raw[off:off+n]=e['value'].to_bytes(n,'little')
  whole=next(z for z in inherited if int(z['start'],16)<=addr and addr+n<=int(z['start'],16)+z['bytes'])
  require(sum(signature(x)==signature(e)for x in whole['stores'])==1,'Native13 event lacks exact whole-zone occurrence')
 require(bytes(private)==finals[0x18301000]and bytes(workspace)==finals[0x3A7F150][32:128],
   'All original13 stores reconstruct actual complete private/WORK afterbytes')
 require(word(workspace,4)==word(workspace,8)==0 and word(workspace,12)==0x18302F90,
   'Actual private-page pools empty despite surviving descriptor freelist')
 require(word(private,0x57C)==0 and word(private,4)==word(private,0x30)==0
   and word(private,0x2FA8-0x1000)==0x18302FD8 and word(private,0x2FAC-0x1000)==0x18305039,
   'Actual selected free-bin removal and new virtual remainder descriptor')
 require(word(private,0x2FD8-0x1000+8)==0x18302FA8 and word(private,0x2FA8-0x1000+8)==0x18302FC0
   and word(private,0x2FC0-0x1000)==0x18302FA8,'Actual linked selected/remainder/end descriptors')
 raw=s['raw_ops'];require(len(raw)==1,'Only initial native heap lock was reached')
 lock=raw[0];require(lock['native_caller']=='0x38851c'and lock['operation']=='lock'and lock['native_body_returned']
   and lock['actual_caller_continuation_seen']and lock['original_return']==lock['actual_return_r0']==0
   and lock['actual_return_SP']=='0x8803f88'and lock['native_owner']=='0x8804fb8',
   'Native initial heap lock genuinely returned acquired on D')
 require(bytes(workspace[28:52]).hex()==lock['whole24_actual_at_caller_hex']
   and struct.unpack('<6I',workspace[28:52])==(0x8810718,0x8804FD8,0x8804FB8,0,0x388D00,0),
   'Actual still-held whole24 heap mutex and retained old owner links')
 tcb=s['TCB_writes'];require(len(tcb)==1 and tcb[0]['PC']=='0x3009d4'and tcb[0]['address']=='0x8804fd8'
   and tcb[0]['value']==0x3A7F18C and tcb[0]['before_hex']=='18078108','Actual native heap owned-list insertion only')
 for task,before in a['actual_before_TCB108'].items():
  expected=bytearray.fromhex(before);t=int(task,16)
  if t==0x8804FB8:struct.pack_into('<I',expected,32,0x3A7F18C)
  require(finals[t]==bytes(expected),'All native TCB108 bytes changed only exactD owned heap head '+task)
 output=[e for e in dstack['stores'][a['output_zone_event_index']:]if int(e['address'],16)==shape['output_cell']]
 require([(e['PC'],e['size'],e['value'])for e in output]==[('0x2dc954',4,0x395535),('0x2dc95c',4,0),('0x3881ca',4,0)],
   'Native aligned wrapper/core output remains original zero; no handle-store success')
 require(not any(f['entry']=='0x38806c'for f in nativeframes),'Stop preceded page-pop function PUSH/body')
 require(r.stock.read(0x3883AE,4).hex()=='fff75dfe'and r.stock.read(0x38806C,2).hex()=='10b5'
   and r.stock.read(0x388084,4).hex()=='b5f630fb','Exact original page-pop call /entry /empty-private diagnostic')
 here=str(Path(__file__).resolve().relative_to(ROOT));common=BASE+'verification/file_verifier_common.py'
 sources={p:sha(p)for p in [here,common,RUNTIME+'terminal-metadata.json',meta['probe'],meta['cold_prefix'],meta['terminal_tool_receipt'],
   meta['GUI_observer'],BASE+'gui-static/native-heap-original-opcodes.json',BASE+'gui-static/native-allocation-observer-v3-contract.json',
   BASE+'gui-static/native-allocation-inherited-provider-audit-v3.json','scripts/analyze_native_sections.py',r.companion_path,'evidence/firmware-analysis/main_02bd.bin']}
 contract=dict(all_passed=True,pure_static_plus_file_observation=True,guest_execution=False,VM_import_or_instantiation=False,
   source_sha256=sources,actual_guest_session=27241,actual_terminal_chunk='61dabd',actual_registers=j['registers'],
   original_containing_function='0x3881bc',actual_containing_function_entry_SP='0x8803f88',
   actual_core_body_SP='0x8803f50',original_call='0x3883ae',original_call_opcode='fff75dfe',actual_caller_LR='0x3883b3',
   page_pop_function='0x38806c',page_pop_body_not_executed_at_this_boundary=True,
   misclassification_correction='38806C is private-page pop, not388E92 invalid-descriptor validation. The prior combined hardstop reason records an unreviewed scope; it is not an observed firmware diagnostic.',
   actual_WORK_fields=dict(private_extent_remaining_head='0x0',free_private_page_head='0x0',free_descriptor_head='0x18302f90'),
   current_fixture_private_bytes=8192,original_prefix_reserve=4096,original_descriptor_pool_page=4096,
   no_remaining_private_page_available_in_current_fixture=True,
   counterfactual_original_branch='388070 observesWORK+8=0;388076 observesWORK+4=0;388084 would call23D6E8. This diagnostic was NOT executed.',
   r0_semantics='Actual395535 is original allocation caller identity used only on page-exhaustion diagnostic; R1/R2 are incidental core virtual-page arithmetic, not page-pop API backing inputs.',
   virtual_remainder_start='0x18305038',virtual_page_to_remap='0x18305000',original_after_page_pop_return='0x3883b2',
   original_after_page_pop_mapping_call='0x3883bc',original_mapping_function='0x221d34',
   MMU_mapping_not_executed=True,original_mapping_TTB_literal='0x3e00000',required_L1_slot='0x3e0060c',
   TTB_L1_L2_actual_input_bytes_not_captured=True,TTB_not_file_backed_or_startup_zero=True,
   minimum_future_input='A NEW declared private extent whose native388B6C recipe leaves real original free private page(s); preserve old inputs and guard scopes via a new explicit config/source. Do not seedWORK pointers or claim synthetic backing as physical RAM.',
   minimum_future_mapping_scope='Capture original221D34 frame, actual page-pop return pointer, original IRQ/cache/TLB callees, actual L1/L2 descriptor before bytes, exact native CPU stores and whole-table after replay before claiming bounded software mapping.',
   existing_frozen_parent_conflict='HeapSettingsVM.verify_extra_zones hardcodes8192 private descriptor/trailing guard, and V1 allocator recipe/handle provenance hardcodes18302000 descriptor page. A larger extent cannot be silently admitted by an entry-only override.',
   new_helper_v4_not_justified_for_current_empty_private_input=True,
   no_native_malloc_success_or_hardware_backing_or_foreground_verified=True)
 dump(CONTRACT,contract);sources[CONTRACT]=sha(CONTRACT)
 result=dict(all_passed=True,source_sha256=sources,verified_runtime_dependencies=meta['source_sha256'],
   actual_guest_session=27241,actual_guest_terminal_chunk='61dabd',actual_guest_terminal_exit_code=1,
   guest_execution_by_verifier=False,VM_import_or_instantiation=False,device_io=False,
   actual_inherited_whole_zone_replays=inheritedproof,actual_body_whole_zone_replays=bodyproof,
   actual_FP_whole_zone_replays=fpproof,actual_initialized_bank_replay=bankproof,
   actual_native_allocator_body_frames=7,actual_native_PUSH_frames=pushes,actual_native_PUSH_CPU_stores=21,
   actual_returned_native_floorlog_helpers=3,actual_returned_descriptor_freelist_pop=1,
   actual_native_allocator_and_mutex_CPU_stores=13,actual_native_raw_lock_returns=1,actual_native_raw_unlock_returns=0,
   native_heap_mutex_still_owned_by_D=True,actual_whole_backend24=workspace[28:52].hex(),
   all_native_TCB108_reconstructed=True,only_currentD_owned_mutex_head_changed=True,
   genuine_native_handle_or_malloc48_8_return_verified=False,original_page_pop_body_executed=False,
   original_MMU_page_mapping_executed=False,actual_next_boundary=j['registers'],next_contract=CONTRACT,
   completed_cold_prefix_reported_by_frozen_runner=True,cold_cache_not_reverified_by_this_bounded_review=True,
   full_Dispatcher_body_or_foreground_or_physical_App_verified=False,
   scope='Actual original malloc aligned-wrapper/core progress, frame PUSHes, acquired raw heap lock, descriptor pop and split CPU stores independently match whole terminal journals. The current declared private pool is exhausted; page-pop was stopped before its body. No allocation return, native page backing, MMU mapping, full constructor or foreground closure.')
 dump(OUT,result)
 print(json.dumps(dict(all_passed=True,inherited_zones=24,body_zones=7,FP_zones=8,native_PUSH_stores=21,
   actual_native_heap_stores=13,actual_native_lock_returns=1,malloc_return_verified=False,
   proof_sha256=sha(OUT),next_contract_sha256=sha(CONTRACT))))
if __name__=='__main__':main()
