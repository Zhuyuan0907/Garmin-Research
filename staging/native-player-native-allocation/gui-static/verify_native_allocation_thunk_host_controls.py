#!/usr/bin/env python3
"""Pure V2 thunk-shape host controls; no VM imported, created or executed."""
import sys
sys.dont_write_bytecode=True
import ast,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];BASE=Path(__file__).resolve().parent
S=BASE/'native_allocation_observer_v2.py'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def require(v,m):
 if not v:raise RuntimeError(m)
def dump(name,v):
 with(BASE/name).open('x')as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')
def main():
 tree=ast.parse(S.read_text());nodes=[]
 for n in tree.body:
  if isinstance(n,ast.Assign)and all(isinstance(t,ast.Name)and t.id in {'D','FLAGS','THUNK','THUNK_INSTRUCTIONS'}for t in n.targets):nodes.append(n)
  if isinstance(n,ast.FunctionDef)and n.name=='validate_native_thunk_shape':nodes.append(n)
 env=dict(require=require);exec(compile(ast.Module(body=nodes,type_ignores=[]),str(S),'exec'),env)
 cases=[]
 for N,cont,firstargs in [(48,0x395534,[48,0xF09098,0x8804058,0xEA60]),(8,0x395544,[8,0x18304FC8,0x18302FD8,0x395535])]:
  shape=dict(B=0x8803FB0,request=N,LR=cont|1)
  for i,(pc,op)in enumerate(env['THUNK_INSTRUCTIONS']):
   args=list(firstargs)
   if i>=1:args[1]=0xF070B0
   if i>=2:args[2]=8
   if i>=3:args[1]=0
   if i>=4:args[3]=cont|1
   e=dict(actor=0x8804FB8,current=0x8804FB8,Thumb=True,PC=pc,opcode=op,SP=shape['B'],LR=cont|1,
     R12=0x2DC9EB,flags_word=0,veneer_BX_seen=True,arguments=args)
   env['validate_native_thunk_shape'](shape,firstargs,i,e);cases.append(dict(name=f'{N}/native instruction{i} valid registers',passed=True))
   for key,val in [('actor',0x9503F90),('current',0),('Thumb',False),('PC',pc+2),('opcode','0000'),('SP',e['SP']-4),
                   ('LR',cont),('R12',0x2DC9EA),('flags_word',1),('veneer_BX_seen',False),('arguments',[0,0,0,0])]:
    altered=dict(e);altered[key]=val
    try:env['validate_native_thunk_shape'](shape,firstargs,i,altered)
    except RuntimeError as error:cases.append(dict(name=f'{N}/{i}/reject{key}',passed=True,error=str(error)))
    else:raise RuntimeError('Bad thunk input admitted')
 for n in ast.walk(tree):
  if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute):require(n.func.attr not in {'mem_write','mem_map','reg_write','ret','emu_start','host_return'},'V2 must only observe/bypass exact native hook')
 probe_path=ROOT/'staging/native-player-native-allocation/runtime/terminal-probe.json'
 j=json.loads(probe_path.read_text());a=j['body_actor_observations']['native_allocation_observer'];pending=a['pending']
 require(j['registers']['pc']=='0x395534' and j['registers']['r0']=='0x88246a0' and j['registers']['sp']=='0x8803fb0','Actual v1 terminal ABI')
 require(a['cold_init_returned']and a['cold_recipe_verified']and a['constructor_stack']['whole_net_zone_matches_original_stores'],'Actual v1 original public ctor complete')
 require(len(a['raw_ops'])==0 and not pending['lower_return_seen']and not pending['query_return_seen']and not pending['prefix_store_seen']
   and not pending['actual_original_caller_return_seen']and len(a['frame_history'])==8,'V1 never executed bounded allocator body')
 require(j['partial_inherited_zone_verification']=={'passed':False,'error':'First/same native FP owner differs'},'Preserve actual missed inherited terminal scope')
 paths=[S,Path(__file__).resolve(),BASE/'native_allocation_observer.py',BASE/'native-allocation-observer-contract.json',
  ROOT/'scripts/emulate_native_player_menu_selection.py',ROOT/'scripts/emulate_native_player_grid.py',
  ROOT/'scripts/probe_native_dispatcher_public_heap_allocation.py',ROOT/'scripts/seal_native_public_heap_attempt.py',
  probe_path,ROOT/'staging/native-player-native-allocation/runtime/runner-at-run.py',
  ROOT/'staging/native-player-native-allocation/terminal-receipt.json',ROOT/'staging/native-player-native-allocation/runtime/cold-prefix-sealed.json',
  BASE/'native-public-heap-input-config.json',BASE/'native-heap-original-opcodes.json']
 sources={str(p.relative_to(ROOT)):sha(p)for p in paths}
 correction=dict(all_passed=True,file_and_source_only=True,guest_execution_by_review=False,source_sha256=sources,
  original_guest_session=87914,original_terminal_chunk='4ab59e',original_exit_code=1,
  actual_registers=j['registers'],original_error=j['error'],native_public_initializer_return_verified_by_runner=True,
  actual_original_constructor_stack_CPU_stores=57,allocator_attempt_rows=1,
  actual_native_malloc_frames=0,actual_native_heap_raw_ops=0,original48_or8_native_allocation_success_verified=False,
  inherited_host_provider_return_observed=True,host_return_pointer='0x88246a0',
  provider_hook_registration='scripts/emulate_native_player_menu_selection.py:52–53 adds2DC9EA raw_allocate',
  provider_effect='scripts/emulate_native_player_grid.py:72–81 creates separate CXX heap bytes and calls self.ret(pointer)',
  observer_local_host_supplied_false_is_not_whole_pipeline_claim=True,
  scope_gap='V1 bypasses ARM3954CC entry but still delegates Thumb2DC9EA to inherited host provider; no native thunk instruction/body recorded.',
  inherited_terminal_after_snapshot_missing=True,actual_inherited_terminal_verification_failure=j['partial_inherited_zone_verification'],
  inherited_terminal_failure_source='Publicheap v1 switched old explicit HeapSettingsVM body verification to virtual ColdFP first/same-controller guard after legitimate D owner.',
  no_retroactive_whole_inherited_terminal_replay_claim=True,firmware_or_allocator_failure_verified=False,
  V1_frozen_sources_not_modified=True,V2_original_memory_inputs_and_native_guards_unchanged=True)
 dump('native-allocation-v1-terminal-scope-correction.json',correction)
 sources[str((BASE/'native-allocation-v1-terminal-scope-correction.json').relative_to(ROOT))]=sha(BASE/'native-allocation-v1-terminal-scope-correction.json')
 parent=json.loads((BASE/'native-allocation-observer-contract.json').read_text())
 for p,h in parent['source_sha256'].items():require(p not in sources or sources[p]==h,'V1 dependency mismatch');sources[p]=h
 doc=dict(all_passed=True,static_only=True,guest_execution=False,VM_import_or_instantiation=False,device_io=False,
  source_sha256=sources,host_only_controls=cases,host_only_control_count=len(cases),
  observer_interface=dict(source_path=str(S.relative_to(ROOT)),class_name='NativeAllocationDispatcherActorObserverMixin',
    parent='frozen native_allocation_observer.py f072a33b...',same_root_init_capture_verify_public_guard_interfaces=True,
    parent_cold_ctor_and_whole16Kstack_and_48_8_native_raw_descriptor_TCB_guards_retained=True),
  exact_new_scope=dict(original_route=['3954CC ARM LDRr12 literal2DC9EB','3954D0 ARM BXr12','2DC9EA ThumbLDR','2DC9EC MOV8',
    '2DC9EE LDRflags','2DC9F0 MOVcallerLR','2DC9F2 tailB2DC954'],
    caller_LR=['0x395535','0x395545'],actual_D='0x8804fb8',SP='captured395520SP-128; actual priorB8803FB0',
    actual_veneer_R12='0x2dc9eb',initial_arguments='actual current native ARMentry registers, no guessed r1/r2/r3',
    expected_effective_native2DC954_arguments='[originalN,originalF070B0=0,8,actualoriginalcallerLR]',
    hook_bypass='returnTrue only original2DC9EA exactpending gate; instruction executes, no host retval or guest patch',
    unknown_callers_and_unknown_native_malloc_page_or_diagnostic_branches_remain_strict=True),
  V1_terminal_provenance_correction=str((BASE/'native-allocation-v1-terminal-scope-correction.json').relative_to(ROOT)),
  original_public_init_in_V1_can_have_independent_file_proof=True,
  native48_8_success_in_V1=False,native48_8_success_in_V2_not_yet_run=True,
  inherited_V1_terminal_whole24_after_capture_absent=True,
  root_NEW_V2_body_verifier_requirement='Explicit HeapSettingsVM.verify_extra_zones plus independent native_fp and publicheap guards; do not use controller-only virtual method after Downer',
  full_Dispatcher_or_foreground_or_physical_App_verified=False)
 dump('native-allocation-observer-v2-contract.json',doc)
 print(json.dumps(dict(all_passed=True,controls=len(cases),helper_sha256=sha(S),contract_sha256=sha(BASE/'native-allocation-observer-v2-contract.json'),
   v1_correction_sha256=sha(BASE/'native-allocation-v1-terminal-scope-correction.json'))))
if __name__=='__main__':main()
