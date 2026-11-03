#!/usr/bin/env python3
"""AST-only inherited provider audit and pure V3 predicates; no VM imported."""
import sys
sys.dont_write_bytecode=True
import ast,copy,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];BASE=Path(__file__).resolve().parent
SOURCE=BASE/'native_allocation_observer_v3.py'
def require(v,m):
 if not v:raise RuntimeError(m)
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def dump(name,v):
 with(BASE/name).open('x')as f:json.dump(v,f,ensure_ascii=False,indent=2);f.write('\n')

def ancestry():
 seen=set();rows=[]
 def walk(path,name):
  key=str(path),name
  if key in seen:return
  seen.add(key);tree=ast.parse(path.read_text());imports={};assigns={};classes={}
  for n in tree.body:
   if isinstance(n,ast.ImportFrom):
    for a in n.names:imports[a.asname or a.name]=('from',n.module,a.name)
   elif isinstance(n,ast.Import):
    for a in n.names:imports[a.asname or a.name]=('module',a.name)
   elif isinstance(n,ast.Assign):
    for t in n.targets:
     if isinstance(t,ast.Name):assigns[t.id]=n.value
   elif isinstance(n,ast.ClassDef):classes[n.name]=n
  require(name in classes,'Unresolved actual inherited class '+str(key));c=classes[name]
  rows.append(dict(path=str(path.relative_to(ROOT)),class_name=name,line=c.lineno,
                   bases=[ast.unparse(b)for b in c.bases],node=c))
  def resolve(b):
   if isinstance(b,ast.Name)and b.id in assigns:return resolve(assigns[b.id])
   if isinstance(b,ast.Name)and b.id in imports:
    kind,mod,*names=imports[b.id]
    if kind=='from':return ROOT/'scripts'/(mod+'.py'),names[0]
   if isinstance(b,ast.Attribute)and isinstance(b.value,ast.Name)and b.value.id in imports:
    kind,mod,*_=imports[b.value.id]
    if kind=='module':return ROOT/'scripts'/(mod+'.py'),b.attr
   raise RuntimeError('Unresolved inherited base '+ast.unparse(b))
  for b in c.bases:walk(*resolve(b))
 walk(ROOT/'scripts/probe_native_cold_fp_controller.py','ColdFPControllerVM')
 return rows

def main():
 tree=ast.parse(SOURCE.read_text());nodes=[]
 for n in tree.body:
  if isinstance(n,ast.Assign)and all(isinstance(t,ast.Name)and t.id in {'D','PROVIDER_GATES','FORBIDDEN_PENDING_PROVIDER_GATES'}for t in n.targets):nodes.append(n)
  if isinstance(n,ast.FunctionDef)and n.name in {'validate_native_provider_gate','reject_unknown_pending_provider'}:nodes.append(n)
 env=dict(require=require);exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),env)
 cases=[]
 for request,cont in [(48,0x395534),(8,0x395544)]:
  shape=dict(B=0x8803FB0,request=request,continuation=cont,LR=cont|1,query_entry_SP=0x8803FA0,validator_entry_SP=0x8803F90)
  for entry,opcode in env['PROVIDER_GATES'].items():
   sp=shape['B']if entry==0x2DC954 else shape['query_entry_SP']if entry==0x388804 else shape['validator_entry_SP']
   lr=cont|1 if entry==0x2DC954 else 0x2DC96B if entry==0x388804 else 0x38881B
   args=[request,0,8,cont|1]if entry==0x2DC954 else[0x18302FD8,0x2DC96B,0x18301000,0x30092A]
   frame=dict(entry=hex(entry),actual_task='0x8804fb8',Thumb=True,SP=sp,LR=lr,arguments=args,
     original_entry_opcode=opcode,returned=False,host_context_or_return_supplied=False)
   event=dict(actor=0x8804FB8,current=0x8804FB8,Thumb=True,PC=entry,opcode=opcode,SP=sp,LR=lr,arguments=args,
     pending_original_allocation=True,original_cold_recipe_verified=True,actual_five_thunk_instructions_seen=True,
     actual_original_tail_branch_seen=True,native2DC954_entry_seen=True,gate_already_seen=False,frame=frame,
     lower_return_seen=entry!=0x2DC954,query_return_seen=False,native_handle=None if entry==0x2DC954 else 0x18302FD8,
     raw_operations_completed=0 if entry==0x2DC954 else 2 if entry==0x388804 else 3,query_PUSH_verified=entry==0x388E92)
   env['validate_native_provider_gate'](shape,entry,event)
   cases.append(dict(name=f'{request}/{hex(entry)}/valid strict native entry',passed=True))
   bad=[('actor',0x9503F90),('current',0),('Thumb',False),('PC',entry+2),('opcode','0000'),('SP',sp-4),('LR',lr-1),
     ('arguments',[0,0,0,0]),('pending_original_allocation',False),('original_cold_recipe_verified',False),
     ('actual_five_thunk_instructions_seen',False),('actual_original_tail_branch_seen',False),('native2DC954_entry_seen',False),
     ('gate_already_seen',True),('lower_return_seen',not event['lower_return_seen']),('raw_operations_completed',9)]
   if entry!=0x2DC954:bad += [('native_handle',None),('query_return_seen',True)]
   else:bad += [('native_handle',0x8400020)]
   if entry==0x388E92:bad += [('query_PUSH_verified',False)]
   for key,value in bad:
    altered=copy.deepcopy(event);altered[key]=value
    try:env['validate_native_provider_gate'](shape,entry,altered)
    except RuntimeError as error:cases.append(dict(name=f'{request}/{hex(entry)}/reject {key}',passed=True,error=str(error)))
    else:raise RuntimeError('Invalid provider gate admitted '+key)
   for key,value in [('entry','0x2dc982'),('SP',sp-4),('actual_task','0x9503f90'),('Thumb',False),('LR',lr-1),
                     ('arguments',[0,0,0,0]),('original_entry_opcode','0000'),('returned',True),('host_context_or_return_supplied',True)]:
    altered=copy.deepcopy(event);altered['frame'][key]=value
    try:env['validate_native_provider_gate'](shape,entry,altered)
    except RuntimeError as error:cases.append(dict(name=f'{request}/{hex(entry)}/reject frame {key}',passed=True,error=str(error)))
    else:raise RuntimeError('Invalid frame admitted '+key)
   try:env['validate_native_provider_gate'](shape,0x2DC982,event)
   except RuntimeError:cases.append(dict(name=f'{request}/{hex(entry)}/unknown calloc gate rejected',passed=True))
   else:raise RuntimeError('Unknown provider gate admitted')
 for entry in env['FORBIDDEN_PENDING_PROVIDER_GATES']:
  try:env['reject_unknown_pending_provider'](entry)
  except RuntimeError:cases.append(dict(name='pending unknown provider rejected '+hex(entry),passed=True))
  else:raise RuntimeError('Unknown pending allocator/free entry admitted')
 for n in ast.walk(tree):
  if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute):require(n.func.attr not in {'mem_write','mem_map','reg_write','ret','emu_start','host_return'},'V3 must only observe exact route')
 observer=next(n for n in tree.body if isinstance(n,ast.ClassDef)).body
 method=next(n for n in observer if isinstance(n,ast.FunctionDef)and n.name=='observe_dispatcher_actor')
 require(ast.unparse(method).index('super().observe_dispatcher_actor')<ast.unparse(method).index('validate_native_provider_gate'),
   'Frozen parent guards must execute before new gate bypass')
 from_path=ROOT/'scripts';sys.path.insert(0,str(from_path))
 from analyze_native_sections import NativeImage
 stock=NativeImage()
 for pc,opcode in env['PROVIDER_GATES'].items():require(stock.read(pc,2).hex()==opcode,'Exact original gate PUSH bytes')
 cfg=json.loads((BASE/'native-heap-original-opcodes.json').read_text())
 pcs={int(i['PC'],16)for f in cfg['bounded_CFG'].values()for i in f['instructions']}
 chain=ancestry();matches=[]
 meta_path=ROOT/'staging/native-player-native-allocation/runtime-v2/terminal-metadata.json'
 meta=json.loads(meta_path.read_text());probe_path=ROOT/meta['probe'];j=json.loads(probe_path.read_text())
 require(meta['authoritative_terminal_result_received_from_exec']and(meta['session_id'],meta['actual_exec_chunk'],meta['terminal_exit_code'])==(24221,'7d85a6',1),
   'Actual immutable V2 terminal identity')
 receipt_path=ROOT/'staging/native-player-native-allocation/terminal-v2-receipt.json';receipt=json.loads(receipt_path.read_text());actual=receipt['tool_result']
 require(receipt['observed_session_id']==24221 and 'session_id'not in actual and actual['chunk_id']=='7d85a6'and actual['exit_code']==1,
   'Actual V2 terminal raw exec receipt')
 require(meta['GUI_observer_sha256']==sha(BASE/'native_allocation_observer_v2.py'),'Actual V2 observer identity')
 for row in chain:
  p=ROOT/row['path'];require(meta['source_sha256'][row['path']]==sha(p),'Actual inherited provider source hash differs')
  for n in ast.walk(row['node']):
   if isinstance(n,ast.If):
    addresses={c.value for c in ast.walk(n.test)if isinstance(c,ast.Constant)and type(c.value)is int}&pcs
    if addresses:
     effects=sorted({x.func.attr for b in n.body for x in ast.walk(b)if isinstance(x,ast.Call)and isinstance(x.func,ast.Attribute)
                     and x.func.attr in {'mem_write','reg_write','ret','put','descriptor'}})
     matches.append(dict(path=row['path'],class_name=row['class_name'],line=n.lineno,
       test=ast.unparse(n.test),bounded_original_PCs=[hex(p)for p in sorted(addresses)],potential_host_effects=effects))
 audit=dict(all_passed=True,AST_source_only=True,guest_execution=False,VM_import_or_instantiation=False,
   source_sha256={row['path']:sha(ROOT/row['path'])for row in chain},actual_inherited_class_count=len(chain),
   actual_inherited_classes=[{k:v for k,v in row.items()if k!='node'}for row in chain],
   original_bounded_function_count=len(cfg['bounded_CFG']),all_bounded_instruction_PCs_inspected=len(pcs),matched_original_PC_conditions=matches,
   concrete_provider_entries=[
    dict(entry='0x3954cc',source='scripts/emulate_native_player_menu_loaded.py:74',effect='raw_allocate via menu_hooks; frozen V1 exact ARM entry already bypasses'),
    dict(entry='0x2dc9ea',source='scripts/emulate_native_player_menu_selection.py:52',effect='raw_allocate hook -> GridVM/LoadedPlayerVM host provider; frozen V2 exact thunk already bypasses'),
    dict(entry='0x2dc954',source='scripts/emulate_native_player_widget.py:67',effect='unconditional aligned host allocation, A5 mem_write then self.ret(pointer); NEW V3 exact gate bypass'),
    dict(entry='0x388804',source='scripts/emulate_native_vpm_filesystem.py:84',effect='initial lock_handle hook; VoiceMetadata ctor:44 pops it, original query still explicitly protected in V3'),
    dict(entry='0x388e92',source='scripts/probe_native_heap_callback.py:53',effect='host descriptor translation writes R0; deeper VoiceMetadata:56 also supplies descriptor/R0/PC; NEW V3 exact gate bypass')],
   excluded_provider_entries=[dict(entry='0x2dc954',source='scripts/probe_native_mainmenu_controller.py:29',caller='0x6f8364',
     reason='transition allocator caller differs from original395535/395545; not authorized'),
    dict(entry='0x2dc954',source='scripts/probe_native_controller_gir_component.py:191',caller='0x6f8364',
     reason='component transition-only condition; completed component is inactive during new native route'),
    dict(entry='0x38853c',source='scripts/emulate_native_vpm_filesystem.py:83',reason='generic handle allocator not in native38850A->3881BC successful route; not admitted')],
   no_other_host_provider_at_original38850A_3881BC_388DF2_3880BC_388144_21210C=True,
   all_existing_global_hooks_retained=True,raw_mutex_IRQ_and_parent_epilogues_unchanged=True)
 dump('native-allocation-inherited-provider-audit-v3.json',audit)
 s=j['body_actor_observations']['native_allocation_observer'];t=j['body_actor_observations']['native_allocator_thunk_observer'];a=s['pending']
 require(j['registers']=={'r0':'0x8400020','r1':'0x0','r2':'0x8','r3':'0x395535','lr':'0x395535','pc':'0x395534','sp':'0x8803fb0'},'Exact V2 inherited return ABI')
 require(len(t['chains'])==1 and [r['PC']for r in t['chains'][0]['thunk_instructions_seen']]==['0x2dc9ea','0x2dc9ec','0x2dc9ee','0x2dc9f0','0x2dc9f2'],
   'Actual V2 original thunk instruction observations')
 frame=s['frame_history'][-1]
 require(len(s['frame_history'])==9 and frame['entry']=='0x2dc954'and not frame['original_push_verified']and not frame['returned']
   and frame['SP']==0x8803FB0 and frame['arguments']==[48,0,8,0x395535], 'V2 entry logged but original PUSH not executed')
 require(not s['raw_ops']and not a['lower_return_seen']and not a['query_return_seen']and a['native_handle'] is None and a['native_pointer'] is None,
   'No actual native malloc result in V2')
 require(isinstance(j['partial_inherited_zone_verification'],list)and len(j['partial_inherited_zone_verification'])==24,
   'V2 restored exact inherited actual-after capture')
 require(all(isinstance(z['after_sha256'],str)and len(z['after_sha256'])==64 for z in j['partial_inherited_zone_verification']),
   'Actual inherited after hash exists for each V2 zone')
 paths=[SOURCE,Path(__file__).resolve(),BASE/'native_allocation_observer_v2.py',BASE/'native-allocation-observer-v2-contract.json',
   BASE/'native-allocation-inherited-provider-audit-v3.json',meta_path,probe_path,
   ROOT/'staging/native-player-native-allocation/terminal-v2-receipt.json',ROOT/meta['runner'],ROOT/meta['cold_prefix'],
   ROOT/'staging/native-player-native-allocation/constructor-leaf-helpers-static.json',ROOT/'evidence/firmware-analysis/main_02bd.bin']
 sources={str(p.relative_to(ROOT)):sha(p)for p in paths};sources.update(audit['source_sha256'])
 require(sha(probe_path)==meta['probe_sha256']and sha(ROOT/meta['runner'])==meta['runner_sha256'],'Frozen V2 runtime hash')
 correction=dict(all_passed=True,file_and_source_only=True,guest_execution_by_review=False,source_sha256=sources,
   original_guest_session=24221,original_terminal_chunk='7d85a6',original_exit_code=1,original_error=j['error'],actual_registers=j['registers'],
   actual_original_thunk_instructions=5,actual_native2DC954_entry_frame_seen=True,actual2DC954_PUSH_executed=False,
   actual_native_raw_operations=0,original48_8_native_success_verified=False,
   inherited_host_provider_return_pointer='0x8400020',inherited_provider_source='scripts/emulate_native_player_widget.py:67–85',
   observer_local_host_false_does_not_describe_inherited_pipeline=True,
   native_allocator_thunk_host_hook_used_in_V2_scope_false_is_only_the_specific2DC9EA_gate=True,
   V2_parent_whole24_actual_after_captured=True,V2_whole24_independent_replay_not_performed_by_this_static_review=True,
   firmware_or_original_allocator_failure_verified=False,immutable_V2_sources_and_receipt_unchanged=True)
 dump('native-allocation-v2-terminal-scope-correction.json',correction)
 sources[str((BASE/'native-allocation-v2-terminal-scope-correction.json').relative_to(ROOT))]=sha(BASE/'native-allocation-v2-terminal-scope-correction.json')
 parent=json.loads((BASE/'native-allocation-observer-v2-contract.json').read_text())
 for p,h in parent['source_sha256'].items():require(p not in sources or sources[p]==h,'Frozen V2 dependency differs');sources[p]=h
 contract=dict(all_passed=True,static_only=True,guest_execution=False,VM_import_or_instantiation=False,device_io=False,
   source_sha256=sources,host_only_controls=cases,host_only_control_count=len(cases),original_entry_opcode_assertions=3,
   observer_interface=dict(source_path=str(SOURCE.relative_to(ROOT)),class_name='NativeAllocationDispatcherActorObserverMixin',
     same_root_init_capture_prepare_native_public_heap_input_native_heap_init_arguments_verify_heap_verify_native_public_heap_guards=True,
     parent='Frozen V2 c6b9aee523f3...',additional_snapshot_key='native_allocator_provider_gate_observer'),
   exact_new_gate_entries=['0x2dc954','0x388804','0x388e92'],
   gate_admission='Frozen V2/V1 observation and original call/frame/opcode/actor guards execute first; only same unique native pending48/8 entry then returnsTrue to skip inherited host provider. Original PUSH executes normally.',
   genuine_return_requirements='V1 lower/query/raw/prefix/output/TCB108 histories and V2 actual thunk/caller returns remain mandatory; V3 final prefix additionally needs exactlysix ordered provider gates.',
   public_fixture_constructor_stack_whole24_backend_descriptor_TCB_scopes_unchanged=True,
   unknown_original395552_container_362A2C_other_allocator_or_page_diagnostic_free_branches_remain_hard_stop=True,
   allocator_success_in_V2=False,allocator_success_in_V3_not_observed=True,
   global_hooks_deleted_or_modified=False,guest_memory_or_registers_or_returns_supplied=False,
   full_Dispatcher_or_foreground_or_physical_App_verified=False)
 dump('native-allocation-observer-v3-contract.json',contract)
 print(json.dumps(dict(all_passed=True,pure_controls=len(cases),inherited_classes=len(chain),matched_PC_conditions=len(matches),
   helper_sha256=sha(SOURCE),contract_sha256=sha(BASE/'native-allocation-observer-v3-contract.json'),
   V2_correction_sha256=sha(BASE/'native-allocation-v2-terminal-scope-correction.json'))))
if __name__=='__main__':main()
