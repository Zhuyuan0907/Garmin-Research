#!/usr/bin/env python3
"""AST-extracted pure shape controls and file verification; never imports a VM."""
import sys
sys.dont_write_bytecode=True
import ast,hashlib,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];BASE=Path(__file__).resolve().parent
SOURCE=BASE/'native_allocation_observer.py'

def sha(path):
 h=hashlib.sha256()
 with path.open('rb')as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def require(v,s):
 if not v:raise RuntimeError(s)
def main():
 tree=ast.parse(SOURCE.read_text());nodes=[]
 names={'WORK','BACKEND','PRIVATE','PRIVATE_BYTES','PUBLIC','PUBLIC_BYTES','ENVELOPE','ENVELOPE_BYTES','DESC_PAGE','DESC','D','RETURN','RAW'}
 for n in tree.body:
  if isinstance(n,ast.Assign)and all(isinstance(t,ast.Name)and t.id in names for t in n.targets):nodes.append(n)
  elif isinstance(n,ast.FunctionDef)and n.name in {'native_public_heap_recipe','allocation_shape','check_allocation_raw'}:nodes.append(n)
 env=dict(struct=struct,require=require);exec(compile(ast.Module(body=nodes,type_ignores=[]),str(SOURCE),'exec'),env)
 cases=[]
 def reject(name,fn):
  try:fn()
  except RuntimeError as e:cases.append(dict(name=name,passed=True,expected_rejection=str(e)));return
  raise RuntimeError('Invalid guard input unexpectedly admitted '+name)
 recipe=env['native_public_heap_recipe']();p=recipe['private'];w=recipe['workspace']
 require(len(p)==8192 and len(w)==96 and recipe['public']==b'\xcc'*16384,'Exact bounded expected image lengths')
 require(struct.unpack_from('<I',w,0x50)[0]==8192 and struct.unpack_from('<2I',w,0x54)==(8192,8192),'Private byte counter vs used descriptor/prefix bytes')
 require(recipe['start']==0x18302FD8 and recipe['end']==0x18302FC0 and recipe['remaining']==0x18302FA8 and recipe['bin_slot']==0x1830157C,'Original descriptor-page arithmetic')
 require(p[0xFD4:0x1000]==bytes(44),'Private prefix last padding remains zero')
 require(p[0x1FF0:0x2000]==b'\xcc'*16,'170*24 descriptor-page tail16 preserved')
 require(p[recipe['start']-0x18301000+12:recipe['start']-0x18301000+16]==b'\xcc'*4,
  'Unused first public descriptor+0C retained initial CC bytes')
 cases.append(dict(name='whole cold public/private fixture recipe including descriptor gaps',passed=True))
 for request,cont in [(48,0x395534),(8,0x395544)]:
  shape=env['allocation_shape'](0x8803FB0,request,cont)
  require(shape['output_cell']==0x8803FA0 and shape['core_body_SP']==0x8803F50 and shape['query_body_SP']==0x8803F90,'Actual sealed B relative native SP formulas')
  for (entry,c), (f,push,op)in env['RAW'].items():
   F=shape['malloc_entry_SP']if f==0x38850A else shape['query_entry_SP']
   event=dict(entry=entry,continuation=c,task=0x8804FB8,current=0x8804FB8,Thumb=True,pointer=0x3A7F18C,
     SP=F-push,LR=c|1,tag=0x388D00,**{'class':0})
   require(env['check_allocation_raw'](shape,F,event)==op,'Valid exact raw guard')
   cases.append(dict(name=f'actual sealed B/{request}/raw {hex(c)} shape',passed=True))
   for field,value in [('task',0x9503F90),('current',0),('Thumb',False),('pointer',0x148E6CC),('SP',event['SP']+4),('LR',c),('tag',0),('class',1)]:
    altered=dict(event);altered[field]=value
    reject(f'{request}/{hex(c)}/reject wrong {field}',lambda e=altered,S=shape,F=F:env['check_allocation_raw'](S,F,e))
 for args in [(0x8803FB2,48,0x395534),(0x8803FB0,16,0x395544),(0x8803FB0,48,0x395544),(0x8803FB0,8,0x395534)]:
  reject('reject unrelated allocator caller/shape '+str(args),lambda args=args:env['allocation_shape'](*args))
 # Independent opcode source identity, all89 bounded store sites, original
 # cold initializer six STRs and actual Thumb raw owned-list sites.
 data=json.loads((BASE/'native-heap-original-opcodes.json').read_text())
 mainfile=ROOT/'evidence/firmware-analysis/main_02bd.bin';require(sha(mainfile)=='10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8','Exact MAIN')
 blob=mainfile.read_bytes()
 for pc,r in data['writer_opcodes'].items():
  o=int(pc,16)-0x50000;require(blob[o:o+len(bytes.fromhex(r['opcode_hex']))].hex()==r['opcode_hex'],'Original opcode '+pc)
 for pc,op in [(0x3008A2,'0160'),(0x3008A4,'4160'),(0x3008A6,'8160'),(0x3008A8,'c160'),(0x3008AA,'0161'),(0x3008AC,'4161'),
               (0x3009D4,'1060'),(0x3008F8,'0a60'),(0x388448,'4462'),(0x395548,'0160'),(0x395550,'0171')]:
  o=pc-0x50000;require(blob[o:o+len(bytes.fromhex(op))].hex()==op,'Original init/TCB/payload writer')
 cases.append(dict(name='89 bounded heap store opcodes + six native initializer + threeTCB + two payload opcodes',passed=True))
 # Source bans: only declared new fixture inputs can host-write; no guest
 # register mutation/host return/host allocation metadata insertion.
 cls=next(n for n in tree.body if isinstance(n,ast.ClassDef))
 calls=[]
 for method in cls.body:
  if not isinstance(method,ast.FunctionDef):continue
  for n in ast.walk(method):
   if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute):
    if n.func.attr in ('reg_write','ret','host_return','emu_start'):raise RuntimeError('Forbidden guest substitution '+n.func.attr)
    if n.func.attr in ('mem_write','mem_map'):
     require(method.name=='prepare_native_public_heap_input','Host mutation outside explicit fixture prepare')
     calls.append(dict(method=method.name,operation=n.func.attr,line=n.lineno))
 require(not any(isinstance(n,ast.Assign)and any(isinstance(t,ast.Subscript)and isinstance(t.value,ast.Attribute)and t.value.attr=='raw_allocations'for t in n.targets)for n in ast.walk(cls)),
  'No host raw allocation inventory impersonation')
 cases.append(dict(name='source forbids guest context/return replacement and native malloc host inventory impersonation',passed=True))
 inputs=[SOURCE,Path(__file__).resolve(),BASE/'native-heap-original-opcodes.json',BASE/'native-public-heap-input-config.json',
  BASE/'build_native_public_heap_contract.py',BASE/'build_native_public_heap_contract_unexecuted_cfg_v1.py',
  ROOT/'staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py',ROOT/'scripts/probe_native_heap_settings_boot.py',
  ROOT/'scripts/native_cold_fp_guard_copies.py',ROOT/'scripts/probe_native_cold_fp_controller.py',ROOT/'scripts/probe_native_task_mutex.py',
  ROOT/'scripts/probe_native_dispatcher_clock_caller.py',ROOT/'staging/native-player-clock-caller/runtime/terminal-probe.json',
  ROOT/'staging/native-player-clock-caller/terminal-receipt.json',ROOT/'staging/native-player-native-allocation/previous-checkpoint.json',mainfile]
 source={str(p.relative_to(ROOT)):sha(p)for p in inputs}
 doc=dict(all_passed=True,static_only=True,guest_execution=False,VM_import_or_instantiation=False,device_io=False,
  source_sha256=source,host_only_controls=cases,host_only_control_count=len(cases),declared_fixture_host_operations=calls,
  actual_prior_terminal=dict(session=5264,chunk='3bd84b',PC='0x3954cc',LR='0x395535',SP='0x8803fb0',r0='0x30',
    allocator_return_not_seen=True,private_only_heap_no_public_free_bins=True),
  observer_interface=dict(source_path=str(SOURCE.relative_to(ROOT)),class_name='NativeAllocationDispatcherActorObserverMixin',
    parent_source_path=str((ROOT/'staging/native-player-clock-caller/gui-static/clock_caller_observer_v2.py').relative_to(ROOT)),
    initialization='root constructor calls init_dispatcher_actor_observer after original super().__init__',
    first_cold_sequence=['after original seal_cold_boot: prepare_native_public_heap_input()',
      'begin_extra_zones(existing inventory,timed)',"phase='heap_ctor'",'native_heap_init_arguments(EXTENT)',
      'original current-controller kernel_invoke388B6D with returned4arguments','verify_heap(cold=True)',
      'verify_native_public_heap_guards()'],
    input_capture='inherited capture_decoder_inputs then capture_dispatcher_settings_inputs; new allocation capture is chained at end',
    body_observer='root observe_dispatcher_actor before parent; True only native allocator entries and exact raw rows and48/8 continuations',
    final_or_partial_guards='always verify_native_public_heap_guards; only complete two-allocation prefix calls verify_native_allocation_prefix',
    new_whole_zones=['public guarded envelope18304000/24576','descriptor page1830B000/4096'],
    heap_ctor_separate_stack_journal='NEW whole actual controller stack16384 before first388B6C, captured originalPUSH/register effects, replay/seal at genuine native RETURN; old five boot zones stay sealed',
    original_epilogues='300A0A/30092A delegate and consume same parent task_mutex_ops ledger'),
  native_public_init=dict(original_ABI='r0/privatearray,r1/count,r2/publicarray,r3/count',new_arguments=['EXTENT',1,'0x1830b020',1],
    original_boot_private=['0x14e5238','0x1800000'],original_boot_public=['0xc0000000','0x10000000'],
    original_boot_file_data_is_not_guest_mapping_or_hardware_free_heap=True,
    actual_WORK96_zero_before_firstcall_required=True,repeated_WORK_reset_or_warm_public_extension_forbidden=True,
    original_initializer='388BCC→3008A0 six native zero STRs; tag388BD2=388D00/class0',
    free_bin_recipe_expected_only=dict(private_extent8192=True,prefix4096=True,descriptor_page4096=True,
      descriptors170_stride24=True,Hstart='0x18302fd8',Hend='0x18302fc0',remaining='0x18302fa8',bin_slot='0x1830157c',
      WORK50=8192,WORK54=8192,WORK58=8192),
    initialization_returns_or_recipe_not_yet_runtime_verified=True),
  native_allocation_scope=dict(native_chain=['3954CC ARMveneer','2DC9EA original F070B0 flags0/alignment8/callerLR','2DC954',
    '38850A rawwrapper','3881BC','388804 rawquery','388E92 handlevalidator','2DC97E prefixstore','2DC980 originalcallerreturn'],
    only_original_callers=['395530→395534 N48','395540→395544 N8'],raw_pairs=['38851C','388534','388812','388826'],
    backend='0x3a7f18c',backend_whole24_actual_histories=True,TCB_whole108_before_and_after_allfive_required=True,
    exact_D_TCB24_offset36_native_ownerhead_only=True,exact_native_raw_D_TCB32_push_restore=True,
    released_stale_links_not_zeroed=True,native_handle24_original_private_descriptor_page_lifetime=True,
    actual_output_cell_cpu_order=['2DC954 PUSHsavedr3=captured callerLR','2DC95C zero','3881CA zero','3884C0 actualH'],
    payload_initializer='original395548 vtableC1C0EC;395550 actualstackbyteB+30;P8+5..7actualbefore preserved',
    no_native_allocations_inserted_in_hostraw_dictionary=True,
    next_explicit_boundary='395552 before post-allocation timer/container initialization; nofree/dtor/362A2C lifecycle admitted',
    allocation_return_or_success_not_yet_runtime_verified=True),
  scope_qualifications=dict(fullcold_run_with_new_public_inputs_verified=False,physical_App_or_foreground_verified=False,
    native_hardware_or_actual_device_free_heap_verified=False,unknown_provider_or_diagnostic_branch_hardstop=True,
    old_manager_clock_controller_timer_FP_decoder_settings_global_inline_checks_retained=True,
    prelaunch_correction='ColdFPControllerVM.seal_cold_boot disables oldcoldjournal. New independent heap_ctor stack ledger implemented; no guest failure or oldjournal restart.',
    host_producer_first_attempt='Original reused CFG utility incorrectly classified conditional BX as immediate branch; saved producer v1 failed before any outputs or guest, new local CFG handles BX modes.'))
 out=BASE/'native-allocation-observer-contract.json'
 with out.open('x')as h:json.dump(doc,h,ensure_ascii=False,indent=2);h.write('\n')
 print(json.dumps(dict(all_passed=True,host_only_controls=len(cases),source_sha256=sha(SOURCE),contract_sha256=sha(out))))
if __name__=='__main__':main()
