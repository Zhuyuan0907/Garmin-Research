#!/usr/bin/env python3
"""New bounded continuation of the frozen warm OS20 Source creation failure.
No imports of old VM observers or global monkeypatches. No fake returns.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,hashlib,struct,traceback
from pathlib import Path
from collections import defaultdict,Counter
from datetime import datetime,timezone
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
OUT=BASE/'guest-v1';BUILD=BASE/'build/manifest.json'
WARM=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json'
PREFIX=ROOT/'staging/native-os20-audio-prefix-v1/journal-reconstructed-prefix.json.gz'
META=PREFIX.parent/'FILE-prefix-proof.json'
READY,CONTROLLER,IDLE,RETURN=0xf09090,0x09503f90,0x09400000,0x08d00000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
 UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
FIELDS=('controller created_tcb entered creator_return_count adapter adapter_tcb ready_before_wait post_returns_before_wait '
 'wrong_actor_bind event controller_after_wait initialized initializer_status ready_posts_at_wake ready_post_returns_at_wake '
 'source_self callback_argument callback_entries publication_checks publication_errors output_initialized queue_running '
 'queue_epoch queue_count observed_ready fail_reason').split()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
 with p.open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def zipped(p,v):
 with p.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,compresslevel=6)as z:z.write(json.dumps(v,separators=(',',':')).encode())
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 for i in range(h[10]):
  k,o,a,_,fs,ms,fl,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if k==1 and ms:yield a,fs,ms,fl,b[o:o+fs]
class Case:
 def __init__(self,prefix,warm,build):
  self.prefix=prefix;self.warm=warm;self.build=build;self.sy=warm['symbols'];self.new=build['symbols']
  self.native=NativeImage();self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.zones=[];self.rx=[];self.count=0;self.stores=[];self.store_count=0;self.hash=hashlib.sha256()
  self.phase='continue_original_OS20_allocator_and_creator';self.done=False;self.boundary=None;self.invalid=None
  self.pending_restore=None;self.restores=[];self.destinations=[];self.calls=[];self.entries=[];self.visit=Counter()
  self.running=CONTROLLER;self.frames=defaultdict(list);self.worker=0;self.source_stack_low=None
  self.md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
  for a,n,permissions in prefix['zones']:
   data=bytes.fromhex(prefix['whole_final'][str(a)]);assert len(data)==n
   self.u.mem_map(a,n,permissions);self.u.mem_write(a,data)
   self.zones.append(dict(start=a,size=n,permissions=permissions,origin='frozen_warm_prefix',before_SHA256=hashlib.sha256(data).hexdigest()))
   if permissions&UC_PROT_EXEC:self.rx.append((a,data,'frozen_warm_guest_mapping'))
  # Missing real source-backed read-only table: no pointer/result is supplied.
  a=0x00c7f000;data=self.native.read(a,4096)
  self.u.mem_map(a,4096,UC_PROT_READ);self.u.mem_write(a,data)
  self.flash=dict(start=a,size=4096,permissions=UC_PROT_READ,source='unchanged MAIN flash bytes',SHA256=hashlib.sha256(data).hexdigest(),table=0xc7f9fc)
  self.zones.append(dict(self.flash,origin='NEW_source_backed_flash',before_SHA256=self.flash['SHA256']))
  for a,fs,ms,flags,payload in segments(ROOT/build['ELF']):
   start=a&~4095;end=(a+ms+4095)&~4095;data=bytearray(b'\xa5'*(end-start))
   data[a-start:a-start+ms]=bytes(ms);data[a-start:a-start+fs]=payload
   perms=UC_PROT_READ|UC_PROT_EXEC if flags&1 else UC_PROT_READ|UC_PROT_WRITE
   self.u.mem_map(start,end-start,perms);self.u.mem_write(start,bytes(data))
   self.zones.append(dict(start=start,size=end-start,logical_start=a,logical_bytes=ms,permissions=perms,
    origin='NEW_C_controller',before_SHA256=hashlib.sha256(data).hexdigest()))
   if flags&1:self.rx.append((start,bytes(data),'NEW_C_controller'))
  for task,rows in prefix['original_open_frames'].items():
   for row in rows:
    self.frames[int(task)].append(dict(name='inherited_original_'+hex(row['entry']),entry=row['entry'],before=row['before'],
     actor=int(task),return_PC=row['return_PC'],inherited_partial_entry=True,entry_ordinal=-1,full_ABI_return=False))
  self.track={0x2120f0:'original_bit_scan_table',0x521e5e:'original_OS20_creator',0x358bf8:'original_context_builder',
   0x2fbbbe:'original_descriptor_registry',0x521e44:'original_OS20_dispatcher',0x358d24:'original_CURRENT',
   0x2fcf44:'original_POST',0x2fd034:'original_WAIT',0x3009a0:'original_mutex_acquire',0x3008b0:'original_mutex_release',
   0x21b6cc:'original_IRQ_save',0x21b6dc:'original_IRQ_restore',0x395440:'original_calloc',0x39544c:'original_workspace_alloc'}
  for n in ('mh_boot_source','mh_os20_source_callback','mh_source_entry','mw_attach_stage1','aas_initialize','aas_pcm_initialize',
      'owned_media_init','media_queue_init','media_queue_begin','memory_output_configure','mcs_install_queue_callback','mh_bind_ready_controller'):
   if n in self.sy:self.track[self.sy[n]['value']]=n
  self.track[self.new['source_ready_controller_v1']['address']]='NEW_C_controller'
  self.entrypoint_bound=prefix['boundary'];self.restore_regs(prefix['boundary'])
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.store);self.u.hook_add(UC_HOOK_MEM_INVALID,self.bad)
 def word(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def symword(self,n):return self.word(self.sy[n]['value'])
 def words(self,a,n):return list(struct.unpack('<'+'I'*n,self.u.mem_read(a,4*n)))
 def snap(self):return dict(GP16=[self.u.reg_read(r)for r in REGS],CPSR=self.u.reg_read(UC_ARM_REG_CPSR),current_TCB=self.word(READY),phase=self.phase,ordinal=self.count)
 def restore_regs(self,state):
  self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
  for r,v in zip(REGS,state['GP16']):self.u.reg_write(r,v)
  self.u.reg_write(UC_ARM_REG_CPSR,state['CPSR'])
  assert self.snap()['GP16']==state['GP16']and self.snap()['CPSR']==state['CPSR']
 def source_view(self):
  names=('mh_os20_adapter','mh_source_tcb','mh_os20_self_tcb','mh_os20_create_returns','mh_os20_callback_argument',
   'mh_os20_worker_entries','mh_os20_publication_checks','mh_os20_publication_errors','mh_initialized',
   'mh_initialize_result','mh_os20_ready_posts','mh_os20_ready_post_returns','mh_os20_ready_status','mw_attempts','mw_attaches','mw_denials')
  return {n:self.symword(n)for n in names}
 def bad(self,u,access,a,size,value,data):
  self.invalid=dict(access=access,address=a,size=size,value=value,state=self.snap());return False
 def code(self,u,address,size,data):
  if self.pending_restore and address==self.pending_restore['PC']:
   self.running=self.pending_restore['target'];self.destinations.append(dict(self.pending_restore,state=self.snap(),ordinal=self.count));self.pending_restore=None
  frames=self.frames[self.running]
  while frames and frames[-1]['return_PC']==address:
   row=frames.pop();b=row['before'];a=self.snap()
   assert b['GP16'][4:12]==a['GP16'][4:12]and b['GP16'][13]==a['GP16'][13],(row['name'],'ABI')
   mask=0x5f if row['entry']in(0x21b6cc,0x21b6dc)else 0xdf
   assert not((b['CPSR']^a['CPSR'])&mask),(row['name'],'mode')
   row.update(after=a,return_ordinal=self.count,full_ABI_return=True)
   if row['name']in('mw_attach_stage1','aas_initialize','aas_pcm_initialize','owned_media_init','media_queue_begin','memory_output_configure'):
    row['source_after']=self.source_view()
   self.calls.append(row)
  if address==RETURN:
   assert self.phase=='continue_original_OS20_allocator_and_creator'
   self.done=True;self.boundary=dict(kind='real_full_mh_boot_source_return',state=self.snap(),source=self.source_view());u.emu_stop();return
  if address==IDLE:
   assert self.phase=='NEW_guest_C_WAIT_and_Source_ready'
   self.boundary=dict(kind='native_idle_after_Source_ready_POST_full_return',state=self.snap(),source=self.source_view());u.emu_stop();return
  if address==self.new['source_ready_failure_v1']['address']:
   raise AssertionError(('NEW_controller_check_failed',self.word(self.new['source_ready_result_v1']['address']+100)))
  if address==0x358ec4:
   target=self.word(READY);frame=self.word(target+12)
   self.pending_restore=dict(target=target,frame=frame,PC=self.word(frame+4)&~1,previous_actor=self.running,ordinal=self.count,host_context_restore=False)
   self.restores.append(dict(self.pending_restore))
  region=next((r for r in self.rx if r[0]<=address and address+size<=r[0]+len(r[1])),None)
  assert region,('unadmitted execution',hex(address))
  raw=region[1][address-region[0]:address-region[0]+size];assert bytes(u.mem_read(address,size))==raw
  assert self.count<160000;self.hash.update(struct.pack('<IHHI',address,size,u.reg_read(UC_ARM_REG_CPSR)&0xff,self.running)+raw)
  self.count+=1;self.visit[region[2]]+=1
  if self.worker and self.running==self.worker:
   sp=u.reg_read(UC_ARM_REG_SP);self.source_stack_low=sp if self.source_stack_low is None else min(self.source_stack_low,sp)
  if address in self.track:
   state=self.snap();name=self.track[address]
   row=dict(name=name,entry=address,before=state,actor=self.running,return_PC=state['GP16'][14]&~1,
    entry_ordinal=self.count-1,full_ABI_return=False,inherited_partial_entry=False)
   if name=='mh_os20_source_callback':assert self.running==self.worker and state['GP16'][0]==self.sy['mh_os20_context']['value']
   if name=='mw_attach_stage1':assert self.running==self.worker
   if name=='original_POST'and state['GP16'][:2]==[CONTROLLER,0x400]:
    row['source_at_ready_POST']=self.source_view();assert self.running==self.worker
    assert row['source_at_ready_POST']['mh_initialized']==1 and row['source_at_ready_POST']['mh_initialize_result']==0
    assert any(c['name']=='mw_attach_stage1'and c['actor']==self.worker and c['after']['GP16'][0]==0 for c in self.calls)
   frames.append(row);self.entries.append(dict(name=name,actor=self.running,ordinal=self.count-1,state=state))
 def store(self,u,access,address,size,value,data):
  z=next((z for z in self.zones if z['start']<=address and address+size<=z['start']+z['size']),None)
  assert z and z['permissions']&UC_PROT_WRITE and size in(1,2,4),(hex(address),size)
  self.store_count+=1
  pc=u.reg_read(UC_ARM_REG_PC);cpsr=u.reg_read(UC_ARM_REG_CPSR)
  ins=next(self.md[bool(cpsr&32)].disasm(bytes(u.mem_read(pc,4)),pc,count=1))
  assert ins.mnemonic.startswith(('str','stm','push','swp'))
  self.stores.append(dict(address=address,size=size,value=value&((1<<(size*8))-1),before_hex=bytes(u.mem_read(address,size)).hex(),
   PC=pc,opcode_hex=ins.bytes.hex(),actor=self.running,ordinal=self.count-1,phase=self.phase))
 def run(self):
  print(json.dumps(dict(stage='resume_frozen_creator_at_original_bitscan_LDRB',source_flash_page='0xC7F000',prefix_not_rerun=True)),flush=True)
  pc=self.entrypoint_bound['GP16'][15];self.u.emu_start(pc|1,0,count=80000,timeout=30_000_000)
  assert self.done and self.boundary['kind']=='real_full_mh_boot_source_return'
  creator_return=self.boundary;self.worker=self.u.reg_read(UC_ARM_REG_R0)
  assert self.worker and self.word(READY)==CONTROLLER
  adapter=self.symword('mh_os20_adapter');assert adapter==0x03a1b294 and self.word(adapter+48)==self.worker
  assert self.symword('mh_os20_create_returns')==1 and self.symword('mh_initialized')==0
  self.phase='NEW_guest_C_WAIT_and_Source_ready';self.boundary=None;self.done=False
  # One explicit new caller entry at the current original native controller.
  # No context switch or Source entry is manufactured by the host.
  self.u.reg_write(UC_ARM_REG_SP,CONTROLLER);self.u.reg_write(UC_ARM_REG_LR,RETURN);self.u.reg_write(UC_ARM_REG_R0,self.worker)
  caller=dict(entry=self.new['source_ready_controller_v1']['address'],state=self.snap(),declared_controller_continuation=True)
  self.u.emu_start(caller['entry'],0,count=80000,timeout=30_000_000)
  assert self.boundary and self.boundary['kind']=='native_idle_after_Source_ready_POST_full_return'
  view=self.source_view();result=self.words(self.new['source_ready_result_v1']['address'],26);r=dict(zip(FIELDS,result))
  assert r['observed_ready']==1 and r['fail_reason']==0
  assert r['ready_post_returns_at_wake']==0 and view['mh_os20_ready_post_returns']==1
  assert view['mh_initialized']==view['mh_os20_ready_posts']==view['mh_os20_worker_entries']==view['mw_attaches']==1
  assert view['mh_initialize_result']==view['mh_os20_ready_status']==view['mh_os20_publication_errors']==view['mw_denials']==0
  assert view['mh_os20_self_tcb']==view['mh_source_tcb']==self.worker
  assert self.symword('mh_source_entries')==1
  required=('memory_output_configure','owned_media_init','media_queue_begin','aas_pcm_initialize','aas_initialize','mw_attach_stage1')
  for n in required:
   rows=[c for c in self.calls if c['name']==n];assert len(rows)==1 and rows[0]['actor']==self.worker and rows[0]['after']['GP16'][0]==0,n
  assert self.words(self.sy['memory_output_control']['value'],12)==[1,8]+[0]*10
  assert self.words(self.sy['memory_output_slots']['value'],24)==[0]*24
  assert self.words(self.sy['media_queue_control']['value'],9)[2:7]==[0,1,1,0,0]
  workspace,length=self.word(adapter),self.word(adapter+4)
  assert length==16536 and workspace<=self.source_stack_low<workspace+length
  # The original TTS runtime prefix and its 40 MAIN ARM jump entries remain.
  tts=next(z for z in self.zones if z['start']==0x02d4b000)
  assert hashlib.sha256(bytes(self.u.mem_read(tts['start'],tts['size']))).hexdigest()==tts['before_SHA256']
  jump_before=self.slice_prefix(0x02d4b994,480);assert bytes(self.u.mem_read(0x02d4b994,480))==jump_before
  for z in self.zones:z['after_SHA256']=hashlib.sha256(bytes(self.u.mem_read(z['start'],z['size']))).hexdigest()
  for a,b,label in self.rx:
   if next(z for z in self.zones if z['start']==a)['permissions']&UC_PROT_WRITE:continue
   assert bytes(self.u.mem_read(a,len(b)))==b
  return dict(all_passed=True,scope='actual original OS20 Source callback -> warm initializer -> existing typed FIFO init -> native ready event',
   prefix=rel(PREFIX),prefix_SHA256=sha(PREFIX),prefix_or_old_guest_instructions_rerun=False,
   inherited_prefix_is_journal_reconstructed_not_whole_instruction_semantics=True,
   source_backed_flash_page=self.flash,original_bitscan_LDRB_executed=True,
   original_creator_return=creator_return,declared_NEW_controller_entry=caller,Source=self.source_view(),controller=r,
   original_context_restores=self.restores,original_context_destinations=self.destinations,full_helper_returns=self.calls,
   entries=self.entries,CPU_store_journal=self.stores,CPU_store_observer_count=self.store_count,
   instruction_count=self.count,instruction_rolling_SHA256=self.hash.hexdigest(),instruction_sources=dict(self.visit),
   whole_instruction_trace_emitted=False,regions=self.zones,worker_TCB=self.worker,adapter=adapter,workspace=workspace,
   workspace_bytes=length,source_stack_low=self.source_stack_low,initializer_required_full_returns=list(required),
   actual_Source_and_guest_C_controller_Original_CURRENT_POST_WAIT=True,
   ready_POST_return_counter_separate_from_controller_wake=True,
   TTS_prefix_and_40_original_MAIN_jump_entries_unchanged=True,inherited_guest_patches=self.prefix['guest_patches'],
   new_guest_original_instruction_patches=0,old_global_VM_monkeypatch_imported=False,
   callback_initializer_or_native_return_hooked=False,synthetic_driver_ready_claim=False,
   synthetic_bootstrap_heap_tables_Timer_preexisting_channels_inherited=True,
   no_media_packets_or_factory_mixer_pulls_in_this_ready_case=True,
   initializer_return_is_logical_warm_Source_ready_not_audio_hardware=True,
   native_channel_all_writers_anchor_ownership=False,exclusive_native_witness=-200,native_STOP_DONE=False,
   stack_adapter_module_pinned=True,physical_install_or_App_phone_A2DP_speaker=False,device_IO=False,boundary=self.boundary)
 def slice_prefix(self,a,n):
  start=next(z[0]for z in self.prefix['zones']if z[0]<=a and a+n<=z[0]+z[1]);raw=bytes.fromhex(self.prefix['whole_final'][str(start)]);return raw[a-start:a-start+n]
def main():
 import unicorn
 assert unicorn.__version__=='2.1.4';assert not OUT.exists();OUT.mkdir()
 meta=json.loads(META.read_text());assert meta['all_passed']and sha(PREFIX)==meta['prefix_sha256']
 for p,h in meta['source_sha256'].items():assert sha(ROOT/p)==h
 build=json.loads(BUILD.read_text());warm=json.loads(WARM.read_text())
 for blob in (build,warm):
  for p,h in blob['source_sha256'].items():assert sha(ROOT/p)==h,p
 for p,h in build['generated_sha256'].items():assert sha(ROOT/p)==h
 deps={rel(p):sha(p)for p in(Path(__file__),BUILD,WARM,PREFIX,META,ROOT/build['ELF'],ROOT/warm['ELF'],ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 deps.update(build['source_sha256']);deps.update(build['generated_sha256']);deps.update(warm['source_sha256']);save(OUT/'inputs-at-run.json',deps)
 case=None
 try:
  prefix=json.load(gzip.open(PREFIX,'rt'));case=Case(prefix,warm,build);proof=case.run();proof['source_sha256']=deps
  proof['updated_utc']=datetime.now(timezone.utc).isoformat();path=OUT/'ready-proof.json.gz';zipped(path,proof)
  small=dict(all_passed=True,proof=rel(path),proof_SHA256=sha(path),instruction_count=case.count,CPU_stores=case.store_count,
   original_context_destinations=len(case.destinations),full_helper_returns=len(case.calls),worker_TCB=case.worker,
   Source_initializer_full_return=True,typed_FIFO_initializer_full_return=True,ready_event=0x400,
   ready_post_returns_at_controller_wake=proof['controller']['ready_post_returns_at_wake'],ready_post_returns_at_idle=1,
   Source_runtime_guest_executed=True,native_STOP_DONE=False,exclusive_native_witness=-200,physical_install_candidate=False,device_IO=False,
   source_sha256=deps)
  save(OUT/'guest-proof.json',small);print(json.dumps({k:v for k,v in small.items()if k!='source_sha256'}),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if case:fail.update(state=case.snap(),invalid_access=case.invalid,source=case.source_view(),native_returns=case.calls,
   entries=case.entries,CPU_stores=case.stores,original_restores=case.restores,original_destinations=case.destinations,
   open_frames=dict(case.frames),source_stack_low=case.source_stack_low,instructions=case.count)
  zipped(OUT/'terminal-failure.json.gz',fail);raise
if __name__=='__main__':main()
