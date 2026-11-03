#!/usr/bin/env python3
"""One new copied-packet/Source/mixer case. Read-only guest observers.

Only initial memory/register restoration and ELF loading are host writes.
All native helpers execute. Existing guest-only MAIN gates are inherited from
the sealed warm endpoint; the new guest C declares the lower driver RAM fixture.
"""
import sys
sys.dont_write_bytecode=True
import gzip,json,hashlib,struct,traceback
from pathlib import Path
from collections import defaultdict,Counter,deque
from datetime import datetime,timezone
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn import UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_INVALID
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
OUT=BASE/'guest-v2';BUILD=BASE/'build/manifest.json'
WARM=ROOT/'staging/native-os20-audio-source-build-v1/manifest.json'
PREFIX=BASE/'prefix/ready-endpoint.json.gz';META=BASE/'prefix/FILE-prefix-proof.json'
READY,IDLE_TCB,RETURN=0xf09090,0x09508f90,0x08d00000
MIXER,RECORD,DESCRIPTOR,BUFFER,SCRATCH=0x034e5cf8,0x034e7f48,0x09800020,0x09801020,0x09803f00
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,
 UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
FIELDS=('bootstrap_actor producer_tcb producer_actor producer_entries packet_copied ingress_result packet_poisoned '
 'producer_parked source_started source_tcb mixer_tcb initialize_completed driver_fixture_installed message_sent '
 'after_message_actor output_write_pointer output_bytes source_error source_initialize_status finished fail_reason').split()
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
  self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.zones=[];self.rx=[];self.count=0;self.stores=[];self.hash=hashlib.sha256();self.visit=Counter();self.tail=deque(maxlen=48)
  self.running=IDLE_TCB;self.frames=defaultdict(list);self.calls=[];self.entries=[];self.pending_restore=None
  self.restores=[];self.destinations=[];self.invalid=None;self.milestones=[];self.publications=[];self.reader_entries=[]
  self.native_pull_entries=[];self.native_pull_returns=[];self.actor_stores=[];self.pending_publication=False
  self.native_thunk_before=None;self.start_source=prefix['worker_TCB'];self.mixer_tcb=0
  self.md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
  for z in prefix['regions']:
   a,n,p=z['start'],z['size'],z['permissions'];b=bytes.fromhex(prefix['whole_ready'][str(a)]);assert len(b)==n
   assert hashlib.sha256(b).hexdigest()==z['after_SHA256']
   self.u.mem_map(a,n,p);self.u.mem_write(a,b)
   self.zones.append(dict(start=a,size=n,permissions=p,origin='sealed_READY_endpoint',before_SHA256=hashlib.sha256(b).hexdigest()))
   if p&UC_PROT_EXEC:self.rx.append((a,b,'sealed_warm_RX'))
  for a,fs,ms,flags,payload in segments(ROOT/build['ELF']):
   start=a&~4095;end=(a+ms+4095)&~4095;b=bytearray(b'\xa5'*(end-start));b[a-start:a-start+ms]=bytes(ms);b[a-start:a-start+fs]=payload
   p=UC_PROT_READ|UC_PROT_EXEC if flags&1 else UC_PROT_READ|UC_PROT_WRITE
   self.u.mem_map(start,end-start,p);self.u.mem_write(start,bytes(b))
   self.zones.append(dict(start=start,size=end-start,logical_start=a,logical_bytes=ms,permissions=p,
    origin='NEW_producer_and_idle_fixture_C',before_SHA256=hashlib.sha256(b).hexdigest()))
   if p&UC_PROT_EXEC:self.rx.append((start,bytes(b),'NEW_producer_and_idle_fixture_C'))
  self.offsets=self.words(self.sy['aas_offsets']['value'],5);self.mh_offsets=self.words(self.sy['mh_offsets']['value'],5)
  self.track={0x358bf8:'original_context_builder',0x2fbbbe:'original_descriptor_registry',0x358d24:'original_CURRENT',
   0x2fcf44:'original_POST',0x2fd034:'original_WAIT',0x3009a0:'original_mutex_acquire',0x3008b0:'original_mutex_release',
   0x21b6cc:'original_IRQ_save',0x21b6dc:'original_IRQ_restore',0x3b9b66:'original_mixer_initializer',
   0x46cc7a:'original_initializer_sync',0x270458:'original_source_registration',0x277536:'original_queue_start',
   0x37bce4:'original_mixer_message_send',0x37bc00:'original_mixer_message_get',0x2f9f2e:'original_selector',
   0x437764:'original_factory',0x437a3e:'original_prepare',0x48edf8:'original_kind10_reader',0x48ee30:'original_kind10_format',
   0x30ed24:'original_mixer_sync_ACK'}
  for n in ('sbi_receive_packet','aas_media_ingress','media_queue_receive','media_queue_step','memory_output_submit',
   'memory_output_register','continuous_media_read','mh_selector_bridge','mcs_mixer_selector_begin','mcs_mixer_selector_after_original',
   'mcs_pull_begin','mcs_pull_end','mcs_pull_bridge','mcs_original_pull_thunk','ms_initializer_sync_bridge','ms_validate_completed_sync',
   'ns_capture_registration','ns_bind_selected','mcs_handoff_source_to_mixer'):
   if n in self.sy:self.track[self.sy[n]['value']&~1]=n
  for n in ('media_case_bootstrap_v1','media_case_producer_v1'):self.track[self.new[n]['address']&~1]=n
  self.restore_initial(prefix['boundary']['state'])
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.store);self.u.hook_add(UC_HOOK_MEM_INVALID,self.bad)
 def word(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def words(self,a,n):return list(struct.unpack('<'+'I'*n,self.u.mem_read(a,4*n)))
 def symword(self,n):return self.word(self.sy[n]['value'])
 def snap(self):return dict(GP16=[self.u.reg_read(r)for r in REGS],CPSR=self.u.reg_read(UC_ARM_REG_CPSR),current_TCB=self.word(READY),ordinal=self.count)
 def restore_initial(self,s):
  self.u.reg_write(UC_ARM_REG_CPSR,s['CPSR'])
  for r,v in zip(REGS,s['GP16']):self.u.reg_write(r,v)
  self.u.reg_write(UC_ARM_REG_CPSR,s['CPSR']);assert self.snap()['GP16']==s['GP16']and self.snap()['CPSR']==s['CPSR']
 def leases(self):
  g=self.sy['aas_guard']['value'];c=self.sy['aas_control']['value']
  return dict(borrow=self.word(g+self.offsets[0]),selected_session=self.word(g+self.offsets[1]),selected_instance=self.word(g+self.offsets[2]),
   media=self.word(c+self.offsets[3]),callback=self.word(c+self.offsets[4]),mixer_TCB=self.word(g+self.mh_offsets[0]),
   pull_entry_LR=self.word(g+self.mh_offsets[4]),actor=self.running,current_TCB=self.word(READY))
 def view(self):
  ns=('mh_initialized','mh_initialize_result','mh_os20_ready_posts','mh_os20_ready_post_returns','mh_os20_self_tcb',
   'mh_source_tcb','mh_started','mh_stream_error','mh_handoff_result','mh_ticket','mh_pcm_cycle','sbi_processed','sbi_errors',
   'sbi_source_events','ms_original_sync_completed','mh_selector_bridge_calls','mh_selector_denied','mh_original_selector_returns')
  return {n:self.symword(n)for n in ns if n in self.sy}
 def result(self):return dict(zip(FIELDS,self.words(self.new['media_case_result_v1']['address'],21)))
 def bad(self,u,access,a,size,value,data):self.invalid=dict(access=access,address=a,size=size,value=value,state=self.snap());return False
 def publication(self):
  row=self.words(self.sy['memory_output_slots']['value'],6);assert row[1]==2,('not READY',row)
  pcm=self.sy['pcm0']['value'];data=bytes(self.u.mem_read(pcm,row[2]));ref=(ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm').read_bytes()[:256]
  assert data==ref and row[0]==4 and row[2]==256
  self.publications.append(dict(slot_words=row,PCM_address=pcm,PCM_hex=data.hex(),PCM_SHA256=hashlib.sha256(data).hexdigest(),
   actual_CPU_READY_store_ordinal=self.stores[-1]['ordinal'],state=self.snap(),copied_packet_poisoned=self.result()['packet_poisoned'],Source=self.view()))
  assert self.running==self.start_source and self.result()['packet_poisoned']==1
 def code(self,u,a,size,data):
  if self.pending_publication:self.publication();self.pending_publication=False
  if self.pending_restore and a==self.pending_restore['PC']:
   self.running=self.pending_restore['target'];self.destinations.append(dict(self.pending_restore,state=self.snap(),ordinal=self.count));self.pending_restore=None
  frames=self.frames[self.running]
  while frames and frames[-1]['return_PC']==a:
   row=frames.pop();b=row['before'];after=self.snap()
   assert b['GP16'][4:12]==after['GP16'][4:12]and b['GP16'][13]==after['GP16'][13],(row['name'],'ABI',b,after)
   mask=0x5f if row['entry']in(0x21b6cc,0x21b6dc)else 0xdf
   assert not((b['CPSR']^after['CPSR'])&mask),(row['name'],'mode',b,after)
   row.update(after=after,return_ordinal=self.count,full_ABI_return=True)
   if row['name']in('mcs_original_pull_thunk','mcs_pull_end','mcs_pull_bridge','mh_selector_bridge','original_selector','original_mixer_initializer','original_initializer_sync'):
    row.update(leases_after=self.leases(),Source_after=self.view())
   if row['name']=='mcs_original_pull_thunk':
    assert self.running==self.word(MIXER+0x78)and self.leases()['media']==self.leases()['callback']==1 and self.leases()['borrow']
    self.native_pull_returns.append(dict(row,full_native_frame_return=True))
   self.calls.append(row)
  if a==self.new['media_case_failure_v1']['address']&~1:raise AssertionError(('compiled_C_check_failed',self.result()))
  if a==0x358ec4:
   target=self.word(READY);frame=self.word(target+12)
   self.pending_restore=dict(target=target,frame=frame,PC=self.word(frame+4)&~1,previous_actor=self.running,ordinal=self.count,host_context_restore=False)
   self.restores.append(dict(self.pending_restore))
  region=next((r for r in self.rx if r[0]<=a and a+size<=r[0]+len(r[1])),None)
  assert region,('unadmitted execution',hex(a))
  raw=region[1][a-region[0]:a-region[0]+size];assert bytes(u.mem_read(a,size))==raw
  assert self.count<450000;self.hash.update(struct.pack('<IHHI',a,size,u.reg_read(UC_ARM_REG_CPSR)&0xff,self.running)+raw)
  self.tail.append(dict(PC=a,size=size,opcode=raw.hex(),actor=self.running));self.count+=1;self.visit[region[2]]+=1
  if a==0x2f9cce:
   lease=self.leases();assert lease['actor']==lease['mixer_TCB']==self.word(MIXER+0x78)and lease['media']==lease['callback']==1 and lease['borrow']
   assert lease['pull_entry_LR']==0x2fa577
   before=next(r['before']for r in reversed(frames)if r['name']=='mcs_original_pull_thunk')
   assert before['GP16'][13]-u.reg_read(UC_ARM_REG_SP)==64
   self.native_pull_entries.append(dict(state=self.snap(),thunk_before=before,actual_original_frame_bytes=64,leases=lease))
  if a in self.track:
   name=self.track[a];s=self.snap();row=dict(name=name,entry=a,before=s,actor=self.running,return_PC=s['GP16'][14]&~1,
    entry_ordinal=self.count-1,full_ABI_return=False)
   if name in('mh_selector_bridge','continuous_media_read','mcs_pull_bridge','mcs_pull_begin','mcs_pull_end','mcs_original_pull_thunk'):
    row['leases_before']=self.leases()
   if name=='mcs_original_pull_thunk':self.native_thunk_before=s
   if name=='mh_selector_bridge':assert s['GP16'][14]==0x2fa299 and self.running==self.word(MIXER+0x78)
   if name=='continuous_media_read':
    assert self.running==self.word(MIXER+0x78)and self.running!=IDLE_TCB
    assert self.leases()['media']==self.leases()['callback']==1 and self.leases()['borrow'];self.reader_entries.append(row.copy())
   frames.append(row);self.entries.append(dict(name=name,actor=self.running,ordinal=self.count-1,state=s))
 def store(self,u,access,a,size,value,data):
  z=next((z for z in self.zones if z['start']<=a and a+size<=z['start']+z['size']),None)
  assert z and z['permissions']&UC_PROT_WRITE and size in(1,2,4),(hex(a),size)
  pc=u.reg_read(UC_ARM_REG_PC);cpsr=u.reg_read(UC_ARM_REG_CPSR)
  ins=next(self.md[bool(cpsr&32)].disasm(bytes(u.mem_read(pc,4)),pc,count=1));assert ins.mnemonic.startswith(('str','stm','push','swp'))
  row=dict(address=a,size=size,value=value&((1<<(size*8))-1),before_hex=bytes(u.mem_read(a,size)).hex(),
   PC=pc,opcode_hex=ins.bytes.hex(),actor=self.running,ordinal=self.count-1)
  self.stores.append(row)
  if a==self.sy['memory_output_slots']['value']+4 and size==4 and value==2:self.pending_publication=True
  if a in(MIXER+0x78,MIXER+0x64,MIXER+0x68,MIXER+0x6c,MIXER+0x70,MIXER+0x74):self.actor_stores.append(dict(row,state=self.snap()))
 def finalize_regions(self):
  for z in self.zones:z['after_SHA256']=hashlib.sha256(bytes(self.u.mem_read(z['start'],z['size']))).hexdigest()
  return self.zones
 def run(self):
  assert self.view()['mh_initialized']==1 and self.view()['mh_os20_ready_post_returns']==1
  assert self.word(READY)==IDLE_TCB;self.u.reg_write(UC_ARM_REG_SP,IDLE_TCB);self.u.reg_write(UC_ARM_REG_LR,RETURN)
  caller=dict(entry=self.new['media_case_bootstrap_v1']['address'],state=self.snap(),declared_actual_idle_caller_boundary=True)
  print(json.dumps(dict(stage='one_NEW_packet_Source_factory_mixer_case',sealed_READY_restored_once=True,old_prefix_not_rerun=True,no_native_return_hooks=True)),flush=True)
  self.u.emu_start(caller['entry']|1,RETURN,count=450000,timeout=60_000_000)
  assert self.u.reg_read(UC_ARM_REG_PC)==RETURN,('bounded_stop',self.snap())
  r=self.result();assert r['finished']==1 and r['fail_reason']==0 and r['output_bytes']==256
  assert r['source_tcb']==self.start_source and r['producer_entries']==1 and r['producer_actor']==r['producer_tcb']
  assert r['source_started']==r['initialize_completed']==r['packet_poisoned']==r['driver_fixture_installed']==1
  assert r['bootstrap_actor']==r['after_message_actor']==IDLE_TCB and r['mixer_tcb']not in(self.start_source,IDLE_TCB,r['producer_tcb'])
  assert len(self.publications)==len(self.native_pull_entries)==len(self.native_pull_returns)==len(self.reader_entries)==1
  assert self.words(self.sy['memory_output_slots']['value'],6)==[4,0,0,0,0,0]
  assert self.leases()['borrow']==self.leases()['media']==self.leases()['callback']==0
  ref=(ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm').read_bytes()[:256]
  actual=bytes(self.u.mem_read(BUFFER+1984,64))+bytes(self.u.mem_read(BUFFER,192));assert actual==ref
  for name in('original_selector','original_factory','original_prepare','mh_selector_bridge','original_mixer_initializer','original_initializer_sync'):
   assert any(c['name']==name and c['full_ABI_return']for c in self.calls),('missing full native return',name)
  for z in self.zones:
   if not z['permissions']&UC_PROT_WRITE:assert hashlib.sha256(bytes(self.u.mem_read(z['start'],z['size']))).hexdigest()==z['before_SHA256']
  tts=next(z for z in self.zones if z['start']==0x02d4b000);assert hashlib.sha256(bytes(self.u.mem_read(tts['start'],tts['size']))).hexdigest()==tts['before_SHA256']
  return dict(all_passed=True,scope='one actual copied packet -> original OS20 Source -> typed FIFO -> original native scheduled mixer factory/reader full pull',
   declared_NEW_idle_caller=caller,result=r,Source=self.view(),publications=self.publications,
   native_mixer_descriptor_CPU_stores=self.actor_stores,reader_entries=self.reader_entries,native_pull_entries=self.native_pull_entries,
   native_pull_full_returns=self.native_pull_returns,original_context_restores=self.restores,original_context_destinations=self.destinations,
   helper_full_returns=self.calls,entries=self.entries,CPU_store_journal=self.stores,instruction_count=self.count,
   instruction_rolling_SHA256=self.hash.hexdigest(),instruction_sources=dict(self.visit),whole_instruction_trace_emitted=False,
   regions=self.finalize_regions(),boundary=self.snap(),leases=self.leases(),output_PCM_hex=actual.hex(),output_PCM_SHA256=hashlib.sha256(actual).hexdigest(),
   inherited_guest_patches=self.prefix['inherited_guest_patches'],new_original_instruction_patches=0,
   host_native_initializer_reader_return_hooks=False,observer_mutations_after_dispatch=False,
   explicit_synthetic_lower_driver_descriptor_ring_scratch_activation=True,
   frozen_warm_37_inputs_40_exports_and_ready_prefix_not_rerun=True,TTS_runtime_unchanged=True,
   native_channel_all_writers_ownership=False,exclusive_native_witness=-200,native_STOP_DONE=False,
   stack_adapter_module_heap_storage_pinned=True,physical_install_App_phone_speaker=False,device_IO=False)
def main():
 import unicorn
 assert unicorn.__version__=='2.1.4';assert not OUT.exists();OUT.mkdir()
 meta=json.loads(META.read_text());assert meta['all_passed']and sha(PREFIX)==meta['prefix_SHA256']
 build=json.loads(BUILD.read_text());warm=json.loads(WARM.read_text());assert sha(ROOT/build['ELF'])==build['ELF_SHA256']
 assert sha(ROOT/warm['ELF'])==warm['ELF_sha256']
 deps={rel(p):sha(p)for p in(Path(__file__),BUILD,WARM,PREFIX,META,ROOT/build['ELF'],ROOT/warm['ELF'],ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm')}
 for blob in(build,warm):
  for p,h in blob['source_sha256'].items():assert sha(ROOT/p)==h;deps[p]=h
 for p,h in build['generated_sha256'].items():assert sha(ROOT/p)==h;deps[p]=h
 save(OUT/'inputs-at-run.json',deps);case=None
 try:
  prefix=json.load(gzip.open(PREFIX,'rt'));case=Case(prefix,warm,build);proof=case.run();proof['source_sha256']=deps
  proof['prefix_SHA256']=sha(PREFIX);proof['updated_utc']=datetime.now(timezone.utc).isoformat();path=OUT/'media-proof.json.gz';zipped(path,proof)
  small=dict(all_passed=True,proof=rel(path),proof_SHA256=sha(path),instruction_count=case.count,CPU_stores=len(case.stores),
   original_context_destinations=len(case.destinations),full_helper_returns=len(case.calls),Source_TCB=case.start_source,
   original_mixer_TCB=proof['result']['mixer_tcb'],packets=1,SBC_frames=1,typed_FIFO_ready_PCM=256,original_mixer_full_pull_PCM=256,
   exclusive_native_witness=-200,native_STOP_DONE=False,physical_install_App_phone_speaker=False,device_IO=False,source_sha256=deps)
  save(OUT/'guest-proof.json',small);print(json.dumps({k:v for k,v in small.items()if k!='source_sha256'}),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if case:fail.update(state=case.snap(),invalid_access=case.invalid,Source=case.view(),result=case.result(),leases=case.leases(),
   native_returns=case.calls,entries=case.entries,CPU_store_journal=case.stores,original_restores=case.restores,
   original_destinations=case.destinations,open_frames=dict(case.frames),instructions=case.count,last_instructions=list(case.tail),
   regions=case.finalize_regions(),publications=case.publications,native_descriptor_stores=case.actor_stores)
  zipped(OUT/'terminal-failure.json.gz',fail);raise
if __name__=='__main__':main()
