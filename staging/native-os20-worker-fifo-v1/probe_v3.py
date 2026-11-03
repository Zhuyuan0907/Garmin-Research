#!/usr/bin/env python3
"""Bounded NEW tail: sealed OS20 endpoint -> copied RTP -> existing typed FIFO.

No prior guest/suite is rerun. Original opcodes run unchanged; after the one
declared endpoint restore, all publications/context switches are guest/native.
No whole instruction trace is emitted. Canary/pinned-lifetime claims stay local.
"""
import sys
sys.dont_write_bytecode=True
import gzip,hashlib,json,struct,traceback
from collections import Counter,defaultdict
from datetime import datetime,timezone
from pathlib import Path
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *
BUILD=BASE/'build-v3/manifest.json';OUT=BASE/'guest-v3'
PREFIX=ROOT/'staging/native-os20-resident-prefix-v1/creation-bootstrap-prefix.json.gz'
META=PREFIX.parent/'FILE-prefix-proof.json'
FRAME=ROOT/'staging/native-os20-resident-music-v2/frames.sbc'
REF=ROOT/'staging/native-os20-resident-music-v2/reference-two-streams.pcm'
JOB,INPUT,OUTPUT=0x09060000,0x09061000,0x09062000
CONTROLLER,IDLE,WORKER=0x0901ff90,0x09073f90,0x183110a0
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
 UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,
 UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,
 UC_ARM_REG_LR,UC_ARM_REG_PC]
FIELDS=('magic controller_tcb adapter observed_argument worker_entries request_seq completed_seq '
 'operation input input_bytes output output_capacity result status active generation wait_returns '
 'notifications notify_returns decode_successes stopped_rejections stops resets event_count '
 'controller_failure controller_finished idle_pulse_request idle_pulse_delivered idle_post_returns '
 'worker_tcb_observed active_start_rejections controller_tcb_observed idle_tcb_observed').split()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def save(p,v):
 with p.open('x')as f:json.dump(v,f,indent=2);f.write('\n')
def zipped(p,v):
 with p.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0,compresslevel=6)as z:
   z.write(json.dumps(v,separators=(',',':')).encode())
def segments(path):
 b=path.read_bytes();h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
 assert h[0][:6]==b'\x7fELF\x01\x01'and h[1:3]==(2,40)
 for i in range(h[10]):
  kind,off,a,_,fs,ms,flags,_=struct.unpack_from('<8I',b,h[5]+i*h[9])
  if kind==1:yield a,fs,ms,flags,b[off:off+fs]

class Tail:
 def __init__(self,native,prefix,build):
  self.native=native;self.prefix=prefix;self.build=build;self.sy=build['symbols']
  self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.zones=[];self.rx=[];self.fixture_writes=[];self.count=0;self.store_count=0
  self.running=CONTROLLER;self.pending_restore=None;self.restores=[];self.destinations=[]
  self.calls=[];self.frames=defaultdict(list);self.entries=[];self.visits=Counter()
  self.protocol_stores=[];self.copy_windows=[];self.decoder_results=[];self.submit_tickets=[]
  self.entry_count=Counter();self.hash=hashlib.sha256();self.boundary=None
  self.decoder_calls=0;self.controlled_factory_entries=[];self.read_index=0
  self.md={False:Cs(CS_ARCH_ARM,CS_MODE_ARM),True:Cs(CS_ARCH_ARM,CS_MODE_THUMB)}
  copy=next(r for r in native.copies if r['runtime_start']==0x50000)
  n=(copy['size']+4095)&~4095
  raw=native.read(0x50000,copy['size'])+bytes(n-copy['size'])
  self.map_rx(0x50000,raw,'unchanged_original_MAIN')
  for z in prefix['zones']:
   raw=bytes.fromhex(prefix['whole_zones_after'][z['name']]);assert len(raw)==z['size']
   perms=UC_PROT_READ if z['name']in('declared_frame_input','input_descriptors')else UC_PROT_READ|UC_PROT_WRITE
   self.u.mem_map(z['start'],z['size'],perms);self.u.mem_write(z['start'],raw)
   self.zones.append(dict(z,read_only=not bool(perms&UC_PROT_WRITE),origin='sealed_prefix',before_SHA256=hashlib.sha256(raw).hexdigest()))
  assert bytes(self.u.mem_read(INPUT,288))==FRAME.read_bytes()
  for path,label in [(ROOT/build['decoder_ELF'],'frozen_decoder'),(ROOT/build['ELF'],'NEW_FIFO_worker')]:
   for address,filesz,memsz,flags,payload in segments(path):
    start=address&~4095;end=(address+memsz+4095)&~4095
    if not memsz:continue
    if flags&1:
     assert not flags&2
     block=bytearray(end-start);block[address-start:address-start+filesz]=payload
     self.map_rx(start,bytes(block),label)
    elif label=='frozen_decoder':
     assert any(z['start']==start and z['size']==end-start and z['name']=='frozen_decoder_RW'for z in self.zones)
    else:
     block=bytearray(b'\xa5'*(end-start))
     block[address-start:address-start+memsz]=bytes(memsz)
     block[address-start:address-start+filesz]=payload
     self.u.mem_map(start,end-start,UC_PROT_READ|UC_PROT_WRITE);self.u.mem_write(start,bytes(block))
     self.zones.append(dict(name=label+'_'+hex(start),start=start,size=end-start,
         logical_start=address,logical_bytes=memsz,read_only=False,origin='NEW_ELF',before_SHA256=hashlib.sha256(block).hexdigest()))
  self.original_factory={0x270458,0x2f9f2e,0x437764,0x2fa0dc,0x2f9cca}
  self.track={0x358d24,0x521e44,0x2fcf44,0x2fd034,0x21b6cc,0x21b6dc,0x0800223c,0x08002284}
  self.names={a:'original_'+hex(a)for a in self.track}
  for n in ('resident_music_worker_v1','resident_controller_v1','resident_idle_v1',
      'fifo_worker_core_v1','fifo_controller_core_v1','fifo_idle_core_v1',
      'media_queue_callback','media_queue_step','media_queue_begin','media_queue_stop',
      'owned_media_consume','memory_output_submit','memory_output_discard','continuous_media_read'):
   a=self.sy[n]['address'];self.names[a]=n;self.track.add(a)
  self.memcpy=self.sy['memcpy']['address']
  self.initial_state=prefix['boundary']['state']
  self.u.reg_write(UC_ARM_REG_CPSR,self.initial_state['CPSR'])
  for r,v in zip(REGS,self.initial_state['GP16']):self.u.reg_write(r,v)
  self.u.reg_write(UC_ARM_REG_CPSR,self.initial_state['CPSR'])
  assert self.snap()==self.initial_state
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.store)
 def map_rx(self,a,b,label):
  self.u.mem_map(a,len(b),UC_PROT_READ|UC_PROT_EXEC);self.u.mem_write(a,b)
  self.rx.append(dict(start=a,size=len(b),label=label,data=b,SHA256=hashlib.sha256(b).hexdigest()))
 def word(self,a):return struct.unpack('<I',self.u.mem_read(a,4))[0]
 def words(self,a,n):return list(struct.unpack('<'+'I'*n,self.u.mem_read(a,n*4)))
 def snap(self):return dict(GP16=[self.u.reg_read(r)for r in REGS],CPSR=self.u.reg_read(UC_ARM_REG_CPSR))
 def slot(self):return self.words(self.sy['memory_output_slots']['address'],6)
 def protocol(self):
  return dict(slot0=self.slot(),owned=self.words(self.sy['owned_media_control']['address'],13),
   reader=self.words(self.sy['continuous_media_control']['address'],8),queue=self.words(self.sy['media_queue_control']['address'],9))
 def code(self,u,address,size,data):
  if self.pending_restore and address==self.pending_restore['destination_PC']:
   self.running=self.pending_restore['target'];self.destinations.append(dict(self.pending_restore,state=self.snap(),ordinal=self.count));self.pending_restore=None
  frames=self.frames[self.running]
  while frames and frames[-1]['return_PC']==address:
   row=frames.pop();before=row['before'];after=self.snap()
   assert before['GP16'][4:12]==after['GP16'][4:12],(row['name'],'callee saved')
   assert before['GP16'][13]==after['GP16'][13],(row['name'],'SP')
   mask=0x5f if row['entry']in(0x21b6cc,0x21b6dc)else 0xdf
   assert not((before['CPSR']^after['CPSR'])&mask),(row['name'],'mode')
   if row['entry']==0x21b6cc:
    assert after['GP16'][0]==before['CPSR'] and after['CPSR']&0x80
   if row['entry']==0x21b6dc:
    assert (after['CPSR']&0xc0)==(before['GP16'][0]&0xc0)
   row.update(after=after,full_ABI_return=True,return_ordinal=self.count)
   if row['entry']==0x08002284:
    result=self.words(row['stack_arg5'],9)
    assert after['GP16'][0]==0 and result[:7]==[72,256,16000,1,128,49,32]and result[7]==0
    row['decoder_result']=result;self.decoder_results.append(result)
   if row['name']=='memory_output_submit':
    self.submit_tickets.append(after['GP16'][0]);row['protocol_after']=self.protocol()
   if row['name']=='reader_copy':
    row['protocol_after']=self.protocol();assert self.slot()[1]==2 and self.slot()[5]==1
    self.copy_windows.append(row)
   self.calls.append(row)
  if address==self.sy['fifo_failure_v1']['address']:
   raise AssertionError(('native_C_check_failed',self.word(JOB+24*4)))
  if address==self.sy.get('__aeabi_idiv0',{}).get('address'):
   raise AssertionError('division-zero handler reached')
  if address==self.sy['fifo_idle_checkpoint_v1']['address']:
   assert self.running==IDLE;self.boundary=dict(kind='native_idle_after_stopped_FIFO_with_pending_PCM',state=self.snap(),ordinal=self.count)
   u.emu_stop();return
  assert address not in (0x358bf8,0x358fa4),'closed creation/exit scope unexpectedly entered'
  if address in self.original_factory:self.controlled_factory_entries.append(address)
  if address==0x358ec4:
   target=self.word(0xf09090);assert target in (CONTROLLER,IDLE,WORKER)
   frame=self.word(target+12)
   self.pending_restore=dict(target=target,frame=frame,destination_PC=self.word(frame+4)&~1,previous_actor=self.running,ordinal=self.count,host_context_restore=False)
   self.restores.append(dict(self.pending_restore))
  region=next(r for r in self.rx if r['start']<=address and address+size<=r['start']+r['size'])
  raw=region['data'][address-region['start']:address-region['start']+size]
  assert bytes(u.mem_read(address,size))==raw
  assert self.count<350000
  self.hash.update(struct.pack('<IHHI',address,size,u.reg_read(UC_ARM_REG_CPSR)&0xff,self.running)+raw)
  self.count+=1;self.visits[region['label']]+=1
  if address in self.track:
   state=self.snap();name=self.names[address];self.entry_count[name]+=1
   row=dict(name=name,entry=address,before=state,actor=self.running,return_PC=state['GP16'][14]&~1,entry_ordinal=self.count-1,full_ABI_return=False)
   if name=='memory_output_submit':
    assert self.running==WORKER and state['GP16'][1]==256;row['protocol_before']=self.protocol()
   if address==0x08002284:
    p,n=state['GP16'][:2];idx=self.decoder_calls;self.decoder_calls+=1
    assert self.running==WORKER and n==72 and idx<4
    assert self.sy['slots']['address']<=p and p+n<=self.sy['slots']['address']+16384
    assert bytes(u.mem_read(p,n))==FRAME.read_bytes()[idx*72:(idx+1)*72]
    assert bytes(u.mem_read(self.sy['packet']['address'],85))==b'\xa5'*85
    row['stack_arg5']=self.word(state['GP16'][13]);row['input_sha256']=hashlib.sha256(bytes(u.mem_read(p,n))).hexdigest()
   if name=='continuous_media_read':assert self.running==CONTROLLER
   if name=='fifo_worker_core_v1':assert self.running==WORKER
   frames.append(row);self.entries.append(dict(name=name,actor=self.running,ordinal=self.count-1))
  elif address==self.memcpy:
   d,s,n=[u.reg_read(r)for r in REGS[:3]]
   if 0x09140000<=s and s+n<=0x09144000:
    assert self.running==CONTROLLER and self.slot()[1]==2 and self.slot()[5]==1
    state=self.snap();frames.append(dict(name='reader_copy',entry=address,before=state,actor=self.running,
     return_PC=state['GP16'][14]&~1,entry_ordinal=self.count-1,full_ABI_return=False,
     protocol_before=self.protocol(),source_bytes_hex=bytes(u.mem_read(s,n)).hex()))
 def store(self,u,access,address,size,value,data):
  zone=next((z for z in self.zones if z['start']<=address and address+size<=z['start']+z['size']),None)
  assert zone and not zone['read_only']and size in(1,2,4),(hex(address),size)
  if zone['origin']=='NEW_ELF':
   assert zone['logical_start']<=address and address+size<=zone['logical_start']+zone['logical_bytes'],('write in canary',hex(address))
  self.store_count+=1
  if zone['origin']=='NEW_ELF' or zone['name']=='declared_job' or 0xf0908c<=address<0xf09098:
   pc=u.reg_read(UC_ARM_REG_PC);cpsr=u.reg_read(UC_ARM_REG_CPSR)
   raw=bytes(u.mem_read(pc,4));ins=next(self.md[bool(cpsr&32)].disasm(raw,pc,count=1))
   assert ins.mnemonic.startswith(('str','stm','push','swp')),(hex(pc),ins.mnemonic)
   self.protocol_stores.append(dict(address=address,size=size,value=value&((1<<(size*8))-1),
     PC=pc,opcode_hex=ins.bytes.hex(),actor=self.running,ordinal=self.count-1,
     before_hex=bytes(u.mem_read(address,size)).hex()))
 def run(self):
  print(json.dumps(dict(stage='NEW_FIFO_tail_from_closed_native_endpoint',prefix_not_rerun=True,commands=12,frames=4)),flush=True)
  self.u.emu_start(self.initial_state['GP16'][15]|1,0,count=350000,timeout=60_000_000)
  assert self.boundary and self.pending_restore is None
  w=self.words(JOB,49);job=dict(zip(FIELDS,w[:33]));job['events']=w[33:]
  assert job['controller_failure']==0 and job['controller_finished']==1
  assert job['worker_entries']==1 and job['observed_argument']==JOB
  assert job['request_seq']==job['completed_seq']==12
  assert job['generation']==job['resets']==job['stops']==2 and job['active']==0
  assert job['decode_successes']==4 and job['stopped_rejections']==2 and job['active_start_rejections']==1
  assert job['wait_returns']==12 and job['notifications']==job['notify_returns']==13
  assert job['worker_tcb_observed']==WORKER and job['controller_tcb_observed']==CONTROLLER and job['idle_tcb_observed']==IDLE
  assert job['event_count']==14 and job['events']==[0x400,0x800]+[0x400]*12+[0]*2
  assert job['idle_post_returns']==job['idle_pulse_request']==job['idle_pulse_delivered']==1
  o=self.words(self.sy['fifo_observations_v1']['address'],67)
  assert o[:4]==[1,0,4,4]and o[4:8]==[1]*4
  assert o[8:12]==[4,8,12,16]and o[12:16]==[WORKER]*4 and o[16:21]==[CONTROLLER]*5
  assert o[21:23]==[4,4]and o[23:27]==[WORKER]*4
  assert o[27:32]==[128,128,256,256,128]
  assert o[32:37]==[1,0,0,0,1]and o[37:42]==[128,0,0,0,128]
  assert o[42:47]==[2,0,0,0,2]and o[47:52]==[0]*5
  signed=[v if v<0x80000000 else v-0x100000000 for v in o[52:57]]
  assert signed==[-28,0,0,-22,-25]
  assert o[57:]==[3,4,16,256,2,128,1,4,0,0]
  assert len(self.decoder_results)==4 and self.submit_tickets==[4,8,12,16]
  assert len(self.copy_windows)==5 and not self.controlled_factory_entries
  assert bytes(self.u.mem_read(OUTPUT,896))==REF.read_bytes()[:896]
  assert bytes(self.u.mem_read(OUTPUT+896,4096-896))==b'\xa5'*(4096-896)
  assert bytes(self.u.mem_read(INPUT,288))==FRAME.read_bytes()
  assert bytes(self.u.mem_read(INPUT+288,4096-288))==b'\xa5'*(4096-288)
  assert bytes(self.u.mem_read(JOB+196,4096-196))==b'\xa5'*(4096-196)
  assert bytes(self.u.mem_read(0x09063000,4096))==b'\xa5'*4096
  assert self.slot()==[16,2,256,0xffffffff,1,0]
  assert self.words(self.sy['owned_media_control']['address'],13)==[1,0,3,0,1,256,16000,1,4,0,0,3,16]
  assert self.words(self.sy['continuous_media_control']['address'],8)==[128,5,896,0,3,0,0,0]
  assert self.words(self.sy['memory_output_control']['address'],12)==[1,8,4,0,0,0,0,0,0,0,0,0]
  all_tasks=[];p=self.word(0xf0908c)
  while p:
   assert p not in all_tasks and len(all_tasks)<3;all_tasks.append(p);p=self.word(p+40)
  assert set(all_tasks)=={CONTROLLER,IDLE,WORKER}
  assert self.word(self.prefix['worker_adapter']+48)==WORKER and self.word(0xf071d0)==1
  assert self.word(0xf09090)==self.running==IDLE
  assert self.entry_count['fifo_worker_core_v1']==self.entry_count['fifo_controller_core_v1']==self.entry_count['fifo_idle_core_v1']==1
  for r in self.rx:assert hashlib.sha256(bytes(self.u.mem_read(r['start'],r['size']))).hexdigest()==r['SHA256']
  for z in self.zones:
   if z['origin']=='NEW_ELF':
    end=z['logical_start']+z['logical_bytes'];padding=z['start']+z['size']-end
    assert bytes(self.u.mem_read(end,padding))==b'\xa5'*padding
   z['after_SHA256']=hashlib.sha256(bytes(self.u.mem_read(z['start'],z['size']))).hexdigest()
  return dict(all_passed=True,scope='same original OS20 resident worker -> copied RTP queue -> existing typed PCM FIFO',
   inherited_prefix=rel(PREFIX),inherited_prefix_SHA256=sha(PREFIX),prefix_creation_restore_not_rerun=True,
   one_declared_frozen_GP_CPSR_endpoint_restore=self.initial_state,
   host_context_switch_or_return_substitution=False,host_commands_after_dispatch=0,
   instructions=self.count,instruction_rolling_SHA256=self.hash.hexdigest(),instruction_source_counts=dict(self.visits),
   CPU_store_observer_count=self.store_count,protocol_CPU_stores=self.protocol_stores,
   protocol_store_observer_is_not_complete_memory_access_boundary_proof=True,
   full_helper_returns=self.calls,entry_counts=dict(self.entry_count),entries=self.entries,
   original_context_restores=self.restores,original_context_destinations=self.destinations,
   queue_to_decoder_inputs_copied_and_original_packet_poisoned=True,decoder_results=self.decoder_results,
   actual_submit_tickets=self.submit_tickets,reader_unlocked_copy_lease_full_returns=self.copy_windows,
   job=job,observations67=o,guard_results=signed,final_FIFO=self.protocol(),zones=self.zones,
   executable_mapping_sha256=[{k:v for k,v in r.items()if k!='data'}for r in self.rx],
   final_all_tasks=all_tasks,worker_adapter=self.prefix['worker_adapter'],worker_TCB=WORKER,
   private_controller_consumer_is_fixture=True,hardware_driver_or_original_mixer_present=False,
   original_Source_factory_reader_registered=False,original_factory_calls=self.controlled_factory_entries,
   source_record_or_anchor_ownership_proven=False,exclusive_native_witness=-200,
   STOP_closes_queue_not_full_audio_STOP_DONE=True,native_STOP_DONE=False,
   held_PCM_ticket16_remaining_bytes=128,stack_adapter_module_and_FIFO_remain_pinned=True,
   output_fixture_verified_PCM_bytes=896,decoded_PCM_bytes=1024,SBC_frames=4,streams=2,commands=12,
   decoder_format_scope='mono 16000 Hz; original converter 16000 bypass',
   initial_controller_idle_ready_membership_fixture=True,software_heap_and_MMU_tables_fixture=True,
   all_three_TCBs_from_verified_original_creation_prefix=True,original_MAIN_patches=0,
   live_radio_phone_speaker_App_menu_install_acceptance=False,device_IO=False,boundary=self.boundary)

def main():
 import unicorn
 assert unicorn.__version__=='2.1.4'
 assert not OUT.exists();OUT.mkdir()
 build=json.loads(BUILD.read_text());meta=json.loads(META.read_text())
 assert build['all_passed']and meta['all_passed']and sha(PREFIX)==meta['prefix_sha256']
 for p,h in meta['source_sha256'].items():assert sha(ROOT/p)==h
 for p,h in build['source_sha256'].items():assert sha(ROOT/p)==h
 for p,h in build['generated_sha256'].items():assert sha(ROOT/p)==h
 assert sha(ROOT/build['ELF'])==build['ELF_sha256']
 assert sha(FRAME)=='8139201e1a8e7a88a1429c94a6c2625c26ce2b7b64f1ad931ef8656e95aa109d'
 assert sha(REF)=='f4bff11f10e4c49f527ad2a7045161b48ed20fd54c56edcf87449b3bceac7a64'
 deps=dict(build['source_sha256'],**build['generated_sha256'])
 for p in(Path(__file__),BUILD,META,PREFIX,FRAME,REF,ROOT/build['ELF'],ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin'):
  deps[rel(p)]=sha(p)
 save(OUT/'inputs-at-run.json',deps)
 model=None
 try:
  prefix=json.load(gzip.open(PREFIX,'rt'));model=Tail(NativeImage(),prefix,build);proof=model.run()
  proof['source_sha256']=deps;proof['updated_utc']=datetime.now(timezone.utc).isoformat()
  path=OUT/'tail-proof.json.gz';zipped(path,proof)
  small={k:proof[k]for k in('all_passed','scope','instructions','CPU_store_observer_count','decoded_PCM_bytes',
   'output_fixture_verified_PCM_bytes','SBC_frames','streams','commands','actual_submit_tickets',
   'native_STOP_DONE','exclusive_native_witness','device_IO')}
  small.update(proof=rel(path),proof_SHA256=sha(path),source_sha256=deps,
   original_context_destinations=len(model.destinations),full_helper_returns=len(model.calls),
   worker_entries=1,all_retained_storage_pinned=True,install_candidate=False)
  save(OUT/'guest-proof.json',small)
  print(json.dumps({k:v for k,v in small.items()if k!='source_sha256'}),flush=True)
 except BaseException as error:
  failure=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if model:failure.update(state=model.snap(),ordinal=model.count,running_actor=model.running,
    original_restores=model.restores,original_destinations=model.destinations,open_frames=dict(model.frames),
    calls=model.calls,protocol=model.protocol(),CPU_stores=model.protocol_stores)
  zipped(OUT/'terminal-failure.json.gz',failure);raise
if __name__=='__main__':main()
