#!/usr/bin/env python3
"""Original native wire/5arg callback -> existing Source/SBC/FIFO, offline.
Real radio, native AVDTP mutex/heap/PSM/transport/event/DMA remain fixtures.
Source/kernel/audio mutex/condition/scheduler/decoder bodies execute.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,hashlib,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from emulate_avdtp_control import STATE,CONTEXT,CHANNELS,DESCRIPTORS,CONFIG
from emulate_avdtp_lifecycle import PEER,MEDIA_LCID
from emulate_native_music_dispatch import TABLE
from emulate_native_l2cap_send import ENTITY,TX,L2_MUTEX,HEAD,TAIL,FREE,SCHEDULED
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
I=load(ROOT/'staging/native-player-sbc-ingress/emulate_sbc_ingress_v4.py','remote_source_ingress')
B=I.B
sha,rel,dump,require=I.sha,I.rel,I.dump,I.require
BT_HEAP=0x09004000
SDP=0x03a7c108

class BindingVM(I.Ingress):
 def __init__(self,stock,elf,source,remote,reference):
  self.remote=remote;self.remote_symbols=remote['symbols'];self.bt_locks={};self.l2_fail=False
  self.native_callbacks=[];self.native_callback_returns=[];self.pending_native_callback=None
  self.native_sends=[];self.native_steps=[];self.bounded_imports=[]
  super().__init__(stock,elf,source,reference,1)
  for a,n in ((0x03a88000,8192),(0x03a7c000,4096),(0x03a96000,8192),(BT_HEAP,4096)):
   self.map(a,n,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
   self.fixture(a,b'\xa5'*n,'declared Bluetooth core/heap arena and guards')
  self.fixture(CONTEXT,bytes(DESCRIPTORS+36-CONTEXT),'declared Bluetooth startup-zero core BSS')
  self.fixture(SDP,bytes(14*12),'declared SDP startup-zero core BSS')
  flat=(ROOT/remote['flat']).read_bytes();base=remote['base'];size=(len(flat)+4095)&~4095
  self.map(base,size,unicorn.UC_PROT_READ|unicorn.UC_PROT_EXEC);self.uc.mem_write(base,flat)
  bss=remote['symbols']['__bss_start'];self.map(bss,4096,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
  self.fixture(bss,b'\xa5'*4096,'remote resident module BSS guards')
  self.fixture(bss,bytes(remote['BSS_bytes']),'declared remote module zero initialization')
  for signal,name in ((2,'music_endpoint_capabilities'),(3,'nr_configuration_gate'),(4,'music_endpoint_capabilities'),
                      (5,'nr_configuration_gate'),(7,'nr_start_suspend_gate'),(9,'nr_start_suspend_gate')):
   self.patch(TABLE+(signal-1)*4,struct.pack('<I',remote['symbols'][name]),'VM-only native signal table binding')
  self.patch(0x5249f8,bytes.fromhex('0200c046'),'VM-only preserve full signal body length')
  self.patch(0x5248fc,bytes.fromhex('0a28'),'VM-only actual ten-signal table bound')
  self.patch(remote['patch']['address'],bytes.fromhex(remote['patch']['after_hex']),'VM-only exact relocated reply prologue')
  self.initial_ordinal=self.ordinal
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC}
  self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}

 def patch(self,address,after,why):
  before=bytes(self.uc.mem_read(address,len(after)));self.uc.mem_write(address,after)
  self.patches.append(dict(address=address,before_hex=before.hex(),after_hex=after.hex(),reason=why))
 def byte(self,a):return self.uc.mem_read(a,1)[0]
 def remote_state(self):
  p=self.remote_symbols['nsg'];words=list(struct.unpack('<24I',self.uc.mem_read(p,96)))
  names=('epoch','accepted','admitting','retired','context','channel','lcid','local_mtu','callback','configuration_command','start_command',
   'config_witness','start_witness','inflight','callbacks','media','accepted_media','rejected_media','retirements',
   'start_notifications','early_start_admissions','stop_requests','last_ingress','last_stop')
  return dict(zip(names,words))
 def av_held(self):return bool(self.bt_locks.get(0xf50098,0))
 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  r=self.regs();sp=uc.reg_read(UC_ARM_REG_SP)
  if self.pending_native_callback and address==self.pending_native_callback['return_PC']:
   p=self.pending_native_callback
   require(sp==p['entry_SP']and self.word(B.READY_TASKS)==self.controller,'full native callback lost original caller/SP')
   require(not self.av_held() and not self.remote_state()['inflight'],'native callback returned with AV lock/reference')
   self.native_callback_returns.append(dict(p,returned=self.snapshot(),r0=uc.reg_read(UC_ARM_REG_R0),remote=self.remote_state()))
   self.pending_native_callback=None
  if address==self.remote_symbols['nsg_native_callback']:
   require(not self.av_held()and not self.pending_native_callback,'native callback under AV mutex/nested')
   length=self.word(sp);h=r[2]
   p=dict(entry=self.snapshot(),entry_SP=sp,return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,args=r+[length],
    handle_defined_4_to_11_hex=bytes(uc.mem_read(h+4,8)).hex(),remote=self.remote_state(),
    native_state=self.byte(STATE+0x12),native_pending=self.byte(STATE+0x13))
   self.pending_native_callback=p;self.native_callbacks.append(p)
  if address==self.build['symbols']['aas_media_ingress']['value']:
   require(self.pending_native_callback and self.pending_native_callback['args'][0]==0xf1,'Source ingress lacks native F1 caller')
   require(not self.av_held() and self.remote_state()['inflight']==1,'AV lock held across Source POST or guard absent')
   self.bounded_imports.append(dict(symbol='aas_media_ingress',state=self.snapshot(),remote=self.remote_state()))
  if address==B.POST and r[0]==self.source_tcb:require(not self.av_held(),'foreign Source POST while holding AV mutex')
  if address in (self.remote_symbols['nr_configuration_gate'],self.remote_symbols['nr_start_suspend_gate'],self.remote_symbols['nr_reply_dispatch']):
   require(self.av_held(),'native command gate missing AV mutex contract')
  if address in (0x5523de,0x5523fc):
   a=r[0];require(a in (0xf50098,0xf50088,L2_MUTEX),'unknown BT mutex fixture')
   held=self.bt_locks.get(a,0)
   if address==0x5523de:
    require(not held,'recursive BT mutex')
    error=-1 if a==L2_MUTEX and self.l2_fail else 0
    if not error:self.bt_locks[a]=self.word(B.READY_TASKS)
   else:
    require(held==self.word(B.READY_TASKS),'wrong BT mutex owner');error=0;self.bt_locks[a]=0
   self.service('explicit BT native mutex service '+hex(a),error&0xffffffff);return
  if address==0x55238e:self.service('explicit AVDTP mutex initializer',0);return
  if address==0x5525bc:self.service('explicit BT log sink',0);return
  if address==0x50c138:
   require(r[0]==25,'PSM configuration');self.fixture(r[1],struct.pack('<I',25)+bytes(48),'explicit PSM default configuration')
   self.service('explicit PSM configuration service',0);return
  if address==0x50c150:self.service('explicit PSM radio registration boundary',0);return
  if address==0x5524da:
   require(0<r[0]<=32,'bounded signaling allocation');self.fixture(BT_HEAP,b'\xa5'*4096,'explicit bounded signaling heap reset')
   self.service('explicit BT allocator',BT_HEAP+4096-32);return
  if address==0x5524ee:self.service('explicit BT signaling free',0);return
  if address==0x5524f6:
   require(0<r[2]<=64,'bounded BT memcpy');self.fixture(r[0],bytes(uc.mem_read(r[1],r[2])),'explicit BT memcpy service')
   self.service('explicit BT memcpy service',r[0]);return
  if address==0x60faec:
   require(self.bt_locks.get(L2_MUTEX),'TX event without native L2 mutex contract')
   self.service('explicit radio TX event submission',0);return
  if address==0x5a7794:
   self.native_sends.append(dict(state=self.snapshot(),args=r,wire_hex=bytes(uc.mem_read(r[2]+4,r[1]-4)).hex()))
  if address in (0x525f1c,0x544bc4,0x525560,0x5450a4):
   self.service('explicit radio L2CAP connection/configuration/disconnection service '+hex(address),0);return

 def boot_both(self):
  self.boot()
  for a in (0x4ccfb4,0x4ccc3c,0x5d7588):self.invoke_kernel(a|1,phase='original AVDTP/SDP boot '+hex(a))
  cb=self.remote_symbols['nsg_native_callback']
  require(self.invoke_kernel(self.remote_symbols['music_endpoint_prepare'],(cb,672),phase='compiled native endpoint provider')==1,'endpoint prepare')
  require(self.invoke_kernel(self.remote_symbols['music_endpoint_publish'],(1,cb),phase='compiled endpoint publication')==0,'endpoint publish')
  self.fixture(CONTEXT+0x13,b'\x00\xff\xff'+PEER,'declared already-established signaling context and synthetic peer')
  self.fixture(CHANNELS,struct.pack('<H',0x40)+bytes([0,0,0,0x10,0,0]),'declared established signaling transport, no SEP state write')
  self.fixture(ENTITY,bytes(880),'declared L2 entity pool')
  for a,b in ((ENTITY+6,struct.pack('<H',0x40)),(ENTITY+0x14,struct.pack('<H',672)),(ENTITY+0x1e,b'\x05'),(ENTITY+0x25,b'\xff')):
   self.fixture(a,b,'declared live signaling L2 entity fixture')
  self.fixture(TX,bytes(52*50),'declared TX pool')
  for i in range(50):self.fixture(TX+i*52+0x2f,b'\xff','declared TX idle slots')
  for a,b in ((0xf6957c,b'\0'),(SCHEDULED,b'\0'),(HEAD,b'\xff'),(TAIL,b'\xff'),(FREE,struct.pack('<H',50)),
    (0xf69584,struct.pack('<H',4)),(0xf69586,struct.pack('<H',8)),(0xf69598,bytes(4)),(0xf695b0,struct.pack('<H',1))):
   self.fixture(a,b,'declared radio TX credit/scheduler starting state')

 def native(self,name,address,args=(),payload=None,pointer_arg=None):
  args=list(args);before=self.producer();remote=self.remote_state();cursor=len(self.native_callbacks)
  if payload is not None:
   self.fixture(I.EXTERNAL-32,b'\xa5'*(4096+64),'ordinary L2CAP caller input guards')
   self.fixture(I.EXTERNAL,payload,'explicit HOST native L2CAP input, not physical phone')
   args[pointer_arg]=I.EXTERNAL
  r=self.invoke_kernel(address|1,args,phase=name)
  require(not any(self.bt_locks.values()) and not self.pending_native_callback,'native outer full return retains callback/BT lock')
  if payload is not None:require(bytes(self.uc.mem_read(I.EXTERNAL,len(payload)))==payload,'native caller input mutated')
  row=dict(name=name,return_value=r,before=before,after=self.producer(),remote_before=remote,remote_after=self.remote_state(),
   state=self.byte(STATE+0x12),pending=self.byte(STATE+0x13),callbacks=self.native_callbacks[cursor:],endpoint=self.endpoints[-1])
  self.native_steps.append(row);return row
 def signal(self,signal,body):return self.native('native wire signal '+str(signal),0x50bbb8,(0x40,0,len(body)+2),bytes([0x10,signal])+body,1)
 def ready(self):
  cfg=self.signal(3,CONFIG);require(cfg['state']==2 and self.remote_state()['accepted']==1,'accepted Configure binding')
  self.signal(6,b'\x04');self.complete_channel()
 def complete_channel(self):
  self.native('native media connection',0x50b988,(0,MEDIA_LCID,0),PEER,0)
  c=bytearray(12);struct.pack_into('<H',c,8,1008)
  self.native('native incoming channel configuration',0x50b3dc,(MEDIA_LCID,0),bytes(c),1)
  row=self.native('native channel completion',0x50b1f8,(MEDIA_LCID,0));require(row['state']==4 and not row['pending'],'native Open completion')
 def media(self,packet):return self.native('native F1 media packet',0x50bbb8,(MEDIA_LCID,0,len(packet)),packet,1)
 def result(self,name):
  require(not self.pending_native_callback and len(self.native_callbacks)==len(self.native_callback_returns),'missing full native callback')
  row=super().result(name,[])
  row.update(native_steps=self.native_steps,native_five_argument_callback_entries=self.native_callbacks,
   native_five_argument_callback_full_returns=self.native_callback_returns,native_L2CAP_sends=self.native_sends,
   actual_Source_imports=self.bounded_imports,remote_final=self.remote_state(),
   one_stream_per_boot_no_resume_after_retirement=True,real_BT_mutex_radio_DMA_warm_ownership_App_or_speaker=False)
  return row

def run_case(m,name):
 m.boot_both()
 if name=='Configure_TX_failure_never_admits':
  m.l2_fail=True;cfg=m.signal(3,CONFIG);m.l2_fail=False
  require(cfg['state']==2 and not m.remote_state()['accepted'],'failed Configure state2 must not be acceptance')
  m.signal(6,b'\x04');m.complete_channel();start=m.signal(7,b'\x04')
  require(start['state']==4 and not start['callbacks'] and not m.remote_state()['admitting'],'Start accepted after failed Config')
  m.media(m.packet(0));require(not m.ingress_entries and not m.codec_entries,'failed Configure reached Source')
  return
 m.ready()
 early=m.media(m.packet(0));require(not m.ingress_entries and not m.codec_entries,'F1 before Start reached Source')
 start=m.signal(7,b'\x04');require(start['state']==8 and not start['pending'] and m.remote_state()['admitting']==1,'full Start did not open admission')
 require(m.remote_state()['start_notifications']==1 and not m.remote_state()['early_start_admissions'],'event17 opened admission prematurely')
 m.media(m.packet(0));require(len(m.codec_returns)==2 and m.remote_state()['accepted_media']==1,'native F1 did not reach actual SBC Source')
 m.complete_first_sync_and_attach_output()
 first=m.cycle(True);m.compare(first,m.expected(0))
 m.native_steps.append(dict(output_packet=0,actual_PCM_hex=first.hex(),expected_prefix_hex=m.expected(0).hex()))
 if name=='two_native_callbacks_then_Suspend_Stop':
  m.media(m.packet(1));second=m.cycle();m.compare(second,m.expected(1))
  m.native_steps.append(dict(output_packet=1,actual_PCM_hex=second.hex(),expected_prefix_hex=m.expected(1).hex()))
  old=len(m.ingress_entries);m.signal(9,b'\x04');m.park();m.media(m.packet(0));m.signal(7,b'\x04')
  require(m.remote_state()['retired'] and not m.remote_state()['admitting'] and len(m.ingress_entries)==old,'retired Suspend session readmitted')
  require(m.remote_state()['stop_requests']==1 and not m.producer()['queue'][4],'Suspend did not stop compressed queue')
 elif name=='Disconnect_retires_and_blocks_new_Config':
  old=len(m.ingress_entries);m.native('native disconnect notification',0x50be1c,(MEDIA_LCID,));m.park();m.media(m.packet(0));m.signal(3,CONFIG)
  require(m.remote_state()['retired'] and not m.remote_state()['admitting'] and len(m.ingress_entries)==old,'disconnect readmitted stale/new data')
  require(m.remote_state()['epoch']==1 and m.remote_state()['stop_requests']==1,'disconnect forged new accepted generation')
 else:
  m.command(6);old=len(m.ingress_entries);before=len(m.codec_entries)
  m.media(m.packet(1));require(len(m.ingress_entries)==old+1 and len(m.codec_entries)==before,'native profile replacement reached decoder')
  require(m.remote_state()['accepted_media']==1 and m.remote_state()['rejected_media']>=1,'profile replacement not rejected')

def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v3';runtime.mkdir(exist_ok=False)
 source=json.loads((ROOT/'staging/native-player-sbc-ingress/build-v3.json').read_text())
 remote=json.loads((BASE/'build-v1.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(remote['source_sha256'],**source['source_sha256'],**source['generated_sha256'],**reference['source_sha256'])
 for p in (Path(__file__),BASE/'build-v1.json',ROOT/remote['flat'],ROOT/remote['elf'],ROOT/source['ELF'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed source input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 e=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','remote_source_elf').ELF32(ROOT/source['ELF'])
 cases=[];m=None
 try:
  for name in ('two_native_callbacks_then_Suspend_Stop','Configure_TX_failure_never_admits','Disconnect_retires_and_blocks_new_Config','original_profile_replacement_rejects_decoder'):
   m=BindingVM(NativeImage(),e,source,remote,reference);run_case(m,name);row=m.result(name);p=runtime/(name+'.json');dump(p,row)
   cases.append(dict(name=name,path=rel(p),sha256=sha(p),passed=True))
   print(json.dumps(dict(case=name,native_callbacks=len(m.native_callbacks),Source_ingress=len(m.ingress_entries),SBC_returns=len(m.codec_returns),native_full_returns=len(m.full_returns))),flush=True);m=None
  proof=dict(all_passed=True,cases=cases,source_sha256=deps,updated_utc=datetime.now(timezone.utc).isoformat(),
   native_F1_Source_SBC_FIFO_same_VM=True,accepted_Config_Start_identity_checked=True,Source_POST_without_AV_mutex=True,
   separate_FILE_review_complete=False,device_IO=False,physical_phone_App_or_warm_ownership=False,
   one_stream_per_boot_resume_restart_STOP_DONE_unload_unimplemented=True)
  dump(BASE/'remote-binding-v1-proof.json',proof)
 except BaseException as error:
  failure=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),cases_completed=cases,source_sha256=deps,device_IO=False)
  if m:failure.update(phase=m.phase,trace=m.trace,state=m.snapshot(),remote=m.remote_state(),producer=m.producer(),native_steps=m.native_steps,
   CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
   final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC},
   native_callbacks=m.native_callbacks,native_callback_returns=m.native_callback_returns,decoder_entries=m.codec_entries,decoder_returns=m.codec_returns)
  dump(runtime/'terminal-failure.json',failure);raise
if __name__=='__main__':main()
