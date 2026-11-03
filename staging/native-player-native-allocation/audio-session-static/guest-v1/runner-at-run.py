#!/usr/bin/env python3
"""Prepared for ROOT to execute: original selector -> full pull -> compiled PCM.
No original MAIN code patch. Explicit single actor/source-list, cold pool,
opaque allocator/query/release, mutex, wake, mixer storage/priority/message
fixtures. Actual getter/IRQ/queue/selector/factory/prepare/reader/copy returns.
No SBC decode, real source->mixer handoff, native mixer caller2FA572, hardware,
capacity consumer, exclusive ownership, STOP_DONE or complete player claim.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,importlib.util,json,struct,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(__file__).resolve().parent
OLD=ROOT/'staging/native-player-session-native-call/emulate_queue_call.py'
spec=importlib.util.spec_from_file_location('frozen_queue_call',OLD)
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
from analyze_native_sections import NativeImage,EXPECTED
UC_PROT_READ=unicorn.UC_PROT_READ;UC_PROT_WRITE=unicorn.UC_PROT_WRITE
CHANNELS=old.CHANNELS;STRIDE=old.STRIDE;RECORD=old.RECORD
POOL=0x034e3cf4;MIXER=0x034e5378+8*0x130
DESCRIPTOR=0x09800020;BUFFER=0x09801020;SCRATCH=0x09803f00
RING_BYTES=2048;CAPACITY=256;INPUT=0x09804020
sha=old.sha;rel=old.rel;dump=old.dump;require=old.require
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path)
 m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

class AudioSession(old.QueueCall):
 def __init__(self,stock,elf,build):
  self.ordinal=0;self.flow=[];self.readers=[];self.full_returns=[]
  self.pending_full=None;self.declared_services=[];self.last_selected=None
  super().__init__(stock,elf,build)
  # New declared cold BSS/mixer/input mappings, no selected index/ticket seed.
  self.map(0x034e3000,0x2000,UC_PROT_READ|UC_PROT_WRITE)
  self.map(0x09800000,0x5000,UC_PROT_READ|UC_PROT_WRITE)
  self.fixture(POOL-32,b'\xa5'*32,'cold provider pool leading boundary')
  self.fixture(POOL+10*0x240,b'\xa5'*4,'cold provider pool trailing boundary')
  require(any(z['runtime_start']<=0x034e3000 and z['runtime_end']>=0x034e5000 for z in stock.zeros),
          'native startup BSS does not cover provider pools')
  self.offsets=list(struct.unpack('<5I',self.uc.mem_read(build['symbols']['aas_offsets']['value'],20)))
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC}
  self.initial_ordinal=self.ordinal
  self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()
                  for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}
 def fixture(self,a,b,why):
  super().fixture(a,b,why);self.ordinal+=1
  self.fixtures[-1].update(ordinal=self.ordinal,event_type='declared_host_fixture')
 def store(self,uc,access,a,n,v,data):
  super().store(uc,access,a,n,v,data);self.ordinal+=1
  self.journal[-1].update(ordinal=self.ordinal,event_type='actual_CPU_store')
 def leases(self):
  g=self.build['symbols']['aas_guard']['value'];c=self.build['symbols']['aas_control']['value']
  b=self.word(g+self.offsets[0])
  return dict(borrow=b,selected_ticket=self.word(g+self.offsets[1]),
   selected_instance=self.word(g+self.offsets[2]),media=self.word(c+self.offsets[3]),
   callback=self.word(c+self.offsets[4]),frame_hex=bytes(self.uc.mem_read(b,72)).hex()if b else None,
   current_TCB=self.word(0xF09090),interrupt_marker=self.word(0xF09094))
 def code(self,uc,a,n,data):
  # Parent executes getter/IRQ/BXLR and original queue bodies, fixtures only
  # its declared lower opaque/mutex boundaries. Additional services below.
  super().code(uc,a,n,data)
  symbols=self.build['symbols']
  watched=(0x277536,0x2f9f2e,0x4379d4,0x437764,0x48ee68,0x437a3e,
           0x455c86,0x2f9cce,0x2f9d1a,0x3732c8,0x358d24,0x21b6cc,0x21b6dc)
  if a in watched or a in [symbols[k]['value']&~1 for k in
      ('aas_pcm_publish','memory_output_submit','mcs_capture_selected','mcs_pull_begin','mcs_pull_end')]:
   self.flow.append(dict(PC=hex(a),args=self.regs(),SP=uc.reg_read(UC_ARM_REG_SP),
    LR=uc.reg_read(UC_ARM_REG_LR),phase=self.phase,ordinal=self.ordinal))
  if a==0x2f9cce:
   require(self.pending_full is None,'nested native full pull')
   view=self.leases()
   require(view['borrow'] and view['media']==1 and view['callback']==1,
           'native full pull entered without both live leases')
   self.pending_full=dict(entered_PC=hex(a),entry_native_frame_SP=uc.reg_read(UC_ARM_REG_SP),
      return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,entry_LR=uc.reg_read(UC_ARM_REG_LR),
      phase=self.phase,entry_leases=view)
  if self.pending_full and a==self.pending_full['return_PC']:
   pending=self.pending_full;view=self.leases()
   require(uc.reg_read(UC_ARM_REG_SP)==pending['entry_native_frame_SP']+64,
           'original full pull did not release its entire64-byte frame')
   require(view['borrow'] and view['media']==1 and view['callback']==1,
           'lease released before complete original full pull return')
   self.full_returns.append(dict(pending,returned_r0=uc.reg_read(UC_ARM_REG_R0),
     returned_SP=uc.reg_read(UC_ARM_REG_SP),return_leases=view))
   self.pending_full=None
  if a in (symbols['memory_output_read']['value'],symbols['continuous_media_read']['value']):
   view=self.leases();require(view['borrow'] and view['media']==1 and view['callback']==1,
                            'compiled PCM reader did not retain full-pull leases')
   self.readers.append(dict(PC=hex(a),args=self.regs(),SP=uc.reg_read(UC_ARM_REG_SP),
     LR=uc.reg_read(UC_ARM_REG_LR),leases=view,phase=self.phase))
  if a not in (0x3887a2,0x2f9c52,0x37bce4,0x3b9674):return
  args=self.regs();row=dict(entry=hex(a),args=args,LR=uc.reg_read(UC_ARM_REG_LR),
   SP=uc.reg_read(UC_ARM_REG_SP),phase=self.phase,
   scope='explicit opaque release / pull priority / message transport / diagnostic fixture')
  if a==0x3887a2:
   handle=self.word(args[0]);h=self.handles[handle]
   require(not h.get('released',False),'duplicate opaque fixture release')
   h['released']=True;row['handle']=handle
   self.fixture(args[0],bytes(4),'opaque release fixture clears caller handle; no native heap execution')
  elif a==0x37bce4:
   row['message_first_two_bytes']=bytes(uc.mem_read(args[1],2)).hex()
  self.declared_services.append(row);self.boundary_return(0)
 def setup(self):
  require(self.call(0x277d27,(8,0,1),phase='original_profile')==0,'original profile failed')
  require(self.word(RECORD+0x160)==0x277c6b,'original profile callback missing')
  self.profile_baseline=bytes(self.uc.mem_read(CHANNELS,18*STRIDE))
  require(self.call('aas_initialize',(RECORD,POOL),phase='compiled_initialize')==0,'new initialization failed')
  require(self.word(RECORD+0x160)==self.build['symbols']['mcs_queue_bridge']['value'],'compiled queue callback missing')
  pcm=struct.pack('<256h',*[(i*181%60001)-30000 for i in range(256)])
  self.fixture(INPUT-32,b'\xa5'*(len(pcm)+64),'declared caller PCM input and boundaries')
  self.fixture(INPUT,pcm,'declared raw PCM input bytes; no decoder claim')
  ticket=self.call('aas_pcm_publish',(INPUT,len(pcm)),phase='actual_compiled_submit_and_fifo_publication')
  require(0<ticket<0x80000000,'actual compiled producer did not return a ticket')
  slots=self.build['symbols']['memory_output_slots']['value']
  require(self.word(slots+24*(ticket&3))==ticket and self.word(slots+24*(ticket&3)+4)==2,
          'real submit ticket/state mismatch')
  require(self.call('aas_register',(ticket,),phase='original_high_queue_registration')==0,'original registration failed')
  require(len(self.lower_calls)==len(self.lower_returns)==1,'original queue writer did not return')
  for args in self.lower_calls:
   require(args[:4]==[RECORD+0x1a8,0xffff,10,12] and args[5:]==[0x20c,0],'original seven queue arguments mismatch')
   require(list(struct.unpack('<5I',self.uc.mem_read(args[4],20)))==
      [1,16000,16,self.word(self.build['symbols']['aas_guard']['value']+12),2],
      'compiled registration params/real static anchor mismatch')
  require(self.call('aas_select',(ticket,),phase='original_start_selector_factory_and_capture')==0,
          'original selected provider not admitted')
  index=self.word(RECORD+0xf0);provider=POOL+index*0x240
  require(index<5 and bytes(self.uc.mem_read(provider+12,1))==b'\x01' and
          bytes(self.uc.mem_read(provider+28,1))==b'\x01','original native provider not busy/prepared')
  require(self.word(RECORD+0x108)==self.build['symbols']['memory_output_read']['value'],
          'post-selector compiled reader was not installed')
  require(self.word(RECORD+0x10c)==0x48ee31 and
          struct.unpack('<HHII',self.uc.mem_read(RECORD+0x138,12))==(1,16,2,16000),
          'original kind10 format differs')
  require(any(int(e['PC'],16)==0x48ee8e and int(e['address'],16)==RECORD+0xf0
              and e['value']==index for e in self.journal),'no original prepare CPU index store')
  require(any(int(e['PC'],16)==0x48ee8c and int(e['address'],16)==provider+12
              and e['value']==1 for e in self.journal),'no original prepare CPU busy store')
  self.ticket=ticket;self.pcm=pcm;self.last_selected=dict(index=index,provider=provider,
     record_F0_native_store_PC='0x48ee8e',busy_native_store_PC='0x48ee8c')
  self.fixture(DESCRIPTOR-32,b'\xa5'*(36+64),'declared nine-word mixer descriptor boundaries')
  self.fixture(BUFFER-32,b'\xa5'*(RING_BYTES+64),'declared empty mixer ring boundaries')
  initial=BUFFER+RING_BYTES-64
  self.fixture(DESCRIPTOR,struct.pack('<9I',0,BUFFER,RING_BYTES,initial,initial,0,0,0,0),
               'declared empty ring with one wrap; no hardware consumer')
  for address,value in ((MIXER,DESCRIPTOR),(MIXER+4,CAPACITY),(MIXER+0x78,0xa002),(MIXER+0xb4,SCRATCH)):
   self.fixture(address,struct.pack('<I',value),'declared mixer storage/capacity/message handle')
  self.fixture(MIXER+0x7f,bytes(1),'declared normal memcpy mixer mode, no resampler')
  self.fixture(SCRATCH-32,b'\xa5'*(CAPACITY+64),'declared original reader scratch boundaries')
 def status(self):
  self.call('aas_status',(old.RESULT,),phase='compiled_status_read')
  return list(struct.unpack('<30I',self.uc.mem_read(old.RESULT,120)))
 def pull(self):
  before=self.word(DESCRIPTOR+16);returns=len(self.full_returns)
  result=self.call('aas_pull',(8,),phase='explicit_full_original_pull_wrapper')
  after=self.word(DESCRIPTOR+16);count=(after-before)%RING_BYTES
  require(len(self.full_returns)==returns+1,'full original pull return missing')
  require(result==self.full_returns[-1]['returned_r0'],'bridge changed native full-pull R0')
  require(count==CAPACITY,'original mixer did not commit exactly256 bytes')
  first=min(count,BUFFER+RING_BYTES-before)
  pcm=bytes(self.uc.mem_read(before,first))
  if first<count:pcm+=bytes(self.uc.mem_read(BUFFER,count-first))
  view=self.leases();require(view['borrow']==view['media']==view['callback']==0,
                          'lease retained after complete wrapper return')
  return dict(full_native_r0=result,committed_bytes=count,PCM_hex=pcm.hex(),wrapped=after<before,
              returned_leases=view)
 def replay(self):
  events=sorted([e for e in self.journal+self.fixtures if e['ordinal']>self.initial_ordinal],
                key=lambda e:e['ordinal'])
  require(len({e['ordinal']for e in events})==len(events),'duplicate mixed event ordinal')
  zones={int(a):bytearray.fromhex(raw)for a,raw in self.initial.items()}
  for e in events:
   a=int(e['address'],16);before=bytes.fromhex(e['before_hex']);n=len(before)
   matches=[base for base,b in zones.items()if base<=a and a+n<=base+len(b)]
   require(len(matches)==1,'event outside exactly one whole RW zone')
   base=matches[0];b=zones[base];offset=a-base
   require(bytes(b[offset:offset+n])==before,'mixed CPU/fixture before-image mismatch')
   if e['event_type']=='actual_CPU_store':
    require(n==e['size'],'CPU width mismatch')
    after=(e['value']&((1<<(8*n))-1)).to_bytes(n,'little')
   else:after=bytes.fromhex(e['after_hex'])
   require(len(after)==n,'fixture width mismatch');b[offset:offset+n]=after
  for a,b in zones.items():require(bytes(self.uc.mem_read(a,len(b)))==bytes(b),'whole RW replay mismatch '+hex(a))
  return dict(passed=True,zone_count=len(zones),joint_event_count=len(events),
              CPU_events=sum(e['event_type']=='actual_CPU_store'for e in events))
 def finish(self,name,pulls):
  status=self.status();require(status[2]==status[6]==status[7]==status[8]==status[12]==0,
           'live borrow/lease/native completion state mismatch')
  require(not any(self.mutex.values()) and self.pending_full is None,'retained lower fixture/native frame')
  for h in self.handles.values():
   a,n=h['pointer'],h['size'];require(bytes(self.uc.mem_read(a-32,32))==b'\xa5'*32 and
      bytes(self.uc.mem_read(a+n,32))==b'\xa5'*32,'opaque backing boundary changed')
  for a,n in ((DESCRIPTOR,36),(BUFFER,RING_BYTES),(SCRATCH,CAPACITY),(INPUT,len(self.pcm))):
   require(bytes(self.uc.mem_read(a-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(a+n,32))==b'\xa5'*32,
           'caller/mixer/reader boundary changed')
  require(bytes(self.uc.mem_read(INPUT,len(self.pcm)))==self.pcm,'producer input changed')
  current=bytes(self.uc.mem_read(CHANNELS,18*STRIDE))
  for i in range(18):
   if i!=8:require(current[i*STRIDE:(i+1)*STRIDE]==self.profile_baseline[i*STRIDE:(i+1)*STRIDE],
                   'neighboring channel changed')
  for a,digest in self.RX_before.items():
   n=next(n for base,n,p in self.zones if str(base)==a)
   require(hashlib.sha256(bytes(self.uc.mem_read(int(a),n))).hexdigest()==digest,'RX bytes changed')
  require(self.word(0xF09090)==old.ACTOR and self.word(0xF09094)==0,'declared actor/normal fixture changed')
  if name=='two_full_original_pulls':
   require(bytes.fromhex(''.join(p['PCM_hex']for p in pulls))==self.pcm,'compiled FIFO/mixer PCM mismatch')
   require(status[3]==status[4]==2 and status[14]==512 and status[15]==0,
           'full-return/read/release counters mismatch')
   require(status[19]==0 and status[20]==status[21]==1 and status[25]==512 and status[27]==1,
           'actual persistent FIFO did not consume its one ticket')
  else:require(status[3]==status[4]==0 and status[5]==1,'Stop admission did not reject new full pull')
  before=bytes(self.uc.mem_read(old.RESULT+256,128))
  r=self.call('mcs_native_ownership_snapshot',(0,1,0x1352,old.RESULT+256),phase='uncertified_witness')
  require(r==(-200&0xffffffff)and bytes(self.uc.mem_read(old.RESULT+256,128))==before,'ownership witness changed')
  return dict(name=name,passed=True,ticket=self.ticket,selected_native_provider=self.last_selected,
   pulls=pulls,status=status,original_queue_seven_args=self.lower_calls,original_queue_returns=self.lower_returns,
   full_native_pull_returns=self.full_returns,reader_live_leases=self.readers,native_and_compiled_flow=self.flow,
   native_visits={hex(k):v for k,v in self.visits.items()},instructions=self.instructions,
   replay=self.replay(),initial_ordinal=self.initial_ordinal,initial_whole_RW_zones=self.initial,
   final_whole_RW_zones={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC},
   zones=[dict(start=a,size=n,protection=p)for a,n,p in self.zones],
   CPU_store_journal=self.journal,declared_fixture_mutations=self.fixtures,
   lower_opaque_mutex_fixtures=self.native_boundaries,additional_declared_service_fixtures=self.declared_services,
   unchanged_RX_sha256=self.RX_before,native_ownership_snapshot=-200,native_STOP_DONE=False,
   actual_native_mixer_actor_2FA572_redirected=False,source_owner_to_mixer_handoff_verified=False,
   native_heap_mutex_scheduler_hardware_or_App_verified=False,full_player_verified=False,device_io=False)

def main():
 require(unicorn.__version__=='2.1.4','requires isolated Unicorn2.1.4')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 source={rel(Path(__file__).resolve()):sha(Path(__file__).resolve()),rel(OLD):sha(OLD),
  'scripts/analyze_native_sections.py':sha(ROOT/'scripts/analyze_native_sections.py'),
  'evidence/firmware-analysis/main_02bd.bin':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 require(source['evidence/firmware-analysis/main_02bd.bin']==EXPECTED,'wrong MAIN')
 build=json.loads((BASE/'build-v3.json').read_text());source.update(build['source_sha256']);source.update(build['generated_sha256'])
 source[rel(BASE/'build-v3.json')]=sha(BASE/'build-v3.json');source[build['ELF']]=sha(ROOT/build['ELF'])
 for p,h in source.items():require(sha(ROOT/p)==h,'input changed '+p)
 (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes());dump(runtime/'inputs-at-run.json',source)
 mod=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','aas_elf')
 elf=mod.ELF32(ROOT/build['ELF']);stock=NativeImage();cases=[];m=None
 try:
  for name in ('two_full_original_pulls','local_Stop_prevents_original_pull'):
   m=AudioSession(stock,elf,build);m.setup();pulls=[]
   if name=='two_full_original_pulls':pulls=[m.pull(),m.pull()]
   else:
    require(m.call('aas_stop',phase='local_stop_request')==1,'local Stop request failed')
    calls=len(m.full_returns);before=bytes(m.uc.mem_read(BUFFER,RING_BYTES))
    require(m.call('aas_pull',(8,),phase='stopped_pull_admission')==0,'denied wrapper did not return0')
    require(len(m.full_returns)==calls and bytes(m.uc.mem_read(BUFFER,RING_BYTES))==before,
            'rejected Stop pull entered native body or altered mixer ring')
   row=m.finish(name,pulls);path=runtime/(name+'.json');dump(path,row)
   cases.append(dict(name=name,path=rel(path),sha256=sha(path),passed=True))
   print(name+' PASS',flush=True);m.uc=None;m=None
  proof=dict(all_passed=True,source_sha256=source,cases=cases,case_count=len(cases),
    updated_utc=datetime.now(timezone.utc).isoformat(),
    actual_compiled_submit_ticket_and_original_selector_provider=True,
    original_full_pull_to_compiled_FIFO_and_complete_lease_returns=True,
    independent_RW_replay=False,in_runner_complete_joint_CPU_fixture_replay=True,
    original_MAIN_code_not_patched=True,raw_PCM_source_input_fixture=True,
    original_queue_selector_factory_reader_copy_not_stubbed=True,
    original_native_mixer_caller_redirected=False,source_owner_to_mixer_handoff_verified=False,
    native_ownership_or_STOP_DONE_or_hardware_or_App_or_complete_player_verified=False,device_io=False)
  dump(BASE/'audio-session-emulation-proof.json',proof)
  print(json.dumps(dict(all_passed=True,proof=rel(BASE/'audio-session-emulation-proof.json'))))
 except BaseException as e:
  row=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),cases_completed=cases,
           source_sha256=source,guest_success=False,device_io=False)
  if m:row.update(phase=m.phase,trace=m.trace,flow=m.flow,readers=m.readers,full_returns=m.full_returns,
    registers={n:hex(m.uc.reg_read(r))for n,r in [('pc',UC_ARM_REG_PC),('lr',UC_ARM_REG_LR),('sp',UC_ARM_REG_SP)]},
    CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,
    lower_fixture_calls=m.native_boundaries,additional_declared_service_fixtures=m.declared_services)
  dump(runtime/'terminal-failure.json',row);raise
if __name__=='__main__':main()
