#!/usr/bin/env python3
"""ROOT offline foreign-caller packets -> typed ingress -> native Source.
No compressed packet or expected PCM is compiled into the image. Packets are
explicit HOST call inputs, not a phone or recovered SEP registration. Original
kernel/source/mixer bodies run with inherited declared cold/hardware fixtures.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,hashlib,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
BASE=Path(__file__).resolve().parent
ROOT=BASE.parents[1]
PARENT=ROOT/'staging/native-player-mixer-sync/emulate_mixer_sync_v3.py'
REFERENCE=ROOT/'staging/native-player-sbc-sync/compressed_input_reference_v1.json'
def load(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
B=load(PARENT,'ingress_original_kernel')
sha,rel,dump,require=B.sha,B.rel,B.dump,B.require
EXTERNAL=0x09900020

class Ingress(B.Handoff):
 def __init__(self,stock,elf,build,reference,index):
  self.reference=reference['streams'][index];self.stream_index=index
  self.codec_entries=[];self.codec_returns=[];self.producer_entries=[]
  self.ingress_entries=[];self.ingress_returns=[];self.pending_codec=None;self.pending_ingress=None
  self.stage1_prefix=None;self.capacity_decoder_overlaps=[]
  self.valid_packets={bytes.fromhex(p['packet_hex']) for p in self.reference['packets']}
  self.valid_packets.add(bytes.fromhex(self.reference['bad_later_frame_CRC_packet_hex']))
  super().__init__(stock,elf,build)
  self.map(EXTERNAL&~4095,8192,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
  self.fixture(EXTERNAL-32,b'\xa5'*8192,'explicit foreign-caller compressed input arena and guards')
  self.initial_ordinal=self.ordinal
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex() for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC}

 def producer(self):
  s=self.build['symbols']
  return dict(owned=list(struct.unpack('<13I',self.uc.mem_read(s['owned_media_control']['value'],52))),
   queue=list(struct.unpack('<9I',self.uc.mem_read(s['media_queue_control']['value'],36))),
   started=self.word(s['mh_started']['value']),stream_error=self.word(s['mh_stream_error']['value']),
   ingress=[self.word(s[n]['value']) for n in ('sbi_callbacks','sbi_accepted','sbi_rejected','sbi_ingress_posts','sbi_capacity_posts','sbi_source_events','sbi_processed','sbi_errors')])

 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  s=self.build['symbols']
  if self.pending_codec and address==self.pending_codec['return_PC']:
   p=self.pending_codec;v=self.leases()
   require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'] and self.word(B.READY_TASKS)==self.source_tcb,'decoder full return actor/SP')
   require(v['media']>=1 and v['callback']>=1,'decoder typed leases lost')
   self.codec_returns.append(dict(p,returned=self.snapshot(),leases=v,r0=uc.reg_read(UC_ARM_REG_R0),
    result=list(struct.unpack('<9I',uc.mem_read(p['result_pointer'],36)))))
   self.pending_codec=None
  if self.pending_ingress and address==self.pending_ingress['return_PC']:
   p=self.pending_ingress
   require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'] and self.word(B.READY_TASKS)==self.controller,'ingress full return did not restore foreign caller')
   require(self.leases()['media']==self.leases()['callback']==0,'ingress retained typed leases after full return')
   self.ingress_returns.append(dict(p,returned=self.snapshot(),r0=uc.reg_read(UC_ARM_REG_R0),producer=self.producer()))
   self.pending_ingress=None
  if address==s['aas_media_ingress']['value']:
   require(self.pending_ingress is None and self.controller and self.word(B.READY_TASKS)==self.controller,'ingress is not a distinct original controller actor')
   length=self.word(uc.reg_read(UC_ARM_REG_SP));ptr=uc.reg_read(UC_ARM_REG_R3)
   require(13<=length<=4096,'explicit foreign packet bound')
   packet=bytes(uc.mem_read(ptr,length));require(packet in self.valid_packets,'unknown foreign compressed packet')
   p=dict(entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,
    packet_hex=packet.hex(),args=self.regs(),bytes=length,producer=self.producer())
   self.ingress_entries.append(p);self.pending_ingress=p
  names=('media_queue_callback','media_queue_step','owned_packet_parse','garmin_sbc_decode_frame','memory_output_submit','sbi_capacity_wake')
  match=next((n for n in names if address==s[n]['value']),None)
  if match:
   v=self.leases();p=dict(symbol=match,entry=self.snapshot(),leases=v,producer=self.producer(),args=self.regs())
   if match=='media_queue_callback':
    require(self.word(B.READY_TASKS)==self.controller and v['media']>=1 and v['callback']>=1,'packet copy lacks foreign ingress lifetime')
   elif match=='sbi_capacity_wake':
    require(self.word(B.READY_TASKS)==self.mixer_tcb and v['borrow'] and self.pending_full,'capacity wake outside original borrowed mixer frame')
    require(p['producer']['started']==1,'capacity wake before first native source initialization')
   else:
    require(self.word(B.READY_TASKS)==self.source_tcb,'decode/step/submit outside actual Source task')
    if match!='media_queue_step':
     require(v['media']>=1 and v['callback']>=1,'producer lacks typed media/callback leases')
     require(self.word(B.RECORD+0x160)==s['mcs_queue_bridge']['value'],'producer ignores callback replacement')
    if v['borrow']:
     require(self.pending_full,'source borrow overlap has no suspended original full frame')
     require(p['producer']['started']==1,'capacity Source would initialize an anchor inside Mixer borrow')
     require(v['selected_instance'] and v['selected_session'],'capacity Source lost selected native source')
     self.capacity_decoder_overlaps.append(p)
   if match=='garmin_sbc_decode_frame':
    require(self.pending_codec is None,'nested decoder')
    length=uc.reg_read(UC_ARM_REG_R1);require(4<=length<=4096,'decoder bound')
    p.update(entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,
     result_pointer=self.word(uc.reg_read(UC_ARM_REG_SP)),frame_hex=bytes(uc.mem_read(uc.reg_read(UC_ARM_REG_R0),length)).hex())
    self.codec_entries.append(p);self.pending_codec=p
   self.producer_entries.append(p)

 def boot(self):
  self.invoke_kernel(0x3008A1,(B.EXIT_LIST+4,),phase='original exit-list mutex constructor')
  for i,(entry,top,priority) in enumerate(((B.IDLE,B.IDLE_STACK+16384,240),(B.IDLE+4,B.CONTROLLER_STACK+16384,16))):
   d=B.DESCRIPTORS+32*i;self.fixture(d,struct.pack('<5I',entry,0,top,priority<<16,0),'declared idle/controller descriptor')
   t=self.invoke_kernel(0x358BF9,(d,),phase='original controller/idle TCB constructor')
   if i==0:self.idle=t
   else:self.controller=t
  for a,v in ((B.READY_TASKS,self.controller),(self.controller,self.idle),(self.idle,0)):
   self.fixture(a,struct.pack('<I',v),'initial ready-list controller/idle fixture')
  self.fixture(self.controller+22,b'\x01','initial controller ready state')
  self.fixture(self.idle+22,b'\x01','initial idle ready state')
  self.invoke_kernel(0xF6E49,phase='direct declared original Timer descriptor constructor')
  self.invoke_kernel(0x353D3D,phase='direct declared original Timer TCB constructor; never posted')
  require(self.word(0xF090A0)==0x02D227C8,'original Timer publication')
  self.invoke_kernel(0x3008A1,(B.RECORD+0x58,),phase='direct original channel mutex constructor')
  self.invoke_kernel(0x3EC541,(B.RECORD+0x70,),phase='direct original channel condition constructor')
  self.source_tcb=self.invoke_kernel('mh_boot_source',phase='compiled Stage1 source bootstrap without input')
  state=self.status();p=self.producer()
  require(state[30]==state[35]==self.source_tcb and state[31]==state[32]==1 and not state[33],'Stage1 initialization failed')
  require(not self.mixer_tcb and not state[10] and not p['owned'][8] and not p['started'] and not self.sync_entries and not self.codec_entries,'Stage1 fabricated first input/anchor/mixer')
  self.stage1_prefix=dict(state=state,producer=p,registers=self.snapshot(),no_input_no_anchor_no_mixer=True)
  self.park()

 def receive(self,packet,accept=True):
  before=self.producer();cursor=len(self.codec_entries)
  self.fixture(EXTERNAL-32,b'\xa5'*(4096+64),'ordinary foreign packet input guards')
  self.fixture(EXTERNAL,packet,'explicit HOST supplied compressed callback input; not phone')
  r=self.invoke_kernel('sbi_receive_packet',(0xF1,0,EXTERNAL,len(packet)),phase='foreign controller invokes compiled ingress ABI shim')
  require((r==0)==accept,'unexpected ingress admission')
  after=self.producer()
  if not accept:
   require(len(self.codec_entries)==cursor and after['owned'][8]==before['owned'][8] and after['queue'][6]==before['queue'][6],'rejected ingress copied/decoded/published packet')
  require(bytes(self.uc.mem_read(EXTERNAL,len(packet)))==packet,'borrowed foreign input modified')
  require(bytes(self.uc.mem_read(EXTERNAL-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(EXTERNAL+len(packet),32))==b'\xa5'*32,'foreign input canary changed')
  if self.pending_sync and self.sync_boot_prefix is None:
   self.sync_boot_prefix=dict(state=self.status(),sync=self.sync_status(),controller=self.snapshot(),
    original_sync_entered=True,original_sync_returned=False,PLAY_open=False,actual_ack_count=len(self.ack_entries),source_TCB=self.source_tcb)
  return dict(return_value=r,before=before,after=after,decoded_entries=len(self.codec_entries)-cursor)

 def complete_first_sync_and_attach_output(self):
  require(self.pending_sync and not self.sync_returns,'first external packet did not reach real native wait')
  self.park();state=self.status();p=self.producer()
  require(p['started']==1 and not p['stream_error'] and len(self.sync_returns)==len(self.ack_entries)==1,'first external packet did not complete native start/sync')
  require(state[36]==self.mixer_tcb and state[42]==state[43]==state[52] and state[42]>=1,'native selector/binding incomplete')
  self.fixture(B.DESCRIPTOR-32,b'\xa5'*(36+64),'output descriptor guards')
  self.fixture(B.BUFFER-32,b'\xa5'*(B.RING_BYTES+64),'explicit hardware ring guards')
  initial=B.BUFFER+B.RING_BYTES-64
  self.fixture(B.DESCRIPTOR,struct.pack('<9I',0,B.BUFFER,B.RING_BYTES,initial,initial,0,0,0,0),'empty hardware output ring fixture')
  for a,v in ((B.MIXER,B.DESCRIPTOR),(B.MIXER+4,B.CAPACITY),(B.MIXER+0xB4,B.SCRATCH)):
   self.fixture(a,struct.pack('<I',v),'hardware buffer/capacity fixture')
  for a,v in ((B.MIXER+0x7F,0),(B.MIXER+0x7E,0),(B.MIXER+0x84,1)):
   self.fixture(a,bytes([v]),'explicit raw output/no seek/hardware activation fixture; not native driver')
  self.fixture(B.SCRATCH-32,b'\xa5'*(B.CAPACITY+64),'output scratch guards')

 def command(self,n):
  require(self.invoke_kernel('mh_request_command',(n,),phase='request source command '+str(n))==0,'source command request failed')
  s=self.status();require(s[45]==n and s[46]==0,'source command result failed')
  self.park();return s

 def cycle(self,kick=False):
  cursor=len(self.chunks)
  if kick:self.command(1)
  else:self.park()
  raw=b''.join(self.chunks[cursor:])
  require(len(raw)<=B.RING_BYTES,'unbounded hardware fixture cycle')
  self.fixture(B.DESCRIPTOR+12,struct.pack('<I',self.word(B.DESCRIPTOR+16)),
   'explicit output consumer advances after full original actor returns; no DMA')
  return raw

 def packet(self,i):return bytes.fromhex(self.reference['packets'][i]['packet_hex'])
 def expected(self,i,reset=False):return bytes.fromhex(self.reference['packets'][i]['expected_after_reset_PCM_hex' if reset else 'expected_continuous_PCM_hex'])
 def compare(self,raw,expected):
  require(len(raw)>=len(expected) and raw[:len(expected)]==expected and raw[len(expected):]==bytes(len(raw)-len(expected)),'original output differs from HOST SBC/FIR+silence reference')

 def result(self,name,records):
  require(self.pending_codec is self.pending_ingress is None,'unfinished ingress/decoder frame')
  require(len(self.codec_entries)==len(self.codec_returns) and len(self.ingress_entries)==len(self.ingress_returns),'missing full callback/decoder return')
  row=super().result(name,[])
  row.update(records=records,stream_index=self.stream_index,Stage1_no_input_prefix=self.stage1_prefix,
   compiled_ingress_entries=self.ingress_entries,compiled_ingress_full_returns=self.ingress_returns,
   compiled_decoder_entries=self.codec_entries,compiled_decoder_full_returns=self.codec_returns,
   producer_entries=self.producer_entries,capacity_Source_decoder_overlaps_with_original_mixer_frame=self.capacity_decoder_overlaps,
   producer_terminal=self.producer(),no_compiled_fixture_or_bootstrap_packet=True,
   host_inputs_are_not_actual_phone_or_original_SEP_registration=True)
  return row

def run_case(m,name):
 m.boot();records=[]
 if name=='Stop_before_first_external_packet':
  m.command(5);records.append(m.receive(m.packet(0),False))
  require(not m.codec_entries and not m.mixer_tcb and not m.sync_entries,'pre-first Stop created native source')
  return records
 if name=='CRC_first_packet_does_not_create_anchor':
  records.append(m.receive(bytes.fromhex(m.reference['bad_later_frame_CRC_packet_hex'])))
  require([r['r0'] for r in m.codec_returns]==[0,0xFFFFFFFA] and not m.mixer_tcb and not m.producer()['owned'][8],'bad first packet published prefix/native anchor')
 records.append(m.receive(m.packet(0)))
 m.complete_first_sync_and_attach_output()
 if name=='PCM_full_capacity_wakes_actual_Source':
  for i in range(1,6):records.append(m.receive(m.packet(i)))
  before=m.producer();require(before['owned'][4]==4 and before['queue'][6]==2,'backpressure did not retain two copied compressed packets behind four PCM slots')
  cursor=len(m.chunks);m.park()
  first=b''.join(m.chunks[cursor:])
  expected=b''.join(m.expected(i) for i in range(6))
  require(first==expected[:len(first)] and 0<len(first)<len(expected),'first capacity output differs')
  self_read=m.word(B.DESCRIPTOR+16)
  m.fixture(B.DESCRIPTOR+12,struct.pack('<I',self_read),'explicit first output consumption after kernel full returns')
  second=m.cycle(True);m.compare(first+second,expected)
  require(m.producer()['queue'][6]==m.producer()['owned'][4]==0 and m.producer()['ingress'][4]>=2 and m.capacity_decoder_overlaps,'capacity never woke Source in suspended native frame')
  records.append(dict(first_PCM_hex=first.hex(),second_PCM_hex=second.hex(),HOST_expected_PCM_hex=expected.hex(),backpressure=before))
  return records
 first=m.cycle(True);expected=m.expected(0,reset=name=='CRC_first_packet_does_not_create_anchor');m.compare(first,expected)
 records.append(dict(PCM_hex=first.hex(),HOST_expected_PCM_hex=expected.hex()))
 if name=='Stop_after_active_rejects_foreign_ingress':
  m.command(5);records.append(m.receive(m.packet(1),False));require(m.producer()['started']==1,'Stop invented source retirement')
 elif name=='profile_rewrite_rejects_foreign_ingress':
  m.command(6);records.append(m.receive(m.packet(1),False))
 elif name=='two_foreign_packets_trigger_Source_events':
  records.append(m.receive(m.packet(1)));second=m.cycle();m.compare(second,m.expected(1))
  records.append(dict(PCM_hex=second.hex(),HOST_expected_PCM_hex=m.expected(1).hex()))
 return records

def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn 2.1.4 required')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v2.json').read_text());reference=json.loads(REFERENCE.read_text())
 sources={**build['source_sha256'],**build['generated_sha256'],**reference['source_sha256']}
 for p in (Path(__file__).resolve(),PARENT,B.PARENT,REFERENCE,BASE/'build-v2.json',ROOT/build['ELF'],ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py'):
  sources[rel(p)]=sha(p)
 for p,h in sources.items():require(sha(ROOT/p)==h,'changed input '+p)
 require(sources[build['ELF']]==build['ELF_sha256'] and sources['evidence/firmware-analysis/main_02bd.bin']==B.EXPECTED,'wrong native input')
 require(sha(Path(reference['reference_library']))==reference['reference_library_sha256'],'changed HOST reference library')
 dump(runtime/'inputs-at-run.json',sources);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 e=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','ingress_elf').ELF32(ROOT/build['ELF'])
 stock=B.NativeImage();cases=[];m=None
 try:
  for name,index in (('two_foreign_packets_trigger_Source_events',1),('PCM_full_capacity_wakes_actual_Source',0),('CRC_first_packet_does_not_create_anchor',1),('Stop_before_first_external_packet',2),('Stop_after_active_rejects_foreign_ingress',1),('profile_rewrite_rejects_foreign_ingress',2)):
   m=Ingress(stock,e,build,reference,index);records=run_case(m,name);row=m.result(name,records)
   p=runtime/(name+'.json');dump(p,row);cases.append(dict(name=name,path=rel(p),sha256=sha(p),passed=True))
   print(json.dumps(dict(case=name,decoder_returns=len(m.codec_returns),native_full_returns=len(m.full_returns),capacity_posts=m.producer()['ingress'][4])),flush=True);m=None
  proof=dict(all_passed=True,source_sha256=sources,cases=cases,case_count=len(cases),updated_utc=datetime.now(timezone.utc).isoformat(),
   no_compiled_compressed_fixture_or_bootstrap_packet=True,typed_foreign_ingress_and_original_Source_events=True,
   independent_FILE_review_complete=False,original_SEP_registration_remoteStart_warm_ownership_phone_App_or_speaker_verified=False,
   native_heap_exclusive_STOP_DONE_verified=False,device_io=False)
  dump(BASE/'sbc-ingress-v1-proof.json',proof);print(json.dumps(dict(all_passed=True,proof=rel(BASE/'sbc-ingress-v1-proof.json'))),flush=True)
 except BaseException as error:
  row=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),source_sha256=sources,cases_completed=cases,device_io=False)
  if m:row.update(phase=m.phase,trace=m.trace,registers=m.snapshot(),producer=m.producer(),CPU_store_journal=m.journal,
   declared_fixture_mutations=m.fixtures,full_returns=m.full_returns,ingress_entries=m.ingress_entries,ingress_returns=m.ingress_returns,
   decoder_entries=m.codec_entries,decoder_returns=m.codec_returns,sync_entries=m.sync_entries,sync_returns=m.sync_returns,
   initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
   final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex() for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC})
  dump(runtime/'terminal-failure.json',row);raise
if __name__=='__main__':main()
