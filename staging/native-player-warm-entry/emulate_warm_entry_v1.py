#!/usr/bin/env python3
"""Original pre-App audio constructors -> selective warm Source -> media.
Explicit kernel start/Timer-not-scheduled/boot service/radio/heap/DMA fixtures.
Original condition/profile/channel bodies execute before the App. No device.
"""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib,importlib.util,traceback
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
T=load(ROOT/'staging/native-player-reserved-tail/emulate_reserved_tail_v2.py','warm_tail_parent')
R,B,I=T.R,T.B,T.I
sha,rel,dump,require=T.sha,T.rel,T.dump,T.require
ROWS=0x034e6f08;STRIDE=0x208;HEADS=0x034e68d8
MIXERS=0x034e5378
class WarmVM(T.TailVM):
 def __init__(self,*args):
  self.boot_services=[];self.warm_observations=[];self.warm_prefix=None;self.pre_app_setup=False
  super().__init__(*args)
 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  if self.pre_app_setup and address in (0x30ee62,0x4379b0,0x2fa5a0,0x4379a0,0x4c28bc):
   self.boot_services.append(dict(PC=address,state=self.snapshot(),args=self.regs(),kind='declared external audio boot service boundary, not warm App'))
   self.service('explicit pre-App audio boot service '+hex(address),0)
 def boot_kernel_only(self):
  self.invoke_kernel(0x3008a1,(B.EXIT_LIST+4,),phase='original exit-list constructor')
  for i,(entry,top,priority)in enumerate(((B.IDLE,B.IDLE_STACK+16384,240),(B.IDLE+4,B.CONTROLLER_STACK+16384,16))):
   d=B.DESCRIPTORS+32*i;self.fixture(d,struct.pack('<5I',entry,0,top,priority<<16,0),'declared idle/controller descriptor')
   t=self.invoke_kernel(0x358bf9,(d,),phase='original controller/idle TCB construction')
   if i==0:self.idle=t
   else:self.controller=t
  for a,v in ((B.READY_TASKS,self.controller),(self.controller,self.idle),(self.idle,0)):
   self.fixture(a,struct.pack('<I',v),'explicit initial ready-list input')
  for t in (self.controller,self.idle):self.fixture(t+22,b'\x01','explicit initial ready state')
  self.invoke_kernel(0xf6e49,phase='direct original Timer descriptor constructor')
  self.invoke_kernel(0x353d3d,phase='direct original Timer TCB constructor; not posted')
  require(self.word(0xf090a0)==0x02d227c8,'Timer publication')
 def construct_preexisting_audio(self):
  self.pre_app_setup=True
  self.invoke_kernel(0x26a017,phase='original all-channel object construction before App')
  self.invoke_kernel(0x269ec1,phase='original all-channel cold profile loop before App')
  self.pre_app_setup=False
  timer=self.word(0xf090a0)
  for ch in range(18):
   a=ROWS+ch*STRIDE
   require(self.word(a+0x88)==0xd4475b83 and self.word(a+0x78)==timer,'native condition/Timer ownership not constructed')
   require(self.word(a+0x160)==0x277c6b and self.byte(a+0x15d)==0,'native original profile loop incomplete')
  require(not self.source_tcb and not self.codec_entries and not self.mixer_tcb,'pre-App fixtures activated player')
  self.preexisting_audio=dict(state=self.snapshot(),conditions=18,profile_callbacks=18,boot_services=self.boot_services,
   full_navigation_boot=False,Timer_not_scheduled=True)
 def semantic(self):
  # Native mutex linkage belongs to kernel bookkeeping. This comparison
  # covers audio state; full raw memory and original CPU stores are saved too.
  a=B.RECORD
  return dict(record_prefix_hex=bytes(self.uc.mem_read(a,0x1c8)).hex(),record_after_mutex_hex=bytes(self.uc.mem_read(a+0x1e0,STRIDE-0x1e0)).hex(),
   global_heads_hex=bytes(self.uc.mem_read(HEADS,18*4)).hex(),mixer_hex=bytes(self.uc.mem_read(B.MIXER,0x130)).hex(),
   other_records=[bytes(self.uc.mem_read(ROWS+ch*STRIDE,STRIDE)).hex()for ch in range(18)if ch!=8],
   private_initialized=self.word(self.build['symbols']['mh_initialized']['value']),callback=self.word(a+0x160))
 def denied(self,name,reason,address=None,data=None):
  previous=bytes(self.uc.mem_read(address,len(data)))if address is not None else None
  if address is not None:self.fixture(address,data,'explicit negative warm state '+name)
  before=self.semantic();cursor=len(self.journal);counts={x:self.visits[x]for x in (0x277e20,0x269f6c,0x277d26,0x3ec540)}
  result=self.invoke_kernel('mw_attach_stage1',phase='compiled warm admission rejects '+name)
  signed=result if result<0x80000000 else result-0x100000000
  require(signed==reason,'unexpected rejection '+name+':'+str(signed))
  require(self.semantic()==before,'rejected attach changed audio state '+name)
  require(all(self.visits[x]==v for x,v in counts.items()),'warm rejection reset native audio')
  self.warm_observations.append(dict(name=name,reason=signed,before=before,after=self.semantic(),CPU_store_start=cursor,CPU_store_end=len(self.journal),endpoint=self.endpoints[-1]))
  if address is not None:self.fixture(address,previous,'restore explicit negative input '+name)
 def guard_negative_controls(self):
  self.denied('condition_magic_missing',-303,B.RECORD+0x88,bytes(4))
  self.denied('profile_callback_foreign',-305,B.RECORD+0x160,struct.pack('<I',0x12345679))
  self.denied('nonempty_target_list',-306,B.RECORD+0x1c0,struct.pack('<H',1))
  self.denied('active_target_mixer',-307,B.MIXER+0x84,b'\x01')
  self.denied('prepared_target_provider',-308,B.RECORD+2,b'\x01')
  self.denied('native_target_state_not_idle',-309,0x034e9398+8,b'\x03')
  self.denied('IRQ_marker_set',-301,0x00f09094,struct.pack('<I',1))
  # Use original lock and ownership-transfer code, not a host owner token.
  self.invoke_kernel(0x3009a1,(B.RECORD+0x1c8,),phase='native profile lock acquired by controller')
  self.invoke_kernel(0x300ae5,(B.RECORD+0x1c8,self.word(0xf090a0)),phase='native profile lock transferred to Timer TCB')
  require(self.word(B.RECORD+0x1d0)==self.word(0xf090a0),'foreign owner transfer not executed')
  self.denied('native_foreign_profile_mutex_owner',-302)
  self.invoke_kernel(0x300ae5,(B.RECORD+0x1c8,self.controller),phase='native profile ownership returned to controller')
  self.invoke_kernel(0x3008b1,(B.RECORD+0x1c8,),phase='native controller releases profile lock')
 def boot(self):
  # Kernel and original preexisting audio have already been constructed.
  # These active-other-channel bytes are explicit occupancy inputs, not proof
  # of a running navigation voice. They expose a forbidden global reset.
  for ch in (3,4):
   self.fixture(HEADS+4*ch,struct.pack('<I',0x01234000+ch*16),'explicit other-channel live head, never dereferenced')
   self.fixture(ROWS+ch*STRIDE+0x1c0,struct.pack('<H',ch),'explicit other-channel nonempty list')
  self.pre_warm=self.semantic();counts={x:self.visits[x]for x in (0x277e20,0x269f6c,0x277d26,0x3ec540)}
  self.source_tcb=self.invoke_kernel('mh_boot_source',phase='compiled warm Source attaches existing channel')
  state=self.status()
  require(state[30]==state[35]==self.source_tcb and state[31]==state[32]==1 and not state[33],'warm Stage1 attach failed')
  after=self.semantic()
  require(after['other_records']==self.pre_warm['other_records']and after['global_heads_hex']==self.pre_warm['global_heads_hex'],'warm Stage1 cleared another channel')
  require(after['callback']==self.build['symbols']['mcs_queue_bridge']['value'],'warm queue bridge missing')
  require(all(self.visits[x]==v for x,v in counts.items()),'warm Source invoked a cold native initializer')
  require(not self.mixer_tcb and not self.codec_entries and not self.sync_entries,'warm attach fabricated PCM/source')
  require(self.word(self.build['symbols']['mw_attaches']['value'])==1,'one attach not observed')
  self.warm_prefix=dict(before=self.pre_warm,after=after,preexisting_audio=self.preexisting_audio,state=state,no_global_reset_or_profile_replacement=True,
   native_free_profile_mutex_acquired_and_released=True,durable_channel_ownership=False)
  self.stage1_prefix=dict(state=state,producer=self.producer(),registers=self.snapshot(),no_input_no_anchor_no_mixer=True)
  self.park()
 def result(self,name):
  row=super().result(name)
  row.update(warm_negative_controls=self.warm_observations,warm_attach_prefix=self.warm_prefix,preexisting_audio=self.preexisting_audio,
   native_live_navigation_ownership_phone_or_App=False)
  return row
def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v1.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(build['source_sha256'],**reference['source_sha256'])
 for p in (Path(__file__),BASE/'build-v1.json',ROOT/build['ELF'],ROOT/build['combined_binary'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 elf=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','warm_elf').ELF32(ROOT/build['ELF'])
 m=None
 try:
  m=WarmVM(R.NativeImage(),elf,build,reference);m.load_native();m.install_tail_gate()
  m.boot_kernel_only();m.construct_preexisting_audio();m.guard_negative_controls();m.boot_both()
  m.ready();m.signal(7,b'\x04');m.media(m.packet(0));m.complete_first_sync_and_attach_output()
  first=m.cycle(True);m.compare(first,m.expected(0))
  m.media(m.packet(1));second=m.cycle();m.compare(second,m.expected(1))
  for ch in (3,4):
   require(m.word(HEADS+4*ch)==0x01234000+ch*16 and struct.unpack('<H',m.uc.mem_read(ROWS+ch*STRIDE+0x1c0,2))[0]==ch,'media reset other active-channel inputs')
  row=m.result('native_preexisting_audio_warm_attach_eight_rejections_two_media_packets')
  path=runtime/'warm-entry-integration.json';dump(path,row)
  proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,cases=[dict(name=row['name'],path=rel(path),sha256=sha(path),passed=True)],
   original_pre_App_conditions_and_profiles=18,negative_controls=len(m.warm_observations),no_global_reset_in_warm_Source=True,
   all_other17_records_unchanged_at_attach=True,two_explicit_other_active_heads_preserved_through_playback=True,native_F1_packets=2,
   durable_native_ownership_or_actual_navigation_App_phone_hardware=False,device_IO=False)
  dump(BASE/'warm-entry-v1-proof.json',proof)
  print(json.dumps(dict(all_passed=True,negative_controls=len(m.warm_observations),native_callbacks=len(m.native_callbacks),SBC_full_returns=len(m.codec_returns),native_audio_full_returns=len(m.full_returns),device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if m:fail.update(phase=m.phase,trace=m.trace,state=m.snapshot(),CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,boot_services=m.boot_services,
   warm_negative_controls=m.warm_observations,warm_prefix=m.warm_prefix)
  dump(runtime/'terminal-failure.json',fail);raise
if __name__=='__main__':main()
