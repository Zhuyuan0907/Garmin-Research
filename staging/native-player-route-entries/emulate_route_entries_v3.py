#!/usr/bin/env python3
"""Selected five native entry barriers with real kernel interference task.
Native pre-App/Timer/BT/hardware/heap fixtures remain explicit. No device.
"""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,struct,hashlib,traceback
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
W=load(ROOT/'staging/native-player-warm-entry/emulate_warm_entry_v1.py','route_warm_parent')
R,B,I=W.R,W.B,W.I
sha,rel,dump,require=W.sha,W.rel,W.dump,W.require
NAMES=('profile','queue','selector','prepare','allocate')
class RouteVM(W.WarmVM):
 def __init__(self,*args):
  self.route_entries=[];self.route_returns=[];self.route_pending={};self.racer_posts=[];self.racer_entries=[];self.racer_checks=[]
  super().__init__(*args)
 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  for name,p in list(self.route_pending.items()):
   if address==p['return_PC'] and self.word(B.READY_TASKS)==p['entry']['current_TCB']:
    require(uc.reg_read(UC_ARM_REG_SP)==p['entry_SP'],'route gate full return SP '+name)
    require(self.snapshot()['GP16'][4:12]==p['entry']['GP16'][4:12],'route gate callee saved '+name)
    self.route_returns.append(dict(p,returned=self.snapshot(),r0=uc.reg_read(UC_ARM_REG_R0)));del self.route_pending[name]
  name=next((n for n in NAMES if address==self.build['symbols']['rg_'+n+'_gate']['value']),None)
  if name:
   require(name not in self.route_pending,'nested same gate '+name)
   args=self.regs()
   if name=='queue':args+=list(struct.unpack('<3I',uc.mem_read(uc.reg_read(UC_ARM_REG_SP),12)))
   row=dict(name=name,entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,args=args,
    claim=self.claim(),callback=self.word(B.RECORD+0x160))
   self.route_entries.append(row);self.route_pending[name]=row
  racer=self.word(self.build['symbols']['rg_racer_tcb']['value'])
  if racer and address==B.POST and uc.reg_read(UC_ARM_REG_R0)==racer:
   self.racer_posts.append(dict(state=self.snapshot(),claim=self.claim(),raw_mutex_owners=[self.word(B.RECORD+off+8)for off in(0x1c8,0x1e0,0x58)],
    racer_tcb=racer,Source_warm_hook=self.phase=='compiled warm Source attaches existing channel'))
  if address==self.build['symbols']['rg_racer_entry']['value']:
   require(racer and self.word(B.READY_TASKS)==racer,'racer entry not original kernel actor')
   self.racer_entries.append(self.snapshot())
 def semantic(self):
  result=super().semantic();a=B.RECORD
  # Native lock links/owner/depth are bookkeeping, not audio payload.
  # V1 accidentally included the two newly held raw mutexes in this view.
  # Actual memory, execution, mappings and whole replay remain unchanged.
  result['record_prefix_hex']=(bytes(self.uc.mem_read(a,0x58))+bytes(self.uc.mem_read(a+0x70,0x1c8-0x70))).hex()
  result['record_after_mutex_hex']=bytes(self.uc.mem_read(a+0x1f8,0x208-0x1f8)).hex()
  return result
 def claim(self):
  s=self.build['symbols']
  return {n:self.word(s['rg_'+n]['value'])for n in('active','owner','epoch','racer_runs','hook_posts')}
 def install_route_gates(self):
  for p in self.build['selected_native_route_entry_barriers']:
   require(bytes(self.uc.mem_read(p['address'],p['patch_bytes'])).hex()==p['before_hex'],'original route prologue differs')
   self.patch(p['address'],bytes.fromhex(p['after_hex']),'VM-only original entry barrier '+p['name'])
   self.uc.ctl_remove_cache(p['address'],p['address']+p['patch_bytes'])
  self.initial_ordinal=self.ordinal
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if p&unicorn.UC_PROT_WRITE}
  self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}
 def check_racer(self,name,runs):
  results=list(struct.unpack('<5I',self.uc.mem_read(self.build['symbols']['rg_attack_results']['value'],20)))
  require(results==[8,8,8,8,0xffff] and self.claim()['racer_runs']==runs,'foreign racer entered protected native body')
  self.racer_checks.append(dict(name=name,results=results,state=self.snapshot(),claim=self.claim()))
 def boot_source_with_body_counter(self):
  # Kernel and original preexisting audio have already been constructed.
  # These active-other-channel bytes are explicit occupancy inputs, not proof
  # of a running navigation voice. They expose a forbidden global reset.
  for ch in (3,4):
   self.fixture(HEADS+4*ch,struct.pack('<I',0x01234000+ch*16),'explicit other-channel live head, never dereferenced')
   self.fixture(ROWS+ch*STRIDE+0x1c0,struct.pack('<H',ch),'explicit other-channel nonempty list')
  self.pre_warm=self.semantic();counts={x:self.visits[x]for x in (0x277e20,0x269f6c,self.build['symbols']['rg_stock_profile']['value']&~1,0x3ec540)}
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
 def boot(self):
  # Register an actual original TCB but leave it waiting/unposted until the
  # compiled warm hook calls native POST while Source owns all three locks.
  self.fixture(self.build['symbols']['racer_stack']['value'],b'\xa5'*8192,'explicit compiled interference stack guards')
  racer=self.invoke_kernel('rg_boot_racer',phase='compiled real interference task creation')
  require(racer and racer!=self.controller,'racer native TCB not built')
  self.boot_source_with_body_counter()
  self.check_racer('higher_priority_actor_preempts_validation_before_private_initialize',1)
  p=self.racer_posts[0]
  require(p['Source_warm_hook'] and p['state']['current_TCB']==self.source_tcb and p['claim']['active']==1 and p['claim']['owner']==self.source_tcb,'warm hook posted before actual claim')
  require(p['raw_mutex_owners']==[self.source_tcb]*3,'Source does not own all three real native mutexes at preemption')
 def challenge_playing(self):
  before=dict(callback=self.word(B.RECORD+0x160),instance=self.word(B.RECORD+0xf0),producer=self.producer(),head=self.word(B.RECORD+0x1ac),
   pool=bytes(self.uc.mem_read(B.POOL+self.word(B.RECORD+0xf0)*576,576)).hex(),mixer=self.mixer_tcb)
  require(self.invoke_kernel('rg_request_attack',phase='controller posts foreign interference during established playback')==self.word(self.build['symbols']['rg_racer_tcb']['value']),'attack request rejected')
  self.check_racer('foreign_actor_attempts_all_five_entries_after_first_playback',2)
  after=dict(callback=self.word(B.RECORD+0x160),instance=self.word(B.RECORD+0xf0),producer=self.producer(),head=self.word(B.RECORD+0x1ac),
   pool=bytes(self.uc.mem_read(B.POOL+self.word(B.RECORD+0xf0)*576,576)).hex(),mixer=self.mixer_tcb)
  require(before==after,'foreign entry mutated private live route')
  self.playing_interference=dict(before=before,after=after)
 def other_route_controls(self):
  result=self.invoke_kernel(0x277d27,(9,0,1),phase='unclaimed channel9 original profile no-op forwarding')
  require(result==0,'other profile blocked')
  instance=self.word(B.RECORD+0xf0);before=bytes(self.uc.mem_read(B.POOL+instance*576,576));pointer=B.old.RESULT+512
  self.fixture(pointer,struct.pack('<I',0xabcdef01),'explicit ordinary other-provider caller output cell')
  result=self.invoke_kernel(0x48ee69,(pointer,),phase='unclaimed output original provider allocator forwarding')
  allocated=self.word(pointer)
  require(result==0 and allocated<5 and allocated!=instance,'other provider allocation blocked or reused private slot')
  require(bytes(self.uc.mem_read(B.POOL+instance*576,576))==before,'other allocation changed private slot')
  self.other_controls=dict(profile9_return=0,provider_allocation_return=result,other_provider=allocated,private_provider=instance,private_pool_preserved=True,
   allocated_other_slot_not_released_in_this_scope=True,all_other_native_APIs_or_actual_phone_unverified=True)
 def result(self,name):
  require(not self.route_pending,'route gate not fully returned')
  row=super().result(name)
  row.update(native_route_gate_entries=self.route_entries,native_route_gate_full_returns=self.route_returns,racer_native_POSTs=self.racer_posts,
   racer_native_entry=self.racer_entries,racer_checks=self.racer_checks,playing_interference=self.playing_interference,other_route_controls=self.other_controls,
   final_route_claim=self.claim(),selected_entry_barriers_not_full_ownership_or_Stop_yield=True)
  return row
def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v3';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v1.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(build['source_sha256'],**reference['source_sha256'])
 for p in(Path(__file__),BASE/'build-v1.json',ROOT/build['ELF'],ROOT/build['combined_binary'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 elf=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','route_elf').ELF32(ROOT/build['ELF'])
 m=None
 try:
  m=RouteVM(R.NativeImage(),elf,build,reference);m.load_native();m.install_tail_gate();m.install_route_gates()
  m.boot_kernel_only();m.construct_preexisting_audio();m.guard_negative_controls();m.boot_both()
  m.ready();m.signal(7,b'\x04');m.media(m.packet(0));m.complete_first_sync_and_attach_output()
  raw=m.cycle(True);m.compare(raw,m.expected(0));m.challenge_playing();m.other_route_controls()
  m.media(m.packet(1));raw=m.cycle();m.compare(raw,m.expected(1))
  require(m.claim()['active']==1 and m.claim()['owner']==m.source_tcb and m.claim()['epoch']==1,'claim lifetime changed')
  row=m.result('five_native_entry_gates_true_kernel_racer_at_warm_attach_and_playback')
  path=runtime/'route-entry-integration.json';dump(path,row)
  proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,cases=[dict(name=row['name'],path=rel(path),sha256=sha(path),passed=True)],
   selected_native_entry_barriers=5,true_kernel_interference_runs=2,target_rejections=10,other_profile_and_provider_controls=True,
   three_native_mutexes_held_at_claim=True,no18channel_reset=True,continuous_native_media_packets=2,
   durable_all_writers_excluded_Stop_yield_full_navigation_App_phone_or_install=False,device_IO=False)
  dump(BASE/'route-entry-v3-proof.json',proof)
  print(json.dumps(dict(all_passed=True,entry_gates=5,real_racer_runs=2,target_rejections=10,gate_full_returns=len(m.route_returns),SBC_full_returns=len(m.codec_returns),native_audio_full_returns=len(m.full_returns),device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if m:fail.update(phase=m.phase,trace=m.trace,state=m.snapshot(),CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,
   route_entries=m.route_entries,route_returns=m.route_returns,route_pending=m.route_pending,racer_posts=m.racer_posts,racer_checks=m.racer_checks)
  dump(runtime/'terminal-failure.json',fail);raise
if __name__=='__main__':main()
