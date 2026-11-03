#!/usr/bin/env python3
"""ROOT-ONLY guest entry. Preparation agent must not import/run this module.

Runs new compiled session guard + unchanged submit/FIFO against exact original
queue/selector/factory/full-pull instructions. One explicit source actor and
the frozen mutex/opaque allocator/wake/storage fixtures remain. The long case
advances mixer read index through an explicitly labelled output-consumer
fixture after a complete native pull return; there is no hardware or mixer
worker claim. All source FIFO tickets/copies/releases are compiled code.
No native MAIN patch, cross-actor handoff/exclusivity, STOP_DONE, phone/App/UI,
native decoder worker, real-time scheduling or hardware playback proof.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[1]
FROZEN=ROOT/'staging/native-player-native-allocation/audio-session-static'
PARENT=FROZEN/'emulate_audio_session_v2.py'
s=importlib.util.spec_from_file_location('frozen_audio_session_v2_for_continuity',PARENT)
v2=importlib.util.module_from_spec(s);s.loader.exec_module(v2)
v1=v2.v1;old=v1.old
sha=v1.sha;rel=v1.rel;dump=v1.dump;require=v1.require

class ContinuousSession(v2.AudioSessionV2):
 def __init__(self,*args):
  self.productions=[];self.output_consumer_fixtures=[];self.denied_calls=[]
  self.expected_payload=b''
  super().__init__(*args)
 def leases(self):
  view=super().leases()
  view['selected_session']=view.pop('selected_ticket')
  return view
 def setup(self):
  super().setup()
  self.session=self.call('aas_session_id',phase='actual_compiled_session_identity_read')
  require(self.session==1 and self.session!=self.ticket,'session not distinct from initial ticket')
  require(self.call('aas_registration_seed',phase='actual_bootstrap_registration_audit_read')==self.ticket,
          'bootstrap registration token differs from actual initial submit')
  self.productions.append(dict(ticket=self.ticket,slot=self.ticket&3,bytes=len(self.pcm),
                              input_hex=self.pcm.hex(),actual_compiled_submit=True))
  self.expected_payload=self.pcm
 def publish_next(self,cycle):
  pcm=struct.pack('<256h',*[(i*313+cycle*1207)%60001-30000 for i in range(256)])
  self.fixture(v1.INPUT,pcm,'declared next raw PCM input only; private FIFO publication is compiled code')
  self.pcm=pcm
  ticket=self.call('aas_pcm_publish',(v1.INPUT,len(pcm)),phase='compiled_recycled_FIFO_submit_'+str(cycle))
  require(ticket>0 and ticket==(cycle+1)*4,'same-slot monotonic submit ticket was not returned')
  slots=self.build['symbols']['memory_output_slots']['value']
  require(self.word(slots)==ticket and self.word(slots+4)==2 and self.word(slots+8)==len(pcm),
          'actual submit generation/READY/length mismatch')
  require(bytes(self.uc.mem_read(0x07700000,len(pcm)))==pcm,'compiled submit did not copy new PCM')
  require(self.call('aas_session_id',phase='session_identity_after_recycled_submit')==self.session,
          'recycled FIFO ticket changed native session identity')
  self.productions.append(dict(ticket=ticket,slot=0,bytes=len(pcm),input_hex=pcm.hex(),
                              actual_compiled_submit=True))
  self.expected_payload+=pcm
  return ticket
 def assert_retained_binding(self):
  status=self.status();index=self.last_selected['index'];p=self.last_selected['provider']
  require(status[0]==self.session and status[1]==index and status[10]==self.ticket and status[11]==1,
          'long-lived session/legacy registration seed/installed changed')
  require(self.word(v1.RECORD+0xf0)==index and
          bytes(self.uc.mem_read(p+12,1))==b'\x01' and bytes(self.uc.mem_read(p+28,1))==b'\x01',
          'original selected native provider was released during FIFO reuse')
  require(self.word(v1.RECORD+0x108)==self.build['symbols']['memory_output_read']['value'] and
          self.word(p+16)==self.word(self.build['symbols']['aas_guard']['value']+12),
          'actual native reader/anchor was replaced')
  require(len(self.lower_calls)==len(self.lower_returns)==1,'continuity re-registered a finite native source')
  require(self.visits[0x437764]==1 and self.visits[0x48ee68]==1,
          'continuity allocated/rebuilt a provider for each FIFO buffer')
  return status
 def consume_output_fixture(self):
  # Only output mixer ring ownership is synthetic; source FIFO release is
  # actual compiled code. This fixture is explicit in the joint ordinal log.
  require(not self.pending_full and self.leases()['borrow']==0,'output drain before full return')
  before=self.word(v1.DESCRIPTOR+12);after=self.word(v1.DESCRIPTOR+16)
  self.fixture(v1.DESCRIPTOR+12,struct.pack('<I',after),
               'explicit test-only output mixer consumer advances read pointer AFTER full original return; no DMA/worker')
  self.output_consumer_fixtures.append(dict(before=before,after=after,ordinal=self.ordinal,
                                           after_full_native_return=True,hardware=False))
 def finish(self,name,pulls):
  status=self.status()
  require(status[2]==status[6]==status[7]==status[8]==status[12]==0,
          'live borrow/lease/invented native completion mismatch')
  require(status[3]==status[4]==len(pulls),'complete return/pull count mismatch')
  require(not any(self.mutex.values()) and self.pending_full is None,'retained fixture/native frame')
  for h in self.handles.values():
   a,n=h['pointer'],h['size']
   require(bytes(self.uc.mem_read(a-32,32))==b'\xa5'*32 and
           bytes(self.uc.mem_read(a+n,32))==b'\xa5'*32,'opaque backing guards changed')
  for a,n in ((v1.DESCRIPTOR,36),(v1.BUFFER,v1.RING_BYTES),(v1.SCRATCH,v1.CAPACITY),(v1.INPUT,len(self.pcm))):
   require(bytes(self.uc.mem_read(a-32,32))==b'\xa5'*32 and
           bytes(self.uc.mem_read(a+n,32))==b'\xa5'*32,'caller/mixer/reader guards changed')
  require(bytes(self.uc.mem_read(v1.INPUT,len(self.pcm)))==self.pcm,'raw input changed')
  current=bytes(self.uc.mem_read(v1.CHANNELS,18*v1.STRIDE))
  for i in range(18):
   if i!=8:require(current[i*v1.STRIDE:(i+1)*v1.STRIDE]==self.profile_baseline[i*v1.STRIDE:(i+1)*v1.STRIDE],
                   'neighboring native channel changed')
  for a,digest in self.RX_before.items():
   n=next(n for base,n,p in self.zones if str(base)==a)
   require(v1.hashlib.sha256(bytes(self.uc.mem_read(int(a),n))).hexdigest()==digest,'RX bytes changed')
  require(self.word(0xF09090)==old.ACTOR and self.word(0xF09094)==0,'actor/normal fixture changed')
  h=[h for h in self.handles.values()if h.get('selector_copy')]
  require(len(h)==1 and h[0].get('released'),'selector temporary handle not released')
  require([int(r['entry'],16)for r in self.selector_opaque_fixture_calls]==
          [0x38853c,0x388804,0x388b22,0x388804],'selector temporary history changed')
  before=bytes(self.uc.mem_read(old.RESULT+256,128))
  r=self.call('mcs_native_ownership_snapshot',(0,1,0x1352,old.RESULT+256),phase='uncertified_witness')
  require(r==(-200&0xffffffff)and bytes(self.uc.mem_read(old.RESULT+256,128))==before,
          'native witness fabricated/mutated')
  return dict(name=name,passed=True,session=self.session,bootstrap_registration_ticket=self.ticket,
   productions=self.productions,pulls=pulls,status=status,selected_native_provider=self.last_selected,
   original_queue_seven_args=self.lower_calls,original_queue_returns=self.lower_returns,
   full_native_pull_returns=self.full_returns,reader_live_leases=self.readers,native_and_compiled_flow=self.flow,
   native_visits={hex(k):v for k,v in self.visits.items()},instructions=self.instructions,
   explicit_output_consumer_fixtures=self.output_consumer_fixtures,denied_calls=self.denied_calls,
   selector_opaque_fixture_calls=self.selector_opaque_fixture_calls,
   replay=self.replay(),initial_ordinal=self.initial_ordinal,initial_whole_RW_zones=self.initial,
   final_whole_RW_zones={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC},
   zones=[dict(start=a,size=n,protection=p)for a,n,p in self.zones],
   CPU_store_journal=self.journal,declared_fixture_mutations=self.fixtures,
   lower_opaque_mutex_fixtures=self.native_boundaries,additional_declared_service_fixtures=self.declared_services,
   unchanged_RX_sha256=self.RX_before,native_ownership_snapshot=-200,native_STOP_DONE=False,
   actual_native_mixer_actor_redirected=False,source_owner_to_mixer_handoff_verified=False,
   native_heap_mutex_scheduler_hardware_phone_UI_or_App_verified=False,complete_player_verified=False,device_io=False)

def run_case(m,name):
 m.setup();pulls=[]
 if name=='twelve_compiled_same_slot_generations_one_native_session':
  for cycle in range(12):
   if cycle:m.publish_next(cycle)
   current=[]
   for _ in range(2):
    p=m.pull();current.append(p);pulls.append(p);m.consume_output_fixture()
   require(bytes.fromhex(''.join(p['PCM_hex']for p in current))==m.pcm,'recycled FIFO PCM mismatch')
   status=m.assert_retained_binding()
   require(status[15]==0 and status[16]==4*(cycle+1) and status[19]==0,
           'actual FIFO release/generation/count mismatch')
   require(status[20]==status[21]==cycle+1 and status[25]==512*(cycle+1) and status[27]==cycle+1,
           'compiled continuous submit/read/release counters mismatch')
  require(bytes.fromhex(''.join(p['PCM_hex']for p in pulls))==m.expected_payload,'whole repeated PCM stream differs')
 elif name=='underrun_silence_then_recycled_FIFO_resumes_same_session':
  pulls.extend((m.pull(),m.pull()));m.assert_retained_binding()
  p=m.pull();pulls.append(p)
  require(bytes.fromhex(p['PCM_hex'])==bytes(v1.CAPACITY),'temporary underrun not exact silence')
  m.publish_next(1);pulls.extend((m.pull(),m.pull()));status=m.assert_retained_binding()
  require(bytes.fromhex(''.join(p['PCM_hex']for p in pulls[:2]+pulls[3:]))==m.expected_payload,
          'resumed stream payload mismatch')
  require(status[20]==status[21]==2 and status[25]==1024 and status[26]==256 and status[27]==2,
          'underrun/second generation counters mismatch')
 elif name=='Stop_after_reuse_denies_new_pull_and_submit_keeps_anchor_pinned':
  pulls.extend((m.pull(),m.pull()));m.publish_next(1);pulls.append(m.pull());m.assert_retained_binding()
  require(m.call('aas_stop',phase='compiled_local_Stop_closes_controller_and_queue')==1,'Stop failed')
  returns=len(m.full_returns);before=bytes(m.uc.mem_read(v1.BUFFER,v1.RING_BYTES))
  slots=m.build['symbols']['memory_output_slots']['value'];before_slots=bytes(m.uc.mem_read(slots,96))
  for entry,args in (('aas_pull',(8,)),('aas_pcm_publish',(v1.INPUT,len(m.pcm))),
                     ('memory_output_release_session',(m.session,))):
   r=m.call(entry,args,phase='Stop_rejection_'+entry)
   require(r==(0 if entry=='aas_pull'else(-201&0xffffffff)),'Stop/release failed closed result differs')
   m.denied_calls.append(dict(entry=entry,result=r))
  require(len(m.full_returns)==returns and bytes(m.uc.mem_read(v1.BUFFER,v1.RING_BYTES))==before and
          bytes(m.uc.mem_read(slots,96))==before_slots,'denied call entered native body/published/freed data')
  status=m.assert_retained_binding()
  require(status[5]==1 and status[9]==0 and status[28]==0 and status[8]==0,
          'Stop admission/queue or fabricated STOP_DONE differs')
 else:raise ValueError('unknown case')
 return m.finish(name,pulls)

def main():
 require(unicorn.__version__=='2.1.4','requires isolated Unicorn2.1.4')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v1.json').read_text())
 source={rel(Path(__file__).resolve()):sha(Path(__file__).resolve()),rel(PARENT):sha(PARENT),
  rel(v2.V1):sha(v2.V1),rel(v1.OLD):sha(v1.OLD),
  'scripts/analyze_native_sections.py':sha(ROOT/'scripts/analyze_native_sections.py'),
  'evidence/firmware-analysis/main_02bd.bin':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 require(source['evidence/firmware-analysis/main_02bd.bin']==v1.EXPECTED,'wrong MAIN')
 source.update(build['source_sha256']);source.update(build['generated_sha256'])
 for p in (BASE/'build-v1.json',ROOT/build['ELF'],FROZEN/'audio-session-emulation-v2-proof.json',
           BASE/'continuous-session-host-controls-v3.json'):
  source[rel(p)]=sha(p)
 for p,h in source.items():require(sha(ROOT/p)==h,'input changed '+p)
 (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes());dump(runtime/'inputs-at-run.json',source)
 mod=v1.load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py',
             'new_continuous_session_elf')
 elf=mod.ELF32(ROOT/build['ELF']);stock=v1.NativeImage();cases=[];m=None
 try:
  for name in ('twelve_compiled_same_slot_generations_one_native_session',
               'underrun_silence_then_recycled_FIFO_resumes_same_session',
               'Stop_after_reuse_denies_new_pull_and_submit_keeps_anchor_pinned'):
   m=ContinuousSession(stock,elf,build);row=run_case(m,name)
   path=runtime/(name+'.json');dump(path,row)
   cases.append(dict(name=name,path=rel(path),sha256=sha(path),passed=True));print(name+' PASS',flush=True)
   m.uc=None;m=None
  proof=dict(all_passed=True,source_sha256=source,cases=cases,case_count=len(cases),
   updated_utc=datetime.now(timezone.utc).isoformat(),
   actual_compiled_repeated_FIFO_submit_read_release=True,scoped_session_independent_of_recycled_ticket=True,
   full_original_pull_leases_retained_to_complete_return=True,Stop_denies_new_submit_and_fullpull=True,
   long_case_output_consumer_is_explicit_host_fixture=True,raw_PCM_input_is_explicit_host_fixture=True,
   source_owner_to_native_mixer_handoff_or_exclusivity_or_STOP_DONE_or_hardware_or_phone_UI_App_verified=False,
   complete_player_verified=False,original_MAIN_unchanged=True,device_io=False)
  dump(BASE/'continuous-session-emulation-v1-proof.json',proof)
  print(json.dumps(dict(all_passed=True,proof=rel(BASE/'continuous-session-emulation-v1-proof.json'))))
 except BaseException as e:
  row=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),cases_completed=cases,
           source_sha256=source,guest_success=False,device_io=False)
  if m:row.update(phase=m.phase,trace=m.trace,flow=m.flow,readers=m.readers,full_returns=m.full_returns,
   registers={n:hex(m.uc.reg_read(r))for n,r in [('pc',UC_ARM_REG_PC),('lr',UC_ARM_REG_LR),('sp',UC_ARM_REG_SP)]},
   CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,
   lower_fixture_calls=m.native_boundaries,additional_declared_service_fixtures=m.declared_services,
   selector_opaque_fixture_calls=m.selector_opaque_fixture_calls,
   initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
   final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC})
  dump(runtime/'terminal-failure.json',row);raise
if __name__=='__main__':main()
