#!/usr/bin/env python3
"""Native Suspend/Start + resident Source pause/resume; offline only.
No host PCM, no CPU context_restore, no device/radio/warm install.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,hashlib,traceback,gc
from datetime import datetime,timezone
import unicorn
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=load(ROOT/'staging/native-remote-source-binding/emulate_remote_binding_v3.py','native_pause_parent')
B,I=R.B,R.I
sha,rel,dump,require=R.sha,R.rel,R.dump,R.require
FIELDS=('mh_remote_paused','mh_remote_pause_epoch','mh_remote_paused_reads','mh_remote_paused_bytes','mh_remote_pause_requests','mh_remote_resume_requests')
class PauseVM(R.BindingVM):
 def __init__(self,*args):
  self.pause_records=[]
  super().__init__(*args)
 def remote_state(self):
  d=super().remote_state();p=self.remote_symbols['nsg']+160
  d.update(zip(('paused','pause_requests','resume_requests','last_playback'),struct.unpack('<4I',self.uc.mem_read(p,16))))
  return d
 def source_pause(self):return {n:self.word(self.build['symbols'][n]['value'])for n in FIELDS}
 def keepalive(self):
  s=self.build['symbols'];slots=bytes(self.uc.mem_read(s['memory_output_slots']['value'],96))
  return dict(owned=self.producer()['owned'],queue=self.producer()['queue'],slots_hex=slots.hex(),
   PCM_pages_sha256=[hashlib.sha256(bytes(self.uc.mem_read(0x07700000+i*4096,4096))).hexdigest()for i in range(4)],
   offset=self.word(s['continuous_media_control']['value']),anchor=self.word(s['continuous_anchor_instance']['value']),
   source_TCB=self.source_tcb,mixer_TCB=self.mixer_tcb,source_pause=self.source_pause(),remote=self.remote_state(),state=self.snapshot())
 def result(self,name):
  row=super().result(name);row.update(pause_records=self.pause_records,source_pause_final=self.source_pause(),
   native_Suspend_resume_same_config_supported=True,reconnect_or_STOP_DONE_or_warm_install_supported=False)
  return row
def unchanged(before,after):
 require(before['owned'][:5]==after['owned'][:5]and before['slots_hex']==after['slots_hex']and
  before['PCM_pages_sha256']==after['PCM_pages_sha256']and before['queue']==after['queue']and before['offset']==after['offset']and
  before['anchor']==after['anchor']and before['source_TCB']==after['source_TCB']and before['mixer_TCB']==after['mixer_TCB'],
  'Pause consumed/reconfigured retained FIFO/codec/anchor/task identity')
def silence_cycle(m):
 before=m.keepalive();n=len(m.codec_entries);raw=m.cycle(True);after=m.keepalive()
 unchanged(before,after);require(raw and raw==bytes(len(raw))and len(m.codec_entries)==n,'Pause did not preserve data and output silence')
 m.pause_records.append(dict(kind='paused_native_reader',before=before,after=after,actual_PCM_hex=raw.hex(),no_new_decode=True))
def music(m,indices,kick=False):
 raw=m.cycle(kick);expected=b''.join(m.expected(i)for i in indices);m.compare(raw,expected)
 m.pause_records.append(dict(kind='resumed_native_output',packet_indices=indices,actual_PCM_hex=raw.hex(),expected_PCM_hex=expected.hex(),state=m.snapshot(),source_pause=m.source_pause(),remote=m.remote_state()))
def start_initial(m,first_input=True):
 m.boot_both();m.ready();m.signal(7,b'\x04');require(m.remote_state()['admitting']==1,'initial Start')
 if first_input:m.media(m.packet(0));m.complete_first_sync_and_attach_output()
def pause(m):
 old=m.keepalive();m.signal(9,b'\x04');m.park();new=m.keepalive()
 require(m.remote_state()['paused']==1 and not m.remote_state()['admitting']and not m.remote_state()['retired']and
  m.source_pause()['mh_remote_paused']==1 and not m.remote_state()['stop_requests'],'Suspend retired or failed Source pause')
 require(old['anchor']==new['anchor']and old['source_TCB']==new['source_TCB']and old['mixer_TCB']==new['mixer_TCB'],'Pause retired native source task')
 m.pause_records.append(dict(kind='Suspend_Source_pause',before=old,after=new))
def resume_start(m):
 m.signal(7,b'\x04');require(m.remote_state()['admitting']==1 and m.remote_state()['paused']==1 and m.source_pause()['mh_remote_paused']==1,'Start before first media prematurely unpaused Source')
def run_case(m,name):
 if name=='pause_before_first_input_then_resume':
  start_initial(m,False);require(not m.mixer_tcb and not m.producer()['started'],'first input fabricated')
  pause(m);resume_start(m);m.media(m.packet(0));m.complete_first_sync_and_attach_output();music(m,[0],True)
  require(m.source_pause()['mh_remote_pause_requests']==m.source_pause()['mh_remote_resume_requests']==1,'before-input command counts')
  return
 start_initial(m)
 if name=='Pause_full_FIFO_keeps_pending_compressed_then_capacity_resumes':
  for i in range(1,5):m.media(m.packet(i))
  require(m.producer()['owned'][4]==4 and m.producer()['queue'][2]==1 and len(m.codec_returns)==8,'declared full PCM FIFO pending compressed prefix')
  pause(m);silence_cycle(m);resume_start(m);m.media(m.packet(5));music(m,list(range(6)))
  require(len(m.codec_returns)==12 and m.producer()['owned'][4]==m.producer()['queue'][2]==0 and m.producer()['ingress'][4]>=1,'real capacity event did not drain resumed compressed queue')
  return
 pause(m);silence_cycle(m)
 if name=='failed_resume_Start_keeps_FIFO_until_retry':
  before=m.keepalive();cursor=len(m.codec_entries);m.l2_fail=True;failed=m.signal(7,b'\x04');m.l2_fail=False
  require(failed['state']==4 and not failed['callbacks']and not m.remote_state()['admitting'],'failed native Start accepted')
  m.media(m.packet(1));after=m.keepalive();unchanged(before,after);require(len(m.codec_entries)==cursor,'failed Start reached decoder')
  m.pause_records.append(dict(kind='failed_Start_keeps_FIFO',before=before,after=after));silence_cycle(m)
 elif name=='profile_rewrite_while_paused_rejects_resume_data':
  m.command(6);cursor=len(m.codec_entries);old=len(m.ingress_entries);resume_start(m);m.media(m.packet(1))
  require(len(m.codec_entries)==cursor and len(m.ingress_entries)==old and m.remote_state()['paused']==1 and m.source_pause()['mh_remote_paused']==1,'source provider replacement resumed/decode')
  require(m.remote_state()['last_playback']and not m.remote_state()['inflight'],'provider replacement lacked explicit rejection')
  return
 elif name=='Disconnect_while_paused_retires_and_rejects_Start':
  cursor=len(m.codec_entries);m.native('native disconnect while paused',0x50be1c,(R.MEDIA_LCID,));m.park();m.signal(7,b'\x04');m.signal(3,R.CONFIG);m.media(m.packet(1))
  require(m.remote_state()['retired']==1 and not m.remote_state()['admitting']and m.remote_state()['stop_requests']==1 and len(m.codec_entries)==cursor,'disconnect left resumable decoder')
  return
 resume_start(m);m.media(m.packet(1));music(m,[0,1]);require(m.source_pause()['mh_remote_paused']==0,'first valid media did not resume Source')
 if name=='two_Suspend_resume_cycles_keep_same_anchor':
  pause(m);silence_cycle(m);resume_start(m);m.media(m.packet(2));music(m,[2])
  require(m.source_pause()['mh_remote_pause_requests']==m.source_pause()['mh_remote_resume_requests']==2,'repeat pause/resume counts')
 require(m.remote_state()['epoch']==1 and not m.remote_state()['retirements']and not m.remote_state()['stop_requests'],'resume forged new config/native Stop')

def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 source=json.loads((BASE/'source-build-v2.json').read_text());remote=json.loads((BASE/'remote-build-v1.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(remote['source_sha256'],**source['source_sha256'],**source['generated_sha256'],**reference['source_sha256'])
 for p in (Path(__file__),BASE/'source-build-v2.json',BASE/'remote-build-v1.json',ROOT/source['ELF'],ROOT/remote['flat'],ROOT/remote['elf'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 e=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','pause_source_elf').ELF32(ROOT/source['ELF'])
 cases=[];m=None
 try:
  for name in ('two_Suspend_resume_cycles_keep_same_anchor','failed_resume_Start_keeps_FIFO_until_retry','pause_before_first_input_then_resume',
               'Pause_full_FIFO_keeps_pending_compressed_then_capacity_resumes','profile_rewrite_while_paused_rejects_resume_data','Disconnect_while_paused_retires_and_rejects_Start'):
   m=PauseVM(R.NativeImage(),e,source,remote,reference);run_case(m,name);row=m.result(name);p=runtime/(name+'.json');dump(p,row)
   cases.append(dict(name=name,path=rel(p),sha256=sha(p),passed=True))
   print(json.dumps(dict(case=name,native_callbacks=len(m.native_callbacks),SBC_full_returns=len(m.codec_returns),native_full_returns=len(m.full_returns),Source_pause=m.source_pause())),flush=True)
   m=None;gc.collect()
  dump(BASE/'remote-pause-v1-proof.json',dict(all_passed=True,cases=cases,source_sha256=deps,native_Suspend_full_Start_first_F1_resumes_existing_Source=True,
   full_RW_RX_FILE_review_complete=False,reconnect_or_native_STOP_DONE_or_warm_App_phone_speaker_verified=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat()))
 except BaseException as error:
  failure=dict(all_passed=False,error=str(error),traceback=traceback.format_exc(),cases_completed=cases,source_sha256=deps,device_IO=False)
  if m:failure.update(phase=m.phase,trace=m.trace,state=m.snapshot(),remote=m.remote_state(),source_pause=m.source_pause(),producer=m.producer(),pause_records=m.pause_records,
   native_steps=m.native_steps,CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
   final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC},
   native_callbacks=m.native_callbacks,native_callback_returns=m.native_callback_returns,decoder_entries=m.codec_entries,decoder_returns=m.codec_returns)
  dump(runtime/'terminal-failure.json',failure);raise
if __name__=='__main__':main()
