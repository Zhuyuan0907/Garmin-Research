#!/usr/bin/env python3
"""Protected native DLL tail survives3 stock voice loads while music continues.
Also reject oversized file and header RAM through original reader, offline.
"""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib,importlib.util,traceback
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
L=load(ROOT/'staging/native-player-loaded-single-image/emulate_loaded_image_v3.py','tail_loaded_parent')
P,R,B,I=L.P,L.R,L.B,L.I
sha,rel,dump,require=L.sha,L.rel,L.dump,L.require
H=load(BASE/'tail_handoff_result_v1.py','tail_result_verifier')
for n in ('MIXER','old','CONTROLLER_STACK','IDLE_STACK','unicorn','hashlib','require'):setattr(H,n,getattr(B,n))
B.Handoff.result=H.tail_handoff_result
class TailVM(L.LoadedVM):
 def __init__(self,*args):
  self.gate_entries=[];self.gate_returns=[];self.pending_gate=None
  self.reader_descriptors=[];self.reloads=[];self.capacity_perturbation=False;self.loader_return_frames=[]
  super().__init__(*args)
  original_end=(L.IMAGE+self.build['original_file_bytes']+4095)&~4095
  if original_end<self.build['protected_tail_start']:
   self.map(original_end,self.build['protected_tail_start']-original_end,
    unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE|unicorn.UC_PROT_EXEC)
  # Coalesce only contiguous identically protected bookkeeping spans. UC
  # mappings/protection and execution are unchanged; file copies can span the
  # original TTS section and its padding inside one replay span.
  a=L.IMAGE&~4095;end=self.build['protected_tail_start'];flags=7
  parts=[(z,n,p)for z,n,p in self.zones if a<=z<end]
  require(sum(n for z,n,p in parts)==end-a and all(p==flags for z,n,p in parts),'mutable prefix mapping gap/protection')
  self.zones=[(z,n,p)for z,n,p in self.zones if not a<=z<end]+[(a,end-a,flags)]
 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  if self.pending_gate and address==self.pending_gate['return_PC']:
   require(uc.reg_read(UC_ARM_REG_SP)==self.pending_gate['entry_SP'],'gate full-return stack changed')
   self.gate_returns.append(dict(self.pending_gate,returned=self.snapshot(),r0=uc.reg_read(B.GP[0])));self.pending_gate=None
  if address==self.remote_symbols['resident_loader_read_gate']:
   require(self.loader_active and self.pending_gate is None,'reader gate caller contract')
   args=self.regs();require(args[0]==L.DESCRIPTOR,'gate descriptor not original shared loader')
   row=dict(entry=self.snapshot(),entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,
    args=args,original_descriptor_hex=bytes(uc.mem_read(args[0],52)).hex())
   self.gate_entries.append(row);self.pending_gate=row
  if address==(self.remote_symbols['stock_reader_tail_relocated']&~1):
   require(self.pending_gate,'native reader has no compiled gate')
   args=self.regs();words=list(struct.unpack('<13I',uc.mem_read(args[0],52)))
   original=list(struct.unpack('<13I',bytes.fromhex(self.pending_gate['original_descriptor_hex'])))
   require(args[0]!=L.DESCRIPTOR and self.pending_gate['entry_SP']-128<=args[0]<self.pending_gate['entry_SP'],'descriptor not caller-local stack')
   require(words[:7]==original[:7]and words[8:]==original[8:]and words[7]==self.build['protected_reader_limit'],'local descriptor copy differs')
   self.reader_descriptors.append(dict(state=self.snapshot(),pointer=args[0],words=words,shared_capacity=self.word(L.DESCRIPTOR+28)))
  if self.capacity_perturbation and self.loader_active and address==0x3b32c0:
   # Explicit alias perturbation, not a simulated full second thread. The
   # real reader must still use its private descriptor in R5.
   self.fixture(L.DESCRIPTOR+28,struct.pack('<I',0x300000),'explicit shared-descriptor capacity rewrite during reader')
   require(self.word(self.uc.reg_read(B.GP[5])+28)==self.build['protected_reader_limit'],'shared rewrite raised private limit')
 def install_tail_gate(self):
  patch=self.build['reader_patch'];self.patch(patch['address'],bytes.fromhex(patch['after_hex']),'VM-only post-load reader protection; physical installer unimplemented')
  self.uc.ctl_remove_cache(patch['address'],patch['address']+8)
  self.initial_ordinal=self.ordinal
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if p&unicorn.UC_PROT_WRITE}
  self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}
 def tail_bytes(self):
  a=self.build['protected_tail_start'];n=L.IMAGE+self.build['combined_ram_bytes']-a
  return bytes(self.uc.mem_read(a,n))
 def reload(self,name,data,expected,perturb=False):
  before=self.tail_bytes();producer=self.producer();source=self.source_tcb;mix=self.mixer_tcb
  original_file=self.loader_file;self.loader_file=data;self.loader_active=True;self.capacity_perturbation=perturb
  start=len(self.loader_events);g=len(self.gate_entries);registered=len(self.registration)
  status=self.invoke_kernel(0x23c3c5,phase='native guarded voice load '+name)
  self.loader_active=False;self.capacity_perturbation=False;self.loader_file=original_file
  require(status==expected and self.pending_gate is None and len(self.gate_entries)==g+1,'guarded INIT return')
  require(self.tail_bytes()==before and self.producer()==producer and self.source_tcb==source and self.mixer_tcb==mix,'voice reload changed protected player/codec/FIFO/task state')
  events=self.loader_events[start:];reads=[e for e in events if e['name']=='read']
  if expected==4:require(not reads and len(self.registration)==registered,'oversize file copied/executed')
  elif expected==9:require(len(reads)==1 and len(self.registration)==registered,'oversize RAM reached module executor')
  else:require(len(reads)==1 and len(self.registration)>registered,'known voice did not execute/register')
  row=dict(name=name,status=status,before_tail_sha256=hashlib.sha256(before).hexdigest(),after_tail_sha256=hashlib.sha256(self.tail_bytes()).hexdigest(),
   native_events=events,producer_before=producer,producer_after=self.producer(),gate=self.gate_entries[-1],gate_return=self.gate_returns[-1],
   original_voice_registration=self.registration[registered:],shared_capacity_perturbation=perturb,
   no_file_copy=not reads,no_new_voice_execution=len(self.registration)==registered)
  self.reloads.append(row)
 def result(self,name):
  row=super().result(name)
  row.update(guarded_native_voice_reloads=self.reloads,reader_gate_entries=self.gate_entries,reader_gate_full_returns=self.gate_returns,
   caller_private_reader_descriptors=self.reader_descriptors,protected_tail_start=self.build['protected_tail_start'],protected_reader_limit=self.build['protected_reader_limit'],
   protected_tail_final_sha256=hashlib.sha256(self.tail_bytes()).hexdigest(),mutable_executable_prefix_zones=[dict(start=a,size=n)for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC and p&unicorn.UC_PROT_WRITE],
   unchanged_RX_claim_excludes_mutable_TTS_prefix=True,permanent_boot_reservation_not_unload_or_whole_selector_concurrency=True)
  return row
def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v2';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v2.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(build['source_sha256'],**reference['source_sha256'])
 for p in (Path(__file__),BASE/'tail_handoff_result_v1.py',BASE/'build-v2.json',ROOT/build['ELF'],ROOT/build['combined_binary'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 elf=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','tail_elf').ELF32(ROOT/build['ELF'])
 m=None
 try:
  m=TailVM(R.NativeImage(),elf,build,reference);m.load_native();dump(runtime/'passive-loader-prefix.json',m.loader_proof)
  m.install_tail_gate();m.boot_both();m.ready();m.signal(7,b'\x04');m.media(m.packet(0));m.complete_first_sync_and_attach_output()
  raw=m.cycle(True);m.compare(raw,m.expected(0));outputs=[dict(packet=0,PCM_hex=raw.hex(),expected_prefix_hex=m.expected(0).hex())]
  for i,stem in enumerate(('Chinese_GB_MeiLing','English_American_Jill','Chinese_Big5_MeiLing'),1):
   p=ROOT/'evidence/firmware-analysis/voice-modules'/stem/'DLLIMG.BIN'
   m.reload(stem,p.read_bytes(),11)
   m.media(m.packet(i));raw=m.cycle();m.compare(raw,m.expected(i));outputs.append(dict(packet=i,PCM_hex=raw.hex(),expected_prefix_hex=m.expected(i).hex()))
   print(json.dumps(dict(stock_voice=stem,status=11,protected_player_preserved=True,packet=i)),flush=True)
  m.reload('player_image_reload_exceeds_protected_file_limit',(ROOT/build['combined_binary']).read_bytes(),4,True)
  m.media(m.packet(4));raw=m.cycle();m.compare(raw,m.expected(4));outputs.append(dict(packet=4,PCM_hex=raw.hex(),expected_prefix_hex=m.expected(4).hex()))
  synthetic=struct.pack('<4I',0xea000000,build['protected_reader_limit']+4,16,0xe12fff1e)
  m.reload('short_file_declared_RAM_overlaps_protected_tail',synthetic,9,True)
  m.media(m.packet(5));raw=m.cycle();m.compare(raw,m.expected(5));outputs.append(dict(packet=5,PCM_hex=raw.hex(),expected_prefix_hex=m.expected(5).hex()))
  require(len(m.gate_entries)==len(m.gate_returns)==5 and len(m.codec_returns)==12,'six-packet/five-reader full return')
  require(m.remote_state()['epoch']==1 and m.remote_state()['accepted_media']==6,'voice reload reset remote stream')
  row=m.result('reserved_tail_three_original_voices_two_rejections_continuous_media');row['continuous_output_records']=outputs
  path=runtime/'reserved-tail-integration.json';dump(path,row)
  proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,
   cases=[dict(name=row['name'],path=rel(path),sha256=sha(path),passed=True)],three_original_native_DLL_reloads_preserve_current_player=True,
   oversize_file_rejected_before_copy=True,oversize_RAM_rejected_before_execute=True,shared_capacity_rewrite_does_not_raise_private_limit=True,
   continuous_original_F1_Source_SBC_mixer_packets=6,guarded_native_reader_full_returns=5,
   full_selector_concurrency_actual_patch_warm_ownership_or_phone_or_App_not_verified=True,
   full_saved_FILE_reconstruction_complete=False,device_IO=False)
  dump(BASE/'reserved-tail-integration-v2-proof.json',proof)
  print(json.dumps(dict(all_passed=True,voice_successes=3,reader_rejections=2,guard_full_returns=5,SBC_full_returns=len(m.codec_returns),native_audio_full_returns=len(m.full_returns),device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if m:fail.update(phase=m.phase,trace=m.trace,state=m.snapshot(),reloads=m.reloads,gate_entries=m.gate_entries,gate_returns=m.gate_returns,reader_descriptors=m.reader_descriptors,
   loader_events=m.loader_events,CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,
   initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,zones=[dict(start=a,size=n,protection=p)for a,n,p in m.zones],
   final_whole_zones=m.capture_zones(),loader_proof=getattr(m,'loader_proof',None),codec_returns=m.codec_returns,full_returns=m.full_returns)
  dump(runtime/'terminal-failure.json',fail);raise
if __name__=='__main__':main()
