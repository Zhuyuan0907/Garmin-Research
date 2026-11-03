#!/usr/bin/env python3
"""Stock loader -> one DLL -> native F1/Source/SBC/mixer, in one live VM.
File, cache, BT/kernel-start/hardware/heap fixtures remain explicit. No device.
"""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib,importlib.util,traceback
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_CPSR
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
def load(p,n):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load(ROOT/'staging/native-player-remote-pause/emulate_remote_pause_v3.py','loaded_pause_parent')
R,B,I=P.R,P.B,P.I
sha,rel,dump,require=R.sha,R.rel,R.dump,R.require
IMAGE=0x02d4bb74;DESCRIPTOR=0x0304bb74;STUBS=0x02d4b994
FILE_CALLBACKS={0x1fb2f8:'close',0x1fb304:'open',0x1fb3a2:'read',0x1fb3ce:'seek',0x1fb3e4:'tell'}
HANDLE=0x12345678
class LoadedVM(P.PauseVM):
 def __init__(self,stock,elf,build,reference):
  self.remote={'symbols':{n:s['value']for n,s in build['symbols'].items()}}
  self.remote_symbols=self.remote['symbols'];self.bt_locks={};self.l2_fail=False
  self.native_callbacks=[];self.native_callback_returns=[];self.pending_native_callback=None
  self.native_sends=[];self.native_steps=[];self.bounded_imports=[]
  self.pause_records=[];self.call_slices=[]
  self.loader_active=False;self.loader_events=[];self.registration=[]
  self.loader_file=(ROOT/build['combined_binary']).read_bytes();self.position=0
  # Skip BindingVM's two synthetic image maps entirely. This ELF contains the
  # stock-address TTS prefix and the whole Source/remote player in one image.
  I.Ingress.__init__(self,stock,elf,build,reference,1)
  for a,n in ((0x03a88000,8192),(0x03a7c000,4096),(0x03a96000,8192),(R.BT_HEAP,4096),(0x0304b000,4096)):
   self.map(a,n,unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE)
   self.fixture(a,b'\xa5'*n,'declared BT services/stock-loader descriptor backing')
  self.fixture(R.CONTEXT,bytes(R.DESCRIPTORS+36-R.CONTEXT),'declared Bluetooth startup-zero core BSS')
  self.fixture(R.SDP,bytes(14*12),'declared SDP startup-zero core BSS')
  for signal,name in ((2,'music_endpoint_capabilities'),(3,'nr_configuration_gate'),(4,'music_endpoint_capabilities'),
                     (5,'nr_configuration_gate'),(7,'nr_start_suspend_gate'),(9,'nr_start_suspend_gate')):
   self.patch(R.TABLE+(signal-1)*4,struct.pack('<I',self.remote_symbols[name]),'VM-only loaded single-image signal binding')
  self.patch(0x5249f8,bytes.fromhex('0200c046'),'VM-only full signal body length')
  self.patch(0x5248fc,bytes.fromhex('0a28'),'VM-only ten-signal table bound')
  patch=build['native_descriptor_patch']
  self.patch(patch['address'],bytes.fromhex(patch['after_hex']),'VM-only loaded reply relocation')
  # Original TTS includes mutable in-file data. This explicit VM map permits
  # its bootstrap writes; physical MMU/cache/writable code is not established.
  prefix_end=build['extension_base']
  new=[]
  for a,n,p in self.zones:
   if a>=IMAGE&~4095 and a+n<=prefix_end:
    p=unicorn.UC_PROT_READ|unicorn.UC_PROT_WRITE|unicorn.UC_PROT_EXEC
    self.uc.mem_protect(a,n,p)
   new.append((a,n,p))
  self.zones=new

 def cstring(self,a):
  b=bytearray()
  for i in range(64):
   v=self.uc.mem_read(a+i,1)[0]
   if not v:return b.decode('ascii')
   b.append(v)
  raise ValueError('unterminated loader fixture string')

 def code(self,uc,address,size,data):
  super().code(uc,address,size,data)
  if not self.loader_active:return
  args=self.regs()
  if address in FILE_CALLBACKS:
   name=FILE_CALLBACKS[address];row=dict(name=name,args=args,state=self.snapshot())
   if name=='open':
    require(self.cstring(args[0])=='dllimg.bin'and self.cstring(args[1])=='rb','loader filename/mode')
    self.position=0;r=HANDLE
   elif name=='close':require(args[0]==HANDLE,'loader close handle');r=0
   elif name=='seek':
    require(args[0]==HANDLE and args[2]in(0,2),'loader seek')
    self.position=len(self.loader_file)if args[2]==2 else args[1];r=0
   elif name=='tell':r=self.position
   else:
    require(args==[IMAGE,1,len(self.loader_file),HANDLE],'loader read destination/size')
    self.fixture(IMAGE,self.loader_file,'explicit file read of whole combined DLL; not ELF injection')
    row.update(file_bytes=len(self.loader_file),file_sha256=hashlib.sha256(self.loader_file).hexdigest());r=len(self.loader_file)
   self.loader_events.append(row);self.service('explicit loader file '+name,r)
   flags=uc.reg_read(UC_ARM_REG_CPSR)
   uc.reg_write(UC_ARM_REG_CPSR,(flags|(1<<30))if not r else(flags&~(1<<30)))
  elif address==0x278964:
   left,right=self.cstring(args[0]),self.cstring(args[1]);self.loader_events.append(dict(name='strcmp',left=left,right=right))
   self.service('explicit loader string comparison',int(left!=right))
  elif address==0x221d2c:
   uc.ctl_remove_cache(IMAGE,IMAGE+self.build['combined_ram_bytes'])
   self.loader_events.append(dict(name='cache_sync',physical_CP15=False))
   self.service('explicit executable cache effect',0)
  elif address==0x2356bc:
   version,_,_,table,_,count=struct.unpack('<6I',uc.mem_read(args[1],24))
   require(count==40,'stock voice export count changed')
   self.registration.append(dict(version=version,descriptor=args[1],targets=list(struct.unpack('<40I',uc.mem_read(table,160)))))

 def capture_zones(self):return {str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones}
 def load_native(self):
  # Remove ALL previously populated ELF bytes. The loaded image must come from
  # the original reader's callback, and private state must be zeroed by CPU.
  self.fixture(IMAGE,b'\xa5'*self.build['combined_ram_bytes'],'poison entire module before stock loader file read')
  self.loader_initial=self.capture_zones();self.loader_initial_ordinal=self.ordinal
  audio_before=bytes(self.uc.mem_read(0x034e3000,0x7000));self.loader_active=True
  status=self.invoke_kernel(0x23c3c5,phase='original stock initializer reads combined DLL')
  self.loader_active=False
  require(status==11 and self.registration,'combined image native loader failed')
  sy=self.build['symbols'];require(self.word(sy['resident_passive_ready']['value'])==1,'passive bootstrap not ready')
  require(self.word(sy['mh_source_tcb']['value'])==0 and self.word(sy['mh_initialized']['value'])==0,'passive bootstrap activated Source')
  require(bytes(self.uc.mem_read(0x034e3000,0x7000))==audio_before,'passive bootstrap mutated global audio')
  require(self.word(DESCRIPTOR+24)==IMAGE and self.word(DESCRIPTOR+28)==0x300000,'stock loader location/capacity changed')
  targets=self.registration[-1]['targets'];storage=struct.unpack('<40I',self.stock.read(self.stock.runtime_to_load(0xf092c4,160),160))
  for i,target in enumerate(targets):
   require(self.word(storage[i])==STUBS+12*i and self.word(STUBS+12*i+8)==target,'original forty exports not installed')
   require(IMAGE<=target&~1<IMAGE+self.build['original_file_bytes'],'voice export redirected into player')
  api=struct.unpack('<14I',self.uc.mem_read(sy['resident_player_api']['value'],56))
  require(api[:3]==(0x52504c31,1,56),'resident API tag/version/length')
  wanted=['mh_boot_source','aas_media_ingress','mh_request_command','nsg_native_callback','resident_pcm_address','nr_configuration_gate','nr_start_suspend_gate','nr_reply_dispatch']
  require(api[6:]==tuple(sy[n]['value']for n in wanted),'resident API link resolution')
  for i,page in enumerate(self.build['pcm_pages']):
   require(self.invoke_kernel('resident_pcm_address',(i,),phase='loaded owning TU resolves PCM page')==page,'PCM page resolution')
  self.loader_final=self.capture_zones();self.loader_final_ordinal=self.ordinal
  self.loader_proof=dict(status=status,registration=self.registration,api=list(api),events=self.loader_events,
   original_forty_exports_retained=True,passive_entry_no_task_or_global_audio_reset=True,
   all_module_bytes_poisoned_before_real_reader=True,loaded_at_stock_address=True,
   physical_cache_memory_lifetime_pin_or_install=False)
  self.fixture(sy['source_stack']['value'],b'\xa5'*16384,'explicit post-bootstrap Source stack guards for offline actor fixture')
  self.initial_ordinal=self.ordinal
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&unicorn.UC_PROT_EXEC}
  self.RX_before={str(a):hashlib.sha256(bytes(self.uc.mem_read(a,n))).hexdigest()for a,n,p in self.zones if p&unicorn.UC_PROT_EXEC}

 def keepalive(self):
  s=self.build['symbols'];slots=bytes(self.uc.mem_read(s['memory_output_slots']['value'],96))
  return dict(owned=self.producer()['owned'],queue=self.producer()['queue'],slots_hex=slots.hex(),
   PCM_pages_sha256=[hashlib.sha256(bytes(self.uc.mem_read(a,4096))).hexdigest()for a in self.build['pcm_pages']],
   offset=self.word(s['continuous_media_control']['value']),anchor=self.word(s['continuous_anchor_instance']['value']),
   source_TCB=self.source_tcb,mixer_TCB=self.mixer_tcb,source_pause=self.source_pause(),remote=self.remote_state(),state=self.snapshot())
 def result(self,name):
  row=super().result(name)
  row.update(stock_loader=self.loader_proof,loader_initial_whole_zones=self.loader_initial,loader_final_whole_zones=self.loader_final,
   loader_initial_ordinal=self.loader_initial_ordinal,loader_final_ordinal=self.loader_final_ordinal,
   one_loaded_DLL_no_VM_Source_or_remote_maps=True,physical_warm_activation_menu_or_lifetime=False)
  return row
def main():
 require(unicorn.__version__=='2.1.4','isolated Unicorn2.1.4 required')
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v2.json').read_text());reference=json.loads(I.REFERENCE.read_text())
 deps=dict(build['source_sha256'],**reference['source_sha256'])
 for p in (Path(__file__),BASE/'build-v2.json',ROOT/build['ELF'],ROOT/build['combined_binary'],I.REFERENCE):deps[rel(p)]=sha(p)
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:deps[rel(Path(p))]=sha(Path(p))
 require(all(sha(ROOT/p)==h for p,h in deps.items()),'changed input')
 dump(runtime/'inputs-at-run.json',deps);(runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 elf=load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','loaded_image_elf').ELF32(ROOT/build['ELF'])
 m=None
 try:
  m=LoadedVM(R.NativeImage(),elf,build,reference);m.load_native()
  # This is a NEW loaded-image integration scope. Native activation still uses
  # the explicitly declared cold fixture, never the passive loader entry.
  m.boot_both();m.ready();P.resume_start(m);m.media(m.packet(0));m.complete_first_sync_and_attach_output()
  first=m.cycle(True);m.compare(first,m.expected(0))
  P.pause(m);P.silence_cycle(m);P.resume_start(m);m.media(m.packet(1));P.music(m,[1])
  require(m.remote_state()['epoch']==1 and m.source_pause()['mh_remote_pause_requests']==1 and m.source_pause()['mh_remote_resume_requests']==1,'loaded pause/resume changed configuration')
  require(not any(a<=0x07000000<a+n or a<=0x08e00000<a+n for a,n,p in m.zones),'old synthetic image mapping survived')
  row=m.result('stock_loaded_single_image_first_media_Suspend_resume')
  path=runtime/'loaded-integration.json';dump(path,row)
  proof=dict(all_passed=True,cases=[dict(name=row['name'],path=rel(path),sha256=sha(path),passed=True)],source_sha256=deps,
   stock_loader_original_forty_exports_retained=True,compiled_single_image_real_native_F1_Source_SBC_mixer=True,
   passive_entry_does_not_activate_or_reset_audio=True,no_old_synthetic_module_maps=True,
   separate_FILE_reconstruction_complete=False,warm_ownership_heap_lifetime_App_phone_or_device_verified=False,
   device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat())
  dump(BASE/'loaded-integration-v1-proof.json',proof)
  print(json.dumps(dict(all_passed=True,native_callbacks=len(m.native_callbacks),Source_ingress=len(m.ingress_entries),SBC_full_returns=len(m.codec_returns),music_bytes=len(first),native_full_returns=len(m.full_returns),loader=m.loader_proof['status'],device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),source_sha256=deps,device_IO=False)
  if m:fail.update(phase=m.phase,trace=m.trace,state=m.snapshot(),loader_events=m.loader_events,CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures)
  dump(runtime/'terminal-failure.json',fail);raise
if __name__=='__main__':main()
