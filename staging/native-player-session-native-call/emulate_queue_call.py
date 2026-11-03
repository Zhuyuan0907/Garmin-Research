#!/usr/bin/env python3
"""Original270458 -> compiled v2 guard -> original277C6A, bounded offline.
Single actor RAM, local tickets, opaque handles, mutexes and wake are declared
fixtures. Original IRQ/current actor and queue/copy instructions run unchanged.
No physical hardware, code redirection in MAIN, App or ownership certificate.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,importlib.util,json,struct,traceback
from datetime import datetime,timezone
from collections import Counter
ROOT=Path(__file__).resolve().parents[2]
BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *
CODE_START=0x50000;CODE_END=0xC00000
CHANNELS=0x34e6f08;STRIDE=0x208;CHANNEL=8;RECORD=CHANNELS+CHANNEL*STRIDE
HEAP=0x09700000;STACK_START=0x08800000;STACK=0x08810000-0x100
ACTOR=0x08820000;PARAMS=0x08a00020;ANCHOR=0x08b00020
RESULT=0x08c00020;RETURN=0x08d00000
def sha(p):
 h=hashlib.sha256()
 with p.open('rb')as f:
  for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
 return h.hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def require(x,reason):
 if not x:raise ValueError(reason)
class QueueCall:
 def __init__(self,stock,elf,build):
  self.stock=stock;self.elf=elf;self.build=build
  self.uc=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.visits=Counter();self.instructions=0;self.trace=[];self.journal=[]
  self.fixtures=[];self.native_boundaries=[];self.mutex=Counter();self.handles={}
  self.next_handle=1;self.fail_allocation=False;self.queue_return=None
  self.pending_lower=None;self.lower_returns=[];self.last_instruction=None
  self.high_calls=[];self.blx_calls=[];self.bridge_calls=[];self.lower_calls=[]
  self.active_call=None;self.phase='fixture_setup';self.zones=[]
  self.map(CODE_START,CODE_END-CODE_START,UC_PROT_READ|UC_PROT_EXEC)
  self.uc.mem_write(CODE_START,stock.read(CODE_START,CODE_END-CODE_START))
  self.map(0xF00000,0x73000,UC_PROT_READ|UC_PROT_WRITE)
  self.uc.mem_write(0xF00000,stock.read(0xCB1980,0x7224c))
  for start,size in ((0x34e5000,0x5000),(HEAP,0x10000),(STACK_START,0x10000),
      (ACTOR,0x1000),(PARAMS&~4095,4096),(ANCHOR&~4095,4096),
      (RESULT&~4095,4096),(RETURN,4096)):
   self.map(start,size,UC_PROT_READ|UC_PROT_WRITE)
  self.uc.mem_protect(RETURN,4096,UC_PROT_READ|UC_PROT_EXEC)
  for s in elf.sections:
   if not s['flags']&2 or not s['size']:continue
   start=s['address']&~4095;size=((s['address']+s['size']+4095)&~4095)-start
   flags=UC_PROT_READ|(UC_PROT_EXEC if s['flags']&4 else UC_PROT_WRITE)
   self.map(start,size,flags)
   if s['type']!=8:self.uc.mem_write(s['address'],elf.data(s))
  for i in range(18):self.fixture(CHANNELS+i*STRIDE,b'\x12','declared inactive channel marker')
  self.fixture(RECORD,bytes([CHANNEL]),'declared channel8 record identity')
  self.fixture(RECORD+0x15d,b'\x02','declared pre-profile input')
  self.fixture(RECORD+0x1f8,bytes([CHANNEL]),'declared queue source identity')
  self.fixture(0xF09090,struct.pack('<I',ACTOR),'declared current TCB, not native task bootstrap')
  self.fixture(0xF09094,bytes(4),'declared no interrupt marker')
  p=bytearray(0x20c);struct.pack_into('<5I',p,0,1,16000,16,ANCHOR,2)
  self.fixture(PARAMS-32,b'\xa5'*(0x20c+64),'parameter guards')
  self.fixture(PARAMS,p,'local exact owned request fingerprint')
  self.fixture(ANCHOR-32,b'\xa5'*68,'local resident source anchor, no native allocation')
  self.initial={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,_ in self.zones if not _&UC_PROT_EXEC}
  self.code_before=hashlib.sha256(bytes(self.uc.mem_read(CODE_START,CODE_END-CODE_START))).hexdigest()
  self.uc.reg_write(UC_ARM_REG_CPSR,0x13)
  self.uc.hook_add(UC_HOOK_CODE,self.code)
  self.uc.hook_add(UC_HOOK_MEM_WRITE,self.store)
 def map(self,a,n,p):
  self.uc.mem_map(a,n,p);self.zones.append((a,n,p))
 def word(self,a):return struct.unpack('<I',self.uc.mem_read(a,4))[0]
 def fixture(self,a,b,why):
  before=bytes(self.uc.mem_read(a,len(b)))
  self.uc.mem_write(a,bytes(b));self.fixtures.append(dict(address=hex(a),before_hex=before.hex(),after_hex=bytes(b).hex(),reason=why,phase=self.phase))
 def regs(self):return [self.uc.reg_read(r)for r in (UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3)]
 def args(self):return self.regs()+list(struct.unpack('<3I',self.uc.mem_read(self.uc.reg_read(UC_ARM_REG_SP),12)))
 def boundary_return(self,value):
  self.uc.reg_write(UC_ARM_REG_R0,value);self.uc.reg_write(UC_ARM_REG_PC,self.uc.reg_read(UC_ARM_REG_LR))
 def code(self,uc,a,n,data):
  self.instructions+=1;self.visits[a]+=1
  self.last_instruction=(a,n,bool(uc.reg_read(UC_ARM_REG_CPSR)&32),bytes(uc.mem_read(a,n)).hex())
  self.trace.append(hex(a));self.trace=self.trace[-32:]
  if a==RETURN:uc.emu_stop();return
  if self.pending_lower and a==self.pending_lower['return_PC']:
   require(uc.reg_read(UC_ARM_REG_SP)==self.pending_lower['entry_SP'],'original lower writer stack did not return')
   self.lower_returns.append(dict(self.pending_lower,actual_r0=uc.reg_read(UC_ARM_REG_R0),actual_SP=uc.reg_read(UC_ARM_REG_SP)))
   self.pending_lower=None
  if a==0x270458:self.high_calls.append(self.args())
  if a==0x2704b2:self.blx_calls.append(dict(PC=hex(a),args=self.args(),target=uc.reg_read(UC_ARM_REG_R6),SP=uc.reg_read(UC_ARM_REG_SP),LR=uc.reg_read(UC_ARM_REG_LR)))
  if a==self.build['symbols']['mcs_queue_bridge']['value']:self.bridge_calls.append(self.args())
  if a==0x277c6a:
   self.lower_calls.append(self.args());self.pending_lower=dict(entry_SP=uc.reg_read(UC_ARM_REG_SP),return_PC=uc.reg_read(UC_ARM_REG_LR)&~1,entry_LR=uc.reg_read(UC_ARM_REG_LR),args=self.args())
  if a not in (0x3009a0,0x3008b0,0x38853c,0x388804,0x388b22):return
  args=self.regs();event=dict(entry=hex(a),args=args,LR=uc.reg_read(UC_ARM_REG_LR),scope='declared lower mutex/opaque handle fixture',phase=self.phase)
  if a==0x3009a0:self.mutex[args[0]]+=1;self.boundary_return(0)
  elif a==0x3008b0:
   require(self.mutex[args[0]]>0,'fixture mutex release without acquire');self.mutex[args[0]]-=1;self.boundary_return(0)
  elif a==0x38853c:
   require(0<args[0]<4000 and args[1]==3,'unexpected opaque allocation shape')
   handle=0
   if self.fail_allocation:self.fail_allocation=False
   else:
    handle=0xd0000000+self.next_handle;pointer=HEAP+(self.next_handle-1)*4096+32;self.next_handle+=1
    self.handles[handle]=dict(pointer=pointer,size=args[0],queries=0)
    self.fixture(pointer-32,b'\xa5'*(args[0]+64),'declared opaque allocation backing and guards')
   self.fixture(args[2],struct.pack('<I',handle),'declared original lower allocator output')
   event['handle']=handle;self.boundary_return(0)
  elif a==0x388804:
   h=self.handles[args[0]];h['queries']+=1;self.boundary_return(h['pointer'])
  elif a==0x388b22:
   require(args[0]in self.handles,'unknown opaque query completion')
   event['original_BX_LR_executed']=True
  self.native_boundaries.append(event)
 def store(self,uc,access,a,n,v,data):
  require(self.last_instruction is not None,'store without CPU instruction')
  pc,ins_size,thumb,opcode=self.last_instruction
  self.journal.append(dict(PC=hex(pc),Thumb=thumb,opcode_hex=opcode,address=hex(a),size=n,value=v,before_hex=bytes(uc.mem_read(a,n)).hex(),phase=self.phase))
 def call(self,entry,args=(),stack_args=(),phase=None):
  self.phase=phase or str(entry);self.active_call=self.phase
  if isinstance(entry,str):entry=self.build['symbols'][entry]['value']
  # Ordinary bounded caller inputs; not context restore during execution.
  self.uc.reg_write(UC_ARM_REG_CPSR,0x13);self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN)
  for reg,value in zip((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3),args):self.uc.reg_write(reg,value)
  if stack_args:self.fixture(STACK,struct.pack('<'+'I'*len(stack_args),*stack_args),'ordinary call stack arguments')
  self.uc.emu_start(entry,RETURN,count=200000,timeout=10000000)
  require(self.uc.reg_read(UC_ARM_REG_PC)==RETURN,'call did not return: '+str(self.trace))
  require(self.uc.reg_read(UC_ARM_REG_SP)==STACK,'call did not restore caller SP')
  return self.uc.reg_read(UC_ARM_REG_R0)
 def setup(self):
  require(self.call(0x277d27,(8,0,1),phase='original_profile')==0,'native profile failed')
  require(self.word(RECORD+0x160)==0x277c6b,'profile did not install original callback')
  self.profile_baseline=bytes(self.uc.mem_read(CHANNELS,18*STRIDE))
  require(self.call('qcs_initialize',(RECORD,0x34e3cf4,ANCHOR),phase='compiled_initialization')==0,'compiled initialization failed')
  require(self.word(RECORD+0x160)==self.build['symbols']['mcs_queue_bridge']['value'],'compiled callback store not observed')
  self.installed=True
 def status(self):
  self.call('qcs_status',(RESULT,),phase='compiled_status_read')
  return list(struct.unpack('<12I',self.uc.mem_read(RESULT,48)))
 def finish(self,name,result,expected,original_expected):
  require(result==expected,'unexpected original high result')
  require(len(self.lower_calls)==original_expected,'wrong number original lower calls')
  require(len(self.lower_returns)==original_expected,'original lower did not actually return')
  for args in self.lower_calls:require(args==[RECORD+0x1a8,0xffff,10,12,PARAMS,0x20c,0],'actual native lower seven arguments differ')
  require(self.call('qcs_end',(result,),phase='compiled_end')==result,'compiled end changed original result')
  status=self.status();require(status[2]==0 and status[10]==0,'invented completion or retained permit')
  require(not any(self.mutex.values()),'retained fixture mutex')
  current=bytes(self.uc.mem_read(CHANNELS,18*STRIDE))
  for i in range(18):
   if i!=8:require(current[i*STRIDE:(i+1)*STRIDE]==self.profile_baseline[i*STRIDE:(i+1)*STRIDE],'other source channel mutated')
  for h in self.handles.values():
   p,n=h['pointer'],h['size'];require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'opaque allocation guards changed')
  require(self.code_before==hashlib.sha256(bytes(self.uc.mem_read(CODE_START,CODE_END-CODE_START))).hexdigest(),'MAIN mapping altered')
  witness_before=bytes(self.uc.mem_read(RESULT+64,128))
  value=self.call('mcs_native_ownership_snapshot',(0,1,0x1352,RESULT+64),phase='compiled_uncertified_witness')
  require(value==(-200&0xffffffff)and bytes(self.uc.mem_read(RESULT+64,128))==witness_before,'uncertified witness accepted or modified output')
  final={str(a):bytes(self.uc.mem_read(a,n)).hex()for a,n,p in self.zones if not p&UC_PROT_EXEC}
  return dict(name=name,passed=True,original_high_return=result,original_lower_calls=len(self.lower_calls),
   original_lower_returns=self.lower_returns,original_lower_seven_args=self.lower_calls,high_calls=self.high_calls,
   original_BLX=self.blx_calls,compiled_bridge_calls=self.bridge_calls,compiled_status=status,
   native_visits={hex(k):v for k,v in self.visits.items()if v},instructions=self.instructions,
   initial_whole_zones=self.initial,final_whole_zones=final,zones=[dict(start=a,size=n,protection=p)for a,n,p in self.zones],
   CPU_store_journal=self.journal,declared_fixture_mutations=self.fixtures,lower_fixture_calls=self.native_boundaries,
   original_IRQ_and_current_actor_instructions=True,MAIN_RO_mapping_unchanged=True,
   native_ownership_snapshot=-200,native_STOP_DONE=False,physical_audio_or_App=False,
   native_mutex_or_heap_or_scheduler_execution=False,full_native_reader_or_player_image=False)
def main():
 runtime=BASE/'guest-v1';runtime.mkdir(exist_ok=False)
 source={rel(Path(__file__).resolve()):sha(Path(__file__).resolve()),
  'scripts/analyze_native_sections.py':sha(ROOT/'scripts/analyze_native_sections.py'),
  'evidence/firmware-analysis/main_02bd.bin':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes())
 build=json.loads((BASE/'build-v3.json').read_text());source.update(build['source_sha256'])
 source[rel(BASE/'build-v3.json')]=sha(BASE/'build-v3.json');source[build['ELF']]=sha(ROOT/build['ELF'])
 for p,h in source.items():require(sha(ROOT/p)==h,'input changed '+p)
 dump(runtime/'inputs-at-run.json',source)
 spec=importlib.util.spec_from_file_location('qcs_elf',ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py')
 mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
 elf=mod.ELF32(ROOT/build['ELF']);stock=NativeImage();cases=[];m=None
 plans=[('owned_original_queue',0,1),('original_allocation_failure5',5,1),
 ('foreign_actor_rejected',8,0),('IRQ_context_rejected',8,0),('wrong_anchor_rejected',8,0),('local_Stop_rejected',8,0)]
 try:
  for name,expected,original_expected in plans:
   m=QueueCall(stock,elf,build);m.setup()
   require(m.call('qcs_begin',phase='compiled_begin')==0,'native permit did not begin')
   if name=='original_allocation_failure5':m.fail_allocation=True
   elif name=='foreign_actor_rejected':m.fixture(0xF09090,struct.pack('<I',ACTOR+16),'negative foreign actor')
   elif name=='IRQ_context_rejected':m.fixture(0xF09094,struct.pack('<I',1),'negative interrupt marker')
   elif name=='wrong_anchor_rejected':m.fixture(PARAMS+12,struct.pack('<I',ANCHOR+4),'negative wrong anchor')
   elif name=='local_Stop_rejected':require(m.call('qcs_stop',phase='compiled_local_Stop')==1,'local Stop failed')
   result=m.call(0x270459,(8,10,12,PARAMS),(0x20c,0,1),phase='original_high_registration')
   if name in ('foreign_actor_rejected','IRQ_context_rejected'):
    m.fixture(0xF09090,struct.pack('<I',ACTOR),'restore declared original actor after rejected call')
    m.fixture(0xF09094,bytes(4),'restore no interrupt fixture after rejected call')
   row=m.finish(name,result,expected,original_expected);path=runtime/(name+'.json');dump(path,row)
   cases.append(dict(name=name,path=rel(path),sha256=sha(path),passed=True));print(name+' PASS',flush=True)
   m.uc=None;m=None
  proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),cases=cases,case_count=len(cases),
   source_sha256=source,actual_original_270458_BLX2704B2_to_compiled_bridge=True,
   actual_original_277C6A_complete_returns=True,MAIN_executable_bytes_not_patched=True,
   compile_image_has_zero_undefined=True,full_player_image=False,explicit_single_actor_and_mutex_heap_wake_fixtures=True,
   physical_App_or_native_audio_or_exclusive_or_STOP_DONE_verified=False,device_io=False)
  dump(BASE/'native-queue-call-emulation-proof.json',proof)
  print(json.dumps(dict(all_passed=True,cases=len(cases),proof=rel(BASE/'native-queue-call-emulation-proof.json'))))
 except BaseException as e:
  error=dict(terminal_error=str(e),traceback=traceback.format_exc(),cases_completed=cases,
   original_guest_success=False,device_io=False)
  if m:
   error.update(trace=m.trace,registers={n:hex(m.uc.reg_read(r))for n,r in [('pc',UC_ARM_REG_PC),('lr',UC_ARM_REG_LR),('sp',UC_ARM_REG_SP)]},
    fixture_calls=m.native_boundaries,CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures)
  dump(runtime/'terminal-failure.json',error);raise
if __name__=='__main__':main()
