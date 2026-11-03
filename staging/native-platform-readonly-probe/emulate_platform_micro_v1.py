#!/usr/bin/env python3
"""Declared CPU-model microcontrols, not physical CPU/MMU observations."""
import sys
sys.dont_write_bytecode=True
import json,hashlib,gzip,traceback,struct
from pathlib import Path
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent;IMAGE=0x02d4bb74;STACK=0x09000000;RETURN=0x09003000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def require(v,m):
 if not v:raise ValueError(m)
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def compressed(p,d):
 with p.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0)as g:g.write(json.dumps(d,separators=(',',':')).encode())
def expected(mode,midr,ctl):
 flags=(mode==31)|(bool(ctl&1)<<1)|(bool(ctl&4)<<2)|(bool(ctl&4096)<<3);return(flags<<12)|((midr>>4)&4095)
class Micro:
 def __init__(self,build,model):
  self.m=build;self.binary=(ROOT/build['combined_file']).read_bytes();self.uc=unicorn.Uc(unicorn.UC_ARCH_ARM,unicorn.UC_MODE_ARM);self.uc.ctl_set_cpu_model(model);self.md=Cs(CS_ARCH_ARM,CS_MODE_ARM)
  a=IMAGE&~4095;end=(IMAGE+build['combined_ram']+4095)&~4095;self.uc.mem_map(a,end-a);self.uc.mem_write(IMAGE,self.binary);self.uc.mem_map(STACK,8192);self.uc.mem_map(RETURN,4096)
  self.s=build['symbols'];self.state=self.s['marker_state'];self.state_bytes=self.s['__marker_bss_end']-self.s['__marker_bss_start'];require(self.state_bytes==124,'hardware state ABI differs')
  self.active=False;self.ordinal=0;self.journal=[];self.trace=[];self.reads=[];self.pending=None
  self.uc.hook_add(unicorn.UC_HOOK_CODE,self.code);self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.write)
 def snapshot(self):return dict(GP16=[self.uc.reg_read(r)for r in REGS],CPSR=self.uc.reg_read(UC_ARM_REG_CPSR))
 def cp(self,crn):return self.uc.cpr_read(15,0,crn,0,0,1,False)
 def code(self,u,a,size,data):
  if not self.active:return
  if self.pending:
   e=self.pending;require(u.reg_read(REGS[e['dest']])==e['reference'],'MRC did not return model register');e['after']=self.snapshot();self.reads.append(e);self.pending=None
  raw=bytes(u.mem_read(a,size));i=next(self.md.disasm(raw,a,count=1),None);require(i is not None,'undecoded actual ARM instruction')
  require(i.mnemonic not in('mcr','mcrr','msr'),'probe wrote system register')
  self.trace.append(dict(PC=a,opcode_hex=raw.hex(),instruction=i.mnemonic+' '+i.op_str,state=self.snapshot()))
  if i.mnemonic=='mrc':
   word=struct.unpack('<I',raw)[0];crn=(word>>16)&15;dest=(word>>12)&15
   require(((word>>8)&15)==15 and ((word>>21)&7)==0 and (word&15)==0 and ((word>>5)&7)==0 and crn in(0,1)and dest<13,'unexpected CP15 read')
   self.pending=dict(PC=a,opcode_hex=raw.hex(),crn=crn,dest=dest,reference=self.cp(crn),before=self.snapshot())
 def write(self,u,access,a,n,value,data):
  if not self.active:return
  if self.state<=a and a+n<=self.state+self.state_bytes:zone='state';origin=self.state
  elif STACK<=a and a+n<=STACK+8192:zone='stack';origin=STACK
  else:raise ValueError('CPU store outside declared private state/stack '+hex(a))
  before=bytes(u.mem_read(a,n)).hex();self.ordinal+=1;pc=u.reg_read(UC_ARM_REG_PC)
  self.journal.append(dict(ordinal=self.ordinal,zone=zone,address=a,size=n,value=value,before_hex=before,PC=pc,opcode_hex=bytes(u.mem_read(pc,4)).hex(),state=self.snapshot()))
 def run(self,name,mode,entry,args):
  self.uc.reg_write(UC_ARM_REG_CPSR,0xa0000000|mode)
  for i,r in enumerate(REGS[:13]):self.uc.reg_write(r,0x11110000+i)
  for r,v in zip(REGS,args):self.uc.reg_write(r,v)
  self.uc.reg_write(UC_ARM_REG_SP,STACK+8192-32);self.uc.reg_write(UC_ARM_REG_LR,RETURN);self.uc.reg_write(UC_ARM_REG_PC,entry)
  self.uc.mem_write(self.state,b'\xa5'*self.state_bytes);self.uc.mem_write(STACK,b'\xa5'*8192)
  before=self.snapshot();cp_before=dict(MIDR=self.cp(0),SCTLR=self.cp(1));initial=dict(state=bytes(self.uc.mem_read(self.state,self.state_bytes)).hex(),stack=bytes(self.uc.mem_read(STACK,8192)).hex())
  self.journal=[];self.trace=[];self.reads=[];self.pending=None;self.ordinal=0;self.active=True
  self.uc.emu_start(entry,RETURN,count=10000,timeout=3000000);self.active=False;after=self.snapshot()
  require(after['GP16'][15]==RETURN and after['GP16'][13]==before['GP16'][13]and after['GP16'][4:12]==before['GP16'][4:12],'bare ARM endpoint full ABI')
  require((after['CPSR']&255)==(before['CPSR']&255),'probe changed mode or interrupt/ISA bits');require(self.pending is None,'unfinished MRC observation')
  cp_after=dict(MIDR=self.cp(0),SCTLR=self.cp(1));require(cp_before==cp_after,'CP15 model registers changed')
  final=dict(state=bytes(self.uc.mem_read(self.state,self.state_bytes)).hex(),stack=bytes(self.uc.mem_read(STACK,8192)).hex());require(bytes.fromhex(final['state'])[:104]==bytes.fromhex(initial['state'])[:104],'legacy private state changed')
  require(sha_bytes(bytes(self.uc.mem_read(IMAGE,len(self.binary))))==sha_bytes(self.binary),'loaded program bytes changed')
  value=after['GP16'][0]
  if entry==self.s['sample_platform']:
   accepted=mode in(19,31);fields=struct.unpack_from('<5I',bytes.fromhex(final['state']),104)
   require(fields[0]==self.trace[0]['state']['CPSR']and fields[3]==int(accepted),'mode snapshot/acceptance mismatch')
   want=expected(mode,cp_before['MIDR'],cp_before['SCTLR'])if accepted else mode
   require(value==fields[4]==want and len(self.reads)==(2 if accepted else 0),'actual sampler tag/read guard mismatch')
   require(list(fields[1:3])==([cp_before['MIDR'],cp_before['SCTLR']]if accepted else[0,0]),'actual sampled model fields')
   tag=f'{want:04X}'if accepted else('U'if mode==16 else'X')+f'{mode:03X}'
  else:
   want=expected(*args);require(value==want and not self.reads and final['state']==initial['state'],'pure formatter behavior');tag=f'{want:04X}'
  return dict(name=name,passed=True,mode=mode,entry=entry,args=args,before=before,after=after,CP15_before=cp_before,CP15_after=cp_after,initial=initial,final=final,CPU_store_journal=self.journal,actual_instruction_trace=self.trace,actual_CP15_read_observations=self.reads,returned=value,tag=tag,actual_model_tag_not_physical_cpu=True)
def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def main():
 out=BASE/'micro-v1';out.mkdir(exist_ok=False);m=json.loads((BASE/'strict_marker/manifest.json').read_text());require(sha(ROOT/m['combined_file'])==m['binary_sha256'],'compiled program changed')
 deps=dict(m['source_sha256']);deps.update({rel(p):sha(p)for p in[Path(__file__),BASE/'strict_marker/manifest.json',BASE/'platform-probe-source-contract-v1.json',ROOT/m['combined_file'],ROOT/'evidence/firmware-analysis/main_02bd.bin']});dump(out/'inputs-at-run.json',deps);rows=[]
 try:
  for label,model in [('ARM926',UC_CPU_ARM_926),('ARM1176',UC_CPU_ARM_1176)]:
   vm=Micro(m,model)
   for mode in(31,19,16,18,17,23):rows.append(vm.run(label+'_mode_'+hex(mode),mode,m['symbols']['sample_platform'],[]))
   midr=vm.cp(0)
   for mode in(19,31):
    for bits in range(8):
     ctl=(bits&1)|((bits&2)<<1)|((bits&4)<<10);rows.append(vm.run(label+'_format_'+hex(mode)+'_'+str(bits),31,m['symbols']['platform_format_tag'],[mode,midr,ctl]))
  require(len(rows)==44 and all(sha(ROOT/p)==h for p,h in deps.items()),'count/dependencies')
  artifact=out/'model-micro-cases.json.gz';compressed(artifact,dict(all_passed=True,cases=rows,source_sha256=deps,explicit_model_and_input_scope=True,device_IO=False));proof=dict(all_passed=True,case_count=44,actual_sampler_cases=12,privileged_sampler_cases=4,skipped_sampler_cases=8,pure_formatter_cases=32,actual_MRC_reads=sum(len(r['actual_CP15_read_observations'])for r in rows),all_sixteen_high_flag_nibbles_covered=True,artifact=rel(artifact),artifact_sha256=sha(artifact),source_sha256=deps,CP15_writes_or_in_run_context_patches=0,physical_CPU_or_MMU_mapping_or_Main_permission_or_App_proven=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat());dump(BASE/'platform-micro-v1-proof.json',proof);print(json.dumps({k:v for k,v in proof.items()if k not in('source_sha256',)}),flush=True)
 except BaseException as e:
  compressed(out/'terminal-failure.json.gz',dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),completed_cases=rows,source_sha256=deps,device_IO=False));raise
if __name__=='__main__':main()
