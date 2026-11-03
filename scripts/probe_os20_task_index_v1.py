#!/usr/bin/env python3
"""Recover stock OS20 bridge and execute bounded task-index helper cases.

No task is created, no allocator/audio/device operation is called. Pool and
current/interrupt words are explicit synthetic inputs, not physical readings.
"""
import sys,json,hashlib,struct,gzip,collections,traceback
from pathlib import Path
from datetime import datetime,timezone
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'staging/native-os20-task-index-v1'
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM,CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM,ARM_OP_MEM,ARM_REG_PC,ARM_INS_B,ARM_INS_BX,ARM_INS_BL,ARM_INS_BLX,ARM_CC_AL
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn.arm_const import *
POOL=0x03a1b294;COUNT=15;STRIDE=64;STACK=0x09010000;RETURN=0x09000000
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def write_new(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def compressed(p,d):
 with p.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0)as z:z.write(json.dumps(d,separators=(',',':')).encode())
def graph(n,start,end):
 md=Cs(CS_ARCH_ARM,CS_MODE_THUMB);md.detail=True;pending=[start];seen={};returns=[]
 while pending:
  a=pending.pop()
  if a in seen:continue
  assert start<=a<end and len(seen)<500
  i=next(md.disasm(n.read(a,4),a,count=1));row=dict(address=a,bytes=i.bytes.hex(),instruction=i.mnemonic+' '+i.op_str)
  if i.mnemonic=='ldr'and i.operands[-1].type==ARM_OP_MEM and i.operands[-1].mem.base==ARM_REG_PC:
   ptr=((a+4)&~3)+i.operands[-1].mem.disp;row.update(literal_address=ptr,literal_value=n.word(ptr))
  if i.mnemonic=='adr':row['address_value']=((a+4)&~3)+i.operands[-1].imm
  seen[a]=row
  if i.id==ARM_INS_B:
   target=i.operands[0].imm;pending.append(target)
   if i.cc==ARM_CC_AL:continue
  if i.id in(ARM_INS_BL,ARM_INS_BLX):
   if i.operands[0].type==ARM_OP_IMM:row['direct_call']=i.operands[0].imm
   else:row['indirect_call_register']=i.op_str
  elif i.id==ARM_INS_BX:
   assert i.op_str=='lr';returns.append(a);continue
  elif i.mnemonic=='pop'and ARM_REG_PC in[i.operands[x].reg for x in range(len(i.operands))]:returns.append(a);continue
  elif ARM_REG_PC in i.regs_access()[1]:raise AssertionError('Unresolved PC write '+hex(a))
  pending.append(a+i.size)
 return dict(entry=start,end_bound=end,instructions=[seen[k]for k in sorted(seen)],normal_return_sites=returns,callees_not_recursively_recovered=True)
class VM:
 def __init__(self,n,pool,current=0x08b01000,interrupt=0):
  self.n=n;self.u=Uc(UC_ARCH_ARM,UC_MODE_ARM);self.u.ctl_set_cpu_model(UC_CPU_ARM_1176)
  self.u.mem_map(0x50000,(len(n.data)+4095)&~4095);self.u.mem_write(0x50000,n.data)
  self.u.mem_map(POOL&~4095,4096);self.u.mem_write(POOL,pool);self.u.mem_map(STACK,8192);self.u.mem_write(STACK,b'\xa5'*8192);self.u.mem_map(RETURN,4096);self.u.mem_write(RETURN,bytes.fromhex('1eff2fe1'))
  self.u.mem_write(n.word(0x358d34),struct.pack('<I',interrupt));self.u.mem_write(n.word(0x358d38),struct.pack('<I',current))
  self.before_pool=pool;self.before_stack=bytes(self.u.mem_read(STACK,8192));self.trace=[];self.writes=[];self.irq=[];self.returned=False;self.boundary=False
  self.u.hook_add(UC_HOOK_CODE,self.code);self.u.hook_add(UC_HOOK_MEM_WRITE,self.store)
 def snapshot(self):return dict(GP16=[self.u.reg_read(r)for r in REGS],CPSR=self.u.reg_read(UC_ARM_REG_CPSR))
 def code(self,u,a,size,unused):
  if a==RETURN:self.returned=True;u.emu_stop();return
  if a==0x521da8:self.boundary=True;self.error_callsite=self.snapshot();u.emu_stop();return
  assert any(lo<=a<hi for lo,hi in[(0x521d7c,0x521de4),(0x358d24,0x358d34),(0x21b6cc,0x21b6e4)]),'Unadmitted code '+hex(a)
  op=bytes(u.mem_read(a,size));assert op==self.n.read(a,size)
  self.trace.append(dict(PC=a,opcode_hex=op.hex(),CPSR=u.reg_read(UC_ARM_REG_CPSR),GP16=[u.reg_read(r)for r in REGS]))
  if a in(0x21b6cc,0x21b6dc):self.irq.append(dict(entry=a,state=self.snapshot()))
 def store(self,u,access,a,size,value,unused):
  zone='pool'if POOL<=a and a+size<=POOL+COUNT*STRIDE else 'stack'if STACK<=a and a+size<=STACK+8192 else None
  assert zone,'Unexpected store '+hex(a)
  self.writes.append(dict(zone=zone,address=a,size=size,value=value,before_hex=bytes(u.mem_read(a,size)).hex(),PC=u.reg_read(UC_ARM_REG_PC),CPSR=u.reg_read(UC_ARM_REG_CPSR)))
 def call(self,entry,arg):
  self.u.reg_write(UC_ARM_REG_CPSR,0xa000005f)
  for j,r in enumerate(REGS[:13]):self.u.reg_write(r,0x11000000+j*0x010101)
  self.u.reg_write(UC_ARM_REG_R0,arg);self.u.reg_write(UC_ARM_REG_SP,STACK+8192-32);self.u.reg_write(UC_ARM_REG_LR,RETURN);before=self.snapshot()
  self.u.emu_start(entry|1,RETURN+4,count=10000,timeout=2000000);after=self.snapshot();assert self.returned or self.boundary
  if self.returned:assert before['GP16'][4:12]==after['GP16'][4:12]and before['GP16'][13]==after['GP16'][13]and (before['CPSR']^after['CPSR'])&0xdf==0
  return before,after
def main():
 assert not OUT.exists();OUT.mkdir();n=NativeImage();source={str(p.relative_to(ROOT)):sha(p)for p in(Path(__file__),ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 assert n.word(0x522080)==POOL and n.word(0x358d34)==0xf09094 and n.word(0x358d38)==0xf09090
 graphs={hex(a):graph(n,a,end)for a,end in[(0x521d7c,0x521db0),(0x521db0,0x521de4),(0x521e44,0x521e5e),(0x521e5e,0x521f16),(0x521f16,0x521f36),(0x521f74,0x521f82)]}
 lookup={r['address']:r for r in graphs['0x521d7c']['instructions']};assert lookup[0x521d94]['instruction']=='cmp r1, #0xf'and lookup[0x521d82]['instruction']=='lsls r3, r1, #6'and lookup[0x521d86]['instruction']=='ldr r3, [r3, #0x30]'
 assert lookup[0x521d9c]['address_value']==0x522084 and lookup[0x521da6]['address_value']==0x522098
 static=dict(all_passed=True,MAIN_sha256=source['evidence/firmware-analysis/main_02bd.bin'],graphs=graphs,adapter_pool_address=POOL,adapter_records=COUNT,stride=STRIDE,underlying_task_pointer_offset=48,not_entire_OS_task_count=True,create_entry='0x521e5e',create_has_two_allocation_calls=['0x395440','0x39544c'],workspace_request_add_bytes=152,descriptor_request_bytes=100,entry_indirect_callback='0x521e54',actual_allocator_nonnull_guarantee_unverified=True,all_callee_bodies_or_physical_task_creation_verified=False,source_sha256=source,device_IO=False)
 write_new(OUT/'static-bridge-proof.json',static)
 def initial():
  b=bytearray(b'\xa5'*(COUNT*STRIDE))
  for j in range(COUNT):struct.pack_into('<I',b,j*STRIDE+48,0x08b00000+j*4096)
  return b
 specs=[]
 for name,index in [('first',0),('middle',7),('last',14)]:
  b=initial();specs.append((name+'_existing',0x521d7c,0x08b00000+index*4096,b,POOL+index*STRIDE,'lookup',index))
 for name,index in [('first',0),('last',14)]:
  b=initial();struct.pack_into('<I',b,index*STRIDE+48,0);specs.append((name+'_free',0x521d7c,0,b,POOL+index*STRIDE,'lookup',index))
 specs.append(('unknown_nonzero',0x521d7c,0x08b90000,initial(),0,'lookup',None));specs.append(('full_zero_error_boundary',0x521d7c,0,initial(),None,'boundary',None))
 specs.append(('current_existing',0x521db0,0,initial(),POOL+STRIDE,'current',1))
 b=initial();struct.pack_into('<I',b,8*STRIDE+48,0);specs.append(('current_lazy_new',0x521db0,0,b,POOL+8*STRIDE,'current_new',8))
 rows=[]
 try:
  for name,entry,arg,pool,want,kind,index in specs:
   current=0x08b01000 if kind!='current_new'else 0x08b90000;vm=VM(n,bytes(pool),current=current);before,after=vm.call(entry,arg)
   final=bytes(vm.u.mem_read(POOL,COUNT*STRIDE));expected=bytearray(pool)
   if kind=='current_new':struct.pack_into('<I',expected,index*STRIDE+48,current);struct.pack_into('<I',expected,index*STRIDE+8,0x59);expected[index*STRIDE+44]=0
   assert final==bytes(expected)
   if want is not None:assert vm.returned and after['GP16'][0]==want
   else:assert vm.boundary and not vm.returned and vm.error_callsite['GP16'][2]==0x522098
   pool_writes=[w for w in vm.writes if w['zone']=='pool'];assert len(pool_writes)==(3 if kind=='current_new'else 0)
   if kind in('current','current_new'):assert [r['entry']for r in vm.irq]==[0x21b6cc,0x21b6dc]
   data=dict(all_passed=True,name=name,entry=entry,input_arg=arg,input_current_TCB=current,input_interrupt_marker=0,before=before,after=after,original_full_return=vm.returned,expected_error_callsite_stop=vm.boundary,original_assert_body_executed=False,trace=vm.trace,CPU_write_journal=vm.writes,pool_before_hex=bytes(pool).hex(),pool_after_hex=final.hex(),stack_before_hex=vm.before_stack.hex(),stack_after_hex=bytes(vm.u.mem_read(STACK,8192)).hex(),native_irq_calls=vm.irq,pool_stores=len(pool_writes),expected_return=want,reference_semantics=kind,reference_slot=index,synthetic_pool_current_TCB_stack_inputs=True,allocator_or_task_create_called=False,device_IO=False)
   artifact=OUT/(name+'.json.gz');compressed(artifact,data);rows.append(dict(name=name,path=str(artifact.relative_to(ROOT)),sha256=sha(artifact),full_return=vm.returned,error_boundary=vm.boundary,pool_stores=len(pool_writes),instructions=len(vm.trace)));print(json.dumps(rows[-1]),flush=True)
  assert all(sha(ROOT/p)==h for p,h in source.items());write_new(OUT/'guest-proof.json',dict(all_passed=True,cases=rows,case_count=9,full_returns=sum(r['full_return']for r in rows),error_callsite_stops=sum(r['error_boundary']for r in rows),pool_CPU_stores=sum(r['pool_stores']for r in rows),source_sha256=source,physical_task_creation_or_live_slot_availability_verified=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat()))
 except BaseException as e:write_new(OUT/'terminal-failure.json',dict(error=str(e),traceback=traceback.format_exc(),completed_cases=rows,device_IO=False));raise
if __name__=='__main__':main()
