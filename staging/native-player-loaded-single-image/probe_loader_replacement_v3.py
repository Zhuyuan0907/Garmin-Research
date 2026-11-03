#!/usr/bin/env python3
"""Run only original 3B3294 reader: another stock voice overwrites the DLL.
No player activation, scheduler reconstruction or device operation is done.
"""
import sys
sys.dont_write_bytecode=True
import json,struct,hashlib
from pathlib import Path
from datetime import datetime,timezone
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_THUMB,UC_HOOK_CODE,UC_HOOK_MEM_WRITE,UC_HOOK_MEM_READ
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
from analyze_native_sections import NativeImage,EXPECTED
IMAGE=0x02d4bb74;DESC=0x0304bb74;TABLE=0x08800100;STACK=0x08804000;RETURN=0x08805000
CALLBACKS={0x1fb2f8:'close',0x1fb304:'open',0x1fb3a2:'read',0x1fb3ce:'seek',0x1fb3e4:'tell'}
GP=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def rel(p):return str(p.relative_to(ROOT))
def require(v,msg):
 if not v:raise ValueError(msg)
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def main():
 out=BASE/'replacement-v3';out.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v3.json').read_text());stock=NativeImage()
 original=ROOT/build['combined_binary'];other=ROOT/'evidence/firmware-analysis/voice-modules/Chinese_GB_MeiLing/DLLIMG.BIN'
 input_bytes=other.read_bytes();before=original.read_bytes()+bytes(build['combined_ram_bytes']-build['combined_file_bytes'])
 uc=Uc(UC_ARCH_ARM,UC_MODE_THUMB);uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
 for p in (0x3b3000,0x38a000,0x1fb000,0x221000):uc.mem_map(p,4096);uc.mem_write(p,stock.read(p,4096))
 uc.mem_map(0x02d4b000,0x301000);uc.mem_write(IMAGE,before)
 uc.mem_map(0x08800000,0x6000)
 descriptor=bytearray(52);descriptor[4:15]=b'dllimg.bin\0';struct.pack_into('<2I',descriptor,24,IMAGE,0x300000);uc.mem_write(DESC,bytes(descriptor))
 uc.mem_write(TABLE,struct.pack('<5I',*[a|1 for a in CALLBACKS]))
 uc.reg_write(UC_ARM_REG_SP,STACK);uc.reg_write(UC_ARM_REG_LR,RETURN|1);uc.reg_write(UC_ARM_REG_R0,DESC);uc.reg_write(UC_ARM_REG_R1,TABLE)
 for i,r in enumerate(GP[4:12]):uc.reg_write(r,0xc0110000+i)
 initial_regs=[uc.reg_read(r)for r in GP];events=[];reads=[];stores=[];trace=[];position=0;returned=False
 def result(value):
  uc.reg_write(UC_ARM_REG_R0,value);flags=uc.reg_read(UC_ARM_REG_CPSR)
  uc.reg_write(UC_ARM_REG_CPSR,(flags|(1<<30))if not value else(flags&~(1<<30)))
  uc.reg_write(UC_ARM_REG_PC,uc.reg_read(UC_ARM_REG_LR))
 def code(u,a,n,unused):
  nonlocal position,returned
  trace.append(dict(PC=a,opcode_hex=bytes(uc.mem_read(a,n)).hex(),GP16=[uc.reg_read(r)for r in GP],CPSR=uc.reg_read(UC_ARM_REG_CPSR)))
  if a==RETURN:returned=True;uc.emu_stop();return
  args=[uc.reg_read(r)for r in GP[:4]]
  if a==0x221d2c:events.append(dict(name='cache_sync',physical=False));result(0);return
  if a not in CALLBACKS:return
  name=CALLBACKS[a];e=dict(name=name,args=args,caller_LR=uc.reg_read(UC_ARM_REG_LR))
  if name=='open':require(bytes(uc.mem_read(args[0],11))==b'dllimg.bin\0','filename');value=0x12345678
  elif name=='seek':position=len(input_bytes)if args[2]==2 else args[1];value=0
  elif name=='tell':value=position
  elif name=='close':value=0
  else:
   require(args==[IMAGE,1,len(input_bytes),0x12345678],'reader file write shape')
   e.update(before_sha256=hashlib.sha256(bytes(uc.mem_read(IMAGE,len(input_bytes)))).hexdigest(),after_sha256=sha(other))
   uc.mem_write(IMAGE,input_bytes);value=len(input_bytes)
  events.append(e);result(value)
 def read(u,access,a,n,v,unused):reads.append(dict(PC=uc.reg_read(UC_ARM_REG_PC),address=a,size=n,bytes_hex=bytes(uc.mem_read(a,n)).hex()))
 def store(u,access,a,n,v,unused):stores.append(dict(PC=uc.reg_read(UC_ARM_REG_PC),address=a,size=n,value=v,before_hex=bytes(uc.mem_read(a,n)).hex()))
 uc.hook_add(UC_HOOK_CODE,code);uc.hook_add(UC_HOOK_MEM_READ,read);uc.hook_add(UC_HOOK_MEM_WRITE,store)
 uc.emu_start(0x3b3295,RETURN+2,count=10000,timeout=5000000)
 require(returned and uc.reg_read(UC_ARM_REG_R0)==11,'reader did not fully accept stock GB voice')
 final_regs=[uc.reg_read(r)for r in GP];require(final_regs[13]==STACK and initial_regs[4:12]==final_regs[4:12],'reader ABI')
 after=bytes(uc.mem_read(IMAGE,len(before)));require(after[:len(input_bytes)]==input_bytes and after[len(input_bytes):]==before[len(input_bytes):],'overwrite range differs')
 spans=[]
 for name in ['resident_music_entry','resident_player_api','aas_media_ingress','mh_source_entry','mh_request_command','nsg_native_callback','garmin_sbc_decode_frame','continuous_media_read','resident_entry_phase','mh_source_tcb','nsg']:
  s=build['symbols'][name];a=s['value']&~1;n=s['size'];off=a-IMAGE
  require(n and 0<=off<off+n<=len(input_bytes),'symbol not overwritten '+name)
  require(before[off:off+n]!=after[off:off+n],'symbol bytes unexpectedly unchanged '+name)
  spans.append(dict(symbol=name,address=a,bytes=n,before_sha256=hashlib.sha256(before[off:off+n]).hexdigest(),after_sha256=hashlib.sha256(after[off:off+n]).hexdigest()))
 guarded=[build['symbols'][n]for n in ['nsg','mh_source_tcb','resident_entry_phase']]
 require(not any(r['address']<s['value']+s['size']and r['address']+r['size']>s['value']for r in reads for s in guarded),'reader consulted player guard')
 for name in ['source_stack','pcm3']:
  s=build['symbols'][name];off=s['value']-IMAGE
  require(off>=len(input_bytes)and before[off:off+s['size']]==after[off:off+s['size']],'tail region unexpectedly overwritten')
 deps={rel(p):sha(p)for p in [Path(__file__),BASE/'build-v3.json',original,other,ROOT/'scripts/analyze_native_sections.py',ROOT/'evidence/firmware-analysis/main_02bd.bin']}
 artifact=dict(all_passed=True,source_sha256=deps,trace=trace,CPU_reads=reads,CPU_stores=stores,explicit_file_cache_events=events,
  overwritten_player_spans=spans,initial_GP16=initial_regs,final_GP16=final_regs,reader_full_return=11,
  current_image_fixture_not_active_player=True,no_player_guard_read_in_examined_original_reader=True,
  stock_source_stack_and_tail_storage_survive_while_player_code_replaced=True,
  full_voice_selection_concurrency_or_hardware_not_tested=True,device_IO=False)
 path=out/'native-reader-control.json';dump(path,artifact)
 proof=dict(all_passed=True,updated_utc=datetime.now(timezone.utc).isoformat(),source_sha256=deps,
  case=dict(path=rel(path),sha256=sha(path)),reader_entry='0x3b3294',reader_full_return=11,
  replacement_voice='Chinese_GB_MeiLing',replacement_bytes=len(input_bytes),overwritten_player_spans=spans,
  resident_module_pin_not_available_in_this_reader=True,earlier_caller_policy_or_global_lock_not_fully_audited=True,
  original_reader_direct_does_not_prove_whole_concurrent_voice_change=True,
  requires_external_lifetime_gate_or_separate_native_owned_storage=True,device_IO=False)
 dump(BASE/'native-reader-replacement-v3-proof.json',proof)
 print(json.dumps(dict(all_passed=True,reader_return=11,overwritten_symbols=len(spans),replacement_bytes=len(input_bytes),native_instructions=len(trace),device_IO=False)),flush=True)
if __name__=='__main__':main()
