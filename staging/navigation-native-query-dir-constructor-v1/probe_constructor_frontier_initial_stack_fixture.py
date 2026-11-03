#!/usr/bin/env python3
"""One original cold DIR-handle branch, stopped before its unknown mutex ABI.

No original allocator/handle/dispatch return is supplied. No old cases/main.
"""
import hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent
def sha(x):return hashlib.sha256(x).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def need(x,m):
 if not x:raise ValueError(m)
def main():
 need(not(HERE/'actual-cold-constructor-frontier.json').exists(),'Exactly one new case')
 base=ROOT/'staging/navigation-native-query-provider-full-getter-v1';seal_raw=(base/'sealed-files.json').read_bytes()
 need(sha(seal_raw)=='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b','Closed source seal pin')
 seal=json.loads(seal_raw);rel=str((base/'MAIN-page-00388000.bin').relative_to(ROOT));entry=next(x for x in seal['files']if x['path']==rel)
 p=ROOT/rel;before=stat(p);allocator=p.read_bytes();need(sha(allocator)==entry['sha256']and stat(p)==before,'Original saved allocator page identity')
 receipt=json.loads((HERE/'capture-00173000-receipt.json').read_bytes());ctor=(HERE/'MAIN-page-00173000.bin').read_bytes()
 need(sha(ctor)==receipt['new_source_reads'][0]['sha256'],'Fresh original constructor code pin')
 mat=ROOT/'staging/navigation-native-jai-img-materializer-abi-v1';ms=json.loads((mat/'sealed-files.json').read_bytes());mfile=mat/'actual-native-materializer-case.json';mr=str(mfile.relative_to(ROOT));e=next(x for x in ms['files']if x['path']==mr);raw=mfile.read_bytes();need(sha(raw)==e['sha256'],'Frozen original result-chain identity')
 frozen=json.loads(raw);need(frozen['actual_native_chain_12byte_records'][0]==[3,48312,0],'Actual source tuple pin')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
 for address,rawpage in [(0x173000,ctor),(0x388000,allocator)]:
  u.mem_map(address,4096,UC_PROT_READ|UC_PROT_WRITE);u.mem_write(address,rawpage);u.mem_protect(address,4096,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(0x09000000,65536,UC_PROT_READ|UC_PROT_WRITE)
 REPLY,CACHE,OUTPUT,OPTIONS,OPAQUE,SP=0x09000000,0x09001000,0x09002000,0x09003000,0x09006000,0x0900d000
 u.mem_write(REPLY,struct.pack('<3I',CACHE,0,0))
 # Guard-passing native cache-record fixture, with the inherited source ID;
 # not the original query cache allocation or a genuine runtime MDR object.
 u.mem_write(CACHE,struct.pack('<4I',5441050,48312,0x0524,0))
 u.mem_write(CACHE+0x10,struct.pack('<I',0x12435687))
 u.mem_write(CACHE+0x1c,struct.pack('<I',0))
 u.mem_write(OPTIONS+0xc,struct.pack('<I',OPAQUE))
 for reg,value in[(UC_ARM_REG_R0,REPLY),(UC_ARM_REG_R1,OUTPUT),(UC_ARM_REG_R2,OPTIONS),(UC_ARM_REG_SP,SP),(UC_ARM_REG_LR,0x0900f001),(UC_ARM_REG_CPSR,0x3f)]:u.reg_write(reg,value)
 trace=[];events=[];stopped=[]
 def hook(uc,a,n,_):
  if a==0x38854a:
   stopped.append(a);events.append(dict(address=a,event='Stop before original BL3009A0 mutex/context ABI; no return substituted',r0=uc.reg_read(UC_ARM_REG_R0),r5_size=uc.reg_read(UC_ARM_REG_R5),r6_flags=uc.reg_read(UC_ARM_REG_R6),r7_handle_out=uc.reg_read(UC_ARM_REG_R7)));uc.emu_stop();return
  trace.append(dict(address=a,hex=bytes(uc.mem_read(a,n)).hex()))
  if a in(0x173b50,0x173b88,0x38853c):events.append(dict(address=a,r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),r2=uc.reg_read(UC_ARM_REG_R2),r3=uc.reg_read(UC_ARM_REG_R3),sp=uc.reg_read(UC_ARM_REG_SP)))
 u.hook_add(UC_HOOK_CODE,hook);u.emu_start(0x173b51,0,count=200,timeout=1000000)
 need(stopped==[0x38854a],'Exact bounded original mutex frontier')
 visit=[x for x in events if x['address']==0x38853c];need(len(visit)==1,'True native allocator entered once')
 need((visit[0]['r0'],visit[0]['r1'],visit[0]['r2'])==(0x17c,0,CACHE+0x1c),'Actual cold handle allocator call ABI')
 need(bytes(u.mem_read(CACHE+0x1c,4))==b'\0'*4,'No synthetic handle success produced')
 need(all(not(0x44b209e<=x['address']<0x44b219e)for x in trace),'Parser not claimed executed')
 result=dict(schema='garmin-native-query-dir-constructor-frontier/v1',created_utc=datetime.now(timezone.utc).isoformat(),name='One guard-passing original selector4006 cold-DIR-handle attempt',entry='0x00173B50',exact_stop='0x0038854A before BL0x003009A0',native_function_return_observed=False,instructions_executed=len(trace),all_assigned_checks_passed=True,events=events,instruction_trace=trace,instruction_trace_sha256=sha(json.dumps(trace,sort_keys=True).encode()),actual_handle_after=0,DIR_allocated=False,DIR_parser_executed=False,DIR154_written=False,DIR160_written=False,fixtures=dict(reply_cache_and_output='Synthetic guard-passing 3-word reply, cache record, output and options',cache_magic='Observedoriginal12435687,notanassumedMDRsignature',source_tuple_inherited=frozen['actual_native_chain_12byte_records'][0],source_tuple_case_replayed=False,cache_descriptor='MapID5441050/nativeStreetID48312/kind24/level3+2 are fixture annotations; no native query created this cache',MDRctx='Opaque initialized-to-zero RAM pointer supplied inoptions+C; not a parsed actual MDR context; never dereferenced bythisboundedcase',cold_handle='cache+1C=0; original38853Centeredwithr0=17C/r1=0/r2=&handle',cold_heap_or_registry_initialized=False,FS_and_SQLite_callbacks_used=False),unknown_callee_returns_faked=False,original_MAIN_patched=False,new_IMG_bytes_read=0,device_IO=False,original_code_sources=[dict(path='staging/navigation-native-query-dir-constructor-v1/MAIN-page-00173000.bin',sha256=sha(ctor)),dict(path=rel,sha256=sha(allocator),source_stat_before=before,source_stat_after=stat(p))],query_to_getter_uninterrupted=False,native_SQLite=False,native_UI=False,physical_acceptance=False,installable=False,source_historical_alias_verified=False,all_source_handles_closed=True)
 with(HERE/'actual-cold-constructor-frontier.json').open('x')as f:json.dump(result,f,ensure_ascii=False,indent=2);f.write('\n')
 print(json.dumps(dict(all_assigned_checks_passed=True,instructions_executed=len(trace),stop='0x0038854A',actual_handle_after=0,DIR_constructor_return=False,IMG_bytes_read=0)))
if __name__=='__main__':main()
