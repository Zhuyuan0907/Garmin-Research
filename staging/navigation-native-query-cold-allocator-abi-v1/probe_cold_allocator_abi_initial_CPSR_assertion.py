#!/usr/bin/env python3
"""One address-constructor ABI continuation; real uncontended native mutex.

Generic native mutex setup plus a reconstructed allocator-wrapper frame;
stop before the original heap core, whose workspace is not initialized.
No warm image, higher return hook, allocator/handle supply or old main/cases.
"""
import hashlib,json,struct
from pathlib import Path
from datetime import datetime,timezone
from unicorn import Uc,UC_ARCH_ARM,UC_MODE_ARM,UC_HOOK_CODE,UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC
from unicorn.arm_const import *
ROOT=Path('/root/garmin');HERE=Path(__file__).resolve().parent;DEPS=[];SEALS={}
def need(x,m):
 if not x:raise ValueError(m)
def sha(b):return hashlib.sha256(b).hexdigest()
def stat(p):
 s=p.stat();return[s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def save(name,d):
 with(HERE/name).open('x')as f:json.dump(d,f,ensure_ascii=False,indent=2);f.write('\n')
def bound(stage,pin,name):
 if stage not in SEALS:
  p=ROOT/'staging'/stage/'sealed-files.json';b=p.read_bytes();need(sha(b)==pin,'Closed source seal pin');SEALS[stage]=json.loads(b);DEPS.append(dict(path=str(p.relative_to(ROOT)),bytes=len(b),sha256=sha(b)))
 p=ROOT/'staging'/stage/name;rel=str(p.relative_to(ROOT));e=next(x for x in SEALS[stage]['files']if x['path']==rel);before=stat(p);b=p.read_bytes();need(sha(b)==e['sha256']and len(b)==e['bytes']and stat(p)==before,'Immutable closed source pin:'+rel)
 DEPS.append(dict(path=rel,bytes=len(b),sha256=sha(b),stat_before=before,stat_after=stat(p),old_cases_executed=False));return b
def small(rel,cap):
 p=ROOT/rel;before=stat(p);need(before[2]<=cap,'Small document bound');b=p.read_bytes();need(stat(p)==before,'Small evidence immutable');DEPS.append(dict(path=rel,bytes=len(b),sha256=sha(b),stat_before=before,stat_after=stat(p),guest_or_old_main_executed=False));return json.loads(b)
def main():
 need(not(HERE/'actual-continuation.json').exists(),'One logical new continuation only')
 getter='navigation-native-query-provider-full-getter-v1';pin='49ea2c9bf1cbb328f52d3120e8654f33bedd203f54ab80d683a3878a9e34368b'
 ctor='navigation-native-query-dir-constructor-v1';cp='db15a000400a1eedfab67146e98dca139159978d30bce0ce7f491f4d3a3b9b89'
 original={0x300000:bound(getter,pin,'MAIN-page-00300000.bin'),0x388000:bound(getter,pin,'MAIN-page-00388000.bin')}
 endpoint=json.loads(bound(ctor,cp,'actual-cold-constructor-frontier.json'));priorproof=json.loads(bound(ctor,cp,'proof.json'));failure=json.loads(bound(ctor,cp,'fixture-preparation-failure-receipt.json'))
 need(endpoint['exact_stop'].startswith('0x0038854A')and endpoint['actual_handle_after']==0,'Frozen genuine cold branch frontier')
 before=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin');need(before==priorproof['source_MAIN_stat_after'],'Original MAIN inherited immutable source stat; no open/hash')
 preflight=small('staging/native-player-mainmenu-native-prep/heap-static/mainmenu-native-heap-mutex-preflight.json',300000)
 task=small('evidence/firmware-analysis/native-task-lifecycle-emulation.json',200000)
 contract=small('native/os20-task-bridge/allocator-contract-v1.json',16000)
 need(preflight['static_only']and not preflight['new_guest_execution'],'Preflight read as static contract only')
 need(contract['current_TCB_and_L1_L2_are_declared_fixtures'],'Prior software heap proof acknowledges fixture boundary')
 need(task['ready_task_list']=='0xf09090','Kernel current/ready head provenance')
 u=Uc(UC_ARCH_ARM,UC_MODE_ARM);u.ctl_set_cpu_model(UC_CPU_ARM_1176)
 for a,b in original.items():
  u.mem_map(a,4096,UC_PROT_READ|UC_PROT_WRITE);u.mem_write(a,b);u.mem_protect(a,4096,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(0x09000000,65536,UC_PROT_READ|UC_PROT_WRITE)
 u.mem_protect(0x0900f000,4096,UC_PROT_READ|UC_PROT_EXEC)
 u.mem_map(0x09100000,4096,UC_PROT_READ|UC_PROT_WRITE)
 u.mem_map(0x00f09000,4096,UC_PROT_READ|UC_PROT_WRITE)
 u.mem_map(0x03a7f000,4096,UC_PROT_READ|UC_PROT_WRITE)
 MUTEX,WORK,TCB,CACHE,OPTIONS,REPLY,OUTPUT,RET=0x03a7f18c,0x03a7f170,0x09100000,0x09001000,0x09003000,0x09000000,0x09002000,0x0900f000
 u.mem_write(0xf09090,struct.pack('<I',TCB));u.mem_write(TCB+0x20,struct.pack('<I',0))
 phase=['mutex-native-setup'];trace=[];events=[];stops=[]
 def hook(uc,a,n,_):
  if phase[0]=='mutex-native-setup'and a==RET:
   stops.append(dict(phase=phase[0],address=a,original_return_r0=uc.reg_read(UC_ARM_REG_R0)));uc.emu_stop();return
  if phase[0]=='constructor-ABI-continuation'and a==0x3881bc:
   stops.append(dict(phase=phase[0],address=a,r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),r2=uc.reg_read(UC_ARM_REG_R2),r3=uc.reg_read(UC_ARM_REG_R3),sp=uc.reg_read(UC_ARM_REG_SP)));uc.emu_stop();return
  trace.append(dict(phase=phase[0],address=a,hex=bytes(uc.mem_read(a,n)).hex(),cpsr=uc.reg_read(UC_ARM_REG_CPSR)))
  if a in(0x38854a,0x3009a0,0x3009a8,0x3009f8,0x38854e,0x38855a):events.append(dict(phase=phase[0],address=a,r0=uc.reg_read(UC_ARM_REG_R0),r1=uc.reg_read(UC_ARM_REG_R1),r2=uc.reg_read(UC_ARM_REG_R2),r3=uc.reg_read(UC_ARM_REG_R3),cpsr=uc.reg_read(UC_ARM_REG_CPSR)))
 u.hook_add(UC_HOOK_CODE,hook)
 # Actual original generic kernel initializer, not a success-return fixture.
 for reg,v in[(UC_ARM_REG_CPSR,0x3f),(UC_ARM_REG_SP,0x0900d000),(UC_ARM_REG_LR,RET|1),(UC_ARM_REG_R0,MUTEX)]:u.reg_write(reg,v)
 u.emu_start(0x3008a1,0,count=50,timeout=1000000)
 need(stops[-1]['address']==RET and bytes(u.mem_read(MUTEX,24))==b'\0'*24,'Six original initializer stores and true original return')
 # Reconstruct only known original wrapper ABI frame. Not a saved whole guest.
 wrapper_entry=next(e for e in endpoint['events']if e['address']==0x38853c)
 original_stop=next(e for e in endpoint['events']if e['address']==0x38854a)
 need(original_stop['r0']==MUTEX and (wrapper_entry['r0'],wrapper_entry['r1'],wrapper_entry['r2'])==(0x17c,0,CACHE+0x1c),'Inherited exact register facts')
 SP=wrapper_entry['sp']-24;frame=[MUTEX,0x17c,OPTIONS,REPLY,OUTPUT,0x173b8d]
 u.mem_write(SP,struct.pack('<6I',*frame));u.mem_write(CACHE+0x1c,struct.pack('<I',0))
 phase[0]='constructor-ABI-continuation'
 for reg,v in[(UC_ARM_REG_CPSR,0x3f),(UC_ARM_REG_SP,SP),(UC_ARM_REG_LR,0x173b8d),(UC_ARM_REG_R0,MUTEX),(UC_ARM_REG_R1,0),(UC_ARM_REG_R2,CACHE+0x1c),(UC_ARM_REG_R3,0),(UC_ARM_REG_R4,0x173b8d),(UC_ARM_REG_R5,0x17c),(UC_ARM_REG_R6,0),(UC_ARM_REG_R7,CACHE+0x1c)]:u.reg_write(reg,v)
 u.emu_start(0x38854b,0,count=200,timeout=1000000)
 need(stops[-1]['address']==0x3881bc,'Next true original heap core entry; no core instruction executed')
 returned=next(e for e in events if e['address']==0x38854e);need(returned['r0']==0 and returned['cpsr']==0x3f,'Real original uncontended mutex return and CPSR restoration')
 lockwords=struct.unpack('<6I',u.mem_read(MUTEX,24));need(lockwords[:3]==(0,TCB+0x20,TCB),'Original mutex owner/owned-list link writes')
 need(struct.unpack('<I',u.mem_read(TCB+0x20,4))[0]==MUTEX,'Actual current-task owned head updated byoriginalcode')
 need(stops[-1]['r0']==0x17c and stops[-1]['r1']==0 and stops[-1]['r2']==CACHE+0x1c and stops[-1]['r3']==0x173b8d,'Actual next heap-core ABI')
 need(bytes(u.mem_read(CACHE+0x1c,4))==b'\0'*4,'No synthetic handle success')
 need(bytes(u.mem_read(WORK+0x18,4))==b'\0'*4,'Cold heap core metadata pointer not silently initialized')
 need(stat(ROOT/'evidence/firmware-analysis/main_02bd.bin')==before,'Original MAIN finalstat stable')
 result=dict(schema='garmin-native-query-cold-allocator-continuation/v1',created_utc=datetime.now(timezone.utc).isoformat(),all_assigned_checks_passed=True,logical_cases=1,entry='0x0038854A ABI-fixture continuation',stop='0x003881BC before original heap core first instruction',original_mutex_return_r0=returned['r0'],original_mutex_return_CPSR=returned['cpsr'],instruction_count=sum(x['phase']=='constructor-ABI-continuation'for x in trace),setup_original_initializer_instruction_count=sum(x['phase']=='mutex-native-setup'for x in trace),trace=trace,trace_sha256=sha(json.dumps(trace,sort_keys=True).encode()),events=events,stops=stops,actual_mutex_words=list(lockwords),actual_current_task_owned_head=MUTEX,actual_handle_after=0,heap_core_executed=False,heap_core_context_initialized=False,DIR_created=False,original_full_allocator_return=False,original_full_constructor_return=False,unknown_original_returns_faked=False,original_MAIN_patched=False,warm_fullimage_used=False,old_closed_cases_replayed=False,fixtures=dict(current_task='F09090→09100000/TCB+20 emptyownedlist; fromexactkernelABIanddeclaredsoftwareTCBfixtures;notnativequerytask/scheduler',mutex='Original3008A0sixzero stores; genericmutex initialized; fullheap388B6C tag/header/listener/bootstrap not executed',allocator_wrapper_frame={'source':'Frozenconstructorfrontierobservedregisters+exactnativepush/frameABI','SP':SP,'words':frame,'same_guest_resumed':False,'saved_complete_guest_or_call_stack':False},heap_workspace='Newzero fixture96B at03A7F170; +18 metadataNULL; noL1/L2/freeextent supplied; cannotallocate',sourceID48312='Frozenprecedingcaseannotation; thiscasehasnosourcequery/packedreader/IMGtextactivity',FS_SQLite_OSreturn_hooks=False),new_MAIN_bytes_read=0,new_MAIN_cap=24576,new_IMG_bytes_read=0,device_IO=False,dependencies=DEPS,source_MAIN_stat_before=before,source_MAIN_stat_after=stat(ROOT/'evidence/firmware-analysis/main_02bd.bin'),all_source_handles_closed=True,query_to_getter_uninterrupted=False,native_SQLite=False,native_UI=False,device_acceptance=False,full_Taiwan_completion=False,App_completion=False,installable=False)
 save('actual-continuation.json',result)
 print(json.dumps(dict(all_assigned_checks_passed=True,new_MAIN_bytes_read=0,new_IMG_bytes_read=0,logical_cases=1,continuation_instructions=result['instruction_count'],native_initializer_instructions=result['setup_original_initializer_instruction_count'],original_mutex_return=0,next_entry='0x003881BC',handle_after=0,full_allocator_return=False)))
if __name__=='__main__':main()
