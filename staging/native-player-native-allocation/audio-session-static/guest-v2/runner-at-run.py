#!/usr/bin/env python3
"""NEW v2: only exact original2777F0 selector temporary kind2 opaque fixture.
Frozen v1 image/session/pull/reader/guards unchanged. No native heap claim.
Selector parameter data is copied by original27783E->3732C8, never host-copied.
Original factory/selector results are not intercepted or fabricated.
Parent ROOT executes guest; this source is prepared by the static agent only.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import importlib.util,json,struct,traceback
from datetime import datetime,timezone
import unicorn
from unicorn.arm_const import *
BASE=Path(__file__).resolve().parent;ROOT=BASE.parents[2]
V1=BASE/'emulate_audio_session.py'
s=importlib.util.spec_from_file_location('frozen_audio_session_v1',V1)
v1=importlib.util.module_from_spec(s);s.loader.exec_module(v1)
sha=v1.sha;rel=v1.rel;dump=v1.dump;require=v1.require
old=v1.old

class AudioSessionV2(v1.AudioSession):
 def __init__(self,*args):
  self.selector_frame=None;self.selector_opaque_fixture_calls=[]
  super().__init__(*args)
 def code(self,uc,a,n,data):
  lr=uc.reg_read(UC_ARM_REG_LR)&~1
  if a==0x2777f0:
   args=self.regs();sp=uc.reg_read(UC_ARM_REG_SP)
   require(lr==0x277aee and args[0]==v1.RECORD+0x1a8,
           'selector copy helper outside original277AC2/list contract')
   require(args[1]==self.word(v1.RECORD+0x1ac),'selector helper key differs from actual native current key')
   require(old.STACK_START<=args[2] and args[2]+4<=old.STACK,
           'selector output cell outside declared stack')
   self.selector_frame=dict(entry=hex(a),args=args,SP=sp,LR=uc.reg_read(UC_ARM_REG_LR),
                            stack_args=list(struct.unpack('<2I',uc.mem_read(sp,8))))
  if a==0x38853c and uc.reg_read(UC_ARM_REG_R1)==2:
   # Do not invoke v1's queue-only kind3 allocator predicate. Preserve its
   # code observer bookkeeping, then perform only this new exact fixture.
   require(self.pending_lower is None and self.pending_full is None,'selector allocation overlaps native pending return')
   self.instructions+=1;self.visits[a]+=1
   self.last_instruction=(a,n,bool(uc.reg_read(UC_ARM_REG_CPSR)&32),bytes(uc.mem_read(a,n)).hex())
   self.trace.append(hex(a));self.trace=self.trace[-32:]
   args=self.regs();sp=uc.reg_read(UC_ARM_REG_SP);node=uc.reg_read(UC_ARM_REG_R4)
   frame=self.selector_frame
   require(frame is not None and self.phase=='original_start_selector_factory_and_capture',
           'kind2 allocation outside selector phase/frame')
   require(lr==0x277832 and args[0]==0x20c and args[1]==2 and args[2]==frame['args'][2],
           'unexpected selector allocation caller/length/kind/output cell')
   require(sp==frame['SP']-48 and args[2]==sp+0x84,
           'selector48-byte helper frame/output-cell provenance mismatch')
   source=[h for h in self.handles.values()if h['pointer']==node and h['size']==0x421 and not h.get('released')]
   require(len(source)==1 and struct.unpack('<H',uc.mem_read(node+0x10,2))[0]==args[0],
           'selector allocation length not from original live queue node')
   require(not self.fail_allocation,'unimplemented selector allocation-failure fixture requested')
   require(self.next_handle<=16,'declared opaque fixture heap exhausted')
   handle=0xd0000000+self.next_handle;pointer=old.HEAP+(self.next_handle-1)*4096+32;self.next_handle+=1
   self.handles[handle]=dict(pointer=pointer,size=args[0],queries=0,kind=2,
                            selector_node=node,selector_copy=True,output_cell=args[2])
   self.fixture(pointer-32,b'\xa5'*(args[0]+64),'exact selector kind2 opaque backing and32-byte guards; no native heap')
   self.fixture(args[2],struct.pack('<I',handle),'exact selector opaque allocator output fixture only')
   row=dict(entry=hex(a),args=args,LR=uc.reg_read(UC_ARM_REG_LR),SP=sp,handle=handle,
    pointer=pointer,node=node,native_node_length=args[0],frame=frame,phase=self.phase,
    scope='NEW exact27782E kind2 selector temporary opaque allocation fixture; no native allocator result claim')
   self.selector_opaque_fixture_calls.append(row);self.native_boundaries.append(row)
   self.boundary_return(0);return
  if a in (0x388804,0x388b22):
   args=self.regs();h=self.handles.get(args[0])
   if h and h.get('selector_copy'):
    allowed={0x388804:(0x277838,0x2f9ff6),0x388b22:(0x277848,)}[a]
    require(lr in allowed and not h.get('released'),'selector temporary query/completion outside exact native caller/lifetime')
    row=dict(entry=hex(a),args=args,LR=uc.reg_read(UC_ARM_REG_LR),SP=uc.reg_read(UC_ARM_REG_SP),
             handle=args[0],pointer=h['pointer'],size=h['size'],phase=self.phase,
             scope='exact selector temporary kind2 query; no pinning or native heap claim')
    if a==0x388b22 or lr==0x2f9ff6:
     before=bytes(uc.mem_read(h['selector_node']+0x12,h['size']))
     actual=bytes(uc.mem_read(h['pointer'],h['size']))
     require(actual==before,'original selector memcpy did not copy complete524-byte params')
     row.update(original_copy_27783E_3732C8_bytes_equal=True,parameter_sha256=v1.hashlib.sha256(actual).hexdigest())
    if a==0x388b22:row['original_BX_LR_executed_by_parent']=True
    self.selector_opaque_fixture_calls.append(row)
  super().code(uc,a,n,data)
 def finish(self,name,pulls):
  result=super().finish(name,pulls)
  h=[h for h in self.handles.values()if h.get('selector_copy')]
  require(len(h)==1 and h[0].get('released'),'original selector temporary handle not released through declared service')
  require([int(r['entry'],16)for r in self.selector_opaque_fixture_calls]==
          [0x38853c,0x388804,0x388b22,0x388804],
          'unexpected temporary selector allocation/query/completion history')
  result['selector_opaque_fixture_calls']=self.selector_opaque_fixture_calls
  result['original_selector_copy_exact524_bytes']=True
  result['native_heap_allocator_or_pinning_verified']=False
  return result

def main():
 require(unicorn.__version__=='2.1.4','requires isolated Unicorn2.1.4')
 runtime=BASE/'guest-v2';runtime.mkdir(exist_ok=False)
 build=json.loads((BASE/'build-v3.json').read_text())
 source={rel(Path(__file__).resolve()):sha(Path(__file__).resolve()),rel(V1):sha(V1),rel(v1.OLD):sha(v1.OLD),
  'scripts/analyze_native_sections.py':sha(ROOT/'scripts/analyze_native_sections.py'),
  'evidence/firmware-analysis/main_02bd.bin':sha(ROOT/'evidence/firmware-analysis/main_02bd.bin')}
 require(source['evidence/firmware-analysis/main_02bd.bin']==v1.EXPECTED,'wrong MAIN')
 source.update(build['source_sha256']);source.update(build['generated_sha256'])
 for p in (BASE/'build-v3.json',ROOT/build['ELF'],BASE/'audio-session-v1-failure-scope-erratum.json',
           BASE/'selector-opaque-v2-preflight.json'):
  source[rel(p)]=sha(p)
 for p,h in source.items():require(sha(ROOT/p)==h,'input changed '+p)
 (runtime/'runner-at-run.py').write_bytes(Path(__file__).read_bytes());dump(runtime/'inputs-at-run.json',source)
 mod=v1.load(ROOT/'staging/native-player-dispatcher-native-body/music-static/analyze_single_image_link_bindings.py','aas_v2_elf')
 elf=mod.ELF32(ROOT/build['ELF']);stock=v1.NativeImage();cases=[];m=None
 try:
  for name in ('two_full_original_pulls','local_Stop_prevents_original_pull'):
   m=AudioSessionV2(stock,elf,build);m.setup();pulls=[]
   if name=='two_full_original_pulls':pulls=[m.pull(),m.pull()]
   else:
    require(m.call('aas_stop',phase='local_stop_request')==1,'local Stop request failed')
    calls=len(m.full_returns);before=bytes(m.uc.mem_read(v1.BUFFER,v1.RING_BYTES))
    require(m.call('aas_pull',(8,),phase='stopped_pull_admission')==0,'denied wrapper did not return0')
    require(len(m.full_returns)==calls and bytes(m.uc.mem_read(v1.BUFFER,v1.RING_BYTES))==before,
            'rejected Stop pull entered native body or altered mixer ring')
   row=m.finish(name,pulls);path=runtime/(name+'.json');dump(path,row)
   cases.append(dict(name=name,path=rel(path),sha256=sha(path),passed=True))
   print(name+' PASS',flush=True);m.uc=None;m=None
  proof=dict(all_passed=True,source_sha256=source,cases=cases,case_count=len(cases),
    updated_utc=datetime.now(timezone.utc).isoformat(),
    actual_compiled_submit_ticket_and_original_selector_provider=True,
    original_full_pull_to_compiled_FIFO_and_complete_lease_returns=True,
    original_selector_copy_exact524_bytes=True,NEW_selector_temporary_kind2_opaque_fixture=True,
    independent_RW_replay=False,in_runner_complete_joint_CPU_fixture_replay=True,
    original_MAIN_code_not_patched=True,raw_PCM_source_input_fixture=True,
    original_queue_selector_factory_reader_copy_not_stubbed=True,
    original_native_mixer_caller_redirected=False,source_owner_to_mixer_handoff_verified=False,
    native_heap_allocator_pinning_mutex_scheduler_hardware_App_exclusive_or_STOP_DONE_verified=False,device_io=False)
  dump(BASE/'audio-session-emulation-v2-proof.json',proof)
  print(json.dumps(dict(all_passed=True,proof=rel(BASE/'audio-session-emulation-v2-proof.json'))))
 except BaseException as e:
  row=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),cases_completed=cases,
           source_sha256=source,guest_success=False,device_io=False)
  if m:
   regs=[('r'+str(i),r)for i,r in enumerate((UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,
     UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,
     UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12))]
   regs += [('pc',UC_ARM_REG_PC),('lr',UC_ARM_REG_LR),('sp',UC_ARM_REG_SP),('cpsr',UC_ARM_REG_CPSR)]
   row.update(phase=m.phase,trace=m.trace,flow=m.flow,readers=m.readers,full_returns=m.full_returns,
    registers={n:hex(m.uc.reg_read(r))for n,r in regs},
    CPU_store_journal=m.journal,declared_fixture_mutations=m.fixtures,
    lower_fixture_calls=m.native_boundaries,additional_declared_service_fixtures=m.declared_services,
    selector_opaque_fixture_calls=m.selector_opaque_fixture_calls,
    initial_ordinal=m.initial_ordinal,initial_whole_RW_zones=m.initial,
    final_whole_RW_zones={str(a):bytes(m.uc.mem_read(a,n)).hex()for a,n,p in m.zones if not p&unicorn.UC_PROT_EXEC})
  dump(runtime/'terminal-failure.json',row);raise
if __name__=='__main__':main()
