#!/usr/bin/env python3
"""Two exact-candidate native-reader controls; lower storage/task/heap fixtures."""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,struct,mmap,gzip,hashlib,traceback,gc,contextlib,io
from pathlib import Path
from datetime import datetime,timezone
from capstone import Cs,CS_ARCH_ARM,CS_MODE_ARM
from unicorn.arm_const import *
ROOT=Path(__file__).resolve().parents[2];BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('frozen_platform_reader_parent',ROOT/'staging/native-player-warm-probe/emulate_candidate_embedded_reader_v1.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
B=P.base;require=P.strict.require;LAST=None
REGS=[UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3,UC_ARM_REG_R4,UC_ARM_REG_R5,UC_ARM_REG_R6,UC_ARM_REG_R7,UC_ARM_REG_R8,UC_ARM_REG_R9,UC_ARM_REG_R10,UC_ARM_REG_R11,UC_ARM_REG_R12,UC_ARM_REG_SP,UC_ARM_REG_LR,UC_ARM_REG_PC]
def sha(p):return B.filehash(p)
def rel(p):return str(p.relative_to(ROOT))
def dump(p,d):
 with p.open('x')as f:json.dump(d,f,indent=2);f.write('\n')
def compressed(p,d):
 with p.open('xb')as f:
  with gzip.GzipFile(fileobj=f,mode='wb',mtime=0)as g:g.write(json.dumps(d,separators=(',',':')).encode())
class PlatformReader(P.ReaderVM):
 def __init__(self,*args):
  self.platform_entries=[];self.platform_returns=[];self.platform_pending=None;self.CP_pending=None;self.platform_reads=[];self.new_register_trace=[];self.arm=Cs(CS_ARCH_ARM,CS_MODE_ARM)
  super().__init__(*args)
 def snapshot(self):return dict(GP16=[self.uc.reg_read(r)for r in REGS],CPSR=self.uc.reg_read(UC_ARM_REG_CPSR))
 def observe(self,u,a,size,unused):
  if self.CP_pending:
   e=self.CP_pending;require(u.reg_read(REGS[e['dest']])==e['reference'],'native loaded probe MRC result differs');e['after']=self.snapshot();self.platform_reads.append(e);self.CP_pending=None
  if self.platform_pending and a==self.platform_pending['return_PC']:
   e=self.platform_pending;r=self.snapshot();require(r['GP16'][13]==e['SP']and r['GP16'][4:12]==e['before']['GP16'][4:12],'loaded platform sample ABI');self.platform_returns.append(dict(e,after=r));self.platform_pending=None
  if self.zones and a==self.manifest['symbols']['sample_platform']:
   require(not self.platform_pending,'nested platform sample');e=dict(before=self.snapshot(),SP=u.reg_read(UC_ARM_REG_SP),return_PC=u.reg_read(UC_ARM_REG_LR)&~1);self.platform_pending=e;self.platform_entries.append(e)
  if self.zones and self.manifest['symbols']['cache_marker_entry']<=a<B.IMAGE+len(self.binary):
   op=bytes(u.mem_read(a,size));ins=next(self.arm.disasm(op,a,count=1),None);require(ins is not None,'new ARM probe instruction decode');require(ins.mnemonic not in('mcr','mcrr','msr'),'new probe wrote system register')
   if ins.mnemonic in('mrs','mrc'):
    row=dict(PC=a,opcode_hex=op.hex(),instruction=ins.mnemonic+' '+ins.op_str,before=self.snapshot());self.new_register_trace.append(row)
    if ins.mnemonic=='mrc':
     word=struct.unpack('<I',op)[0];crn=(word>>16)&15;dest=(word>>12)&15;require(((word>>8)&15)==15 and ((word>>21)&7)==0 and (word&15)==0 and ((word>>5)&7)==0 and crn in(0,1),'new unexpected CP read');row.update(crn=crn,dest=dest,reference=u.cpr_read(15,0,crn,0,0,1,False));self.CP_pending=row
  return super().observe(u,a,size,unused)
def run(stock,inventory,m,bundle,kind,out):
 global LAST
 log=io.StringIO()
 with contextlib.redirect_stdout(log):vm=PlatformReader(stock,inventory,(ROOT/m['combined_file']).read_bytes(),m);LAST=vm;enum=vm.enumerate()
 require(len(vm.metadata_rows)==1 and vm.metadata_rows[0]['raw_return']==1 and not vm.metadata_pending,'candidate native metadata failed');require(vm.metadata_rows[0]['parsed_checksum']==0xca73f5a,'metadata checksum tag changed')
 record=enum['registry'][0];pointer=vm.handles[record['handle']]['pointer'];outer=vm.typed_outer_file(record['filename'],'wrong_current_path'if kind=='wrong_outer_path'else'valid_unique_repeat');vm.allow_module_execution=True;require(not vm.loader_input,'BIN input callbacks enabled')
 vm.cpu_input_write(B.IMAGE,b'\xa5'*m['combined_ram']);vm.begin_journal(pointer);bs=m['symbols']['__marker_bss_start'];be=m['symbols']['__marker_bss_end']
 vm.zones.update(outer_file=(P.strict.FILE,72),slot_record=(P.strict.PARENT,36),private_state=(bs,be-bs),provider=(P.strict.PROVIDER,64),driver=(P.strict.DRIVER,4),map_entry=(P.strict.MAP+198,2),native_audio_bank=(P.warm.AUDIO,P.warm.AUDIO_BYTES));vm.zone_before={k:bytes(vm.uc.mem_read(a,n))for k,(a,n)in vm.zones.items()}
 callbacks=[0x1fb2f8,0x1fb304,0x1fb3a2,0x1fb3ce,0x1fb3e4];before={a:vm.visits[a]for a in callbacks};raw=vm.call(0x240498,(0,0));require(raw==11 and not vm.file_events and all(vm.visits[a]>before[a]for a in callbacks),'actual stock candidate loader did not finish all5 original callbacks')
 state=m['symbols']['marker_state'];first=bytes(vm.uc.mem_read(state,124));reason=struct.unpack_from('<I',first,24)[0];fields=struct.unpack_from('<5I',first,104);repeat=None
 if kind=='positive_cached_repeat':
  require(reason==0 and len(vm.marker_stores)==5 and len(vm.platform_entries)==len(vm.platform_returns)==1 and len(vm.platform_reads)==2 and fields[3]==1,'loaded probe not complete')
  mode=fields[0]&31;ctl=fields[2];flags=int(mode==31)|((ctl&1)<<1)|(ctl&4)|((ctl>>9)&8);want=(flags<<12)|((fields[1]>>4)&4095);require(fields[4]==want,'cached platform tag differs');version=f'{want:04X}\0'
  count=len(vm.platform_reads);require(vm.call(0x240498,(0,0))==11,'cached repeat changed original raw return');repeat=bytes(vm.uc.mem_read(state,124));require(struct.unpack_from('<I',repeat,24)[0]==17 and struct.unpack_from('<I',repeat,16)[0]==2 and repeat[40:]==first[40:]and len(vm.platform_reads)==count and len(vm.marker_stores)==5,'same-image repeat sampled again or changed retained tag')
 else:
  require(reason==16 and not vm.platform_entries and not vm.platform_reads and not vm.marker_stores,'wrong outer path was sampled or marked');version='2.10\0'
 output=0x0801b000;vm.call(0x2744f6,(0,output));observed=bytes(vm.uc.mem_read(output,10));require(observed==version.encode('utf-16le'),'original getter did not return actual CPU tag')
 frame=B.STACK-0x500;vm.uc.reg_write(UC_ARM_REG_SP,frame);vm.uc.reg_write(UC_ARM_REG_R0,0);vm.uc.reg_write(UC_ARM_REG_R1,frame+0x2bc);vm.fragment(0x6817d2,0x6817d6);require(bytes(vm.uc.mem_read(frame+0x2bc,10))==observed,'original AudVer input mismatch')
 require(not vm.platform_pending and not vm.CP_pending,'platform call pending');zones=vm.finish_journal();require(zones['native_audio_bank']['before_hex']==zones['native_audio_bank']['after_hex']and not vm.audio_writes and not vm.probe_reads,'platform probe touched audio bank');vm.verify_closed_files()
 baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text());runtime=bytes(vm.uc.mem_read(B.IMAGE,2296496));require(B.digest(runtime[12:])==baseline['original_module_postheader_runtime_sha256']and B.digest(bytes(vm.uc.mem_read(B.STUBS,480)))==baseline['original40_stubs_sha256'],'original voice/runtime40 changed')
 row=dict(all_passed=True,name=kind,candidate_sha256=bundle['candidate_sha256'],native_metadata_rows=vm.metadata_rows,native_metadata_points=vm.metadata_points,original_selector_calls=vm.calls,original_entry_rows=vm.entry_rows,original_bootstrap_rows=vm.bootstrap_rows,original_registration_rows=vm.registration_rows,original40_targets=vm.registration_rows[-1]['targets'],actual_original_loader_callbacks={hex(a):vm.visits[a]-before[a]for a in callbacks},BIN_callback_input_fixture=False,typed_outer_file_input=outer,first_private_state_hex=first.hex(),repeat_private_state_hex=repeat.hex()if repeat else None,platform_entries=vm.platform_entries,platform_full_returns=vm.platform_returns,actual_platform_MRC_observations=vm.platform_reads,new_probe_register_instruction_trace=vm.new_register_trace,CPU_version_stores=vm.marker_stores,CPU_write_journal=vm.journals,whole_zone_CPU_replay=zones,getter_and_page_input_utf16_hex=observed.hex(),tag=version.rstrip('\0'),new_audio_reads=vm.probe_reads,new_audio_writes=vm.audio_writes,original_postheader_runtime_sha256=B.digest(runtime[12:]),original40_stubs_sha256=B.digest(bytes(vm.uc.mem_read(B.STUBS,480))),explicit_lower_FAT_heap_TCB_platform_cache_outer_identity_fixtures=True,CPU_values_are_emulator_model_not_unit_measurements=True,device_IO=False)
 artifact=out/(kind+'.json.gz');compressed(artifact,row);LAST=None;del vm;gc.collect();return dict(name=kind,path=rel(artifact),sha256=sha(artifact),tag=row['tag'],MRC=len(row['actual_platform_MRC_observations']),version_stores=len(row['CPU_version_stores']),passed=True)
def main():
 out=BASE/'reader-v1';out.mkdir(exist_ok=False);m=json.loads((BASE/'strict_marker/manifest.json').read_text());bundle=json.loads((BASE/'local-platform-probe-bundle-v1.json').read_text());candidate=ROOT/bundle['candidate_path'];require(sha(candidate)==bundle['candidate_sha256'],'candidate changed');stock=B.NativeImage();f=candidate.open('rb');data=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);inventory=[dict(name='Chinese_Big5_MeiLing.vpm',data=data)]
 deps=dict(m['source_sha256']);sources=[Path(__file__),BASE/'strict_marker/manifest.json',ROOT/m['combined_file'],BASE/'local-platform-probe-bundle-v1.json',candidate,ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json']
 for module in list(sys.modules.values()):
  p=getattr(module,'__file__',None)
  if p and Path(p).is_file()and Path(p).is_relative_to(ROOT)and 'site-packages'not in Path(p).parts:sources.append(Path(p))
 deps.update({rel(p):sha(p)for p in sources});dump(out/'inputs-at-run.json',deps);(out/'runner-at-run.py').write_bytes(Path(__file__).read_bytes());cases=[]
 try:
  for kind in('positive_cached_repeat','wrong_outer_path'):
   cases.append(run(stock,inventory,m,bundle,kind,out));print(json.dumps(cases[-1]),flush=True)
  require(all(sha(ROOT/p)==h for p,h in deps.items()),'reader dependencies changed');proof=dict(all_passed=True,case_count=2,cases=cases,source_sha256=deps,exact_candidate_original_container_and_five_callbacks=True,cached_repeat_not_live_diagnostic=True,new_probe_CP15_writes=0,physical_candidate_acceptance_CPU_or_Main_permission_or_App_proven=False,device_IO=False,updated_utc=datetime.now(timezone.utc).isoformat());dump(BASE/'platform-candidate-reader-v1-proof.json',proof);print(json.dumps(dict(all_passed=True,case_count=2,actual_model_tags=[r['tag']for r in cases],device_IO=False)),flush=True)
 except BaseException as e:
  fail=dict(all_passed=False,error=str(e),traceback=traceback.format_exc(),completed_cases=cases,source_sha256=deps,device_IO=False)
  if LAST:fail.update(last_PC=LAST.last_pc,platform_entries=LAST.platform_entries,platform_reads=LAST.platform_reads,CPU_write_journal=LAST.journals)
  compressed(out/'terminal-failure.json.gz',fail);raise
if __name__=='__main__':main()
