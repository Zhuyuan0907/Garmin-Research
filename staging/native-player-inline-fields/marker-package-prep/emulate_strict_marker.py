#!/usr/bin/env python3
"""NEW bounded strict marker controls. Current outer file/map inputs are fixtures.
Original bootstrap,40 registration, mixed mutex/try bodies,2D30AE,opaque query,
selector/getter and page callsite execute. No physical or package acceptance.
"""
import sys
sys.dont_write_bytecode=True
import importlib.util,json,struct,hashlib,gc,mmap,traceback
from pathlib import Path
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
basepath=ROOT/'staging/native-player-inline-fields/code-marker/source-at-v4-run.py'
spec=importlib.util.spec_from_file_location('frozen_marker_v4',basepath);base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from unicorn.arm_const import *
import unicorn
LIST=base.LIST;HEAP=base.HEAP;TCB=base.TCB;STACK=base.STACK;IMAGE=base.IMAGE
MAP=0x105e424;PARENT=0x105e624;SLOTSEM=PARENT+4;FILE=0x0803b000;FILESEM=FILE+32;PROVIDER=0x0803c000;DRIVER=0x0803c100;OTHER=0x0803d000
RESOURCES=[];LAST_VM=None
def require(v,m):
 if not v:raise ValueError(m)
def guard(stage):
 text=Path('/proc/self/status').read_text();vals={k:int(line.split(':')[1].split()[0]) for line in text.splitlines() for k in ['VmRSS','VmHWM'] if line.startswith(k+':')};RESOURCES.append({'stage':stage,**vals});require(max(vals.values())<200*1024,'Actual /proc VmRSS/VmHWM exceeds200MiB')
def save(p,o):p.write_text(json.dumps(o,ensure_ascii=False,indent=2)+'\n')
class StrictVM(base.MarkerVM):
 def __init__(self,*args):
  self.try_pending=[];self.try_calls=[];self.setup=False;super().__init__(*args)
  self.uc.mem_map(MAP&~4095,4096);self.call(0x3008a0,(SLOTSEM,));self.call(0x3008a0,(FILESEM,));guard('constructor')
 def observe(self,uc,address,size,unused):
  if self.instructions%100000==0:guard('native instruction boundary')
  if self.try_pending and address==(self.try_pending[-1]['lr']&~1):
   row=self.try_pending.pop();p=row['pointer'];raw=uc.reg_read(UC_ARM_REG_R0)
   require(row['epilog'] and uc.reg_read(UC_ARM_REG_SP)==row['sp'] and raw in [0,1],'Original try epilog/SP/result')
   require(bool(uc.reg_read(UC_ARM_REG_CPSR)&32)==bool(row['lr']&1),'Original try ARM/Thumb continuation')
   require((self.word(p+8)==row['current']) if raw else (bytes(uc.mem_read(p,24)).hex()==row['before']),'Original try owner/result semantics')
   row.update(raw_return=raw,returned=True,after=bytes(uc.mem_read(p,24)).hex());self.try_calls.append(row)
  if address==0x300934:
   p=uc.reg_read(UC_ARM_REG_R0)
   if p in [LIST,SLOTSEM,FILESEM]:self.try_pending.append({'entry':hex(address),'pointer':p,'lr':uc.reg_read(UC_ARM_REG_LR),'sp':uc.reg_read(UC_ARM_REG_SP),'current':self.word(0xf09090),'before':bytes(uc.mem_read(p,24)).hex(),'epilog':False})
  if address==0x300998 and self.try_pending:self.try_pending[-1]['epilog']=True
  if address==0x3008b0 and uc.reg_read(UC_ARM_REG_R0) in [SLOTSEM,FILESEM]:
   p=uc.reg_read(UC_ARM_REG_R0);self.pending.append({'entry':hex(address),'pointer':p,'lr':uc.reg_read(UC_ARM_REG_LR),'sp':uc.reg_read(UC_ARM_REG_SP),'before':bytes(uc.mem_read(p,24)).hex(),'epilog_seen':False});return
  return super().observe(uc,address,size,unused)
 def write(self,uc,access,address,size,value,unused):
  if not self.zones:return
  for name,(a,n) in self.zones.items():
   if address<a+n and address+size>a:
    require(a<=address and address+size<=a+n and size in [1,2,4,8],'Strict whole-zone boundary/width')
    row={'zone':name,'address':address,'size':size,'value':value,'before_hex':bytes(uc.mem_read(address,size)).hex(),'pc':self.last_pc,'opcode_hex':bytes(uc.mem_read(self.last_pc,self.last_size)).hex(),'cpsr':uc.reg_read(UC_ARM_REG_CPSR)};self.journals.append(row)
    if name=='record' and a+0x6b8<=address<a+0x6c2:
     require(size==2 and self.manifest['symbols']['cache_marker_entry']<=self.last_pc<IMAGE+self.manifest['combined_ram'],'Strict marker not compiled STRH')
     require(self.word(TCB+32)==FILESEM and self.word(FILESEM)==SLOTSEM and self.word(SLOTSEM)==LIST and self.word(LIST)==0,'Strict native three-owned chain')
     require(all(self.word(s+8)==TCB for s in [LIST,SLOTSEM,FILESEM]),'Strict marker lacks all native owners');self.marker_stores.append(row)
    if name=='selected':self.publications.append(row)
 def typed_outer_file(self,path,kind):
  self.uc.mem_write(MAP+2*99,bytes([0 if kind=='inactive_region' else 1,0]));self.put(PARENT+28,FILE)
  self.uc.mem_write(FILE,b'\x01');self.put(FILE+12,PROVIDER);self.put(PROVIDER+44,DRIVER);self.uc.mem_write(DRIVER+1,bytes([10 if kind=='multidigit_driver' else 0]))
  name=('/Garmin/Voice/other.vpm' if kind=='wrong_current_path' else path[2:]);handle=self.filename_handle(name);self.put(FILE+4,handle)
  if kind=='inactive_file':self.uc.mem_write(FILE,b'\0')
  return {'fixture':True,'region':99,'map_address':MAP+198,'slot':0,'slot_sem':SLOTSEM,'generic_file':FILE,'generic_file_bytes':72,'file_sem':FILESEM,'provider':PROVIDER,'driver_descriptor':DRIVER,'driver_byte1':10 if kind=='multidigit_driver' else 0,'borrowed_original_file_name_handle':handle,'name_utf16':name,'original_2D30AE_body_not_hooked':True}

def run(stock,inventory,manifest,kind):
 global LAST_VM
 vm=StrictVM(stock,inventory,(ROOT/manifest['combined_file']).read_bytes(),manifest);LAST_VM=vm
 e=vm.enumerate();r=e['registry'][0];h=r['handle'];p=vm.handles[h]['pointer'];outer=vm.typed_outer_file(r['filename'],kind);typed=[]
 if kind=='duplicate_ID':
  raw=bytes(vm.uc.mem_read(p,1912));nh=0xd0000000+len(vm.handles)+1;np=vm.next_heap;vm.next_heap+=(1912+127)&~63;vm.uc.mem_write(np-32,b'\xa5'*(1912+64));vm.uc.mem_write(np,raw);vm.put(np+0x774,0);vm.put(p+0x774,nh);vm.handles[nh]={'pointer':np,'length':1912,'locks':0,'freed':False};typed.append({'duplicate_1912_RAM_record_fixture':True,'handle':nh,'payload':np,'not_original_enumerator_produced':True})
 if kind=='preexisting_marker_unknown_history':vm.uc.mem_write(p+0x6b8,'M7Q9\0'.encode('utf-16le'));typed.append({'host_negative_RAM_input_only':'preexisting marker, never claimed code marker execution'})
 if kind=='foreign_file_lock':
  vm.put(0xf09090,OTHER);vm.call(0x300934,(FILESEM,));vm.put(0xf09090,TCB);require(vm.word(FILESEM+8)==OTHER,'Actual native foreign try lock did not acquire');typed.append({'current_head_fixture_transition':[TCB,OTHER,TCB],'foreign_owner_obtained_by_original300934':True,'foreign_TCB':OTHER})
 vm.allow_module_execution=True;vm.loader_input=True;vm.cpu_input_write(IMAGE,b'\xa5'*manifest['combined_ram']);vm.begin_journal(p)
 bss=manifest['symbols']['__marker_bss_start'];end=manifest['symbols']['__marker_bss_end'];vm.zones.update(outer_file=(FILE,72),slot_record=(PARENT,36),private_state=(bss,end-bss),provider=(PROVIDER,64),driver=(DRIVER,4),map_entry=(MAP+198,2))
 vm.zone_before={k:bytes(vm.uc.mem_read(a,n)) for k,(a,n) in vm.zones.items()};s1=vm.call(0x240498,(0,0));guard(kind+' selector')
 first=bytes(vm.uc.mem_read(manifest['symbols']['marker_state'],52));expected_reason={'valid_unique_repeat':0,'duplicate_ID':8,'wrong_current_path':16,'inactive_region':10,'inactive_file':15,'multidigit_driver':16,'preexisting_marker_unknown_history':18,'foreign_file_lock':14}[kind]
 require(struct.unpack_from('<I',first,24)[0]==expected_reason,'Strict reason differs '+kind)
 if kind=='valid_unique_repeat':
  vm.call(0x240498,(0,0));second=bytes(vm.uc.mem_read(manifest['symbols']['marker_state'],52));require(first[40:50]==second[40:50]=='2.10\0'.encode('utf-16le'),'Repeated entry lost actual original before bytes');require(struct.unpack_from('<I',second,24)[0]==17 and struct.unpack_from('<I',second,16)[0]==2,'Repeat not recognized without state clear')
 else:second=None
 require(s1==11 and all(x['raw_return']==11 for x in vm.entry_rows) and vm.word(base.SELECTED)==0,'Strict optional marker changed original success/result')
 require(len(vm.marker_stores)==(5 if kind=='valid_unique_repeat' else 0),'Strict unexpected version stores')
 out=0x0801b000;vm.call(0x2744f6,(0,out));version=bytes(vm.uc.mem_read(out,10));expect='M7Q9\0' if kind in ['valid_unique_repeat','preexisting_marker_unknown_history'] else '2.10\0';require(version==expect.encode('utf-16le'),'Strict getter result')
 frame=STACK-0x500;vm.uc.reg_write(UC_ARM_REG_SP,frame);vm.uc.reg_write(UC_ARM_REG_R0,0);vm.uc.reg_write(UC_ARM_REG_R1,frame+0x2bc);vm.fragment(0x6817d2,0x6817d6);require(bytes(vm.uc.mem_read(frame+0x2bc,10))==version,'Strict page getter input')
 require(not vm.try_pending and all(x['returned'] for x in vm.try_calls),'Try scopes not complete')
 zones=vm.finish_journal();guard(kind+' endpoint');module=bytes(vm.uc.mem_read(IMAGE,2296496));exports=vm.registration_rows[-1]['targets']
 result={'name':kind,'all_passed':True,'typed_outer_file_and_map_input':outer,'additional_typed_negative_inputs':typed,'original_metadata_enumerator_registry':r,'native_entry_and_bootstrap_rows':{'entry':vm.entry_rows,'bootstrap':vm.bootstrap_rows},'first_private_state_hex':first.hex(),'second_private_state_hex':second.hex() if second else None,'actual_retained_before_utf16_hex':first[40:50].hex(),'reason':expected_reason,'CPU_marker_stores':vm.marker_stores,'original_getter_and_page_input_utf16_hex':version.hex(),'try_calls':vm.try_calls,'native_lock_unlock_calls':vm.native_mutex,'whole_zone_CPU_replay':zones,'CPU_write_journal':vm.journals,'original40_targets':exports,'original_postheader_runtime_sha256':base.digest(module[12:]),'original40_stubs_sha256':base.digest(bytes(vm.uc.mem_read(base.STUBS,480))),'original99_imports_sha256':base.digest(bytes(vm.uc.mem_read(0xf09364,396))),'native_calls':vm.calls,'instructions':vm.instructions,'full_physical_opaque_lifecycle_or_package_acceptance_verified':False}
 save(OUT/(kind+'-control.json'),result);LAST_VM=None;del vm;gc.collect();return result

def main():
 require(unicorn.__version__=='2.1.4','Only isolated2.1.4');guard('before inputs');ledger=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/sealed-source-output-ledger.json').read_text());require(all(base.filehash(ROOT/p)==h for p,h in ledger['output_sha256'].items()),'Frozen earlier controls changed')
 before=base.protected();m=json.loads((OUT/'strict_marker/manifest.json').read_text());stock=base.NativeImage();rows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers'];row=next(r for r in rows if 'Chinese_Big5_MeiLing' in r['file']);f=(ROOT/row['file']).open('rb');package=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);inventory=[{'name':Path(row['file']).name,'data':package}]
 cases=[]
 for kind in ['valid_unique_repeat','duplicate_ID','wrong_current_path','inactive_region','inactive_file','multidigit_driver','preexisting_marker_unknown_history','foreign_file_lock']:
  r=run(stock,inventory,m,kind);cases.append(r);print(json.dumps({'control':kind,'passed':True,'stores':len(r['CPU_marker_stores']),'reason':r['reason']}),flush=True)
 baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text())
 for r in cases:
  for k in ['original_postheader_runtime_sha256','original40_stubs_sha256','original99_imports_sha256']:
   originalkey={'original_postheader_runtime_sha256':'original_module_postheader_runtime_sha256','original99_imports_sha256':'original99_imports_sha256','original40_stubs_sha256':'original40_stubs_sha256'}[k];require(r[k]==baseline[originalkey],'Strict variant altered original bootstrap/runtime')
 require(base.protected()==before,'Protected previous sources changed');guard('after final protected streamhash')
 sources=[Path(__file__),OUT/'strict_cache_marker_entry.c',OUT/'build_strict_marker.py',basepath,ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/row['file'],ROOT/'scripts/analyze_tts_vpm.py',ROOT/'staging/native-player-inline-fields/code-marker/cache-marker-seal.json']
 save(OUT/'strict-marker-control-proof.json',{'all_passed':True,'control_count':8,'cases':[{'path':str((OUT/(r['name']+'-control.json')).relative_to(ROOT)),'sha256':base.filehash(OUT/(r['name']+'-control.json')),'name':r['name']} for r in cases],'source_sha256':{str(p.relative_to(ROOT)):base.filehash(p) for p in sources},'resource_samples':RESOURCES,'1363protected_unchanged':True,'native_baseline_original40_imports_postheader_RAM_unchanged':True,'normal_original_and_wrapper_raw_return':11,'currentloader_file_slot_name_inputs_are_declared_fixtures':True,'original_2D30AE_and_300934_and_388804_bodies_execute':True,'actual_source_of_physical_currentloader_inputs_not_dynamically_verified':True,'negative_inputs_no_version_CPU_stores':True,'repeat_retains_actual_original_before_bytes':True,'device_io':False,'package_signature_acceptance':False,'physical_UI_marker':False,'limits':['8 bounded controls under explicit singleTCB/outer-file-map/opaque-descriptor/allocator/release fixtures; not full original FS/kernel/opaque lifecycle or physical acceptance.','Whole native cache/sem/TCB/outerfile/slot/private-state CPU replay; original MAIN APIs and40 exports retained.','Direct file-name identity mirrors original1FDB8E prefix composition but excludes allocation; driver0fixture tested, >=10 refused.','Any mismatch/contention skips optional marker and preserves genuine original raw result. No install/device/sound in this harness.']})
 print(json.dumps({'all_passed':True,'controls':8,'proof':'staging/native-player-inline-fields/marker-package-prep/strict-marker-control-proof.json'}),flush=True)
if __name__=='__main__':
 try:main()
 except Exception as e:
  o={'all_passed':False,'error':repr(e),'traceback':traceback.format_exc(),'resources':RESOURCES,'source_sha256':base.filehash(Path(__file__))}
  if LAST_VM is not None:o['partial_VM']={'last_pc':hex(LAST_VM.last_pc),'pending':LAST_VM.pending,'try_pending':LAST_VM.try_pending,'entries':LAST_VM.entry_rows,'CPU_journal':LAST_VM.journals}
  save(OUT/'strict-terminal-failure.json',o);raise
