#!/usr/bin/env python3
"""Bounded EMULATION-ONLY preserving-entry/cache/getter controls. No device I/O.

Native registry/metadata/mixed mutex bodies and stock selection/load/entry/getter
execute. Outer storage, lower descriptors/allocations/releases, single TCB and
BIN file input are named fixtures, never physical changed-package acceptance.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
ROOT=Path('/root/garmin'); OUT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'scripts'))
import json,struct,hashlib,time,gc,resource,traceback
import unicorn
from unicorn.arm_const import *
from analyze_native_sections import NativeImage, EXPECTED
from analyze_native_loader import INIT,IMAGE,DESCRIPTOR,STUBS
from emulate_native_voice_registry import RegistryVM,ENUM,DIRECTORY,HEAD
from emulate_native_vpm_filesystem import REGS,STACK,RETURN,TCB
from emulate_native_voice_metadata import require
LIST=0x344cf00; HEAP=0x3a7f18c; SELECTED=0xf095b0
CALLBACKS={0x1fb2f8:'close',0x1fb304:'open',0x1fb3a2:'read',0x1fb3ce:'seek',0x1fb3e4:'tell'}
def digest(b):return hashlib.sha256(b).hexdigest()
def filehash(p):
 h=hashlib.sha256()
 with Path(p).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def save(p,o): p.write_text(json.dumps(o,ensure_ascii=False,indent=2)+'\n')
def protected():
 a=json.loads((ROOT/'staging/native-player-inline-fields/previous-audit.json').read_text())
 return {p:filehash(ROOT/p) for p in a['protected_sources']}

class MarkerVM(RegistryVM):
 def __init__(self,stock,inventory,binary,manifest=None):
  self.pending=[];self.native_mutex=[];self.entry_rows=[];self.bootstrap_rows=[];self.registration_rows=[]
  self.file_events=[];self.binary=binary;self.manifest=manifest;self.loader_input=False;self.position=0
  self.instructions=0;self.stop_pc=None;self.journals=[];self.zones={};self.marker_stores=[];self.publications=[]
  self.getter_entries=[];self.mapper_rows=[];self.bootstrap_pending=[];self.registration_pending=[]
  self.last_pc=0;self.last_size=0
  super().__init__(stock,inventory)
  for p in [LIST&~4095,HEAP&~4095]:self.uc.mem_map(p,4096)
  self.put(0xf09094,0)
  # Fixture TCB already supplied by frozen parent; no live kernel lifecycle.
  self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.write)
  for sem,tagpc,reg,value,stop in [(LIST,0x25506e,UC_ARM_REG_R1,LIST,0x255072),(HEAP,0x388bd0,UC_ARM_REG_R5,HEAP-0x1c,0x388bd4)]:
   require(bytes(self.uc.mem_read(sem,24))==bytes(24),'Cold semaphore storage not zero')
   self.call(0x3008a0,(sem,))
   self.uc.reg_write(reg,value);self.fragment(tagpc,stop)
   require(self.word(sem+8)==0 and self.word(sem+12)==0 and self.word(sem+16)!=0,'Native cold initializer/tag incomplete')
  require(self.word(TCB+32)==0,'Native cold init unexpectedly owns mutex')
  self.init_images={hex(s):bytes(self.uc.mem_read(s,24)).hex() for s in [LIST,HEAP]}
 def fragment(self,pc,stop):
  self.stop_pc=stop;self.returned=False
  self.uc.emu_start(pc|1,stop+2,count=100000,timeout=3000000)
  require(self.returned,'Original fragment failed to reach exact stop');self.stop_pc=None
 def cstring(self,p):
  b=bytearray()
  for i in range(128):
   c=self.uc.mem_read(p+i,1)[0]
   if not c:return b.decode('ascii')
   b.append(c)
  raise ValueError('Unterminated loader input string')
 def call(self,address,args):
  self.returned=False
  for r,v in zip(REGS,args):self.uc.reg_write(r,v)
  self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
  start=time.monotonic();before=self.instructions
  self.uc.emu_start(address|1,RETURN+2,count=1200000,timeout=12000000)
  require(self.returned,f'Bounded native call failed to return: {address:x} PC={self.uc.reg_read(UC_ARM_REG_PC):x}')
  require(not self.pending and not any(self.mutexes.values()),'Mutex scope pending at native return')
  require(self.word(TCB+32)==0,'Fixture task retained owned mutex at native return')
  self.calls.append({'entry':hex(address),'r0':self.uc.reg_read(UC_ARM_REG_R0),'instructions':self.instructions-before,'seconds':time.monotonic()-start})
  return self.uc.reg_read(UC_ARM_REG_R0)
 def observe(self,uc,address,size,unused):
  self.instructions+=1;self.last_pc=address;self.last_size=size
  if self.stop_pc is not None and address==self.stop_pc:
   self.returned=True;uc.emu_stop();return
  # Exact return mode and stack restoration from original mixed body.
  if self.pending and address==(self.pending[-1]['lr']&~1):
   row=self.pending.pop();require(row['epilog_seen'],'Target mutex bypassed original epilog')
   require(uc.reg_read(UC_ARM_REG_SP)==row['sp'],'Native mutex continuation SP mismatch')
   require(bool(uc.reg_read(UC_ARM_REG_CPSR)&32)==bool(row['lr']&1),'Native mutex ARM/Thumb return mismatch')
   row['returned']=True;row['after']=bytes(uc.mem_read(row['pointer'],24)).hex();row['owned_head_after']=self.word(TCB+32)
   self.native_mutex.append(row)
  if address in (0x3009a0,0x3008b0) and uc.reg_read(UC_ARM_REG_R0) in (LIST,HEAP):
   p=uc.reg_read(UC_ARM_REG_R0);self.visits[address]+=1
   require(self.word(0xf09090)==TCB and self.word(0xf09094)==0,'Explicit normal single TCB fixture changed')
   require(self.word(p+12)==0,'Unrecovered contention/waiter scope')
   self.pending.append({'entry':hex(address),'pointer':p,'lr':uc.reg_read(UC_ARM_REG_LR),'sp':uc.reg_read(UC_ARM_REG_SP),'before':bytes(uc.mem_read(p,24)).hex(),'epilog_seen':False})
   return
  if address in (0x300a0a,0x30092a) and self.pending:
   row=self.pending[-1];require(uc.reg_read(UC_ARM_REG_R3)==row['lr'],'Native mutex epilog LR mismatch')
   row['epilog_seen']=True;p=row['pointer'];owner=self.word(p+8);require(owner in [0,TCB],'Unexpected native owner')
   self.mutexes[p]=0 if owner==0 else 1+struct.unpack('<H',uc.mem_read(p+20,2))[0]
  if address in (0x300d08,0x358e70) and self.pending:raise ValueError('Target lock requires unrecovered kernel contention')
  if self.loader_input and address in CALLBACKS:
   a=[uc.reg_read(r) for r in REGS];op=CALLBACKS[address];row={'entry':hex(address),'operation':op,'args':a,'fixture':'BIN file input only'}
   if op=='open':
    require(self.cstring(a[0]).lower()=='dllimg.bin' and self.cstring(a[1])=='rb','Unexpected loader file request')
    self.position=0;value=0x12345678;row['binary_sha256']=digest(self.binary)
    cpsr=uc.reg_read(UC_ARM_REG_CPSR);uc.reg_write(UC_ARM_REG_CPSR,cpsr&~(1<<30))
   elif op=='seek':
    require(a[0]==0x12345678 and a[2] in [0,2],'Loader seek ABI');self.position=(len(self.binary) if a[2]==2 else a[1]);value=0
   elif op=='tell':require(a[0]==0x12345678,'Loader tell ABI');value=self.position
   elif op=='read':
    require(a==[IMAGE,1,len(self.binary),0x12345678],'Loader read ABI');uc.mem_write(IMAGE,self.binary);self.position=len(self.binary);value=len(self.binary)
   else:require(a[0]==0x12345678,'Loader close ABI');value=0
   row['result']=value;self.file_events.append(row);self.ret(value);return
  if address==0x3316ec:
   require(uc.reg_read(UC_ARM_REG_R0)==409,'Unexpected compatibility diagnostic');self.ret(0);return
  if address==0x3b3332:
   require(uc.reg_read(UC_ARM_REG_R0)==DESCRIPTOR and uc.reg_read(UC_ARM_REG_R1)==IMAGE,'Original BLX entry ABI')
   self.entry_rows.append({'caller':hex(address),'entry':hex(IMAGE),'descriptor':DESCRIPTOR,'requested_version':self.word(DESCRIPTOR),'raw_return_pc':'0x3b3334','raw_return':None})
  if address==0x3b3334:self.entry_rows[-1]['raw_return']=uc.reg_read(UC_ARM_REG_R0)
  if address==IMAGE+60868:
   ptr=uc.reg_read(UC_ARM_REG_R0);lr=uc.reg_read(UC_ARM_REG_LR)
   self.bootstrap_pending.append({'entry':hex(address),'descriptor':ptr,'requested_version':self.word(ptr),'return_pc':hex(lr&~1),'lr':lr})
  if self.bootstrap_pending and address==(self.bootstrap_pending[-1]['lr']&~1):
   row=self.bootstrap_pending.pop();row['raw_return']=uc.reg_read(UC_ARM_REG_R0);self.bootstrap_rows.append(row)
  if address==0x2356bc:
   ptr=uc.reg_read(UC_ARM_REG_R1);table=self.word(ptr+12);count=self.word(ptr+20)
   require(count==40,'Original registration did not retain all 40 APIs')
   self.registration_pending.append({'entry':hex(address),'loader_descriptor':uc.reg_read(UC_ARM_REG_R0),'requested_version':self.word(uc.reg_read(UC_ARM_REG_R0)),'module_version':self.word(ptr),'count':count,'targets':list(struct.unpack('<40I',uc.mem_read(table,160))),'lr':uc.reg_read(UC_ARM_REG_LR)})
  if self.registration_pending and address==(self.registration_pending[-1]['lr']&~1):
   row=self.registration_pending.pop();row['actual_callback_return']=uc.reg_read(UC_ARM_REG_R0);row['return_pc']=hex(address);self.registration_rows.append(row)
  if address in (0x23c434,0x23c46c,0x2404c6):self.mapper_rows.append({'pc':hex(address),'r0':uc.reg_read(UC_ARM_REG_R0),'r4':uc.reg_read(UC_ARM_REG_R4),'requested_version':self.word(DESCRIPTOR)})
  if address==0x2744f6:self.getter_entries.append({'entry':hex(address),'index':uc.reg_read(UC_ARM_REG_R0),'destination':uc.reg_read(UC_ARM_REG_R1),'lr':uc.reg_read(UC_ARM_REG_LR)})
  return super().observe(uc,address,size,unused)
 def begin_journal(self,p):
  self.zones={'record':(p,0x778),'list_mutex':(LIST,24),'heap_mutex':(HEAP,24),'fixture_tcb':(TCB,108),'selected':(SELECTED,4)}
  self.zone_before={k:bytes(self.uc.mem_read(a,n)) for k,(a,n) in self.zones.items()}
 def write(self,uc,access,address,size,value,unused):
  if not self.zones:return
  for name,(start,n) in self.zones.items():
   if address<start+n and address+size>start:
    require(start<=address and address+size<=start+n and size in (1,2,4,8),'Journal boundary/store width')
    before=bytes(uc.mem_read(address,size));row={'zone':name,'address':address,'size':size,'value':value,'before_hex':before.hex(),'pc':self.last_pc,'opcode_hex':bytes(uc.mem_read(self.last_pc,self.last_size)).hex(),'cpsr':uc.reg_read(UC_ARM_REG_CPSR)};self.journals.append(row)
    if name=='record' and start+0x6b8<=address<start+0x6c2:
     require(self.manifest is not None and size==2,'Version write is not prototype UTF16 CPU store')
     require(IMAGE+self.manifest['symbols']['cache_marker_entry']-IMAGE<=self.last_pc<IMAGE+self.manifest['combined_ram'],'Version writer outside compiled prototype')
     require(self.word(LIST+8)==TCB and self.word(TCB+32)==LIST,'Marker CPU store without original lock/owned chain')
     self.marker_stores.append(row)
    if name=='selected':self.publications.append(row)
 def finish_journal(self):
  replay={k:bytearray(v) for k,v in self.zone_before.items()}
  for row in self.journals:
   k=row['zone'];off=row['address']-self.zones[k][0];n=row['size'];require(bytes(replay[k][off:off+n]).hex()==row['before_hex'],'Independent CPU journal before mismatch');replay[k][off:off+n]=row['value'].to_bytes(n,'little')
  final={k:bytes(self.uc.mem_read(a,n)) for k,(a,n) in self.zones.items()}
  require(all(bytes(replay[k])==v for k,v in final.items()),'Whole-zone CPU replay failed/unrecorded host mutation')
  return {k:{'address':self.zones[k][0],'bytes':self.zones[k][1],'before_hex':self.zone_before[k].hex(),'after_hex':v.hex(),'replay_passed':True} for k,v in final.items()}

def one(stock,inventory,name,binary,manifest=None):
 vm=MarkerVM(stock,inventory,binary,manifest)
 require(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss<200*1024,'Host RSS bound exceeded')
 enum=vm.enumerate();rows=enum['registry'];require(len(rows)==1 and rows[0]['volume_id']=='mei-lingb','Original registry identity')
 h=rows[0]['handle'];p=vm.handles[h]['pointer'];before=bytes(vm.uc.mem_read(p,0x778));require(before[0x6b8:0x6c2]=='2.10\0'.encode('utf-16le'),'Original native version input')
 vm.allow_module_execution=True;vm.loader_input=True;vm.uc.mem_write(IMAGE,b'\xa5'*(manifest['combined_ram'] if manifest else 2296496));vm.begin_journal(p)
 result=vm.call(0x240498,(0,0));after=bytes(vm.uc.mem_read(p,0x778));selected=vm.word(SELECTED)
 # Then read with original getter and stop original page callsite after getter.
 out=0x0801b000;vm.uc.mem_write(out,b'\xa5'*32);vm.call(0x2744f6,(0,out));version=bytes(vm.uc.mem_read(out,10))
 frame=STACK-0x500;vm.uc.reg_write(UC_ARM_REG_SP,frame);vm.uc.reg_write(UC_ARM_REG_R0,0);vm.uc.reg_write(UC_ARM_REG_R1,frame+0x2bc);vm.uc.mem_write(frame+0x2bc,b'\xa5'*16);vm.fragment(0x6817d2,0x6817d6);consumer=bytes(vm.uc.mem_read(frame+0x2bc,10));require(consumer==version,'Original AudVer callsite consumer input differs')
 zones=vm.finish_journal();marked=name=='preserving_marker';expected='M7Q9\0' if marked else '2.10\0';require(version==expected.encode('utf-16le'),f'{name}: getter {version.hex()} expected {expected}')
 require(before[:0x6b8]==after[:0x6b8] and before[0x6c2:]==after[0x6c2:],'Record changed outside ten-byte RAM marker')
 require(len(vm.marker_stores)==(5 if marked else 0),'Expected exactly five CPU STRH marker stores')
 if marked: require([r['value'] for r in vm.marker_stores]==[ord(c) for c in 'M7Q9']+[0],'Marker units/NUL')
 require(selected==(255 if name=='retry_native_raw6' else 0),'Original late selection publication differs')
 expected_raw={'original_baseline':[11],'preserving_marker':[11],'wrong_identity':[11],'first_native_raw6':[6],'retry_native_raw6':[5,6]}[name]
 require([r['raw_return'] for r in vm.entry_rows]==expected_raw,'Actual raw entry returns differ')
 require([r['raw_return'] for r in vm.bootstrap_rows]==expected_raw,'Actual raw original bootstrap returns differ')
 if manifest: state=bytes(vm.uc.mem_read(manifest['symbols']['marker_state'],40)).hex()
 else:state=None
 require(all(r['returned'] for r in vm.native_mutex),'Native target mutex pending')
 vm.verify_closed_files()
 module=bytes(vm.uc.mem_read(IMAGE,2296496));stubs=bytes(vm.uc.mem_read(STUBS,480));storage=bytes(vm.uc.mem_read(0xf092c4,160));imports=bytes(vm.uc.mem_read(0xf09364,396))
 result={'name':name,'passed':True,'selector_r0':result,'selected_index':selected,'native_registry':rows,'original_metadata_version_utf16_hex':before[0x6b8:0x6c2].hex(),'original_metadata_record_sha256':digest(before),'cache_after_sha256':digest(after),'getter_version_utf16_hex':version.hex(),'consumer_input_utf16_hex':consumer.hex(),'consumer_fragment':{'entry':'0x6817d2','original_ARM_veneer':'0x52c5ec','original_getter':'0x2744f6','stop_before':'0x6817d6','rendered_UI':False},'entry_layers':vm.entry_rows,'original_bootstrap_layers':vm.bootstrap_rows,'native_registration':vm.registration_rows,'MAIN_mapper_layers':vm.mapper_rows,'prototype_state_hex':state,'marker_CPU_stores':vm.marker_stores,'late_selection_CPU_stores':vm.publications,'native_mutex_calls':vm.native_mutex,'cold_original_initializer_images':vm.init_images,'loader_BIN_input_fixture_events':vm.file_events,'calls':vm.calls,'whole_zone_CPU_replay':zones,'CPU_write_journal':vm.journals,'original_module_postheader_runtime_sha256':digest(module[12:]),'original40_stubs_sha256':digest(stubs),'original40_storage_sha256':digest(storage),'original99_imports_sha256':digest(imports),'instructions':vm.instructions,'host_peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
 save(OUT/(name+'-control.json'),result)
 del vm;gc.collect()
 return result,{'module':module[12:],'stubs':stubs,'storage':storage,'imports':imports}

def main():
 require(unicorn.__version__=='2.1.4','Use isolated Unicorn2.1.4 only')
 before=protected();expected=json.loads((ROOT/'staging/native-player-inline-fields/previous-audit.json').read_text())['protected_sources'];require(before==expected,'Protected source mismatch before run')
 stock=NativeImage();rows=json.loads((ROOT/'evidence/firmware-analysis/tts-vpm-containers.json').read_text())['containers'];row=next(r for r in rows if 'Chinese_Big5_MeiLing' in r['file']);package=(ROOT/row['file']).read_bytes();require(digest(package)==row['sha256'],'Immutable original package differs')
 inventory=[{'name':Path(row['file']).name,'data':package}];original=(ROOT/row['module']['extracted_binary']).read_bytes()
 builds=json.loads((OUT/'build-manifest.json').read_text())['builds'];cases=[]
 r,baseline=one(stock,inventory,'original_baseline',original);cases.append(r);print(json.dumps({'case':r['name'],'passed':True,'raw_returns':[e['raw_return'] for e in r['entry_layers']]}),flush=True)
 for m in builds:
  b=(ROOT/m['combined_file']).read_bytes();require(digest(b)==m['binary_sha256'],'Compiled BIN differs')
  r,observed=one(stock,inventory,m['name'],b,m)
  if m['control'] in [0,3]:require(observed==baseline,'Normal preserving entry changed original40/imports/postheader RAM')
  else:require(observed['stubs']==baseline['stubs'] and observed['storage']==baseline['storage'],'Typed ABI input control changed original40')
  cases.append(r);print(json.dumps({'case':r['name'],'passed':True,'raw_returns':[e['raw_return'] for e in r['entry_layers']],'CPU_marker_stores':len(r['marker_CPU_stores'])}),flush=True)
 after=protected();require(after==before,'Protected source changed after controls')
 sources=[Path(__file__),OUT/'cache_marker_entry.c',OUT/'build_cache_marker_prototype.py',ROOT/'staging/native-player-global-subobject/package-marker/runtime-cache-code-marker-contract.json',ROOT/'staging/native-player-inline-fields/previous-audit.json',ROOT/row['file'],ROOT/row['module']['extracted_binary'],ROOT/'evidence/firmware-analysis/main_02bd.bin',ROOT/'evidence/firmware-analysis/tts-vpm-containers.json']+[ROOT/'scripts'/p for p in ['emulate_native_voice_registry.py','emulate_native_voice_metadata.py','emulate_native_vpm_filesystem.py','analyze_native_sections.py','analyze_native_voice_acceptance.py','analyze_tts_vpm.py','analyze_native_loader.py','emulate_native_loader.py','analyze_sdp_activation.py']]
 out={'all_passed':True,'case_count':len(cases),'cases':[{'name':c['name'],'artifact':str((OUT/(c['name']+'-control.json')).relative_to(ROOT)),'artifact_sha256':filehash(OUT/(c['name']+'-control.json')),'passed':True} for c in cases],'MAIN_sha256':EXPECTED,'source_sha256':{str(p.relative_to(ROOT)):filehash(p) for p in sources},'output_sha256':{str(p.relative_to(ROOT)):filehash(p) for p in OUT.rglob('*') if p.is_file() and p.suffix in ['.c','.py','.elf','.bin','.ld','.map','.json']},'protected_before_after':{'count':len(before),'all_unchanged':True,'registry_sha256':digest(json.dumps(before,sort_keys=True).encode())},'unchanged_backup_member_sha256':{k:row['files'][k]['sha256'] for k in ['DLLINFO.TXT','DLLIMG.BIN','DLLIMG.SIG']},'emulation_only':True,'compiled_appended_ARM_instructions_executed':True,'actual_five_UTF16_CPU_stores_to_native_registry_record':True,'original_2744F6_and_page_getter_callsite_executed':True,'original40_exports_and_imports_and_postheader_RAM_preserved_normal_entry':True,'normal_original_bootstrap_raw_return':11,'typed_ABI_input_control_results':{'first_minor_mismatch':{'bootstrap_raw':6,'entry_raw':6,'MAIN_first_mapped':11},'retry_major_then_minor_mismatch':{'bootstrap_raw':[5,6],'entry_raw':[5,6],'MAIN_retry_return':6,'selected_index':255}},'fixtures':['outer directory/file-region binding and drive activation tail routing','original immutable package sector block-read fixture','platform predicate/locale initial values','opaque handle allocations/descriptors/releases','BIN file callbacks give local compiled BIN directly without VPM repack','single explicit RAM TCB/current/IRQ-zero fixture, IRQ services, unrelated FS mutex counters','code-cache invalidation and compatibility diagnostic submission','page frame and callsite inputs, no UI construction/rendering'],'limits':['Aud Ver is original cached DLLINFO version data, not a DLL export. This prototype changes the RAM cache through actually executed appended code, never original metadata bytes.','No physical VPM/SIG acceptance, FAT32 outer mount/open policy or signature enforcement established.','LIST and HEAP unchanged mixed mutex bodies execute uncontended/reentrant normal fixture paths; no full scheduler/waiter/lifetime/kernel proof.','Page consumer input only; full Audio Test UI rendering/reopening/lifetime and modified component installation remain unverified.','Version controls CPU-copy typed loader descriptor to stack and alter only shadow requested-version word; they are explicit ABI controls, not normal preserving candidate.','No navigation/TTS synthesis/40 individual APIs tested, no audio/device/BT/installer/VPM/SIG writes.'], 'device_io':False,'audible_output':False,'modified_VPM_or_SIG_generated':False,'device_install_candidate':False,'physical_changed_code_acceptance_verified':False,'complete_App_or_music_goal':False}
 save(OUT/'cache-marker-emulation-proof.json',out);print(json.dumps({'proof':str((OUT/'cache-marker-emulation-proof.json').relative_to(ROOT)),'all_passed':True,'cases':len(cases)}),flush=True)
if __name__=='__main__':
 try:main()
 except Exception as e:
  save(OUT/'terminal-failure.json',{'all_passed':False,'exception':repr(e),'traceback':traceback.format_exc(),'source_sha256':filehash(Path(__file__)),'emulation_only':True,'no_device_io':True});raise
