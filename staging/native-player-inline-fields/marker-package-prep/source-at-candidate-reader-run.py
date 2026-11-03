#!/usr/bin/env python3
"""ONE new original embedded-reader control on exact local candidate VPM.
No BIN callbacks are intercepted. Lower region/outer file-map/heap/TCB inputs
remain explicit fixtures; higher physical FAT/SIG acceptance is unverified.
"""
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import json,importlib.util,struct,mmap,traceback,gc
ROOT=Path('/root/garmin');OUT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('sealed_strict',OUT/'source-at-strict-first-run.py');strict=importlib.util.module_from_spec(spec);spec.loader.exec_module(strict)
base=strict.base
from unicorn.arm_const import *
VM=None
class ReaderVM(strict.StrictVM):
 def call(self,address,args):
  self.returned=False
  for reg,value in zip(base.REGS,args):self.uc.reg_write(reg,value)
  self.uc.reg_write(UC_ARM_REG_SP,base.STACK);self.uc.reg_write(UC_ARM_REG_LR,base.RETURN|1)
  before=self.instructions;self.uc.emu_start(address|1,base.RETURN+2,count=4000000,timeout=15000000)
  strict.require(self.returned,'Original candidate reader call exceeded4M/15s: '+hex(self.last_pc));strict.require(not self.pending and not self.try_pending and not any(self.mutexes.values()),'Original candidate reader scope pending');strict.require(self.word(base.TCB+32)==0,'Candidate reader left task-owned mutex');self.calls.append({'entry':hex(address),'r0':self.uc.reg_read(UC_ARM_REG_R0),'instructions':self.instructions-before});return self.uc.reg_read(UC_ARM_REG_R0)
def main():
 global VM
 strict.guard('before reader inputs');m=json.loads((OUT/'strict_marker/manifest.json').read_text());bundle=json.loads((OUT/'local-marker-bundle-manifest-v2.json').read_text());p=ROOT/bundle['candidate_path'];strict.require(base.filehash(p)==bundle['candidate_sha256'],'Exact local candidate changed');f=p.open('rb');data=mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ);stock=base.NativeImage();vm=ReaderVM(stock,[{'name':'Chinese_Big5_MeiLing.vpm','data':data}],(ROOT/m['combined_file']).read_bytes(),m);VM=vm
 enum=vm.enumerate();r=enum['registry'][0];record=vm.handles[r['handle']]['pointer'];outer=vm.typed_outer_file(r['filename'],'valid_unique_repeat');vm.allow_module_execution=True
 # loader_input remains FALSE: all5 stock file callbacks execute on candidate.
 strict.require(not vm.loader_input,'BIN input callback fixture activated');vm.cpu_input_write(base.IMAGE,b'\xa5'*m['combined_ram']);vm.begin_journal(record);bs=m['symbols']['__marker_bss_start'];be=m['symbols']['__marker_bss_end'];vm.zones.update(outer_file=(strict.FILE,72),slot_record=(strict.PARENT,36),private_state=(bs,be-bs),provider=(strict.PROVIDER,64),driver=(strict.DRIVER,4),map_entry=(strict.MAP+198,2));vm.zone_before={k:bytes(vm.uc.mem_read(a,n)) for k,(a,n) in vm.zones.items()}
 callbacks=[0x1fb2f8,0x1fb304,0x1fb3a2,0x1fb3ce,0x1fb3e4];before={a:vm.visits[a] for a in callbacks};status=vm.call(0x240498,(0,0));strict.guard('after candidate actual embedded reader and entry');strict.require(status==11 and len(vm.marker_stores)==5 and not vm.file_events,'Original candidate embedded loader did not execute actual marker');strict.require(all(vm.visits[a]>before[a] for a in callbacks),'A stock loader file callback did not execute')
 output=0x0801b000;vm.call(0x2744f6,(0,output));version=bytes(vm.uc.mem_read(output,10));strict.require(version=='M7Q9\0'.encode('utf-16le'),'Actual candidateVPM getter did not readCPUmarker');frame=base.STACK-0x500;vm.uc.reg_write(UC_ARM_REG_SP,frame);vm.uc.reg_write(UC_ARM_REG_R0,0);vm.uc.reg_write(UC_ARM_REG_R1,frame+0x2bc);vm.fragment(0x6817d2,0x6817d6);strict.require(bytes(vm.uc.mem_read(frame+0x2bc,10))==version,'Actual candidate page input differs')
 zones=vm.finish_journal();vm.verify_closed_files();baseline=json.loads((ROOT/'staging/native-player-inline-fields/code-marker/original_baseline-control.json').read_text());runtime=bytes(vm.uc.mem_read(base.IMAGE,2296496));strict.require(base.digest(runtime[12:])==baseline['original_module_postheader_runtime_sha256'],'Actual candidate read changed original module runtime');strict.require(base.digest(bytes(vm.uc.mem_read(base.STUBS,480)))==baseline['original40_stubs_sha256'],'Actual candidate read changed original40')
 strict.guard('candidate reader endpoint');sources=[Path(__file__),OUT/'source-at-strict-first-run.py',ROOT/'staging/native-player-inline-fields/code-marker/source-at-v4-run.py',OUT/'strict_marker/manifest.json',ROOT/m['combined_file'],OUT/'local-marker-bundle-manifest-v2.json',p,ROOT/'evidence/firmware-analysis/main_02bd.bin']
 result={'all_passed':True,'bounded_control_count':1,'candidate_sha256':bundle['candidate_sha256'],'source_sha256':{str(p.relative_to(ROOT)):base.filehash(p) for p in sources},'actual_original5_loader_callbacks_not_intercepted':True,'loader_file_callback_entries_during_selection':{hex(a):vm.visits[a]-before[a] for a in callbacks},'metadata_and_loader_native_open_names':vm.open_attempts,'native_selector_and_bootstrap_rows':{'calls':vm.calls,'entry':vm.entry_rows,'bootstrap':vm.bootstrap_rows,'registration':vm.registration_rows},'actual_CPU_marker_stores':vm.marker_stores,'whole_zone_CPU_replay':zones,'CPU_write_journal':vm.journals,'getter_and_page_input_utf16_hex':version.hex(),'original40_and_postheader_runtime_match_baseline':True,'native_embedded_mount_open_read_seek_tell_executed':True,'current_outer_file_identity_fixture':outer,'lower_region_fixture_read_count':len(vm.reads),'lower_region_fixture_reads':vm.reads,'resource_samples':strict.RESOURCES,'case_instruction_observations':vm.instructions,'candidate_SIG72_payload_unchanged':True,'actual_physical_higher_FAT_or_signature_acceptance_verified':False,'device_transfer_or_UIrendering':False,'BIN_file_input_fixture_used':False,'explicit_fixtures':['outerdirectory/binding/driveactivation tail tooriginalembeddedmount','lower readonly candidateVPM sector reads','opaque allocator/descriptor/release/locale/platform','singleTCB andIRQ/unrelated FSmutex controls','currentouterfile/provider/regionmap typedinput','cache-sync effect anddiagnostic submission','page getter frame input'],'limits':'Exact newlybuiltVPM fed tostock embeddedcontainer filesystem andall5 unchanged loaderfilecallbacks, then originalBootstrap40 andactual strictARM code/getter. The higherFAT/physicalregionbinding andcurrentouterfile identity remainfixtures; no physicalchangedpackage/SIG acceptance oractualUI/sound/kernel lifecycle claim.'}
 strict.save(OUT/'candidate-embedded-reader-control.json',result);print(json.dumps({'all_passed':True,'candidate_sha256':bundle['candidate_sha256'],'CPU_marker_stores':5,'all5_original_file_callbacks':True,'proof':'staging/native-player-inline-fields/marker-package-prep/candidate-embedded-reader-control.json'}),flush=True)
if __name__=='__main__':
 try:main()
 except Exception as e:
  o={'all_passed':False,'error':repr(e),'traceback':traceback.format_exc(),'source_sha256':base.filehash(Path(__file__)),'resource_samples':strict.RESOURCES}
  if VM is not None:o['partial_VM']={'last_pc':hex(VM.last_pc),'entries':VM.entry_rows,'pending':VM.pending,'try_pending':VM.try_pending,'reads':VM.reads,'CPU_journal':VM.journals}
  strict.save(OUT/'candidate-reader-terminal-failure.json',o);raise
