#!/usr/bin/env python3
"""Native directory->registry->voice selection->real embedded reader->loader.

Runs a known compiled preserving component in the original voice reservation.
Outer filesystem binding/activation, heap/kernel and diagnostic UI are explicit
fixtures. This is not a real package installation or signature-policy proof.
"""
from datetime import datetime,timezone
import json,struct
from pathlib import Path
from unicorn.arm_const import UC_ARM_REG_SP,UC_ARM_REG_PC,UC_ARM_REG_CPSR
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import INIT,IMAGE,DESCRIPTOR,STUBS
from analyze_tts_vpm import parse_image,sha,require
from emulate_native_loader import simulate
from emulate_native_voice_registry import RegistryVM,REGS,STACK
from build_native_voice_package_fixture import repack

APP='staging/native-app-component-emulation/Chinese_Big5_MeiLing/manifest.json'
PACKAGE='staging/native-voice-package-fixture/manifest.json'


class SelectionVM(RegistryVM):
    def __init__(self,*args,**kwargs):
        self.diagnostics=[];self.loader_return=None;self.execution_resumes=[]
        super().__init__(*args,**kwargs)

    def observe(self,uc,address,size,unused):
        if address==0x2404c6:
            self.loader_return=uc.reg_read(REGS[0])
        if address==0x3316ec:
            self.visits[address]+=1
            args=[uc.reg_read(r) for r in REGS]
            require(args[0]==409,'Unexpected selection diagnostic')
            self.diagnostics.append({'code':409,'operation':'diagnostic_UI_submission_fixture',
                'native_language_compatibility_helper_not_overridden':True})
            self.ret();return
        return super().observe(uc,address,size,unused)

    def call(self,address,args):
        try:return super().call(address,args)
        except ValueError as error:
            if address!=0x240498 or not str(error).startswith('Stock call did not return'):raise
            # Budget yield is not native termination. Continue THIS SAME VM
            # with PC/CPSR/SP/LR/registers unchanged, without redoing setup.
            for _ in range(4):
                pc=self.uc.reg_read(UC_ARM_REG_PC);cpsr=self.uc.reg_read(UC_ARM_REG_CPSR)
                self.execution_resumes.append({'entry':hex(address),'PC':hex(pc),'CPSR':hex(cpsr),
                    'same_VM_registers_and_stack_preserved':True})
                self.uc.emu_start(pc|int(bool(cpsr&0x20)),0x10002,count=6000000,timeout=30000000)
                if self.returned:
                    value=self.uc.reg_read(REGS[0]);self.calls.append({'entry':hex(address),'result':hex(value)})
                    require(not any(self.mutexes.values()),'Resumed selector left mutex held')
                    return value
            raise ValueError('Native selection exhausted bounded same-VM execution slices') from error

    def select(self,index,binary,ram_bytes,*,expect_loaded=True):
        readback=None
        if expect_loaded:
            require(self.mount(),'Native embedded parser rejected package before execution')
            status,handle=self.open('dllimg.bin')
            require(status==0 and handle,'Native binary open failed')
            readback=self.read_file(handle);self.close(handle)
            require(readback==binary,'Native package reader differs from independent module before execution')
        self.allow_module_execution=True
        self.uc.mem_write(IMAGE,b'\xa5'*ram_bytes)
        callbacks=[0x1fb2f8,0x1fb304,0x1fb3a2,0x1fb3ce,0x1fb3e4]
        before={a:self.visits[a] for a in callbacks}
        records_before=self.registry()
        self.call(0x240498,(index,0))
        require(self.uc.reg_read(UC_ARM_REG_SP)==STACK,'Selector SP not restored')
        selected=self.word(0xf095b0)
        counts={hex(a):self.visits[a]-before[a] for a in callbacks}
        self.verify_closed_files()
        require(self.registry()==records_before,'Voice selection altered registry')
        require(all(bytes(self.uc.mem_read(a,len(raw)))==raw for a,raw in self.code_images),'Selection changed stock code')
        if not expect_loaded:
            require(selected==255 and self.init_calls==0 and not self.module_executed,'Invalid selection loaded code')
            return {'selected_index':selected,'INIT_calls':0,'module_executed':False,
                'native_selector_lookup_mount_original_functions_executed':{hex(a):self.visits[a] for a in
                    [0x240498,0x2741f4,0x273a84,0x2747cc,0x273e52,0x273abc]},
                'registry_unchanged_code_SP_guards_intact':True}
        require(selected==index and self.init_calls==1 and self.module_executed and self.loader_return==11,
            'Native selector did not execute DLL once or receive11')
        require(all(counts.values()),'Original loader file callbacks were bypassed')
        # Independent existing loader harness consumes identical module bytes;
        # actual selection uses unhooked filesystem callbacks in this VM.
        control,report=simulate(self.stock,'extended_voice',module_bytes=binary,
            module_ram_bytes=ram_bytes,poison_module_ram=True,return_session=True)
        loaded=bytes(self.uc.mem_read(IMAGE,ram_bytes));tramp=bytes(self.uc.mem_read(STUBS,40*12))
        require(loaded==bytes(control.mem_read(IMAGE,ram_bytes)),'Selected runtime differs from direct-loader control')
        require(tramp==bytes(control.mem_read(STUBS,40*12)),'Native selector changed40 trampolines')
        require(IMAGE+ram_bytes<=DESCRIPTOR,'Selected component exceeds original3MiB reservation')
        retained={r['handle'] for r in self.registry()}
        for handle,e in self.handles.items():
            p,n=e['pointer'],e['length']
            require(e['freed']==(handle not in retained),'Selector leaked temporary handle')
            require(bytes(self.uc.mem_read(p-32,32))==b'\xa5'*32 and bytes(self.uc.mem_read(p+n,32))==b'\xa5'*32,'Heap guard changed')
        return {'selected_index':selected,'INIT_calls':self.init_calls,'module_executed':True,
            'runtime_bytes':ram_bytes,'runtime_sha256':sha(loaded),'within_original_3MiB_reservation':True,
            'native_file_readback_before_execution_bytes':len(readback),'native_file_readback_before_execution_sha256':sha(readback),
            'native_file_readback_before_execution_matches_independent_extraction':True,
            'native_execution_budget_resumes':self.execution_resumes,
            'matches_independent_direct_loader_control':True,'original40_trampolines_identical':True,
            'loader_result_captured_before_native_compare':self.loader_return,
            'independent_control_loader_result':report['status'],
            'original_loader_file_callback_visits':counts,'selection_diagnostics':self.diagnostics,
            'native_selector_lookup_mount_original_functions_executed':{hex(a):self.visits[a] for a in
                [0x240498,0x2741f4,0x273a84,0x2747cc,0x2745cc,0x273e52,0x273abc,0x1d8514,
                 0x222a34,INIT,0x3b3294,0x3b3332,0x2356bc]},
            'original_code_registry_heap_SP_guards_intact':True,'temporary_handles_released_native_registry_retained':True}


def main():
    stock=NativeImage();app=json.loads((ROOT/APP).read_text());package=json.loads((ROOT/PACKAGE).read_text())
    original=(ROOT/app['voice_package']).read_bytes();files,g=parse_image(original)
    module=(ROOT/app['combined_binary']).read_bytes()
    require(sha(module)==app['combined_sha256'],'Combined module changed')
    require(sha((ROOT/package['package']).read_bytes())==package['package_sha256'],'Package fixture changed')
    cases=[]
    extended=(ROOT/package['package']).read_bytes()
    stale,_=repack(original,module,checksum=False)
    zero,_=repack(original,module,zero_signature=True)
    inventory=[('original_voice',original,False),('preserving_component_updated_sum_original_SIG',extended,True),
        ('preserving_component_stale_sum_original_SIG',stale,True),('preserving_component_updated_sum_zero_SIG',zero,True)]
    for name,data,changed in inventory:
        vm=SelectionVM(stock,[{'name':'Chinese_Big5_MeiLing.vpm','data':data}]);enumeration=vm.enumerate()
        require(len(enumeration['registry'])==1,'Selection fixture not registered')
        f,_=parse_image(data);binary=f['DLLIMG.BIN']['content'];ram=struct.unpack_from('<I',binary,4)[0]
        loaded=vm.select(0,binary,ram)
        if changed:
            state=app['symbols']['app_component_state']['address']
            require(struct.unpack('<Iii',vm.uc.mem_read(state,12))==(1,11,0),'Preserving entry did not initialize both paths')
            table=app['symbols']['app_component_api']['address'];names=app['private_api']
            require(list(struct.unpack('<12I',vm.uc.mem_read(table,48)))==[app['symbols'][n]['address'] for n in names],
                'Private API table was not initialized at reserved addresses')
            loaded.update(preserving_component_state=[1,11,0],private12_API_table_points_to_reserved_component=True,
                private_API_or_audio_workers_not_called_by_this_test=True)
        cases.append({'name':name,'passed':True,'changed_package_local_fixture':changed,
            'package_sha256':sha(data),'dll_byte_sum':sum(binary)&0xffffffff,
            'metadata_sum':enumeration['registry'][0]['metadata_checksum'],
            'signature_sha256':sha(f['DLLIMG.SIG']['content']),
            'enumeration':enumeration,'selection':loaded})
    for name,items,index,predicate in [
        ('out_of_range_index_skips_loader',[{'name':'Chinese_Big5_MeiLing.vpm','data':extended}],1,True),
        ('platform_reject_leaves_no_voice_to_load',[{'name':'Chinese_Big5_MeiLing.vpm','data':extended}],0,False)]:
        vm=SelectionVM(stock,items,predicate_accept=predicate);enumeration=vm.enumerate()
        result=vm.select(index,module,app['combined_ram_bytes'],expect_loaded=False)
        cases.append({'name':name,'passed':True,'enumeration':enumeration,'selection':result})
    deps=[Path(__file__),ROOT/'scripts/emulate_native_voice_registry.py',ROOT/'scripts/emulate_native_voice_metadata.py',
        ROOT/'scripts/emulate_native_vpm_filesystem.py',ROOT/'scripts/build_native_voice_package_fixture.py',
        ROOT/'scripts/analyze_native_sections.py',ROOT/'scripts/analyze_tts_vpm.py',
        ROOT/'scripts/analyze_native_loader.py',ROOT/'scripts/emulate_native_loader.py']
    out={'updated_utc':datetime.now(timezone.utc).isoformat(),'MAIN_sha256':EXPECTED,'case_count':len(cases),'all_passed':True,
        'cases':cases,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in deps},
        'component_manifest':APP,'component_manifest_sha256':sha((ROOT/APP).read_bytes()),
        'package_manifest':PACKAGE,'package_manifest_sha256':sha((ROOT/PACKAGE).read_bytes()),
        'original_enumerator_registry_selector_embedded_reader_loader_same_VM':True,
        'modified_preserving_component_executed_in_original_reservation':True,
        'stale_checksum_and_zero_SIG_loaded_only_under_declared_fixtures':True,
        'real_outer_storage_mount_and_live_platform_values_verified':False,
        'global_signature_policy_absence_proven':False,'device_package_acceptance_verified':False,
        'native_App_menu_or_physical_audio_verified':False,'device_io':False,'backup_modified':False,
        'device_install_candidate':False,
        'limits':'Original enum/metadata/predicate/sorted registry/lookup/selector/mount caller and loader execute in same VM; outer directory inventory/file-to-region binding/activation wrapper, cached platform values/heap/kernel/diagnostic UI are fixtures. FEA50 tail-routes to native embedded parser rather than full original outer mount. Selector emits compatibility diagnostic409 in fixture environment; native compatibility helper executes unmodified, diagnostic UI submission intercepted. Known compiled preserving component with40 original exports and initialized12 private API executes inside original3MiB reservation; no actual worker playback/UI/phone or real device package acceptance. Stale-sum/zeroSIG loaded on this path under fixtures, not proof of absent checks elsewhere or transferable install candidate. Opaque container header semantics, full loader/lifetime/device cache and actual platform conditions remain unverified.'}
    path=ROOT/'evidence/firmware-analysis/native-voice-selection-emulation.json';path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'evidence':str(path.relative_to(ROOT)),'case_count':len(cases),'all_passed':True}))


if __name__=='__main__':main()
