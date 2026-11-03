#!/usr/bin/env python3
"""Native descriptor validation/registration/preservation and rejection controls."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import NativeImage,ROOT,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_heap_callback import HeapDescriptorVM,STAGE
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());vm=HeapDescriptorVM(NativeImage(),build);cases=[];database_sha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        handle=vm.invoke(0x38853d,(96,0,0));payload=vm.handles[handle]['pointer']
        vm.uc.mem_write(payload,bytes(range(96)));before=bytes(vm.uc.mem_read(payload,96))
        validation_before=len(vm.native_heap_validation_returns)
        actual=vm.invoke(0x388805,(handle,));descriptor=vm.heap_descriptors[handle]
        require(actual==payload and vm.word(descriptor+4)==payload|4 and len(vm.native_heap_validation_returns)==validation_before+1,
            'Original validator/query did not return the translated descriptor payload')
        record('original_validator_and_pointer_wrapper_return_payload_from_explicit_stable_descriptor',
            opaque_handle=hex(handle),descriptor=hex(descriptor),payload=hex(payload),low3_flags=4,
            original_validator_body_executed=True,host_returned_validation_success=False)
        vm.invoke(0x388af5,(handle,0x388b23))
        require(vm.word(descriptor+12)==0x388b23 and vm.word(descriptor+4)==payload|6,
            'Original registration did not store callback and OR flag2')
        record('original_registration_stores_callback_and_sets_flag2_without_payload_mutation',
            original_entry='0x388af4',callback='0x388b23',low3_flags_after=6,
            actual_callback_executed=False)
        queried=[vm.invoke(0x388805,(handle,))for _ in range(3)]
        require(queried==[payload]*3 and vm.word(descriptor+4)==payload|6 and vm.word(descriptor+12)==0x388b23,
            'Subsequent queries erased native callback/flags')
        record('three_original_queries_preserve_registered_callback_low_flags_and_stable_descriptor',
            native_query_count=3,query_returns=[hex(p)for p in queried],registered_callback_unchanged=True,
            descriptor_fields_not_reseeded_by_host=True)
        vm.invoke(0x388af5,(handle,0x388b22));vm.invoke(0x388af5,(handle,0))
        require(vm.word(descriptor+12)==0 and vm.word(descriptor+4)==payload|6,
            'Original replacement/zero registration unexpectedly clears flags')
        record('original_callback_replacement_then_zero_store_leaves_flag2_set',
            final_callback=0,low3_flags_after_zero_store=6,
            zero_callback_store_not_proven_as_safe_unregister_or_lifetime_cleanup=True)
        vm.allow_direct_descriptor_controls=True;negative=[]
        for kind in ['invalid_low_flags','mismatched_backlink']:
            valid=bytes(vm.uc.mem_read(descriptor,32))
            if kind=='invalid_low_flags':vm.put(descriptor+4,payload|3)
            else:vm.put(descriptor+16,descriptor+4)
            # Original validator's failure path unlocks the heap mutex before
            # entering fatal reporter. Supply explicit fixture ownership;
            # there is no real task, mutex scheduler or asynchronous callback.
            vm.mutexes[0x3a7f18c]=1;fatal_before=len(vm.native_fatal_entries)
            try:
                vm.invoke(0x388e93,(descriptor,0x12345678));raise ValueError('Invalid descriptor unexpectedly returned')
            except ValueError as error:
                require('Original fatal reporter entry23D6E8'in str(error),'Negative failed outside original fatal branch: '+str(error))
            require(len(vm.native_fatal_entries)==fatal_before+1 and vm.native_fatal_entries[-1]['arguments'][0]=='0x6e5d8002'and
                not any(vm.mutexes.values()),'Original invalid descriptor fatal/unlock differs')
            negative.append(dict(kind=kind,original_fatal=vm.native_fatal_entries[-1],unconditional_fatal_loop_not_executed=True))
            vm.uc.mem_write(descriptor,valid)
        record('two_original_invalid_descriptor_controls_unlock_then_enter_fatal_reporter',controls=negative,
            original_validator_not_replaced_by_success_stub=True)
        require(bytes(vm.uc.mem_read(payload,96))==before,'Payload changed during descriptor-only controls')
        out=INPUT+0x800;vm.put(out,handle);vm.invoke(0x3887a3,(out,))
        require(vm.handles[handle]['freed']and vm.word(out)==0,'Lower release fixture did not release test payload')
        vm.verify_descriptor_guards();require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes,
            'Focused heap controls faulted, requested audio or mutated conditional GUI data')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original voice RAM/40 exports changed')
        require(sha(DATABASE)==database_sha and not vm.statements,'Backup DB changed or unexpected SQL')
        snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            STAGE/'heap-callback-static-preflight.json'}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            name=getattr(module,'__file__',None)
            if name:
                p=Path(name).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            case_count=len(cases),all_passed=True,cases=cases,load=load,snapshot=snapshot,
            heap_descriptor_entries=vm.heap_descriptor_entries,native_heap_validation_returns=vm.native_heap_validation_returns,
            heap_registration_writes=vm.heap_registration_writes,original_voice_RAM_and40_exports_unchanged=True,
            raw_DB_backup_unchanged=True,no_GUI_conditional_initialized_data_changes=True,descriptor_canaries_verified=True,
            actual_callback_delivery_release_resize_or_full_heap_lifetime_verified=False,
            general_MainMenu_constructor_returned=False,device_io=False,sounds_emitted=False,
            limits='Five scoped controls run original descriptor validation, pointer queries, callback field/flag registration, repeated queries, replacement/zero-store and native fatal branches. Opaque handles translate into guarded descriptors with explicit initial flags/backlinks; original validation is not bypassed. Payload allocation/release and mutex/task services remain fixtures; real callback dispatch, resize/release lifetime, general menu, accepted loading/device App/audio remain unverified.')
        path=ROOT/'evidence/firmware-analysis/native-heap-callback-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        failure=dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,recent=list(vm.recent),
            invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,heap_descriptor_entries=vm.heap_descriptor_entries)
        (STAGE/'focused-heap-failure.json').write_text(json.dumps(failure,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases))),flush=True);sys.exit(1)

if __name__=='__main__':main()
