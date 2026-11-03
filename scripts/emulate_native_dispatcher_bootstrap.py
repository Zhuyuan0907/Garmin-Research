#!/usr/bin/env python3
"""Native backend zero-init and original dispatcher bootstrap controls; no device I/O."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_gui_runtime_bootstrap import MUTEX
from probe_native_dispatcher_condition import DispatcherVM
STAGE=ROOT/'staging/native-player-dispatcher-bootstrap'
from probe_native_player_mainmenu import BUILD
from probe_native_player_resources import INPUT
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import require

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());STAGE.mkdir(exist_ok=True);vm=DispatcherVM(NativeImage(),build);cases=[];dbsha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        buffer=vm.invoke(0x3954cc,(48,));vm.uc.mem_write(buffer,b'\xa5'*48)
        vm.allow_direct_backend_control=True
        try:returned=vm.invoke(0x3008a1,(buffer,))
        finally:vm.allow_direct_backend_control=False
        require(returned==buffer and bytes(vm.uc.mem_read(buffer,48))==b'\0'*24+b'\xa5'*24,
            'Original backend initializer did not clear exactly24 poisoned bytes')
        vm.verify_guard(buffer,vm.raw_allocations[buffer])
        record('original_backend_initializer_clears_six_words_in_poisoned_guarded_storage',
            original_entry='0x3008a0',native_zero_bytes=24,native_zero_stores=vm.backend_initializations[-1]['native_zero_writes'],
            remaining_payload_and_outer_canaries_unchanged=True,host_seeded_backend_fields=False)
        require(bytes(vm.uc.mem_read(MUTEX,28))==b'\0'*28 and vm.word(0xf11c8c)==0,
            'Original zero BSS mutex/singleton inventory differs')
        record('original_zero_BSS_mutex_is_unconstructed_and_singleton_absent',
            mutex='0x34a59a8',mutex_bytes=28,original_vtable_before=0,singleton_pointer_before=0,
            original_zero_fill_page_materialized_for_inspection_only=True,host_seeded_mutex_or_singleton=False)
        value=vm.invoke(0x5d2f7d,());expected=struct.pack('<7I',0xc1b5dc,0,0,0,0,0x31041c,0)
        require(value==0 and bytes(vm.uc.mem_read(MUTEX,28))==expected and vm.word(0xf11c8c)==0,
            'Original full bootstrap did not construct mutex or prematurely created singleton')
        registry=vm.invoke(0x2c0a1f,());begin,end,capacity=[vm.word(registry+4*n)for n in [1,2,3]]
        require(begin and end-begin==12 and capacity>=end and vm.word(begin+8)==0x5d29df,
            'Original diagnostic registration does not hold one12-byte record')
        record('original_bootstrap_constructs_mutex_and_registers_diagnostic_without_running_it',
            original_entry='0x5d2f7c',original_return=0,native_mutex_words=[hex(n)for n in struct.unpack('<7I',expected)],
            original_vtable='0xc1b5dc',original_virtual_lock='0x310400',original_virtual_unlock='0x31040c',
            diagnostic_registry=hex(registry),diagnostic_record=hex(begin),registered_callback='0x5d29df',
            diagnostic_key='Dispatcher::DispatcherTest::testDispatcher',diagnostic_or_UI_event_delivery_executed=False,
            true_boot_sequence_kernel_thread_owner_or_safe_dtor_lifetime_verified=False)
        out=INPUT+0x800;vm.uc.mem_write(out-16,b'\xa5'*36)
        returned=vm.invoke_owned_mutex_guard(0x351bd1,out)
        require(returned==out and vm.word(out)==MUTEX and vm.mutexes[MUTEX+4]==1 and
            bytes(vm.uc.mem_read(out-16,36))==b'\xa5'*16+struct.pack('<I',MUTEX)+b'\xa5'*16,
            'Original scoped lock guard did not retain mutex with bounded output')
        returned=vm.invoke_owned_mutex_guard(0x351be3,out)
        require(returned==out and vm.mutexes[MUTEX+4]==0 and bytes(vm.uc.mem_read(MUTEX,28))==expected and
            bytes(vm.uc.mem_read(out-16,36))==b'\xa5'*16+struct.pack('<I',MUTEX)+b'\xa5'*16,
            'Original virtual unlock or output/fixture mutex balance differs')
        record('original_scoped_guard_executes_native_virtual_lock_and_unlock_with_output_canaries',
            original_guard='0x351bd0',original_guard_destructor='0x351be2',mutex='0x34a59a8',
            native_backend_pointer='0x34a59ac',fixture_mutex_counts=[1,0],guard_output_bytes=4,
            surrounding_canaries_and_original_mutex_words_unchanged=True,
            real_kernel_thread_owner_recursive_lock_or_concurrency_verified=False)
        row=bytes(vm.uc.mem_read(begin,12));vector=(begin,end,capacity)
        require(vm.invoke(0x2c0e9b,(registry,0x5d3008,0x5d29df))==0 and
            tuple(vm.word(registry+4*n)for n in [1,2,3])==vector and bytes(vm.uc.mem_read(begin,12))==row,
            'Original existing diagnostic name changed vector or callback')
        record('original_diagnostic_name_registration_keeps_existing_record_without_delivery',
            original_entry='0x2c0e9a',diagnostic_vector_record_count=1,native_vector_and_callback_unchanged=True,
            destructor_registry_not_reregistered=True,diagnostic_callback_not_executed=True)
        obj=vm.invoke(0x5d2131,())
        require(obj and vm.word(0xf11c8c)==obj and vm.word(obj)==0xc1b290 and not any(vm.mutexes.values()),
            'Original mutex-protected singleton constructor did not initialize or unlock')
        contents=bytes(vm.uc.mem_read(obj,0x4ba8));count=len(vm.raw_allocations)
        again=vm.invoke(0x5d2131,())
        require(again==obj and len(vm.raw_allocations)==count and bytes(vm.uc.mem_read(obj,0x4ba8))==contents and
            not any(vm.mutexes.values()),'Original cached singleton path recreated or changed object/lock state')
        record('original_mutex_protected_singleton_constructor_and_cached_lookup_return_same_object',
            original_entry='0x5d2130',original_constructor='0x5d2232',object=hex(obj),original_vtable='0xc1b290',
            native_allocation_bytes=0x4ba8,singleton_pointer_written_by_original=True,
            cached_lookup_without_new_allocation_or_object_changes=True,
            native_mutex_lock_unlock_balanced=True,real_event_dispatch_renderer_or_full_controller_unverified=True)
        require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes and
            not any(vm.mutexes.values())and vm.active_backend is None and vm.active_condition is None,'Focused bootstrap faulted, requested audio/GUI data or retained locks')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original whole voice RAM/40 exports changed')
        require(sha(DATABASE)==dbsha and not vm.statements,'Readonly backup DB changed or unexpected SQL')
        vm.verify_descriptor_guards();snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve(),
            ROOT/'staging/native-player-gui-bootstrap/gui-runtime-bootstrap-static-preflight.json'}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,snapshot=snapshot,
            original_bootstrap_entries=vm.gui_bootstrap_entries,original_voice_RAM_and40_exports_unchanged=True,
            native_backend_initializations=vm.backend_initializations,native_condition_constructor_runs=vm.condition_constructor_runs,
            retained_condition_bootstrap_tokens=list(vm.dispatcher_condition_tokens.values()),
            descriptor_guards_and_raw_DB_backup_unchanged=True,no_GUI_initialized_data_changes=True,
            real_boot_thread_owner_dispatcher_events_controller_foreground_safe_lifetime_or_device_App_verified=False,
            device_io=False,sounds_emitted=False,
            limits='Six scoped controls execute original5D2F7C full mutex/atexit/diagnostic bootstrap, native351BD0/351BE2 virtual lock/unlock, unchanged existing diagnostic registration, original5D2130/5D2232 singleton4BA8 allocation and cached lookup. Poison control confirms original3008A0 six native zero stores over exactly24 bounded bytes. Original3EC540/300AE4 condition init runs after six-zero backend init; exact constructor lock is a separately retained explicit bootstrap token, not an ordinary counter sweep or actual thread ownership proof. MutexC1B5DC/tag and singletonC1B290/pointer are native stores, not host seeded. Clock/storage/heap/mutex/IRQ/kernel remain fixtures, no real owner/boot order/diagnostic execution/dispatcher event delivery/render/full controller/foreground/safe dtor or unload/device App/audio. Whole voice40/private12/player2/code/canary/DB final guards pass with same EMULATION-ONLY package.')
        path=ROOT/'evidence/firmware-analysis/native-dispatcher-bootstrap-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        (STAGE/'focused-dispatcher-bootstrap-failure.json').write_text(json.dumps(dict(error=str(error),completed_cases=cases,
            all_final_guards_passed=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            bootstrap_entries=vm.gui_bootstrap_entries,native_fatal_entries=vm.native_fatal_entries,
            backend_initializations=vm.backend_initializations,condition_constructor_runs=vm.condition_constructor_runs,
            active_condition=vm.active_condition,retained_condition_tokens=list(vm.dispatcher_condition_tokens.values()),mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},
            conditional_writes=vm.conditional_region_writes),ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True);sys.exit(1)

if __name__=='__main__':main()
