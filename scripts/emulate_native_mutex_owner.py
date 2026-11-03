#!/usr/bin/env python3
"""Original immediate mutex owner/list and condition constructor controls."""
from datetime import datetime,timezone
from pathlib import Path
import hashlib,json,struct,sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR,UC_ARM_REG_SP
from analyze_native_sections import ROOT,NativeImage,EXPECTED
from analyze_native_loader import IMAGE,STUBS
from probe_native_mutex_owner import OwnerVM
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import SelectionPlayerVM,DATABASE,sha
from emulate_native_vpm_filesystem import REGS,require

STAGE=ROOT/'staging/native-player-mutex-owner'

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());STAGE.mkdir(exist_ok=True)
    vm=OwnerVM(NativeImage(),build);cases=[];dbsha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    def assert_guard(pointer,length):
        vm.verify_guard(pointer,vm.raw_allocations[pointer])
        require(bytes(vm.uc.mem_read(pointer+24,length-24))==b'\xa5'*(length-24),'Native mutex wrote past24 bytes')
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        thread=vm.configure_thread_fixture();sems=[]
        for _ in range(2):
            pointer=vm.invoke(0x3954cc,(48,));vm.uc.mem_write(pointer,b'\xa5'*48)
            vm.register_native_semaphore(pointer)
            require(vm.invoke_mutex_control(0x3008a1,(pointer,),{})==pointer,'Original backend init return differs')
            require(bytes(vm.uc.mem_read(pointer,24))==b'\0'*24,'Original backend did not clear24 bytes')
            assert_guard(pointer,48);sems.append(pointer)
        a,b=sems
        record('original_six_store_initialization_on_two_poisoned_guarded_semaphores',
            semaphores=[hex(a),hex(b)],original_entry='0x3008a0',original_zero_bytes=24,
            surrounding_payload_and_canaries_unchanged=True,host_seeded_semaphore_owner_or_links=False,
            fixture_thread_inventory=vm.fixture_thread_inventory)
        require(vm.invoke_mutex_control(0x3009a1,(a,),{a:1})==0,'Original uncontended lock returned failure')
        require([vm.word(a+4*n)for n in range(6)]==[0,thread+32,thread,0,0,0]and vm.word(thread+32)==a,
            'Original lock did not store owner and insert owned list')
        assert_guard(a,48)
        record('original_mixed_ARM_Thumb_lock_stores_owner_and_inserts_owned_list',
            original_entry='0x3009a0',semaphore=hex(a),native_owner=hex(thread),
            original_return=0,native_thread_owned_list_head=hex(a),native_recursion_count=0,
            fields_written_by_original=True,real_task_or_scheduler_verified=False)
        require(vm.invoke_mutex_control(0x3009a1,(a,),{a:2})==0 and vm.word(a+8)==thread and
            int.from_bytes(vm.uc.mem_read(a+20,2),'little')==1 and vm.word(thread+32)==a,'Native recursive lock differs')
        vm.invoke_mutex_control(0x3008b1,(a,),{a:1})
        require(vm.word(a+8)==thread and int.from_bytes(vm.uc.mem_read(a+20,2),'little')==0 and
            vm.word(thread+32)==a,'Native recursive unlock released base ownership')
        assert_guard(a,48)
        record('original_recursive_lock_and_partial_unlock_preserve_base_ownership',
            original_lock='0x3009a0',original_unlock='0x3008b0',native_recursion_counts=[1,0],
            base_owner_and_owned_list_preserved=True,host_changed_recursion_or_owner=False)
        require(vm.invoke_mutex_control(0x3009a1,(b,),{a:1,b:1})==0,'Second native mutex lock failed')
        require(vm.word(thread+32)==b and vm.word(b)==a and vm.word(b+4)==thread+32 and vm.word(a+4)==b,
            'Original two-mutex list linkage differs')
        vm.invoke_mutex_control(0x3008b1,(a,),{b:1})
        require(vm.word(a+8)==0 and vm.word(b)==0 and vm.word(thread+32)==b,'Original nonhead unlink differs')
        vm.invoke_mutex_control(0x3008b1,(b,),{})
        require(vm.word(b+8)==0 and vm.word(thread+32)==0,'Original final release did not clear owner/list head')
        assert_guard(a,48);assert_guard(b,48)
        record('original_nonhead_unlink_and_final_release_clear_owners_and_thread_head',
            native_two_mutex_linked_list=True,native_nonhead_unlink=True,native_thread_list_empty=True,
            host_cleared_owner_or_links=False,no_waiters_or_other_threads_scheduled=True)
        condition=vm.invoke(0x3954cc,(64,));vm.uc.mem_write(condition,b'\xa5'*64)
        value=vm.invoke_mutex_control(0x3ec541,(condition,),{})
        require(vm.active_condition is None and vm.condition_constructor_runs[-1]['native_constructor_returned']and
            vm.word(condition+8)==thread and vm.word(thread+32)==condition and
            vm.word(condition+24)==vm.native_condition_magic and
            bytes(vm.uc.mem_read(condition+28,24))==b'\0'*24 and bytes(vm.uc.mem_read(condition+52,12))==b'\xa5'*12,
            'Original condition constructor owner/init/return differs')
        require(vm.condition_constructor_runs[-1]['original_IRQ_restore_call_completed']and
            vm.condition_constructor_runs[-1]['original_return_branch_reached'],'Original condition epilogue not verified')
        vm.invoke_mutex_control(0x3008b1,(condition,),{})
        require(vm.word(condition+8)==0 and vm.word(thread+32)==0 and
            vm.dispatcher_condition_tokens[condition]['released_by_original_unlock_control'],
            'Original explicit condition token unlock did not empty list')
        vm.verify_guard(condition,vm.raw_allocations[condition])
        record('original_condition_constructor_retains_native_owned_token_then_explicit_original_unlock',
            original_entry='0x3ec540',original_return=value,condition=hex(condition),native_owner=hex(thread),
            native_constructor_return_observed_after_IRQ_restore_and_LR_branch=True,
            original_owner_transfer_300AE4_same_owner_branch_executed=True,
            owner_and_owned_list_written_by_original_mutex_body=True,
            constructor_retained_token_released_by_original_unlock_control=True,
            original_condition_wait_or_event_dispatch_not_executed=True,
            real_kernel_owner_or_boot_sequence_or_safe_condition_destructor_verified=False)
        require(bytes(vm.uc.mem_read(thread,96))==b'\0'*96,'Synthetic TCB inventory has unexpected native changes')
        for address,original in vm.fixture_thread_inventory['original_global_words'].items():vm.put(int(address,16),original)
        require(not vm.invalid_accesses and not vm.audio and not vm.conditional_region_writes and
            not any(vm.mutexes.values())and vm.active_backend is None and vm.active_condition is None and
            vm.native_lock_run is None,'Focused owner controls faulted, emitted requests or retained ordinary locks')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Original whole voice RAM/40 exports changed')
        require(sha(DATABASE)==dbsha and not vm.statements,'Readonly backup DB changed or unexpected SQL')
        vm.verify_descriptor_guards();snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        deps={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve()}
        deps.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                p=Path(filename).resolve()
                if p.is_file()and p.is_relative_to(ROOT/'scripts'):deps.add(p)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,build_manifest=BUILD,
            build_manifest_sha256=sha(BUILD),source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(deps)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,snapshot=snapshot,
            native_mutex_operations=vm.native_mutex_runs,native_backend_initializations=vm.backend_initializations,
            original_condition_constructor_runs=vm.condition_constructor_runs,
            condition_tokens=list(vm.dispatcher_condition_tokens.values()),fixture_thread_inventory=vm.fixture_thread_inventory,
            original_thread_global_words_restored=True,host_seeded_semaphore_owner_fields=False,
            original_voice_RAM_and40_exports_unchanged=True,descriptor_guards_and_raw_DB_backup_unchanged=True,
            no_GUI_initialized_data_changes=True,real_condition_wait_scheduler_dispatcher_foreground_or_device_App_verified=False,
            device_io=False,sounds_emitted=False,
            limits='Five complete controls execute original3008A0 six stores, original3009A0/3008B0 mixed ARM/Thumb immediate/recursive lock and nonhead unlink, and original3EC540 condition constructor plus same-owner300AE4 path/IRQ restore/LR return. A96-byte explicitly fictional TCB and equal F09090/F090A0 are input inventory; owner/link/recursion fields are written by unchanged original bodies, not host seeded. Constructor retains real guest owner/list token then explicit original unlock releases it; no safe condition destructor or wait/event/scheduler claim. Real task/boot/IRQ/device environment and full dispatcher/controller remain unverified. Original globals restored, whole voice40/private12/player2/code/canary/DB guards pass with unchanged EMULATION-ONLY player.')
        path=ROOT/'evidence/firmware-analysis/native-mutex-owner-emulation.json';require(not path.exists(),'Use new proof namespace')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(deps))),flush=True)
    except Exception as error:
        result=dict(error=str(error),completed_cases=cases,all_final_guards_passed=False,recent=list(vm.recent),
            invalid_accesses=vm.invalid_accesses,registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
                ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
            native_fatal_entries=vm.native_fatal_entries,native_mutex_operations=vm.native_mutex_runs,
            active_native_mutex_operation=vm.native_lock_run,native_backend_initializations=vm.backend_initializations,
            active_condition=vm.active_condition,condition_constructor_runs=vm.condition_constructor_runs,
            retained_condition_tokens=list(vm.dispatcher_condition_tokens.values()),mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},
            fixture_thread_inventory=vm.fixture_thread_inventory)
        (STAGE/'focused-mutex-owner-failure.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(error=str(error),completed_cases=len(cases),all_final_guards_passed=False)),flush=True);sys.exit(1)

if __name__=='__main__':main()
