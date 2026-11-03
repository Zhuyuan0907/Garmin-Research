#!/usr/bin/env python3
"""Loaded player with unpatched original normal-context event round trips."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_CPSR
from analyze_native_sections import ROOT, NativeImage, EXPECTED
from analyze_native_loader import IMAGE, STUBS
from probe_native_kernel_context import KernelContextVM, POST, WAIT, RESTORE, CODE, CONTROLLER_STACK, IDLE_STACK, STACK_BYTES, STAGE
from probe_native_player_mainmenu import BUILD
from emulate_native_player_menu_selection import SelectionPlayerVM, DATABASE, sha
from emulate_native_vpm_filesystem import require

class RoundtripVM(KernelContextVM):
    def __init__(self, stock, build):
        self.dispatch_destinations=[];self.pending_restore=None
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        if self.pending_restore is not None and address==int(self.pending_restore['saved_PC'],16)&~1:
            self.pending_restore['original_task_resume_destination_reached']=True
            self.dispatch_destinations.append(dict(address=hex(address),task=hex(self.word(0xf09090))))
            self.pending_restore=None
        value=super().observe(uc,address,size,data)
        if self.kernel_active and address==RESTORE:
            self.pending_restore=self.kernel_restores[-1]
            self.pending_restore['original_task_resume_destination_reached']=False
        return value

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    build=json.loads((ROOT/BUILD).read_text());vm=RoundtripVM(NativeImage(),build);cases=[]
    source_sha=hashlib.sha256(Path(__file__).read_bytes()).hexdigest();dbsha=sha(DATABASE)
    def record(name,**fields):
        cases.append(dict(name=name,passed=True,**fields));print(json.dumps(dict(case=name,passed=True)),flush=True)
    try:
        load=vm.load();oldram=struct.unpack_from('<I',(ROOT/build['original_binary']).read_bytes(),4)[0]
        voice=bytes(vm.uc.mem_read(IMAGE+12,oldram-12));exports=bytes(vm.uc.mem_read(STUBS,480))
        before_mode=vm.uc.reg_read(UC_ARM_REG_CPSR)
        # Explicit initial normal task CPU-mode input, not a CPU-context restore.
        vm.uc.reg_write(UC_ARM_REG_CPSR,(before_mode&~0x1f)|0x1f)
        inventory=vm.configure_native_kernel_inventory()
        require(vm.owner_thread==vm.controller and vm.timer_task!=vm.controller and
            bytes(vm.uc.mem_read(vm.timer_task+17,1))==b'\x01'and
            bytes(vm.uc.mem_read(vm.controller+17,1))==b'\x10'and
            bytes(vm.uc.mem_read(vm.idle+17,1))==b'\xf0','Native task priorities/owner inventory differ')
        record('original_builder_constructs_controller_idle_and_distinct_timer_without_MAIN_patch',
            inventory=inventory,original_timer_initialization=vm.original_timer_initialization,
            initial_CPU_system_mode_is_fixture=True,CPU_mode_before_input=hex(before_mode&31),
            construction_bookkeeping_not_patched_or_replaced=True)
        start=len(vm.kernel_restores);value=vm.kernel_invoke(POST,(vm.timer_task,0x10))
        require(vm.returned and vm.word(0xf09090)==vm.controller and vm.word(vm.timer_task+4)==0 and
            bytes(vm.uc.mem_read(vm.timer_task+22,1))==b'\x02','Original timer did not block and restore controller')
        rows=vm.kernel_restores[start:]
        require([r['current']for r in rows]==[hex(vm.timer_task),hex(vm.controller)]and
            all(r['original_task_resume_destination_reached']for r in rows),'Original timer/controller resume endpoints missing')
        record('original_timer_boot_post_preempts_controller_then_wait_restores_post_caller',
            post_target=hex(vm.timer_task),explicit_boot_event='0x10',post_return=hex(value),
            native_restore_tasks=[r['current']for r in rows],timer_mailbox_after=0,timer_state_after=2,
            original_timer_entry_and_controller_post_resume_reached=True,host_context_restore=False)
        before=len(vm.kernel_restores);timerwords=bytes(vm.uc.mem_read(vm.timer_task,108))
        vm.kernel_invoke(POST,(vm.timer_task,0))
        require(vm.returned and vm.word(0xf09090)==vm.controller and len(vm.kernel_restores)==before and
            bytes(vm.uc.mem_read(vm.timer_task,108))==timerwords,'Zero event fabricated wake or modified blocked timer')
        record('original_zero_event_post_does_not_wake_blocked_timer_or_switch_context',
            post_event=0,original_post_body_executed=True,blocked_timer_TCB_unchanged=True,no_context_switch=True)
        vm.kernel_invoke(WAIT)
        require(vm.idle_endpoint and vm.word(0xf09090)==vm.idle and vm.word(vm.controller+4)==0 and
            bytes(vm.uc.mem_read(vm.controller+22,1))==b'\x02','Original controller wait did not park on idle')
        value=vm.kernel_invoke(POST,(vm.controller,1))
        require(vm.returned and value==1 and vm.word(0xf09090)==vm.controller and vm.word(vm.controller+4)==0,
            'Original controller wait did not resume with posted event1')
        require(all(r['original_task_resume_destination_reached']for r in vm.kernel_restores),
            'Native restore entered without reaching saved original task PC')
        record('original_controller_wait_blocks_and_resumes_with_event_posted_from_idle',
            original_wait='0x2fd034',idle_entry_is_explicit_sentinel=hex(CODE),posted_event=1,
            resumed_controller_wait_result=1,returned_call_is_controller_wait_not_idle_post=True,
            idle_post_call_remains_suspended_and_resident=True,host_context_restore=False)
        require(not vm.invalid_accesses and not vm.native_fatal_entries and not vm.audio and
            not vm.conditional_region_writes and not any(vm.mutexes.values()),'Kernel controls faulted or requested audio/GUI/retained ordinary lock')
        for base in [CONTROLLER_STACK,IDLE_STACK]:
            require(bytes(vm.uc.mem_read(base,64))==b'\xa5'*64,'Native context crossed explicit stack leading canary')
        require(bytes(vm.uc.mem_read(0x2d226f4,24))==b'\xa5'*24,'Timer context crossed original stack leading canary')
        require(bytes(vm.uc.mem_read(IMAGE+12,oldram-12))==voice and bytes(vm.uc.mem_read(STUBS,480))==exports,
            'Whole original voice RAM/40 exports changed')
        require(sha(DATABASE)==dbsha and not vm.statements,'Backup DB changed or unexpected SQL')
        vm.verify_descriptor_guards();snapshot=SelectionPlayerVM.finish(vm);vm.db.close()
        paths={ROOT/BUILD,ROOT/DATABASE,ROOT/build['package'],ROOT/build['combined_binary'],ROOT/build['extension_elf'],
            ROOT/build['extension_flat'],ROOT/'evidence/firmware-analysis/main_02bd.bin',Path(__file__).resolve()}
        paths.update(ROOT/p for p in build['source_sha256'])
        for module in tuple(sys.modules.values()):
            filename=getattr(module,'__file__',None)
            if filename:
                path=Path(filename).resolve()
                if path.is_file()and path.is_relative_to(ROOT/'scripts'):paths.add(path)
        proof=dict(updated_utc=datetime.now(timezone.utc).isoformat(),MAIN_sha256=EXPECTED,
            build_manifest=BUILD,build_manifest_sha256=sha(BUILD),
            source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()for p in sorted(paths)},
            all_passed=True,case_count=len(cases),cases=cases,load=load,snapshot=snapshot,
            kernel_inventory=inventory,kernel_events=vm.kernel_events,kernel_restores=vm.kernel_restores,
            kernel_calls=vm.kernel_calls,original_task_resume_destinations=vm.dispatch_destinations,
            original_voice_RAM_and40_exports_unchanged=True,no_GUI_initialized_data_changes=True,
            descriptor_and_raw_DB_and_stack_canaries_unchanged=True,original_MAIN_patch_bytes=0,
            current_native_timer_boot_wait_and_normal_event_context_roundtrips_verified=True,
            actual_dispatcher_condition_wait_root_foreground_device_App_safe_lifetime_or_phone_audio_verified=False,
            device_io=False,sounds_emitted=False,
            limits='Original358BF8 creates native controller/idle/timer TCBs and contexts. Original2FCF44 normal-context post,2FD034 wait and358EC4 native restore execute unchanged MAIN in the loaded-player VM. Real saved destination PCs are reached, timer boot preempts/blocks/restores post caller, zero-event negative control does not wake, controller blocks to explicit idle sentinel and posted1 resumes its original wait. OriginalF5030 construction bookkeeping is neither patched nor substituted. Synthetic descriptors/stacks, initial controller-idle ready membership, explicit initial system CPU mode and explicit timer boot event remain inputs; no actual boot/IRQ clock. Idle post continuation, tasks/stacks and loaded module remain resident; no safe cleanup/unload. Filesystem/settings/heap/IRQ service inputs remain existing fixtures. Actual GUI dispatcher condition contention, root/controller/foreground/touch/display, device App/direct-phone native music and accepted package are not proven. Whole code, voice40/private12/player2, allocation and descriptor/DB/GUI-region/stack canary final guards pass.')
        path=ROOT/'evidence/firmware-analysis/native-kernel-context-emulation.json'
        require(not path.exists(),'Keep proof namespace immutable')
        path.write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(dict(all_passed=True,groups=len(cases),exact_dependencies=len(paths))),flush=True)
    except Exception as error:
        (STAGE/'focused-original-kernel-context-failure.json').write_text(json.dumps(dict(error=str(error),
            source_sha256_before_run=source_sha,completed_cases=cases,planned_case_count=4,
            all_final_guards_passed=False,recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,
            kernel_events=vm.kernel_events,kernel_restores=vm.kernel_restores,kernel_calls=vm.kernel_calls,
            native_fatal_entries=vm.native_fatal_entries,CPU_status=hex(vm.uc.reg_read(UC_ARM_REG_CPSR)),
            device_io=False,sounds_emitted=False),ensure_ascii=False,indent=2)+'\n')
        raise

if __name__=='__main__':main()
