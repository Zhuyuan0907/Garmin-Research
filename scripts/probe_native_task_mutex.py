#!/usr/bin/env python3
"""Observe original GUI mutex/wait paths per native running task, offline only.

F09090 can change before the CPU switches stacks.  Operation attribution uses
the last actually reached native restore destination, never the ready head
alone.  Guest ownership, waiter links, priorities and context restores remain
original instructions.  Frozen single-task proof sources are not edited.
"""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import hashlib, json, struct, sys
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP, UC_ARM_REG_CPSR, UC_ARM_REG_R4
from analyze_native_sections import ROOT, NativeImage
from probe_native_dispatcher_kernel_context import DispatcherKernelVM
from probe_native_dispatcher_condition import DispatcherVM
from probe_native_kernel_context import POST, RESTORE, CODE
from probe_native_player_mainmenu import BUILD
from emulate_native_vpm_filesystem import REGS, RETURN, require

STAGE = ROOT / 'staging/native-player-task-mutex'

class NativeTaskMutexVM(DispatcherKernelVM):
    def __init__(self, stock, build):
        self.running_task = None
        self.task_mutex_ops = defaultdict(list)
        self.task_waits = defaultdict(list)
        self.task_releases = defaultdict(list)
        self.task_lower_waits = defaultdict(list)
        self.task_notifications = defaultdict(list)
        self.task_constructors = {}
        self.native_task_descriptors = []
        self.contention_entries = []
        self.condition_notifications = []
        super().__init__(stock, build)

    def sync_counter_from_native(self, ptr):
        owner = self.word(ptr+8)
        depth = int.from_bytes(self.uc.mem_read(ptr+20, 2), 'little')
        require(owner == 0 or owner in self.native_TCBs, 'Native mutex owner lacks original TCB construction')
        retained = self.native_semaphores[ptr]['retained_condition_token']
        self.mutexes[ptr] = 0 if retained else (1+depth if owner else 0)
        if retained and ptr in self.dispatcher_condition_tokens:
            self.dispatcher_condition_tokens[ptr].update(native_owner=hex(owner),
                observed_native_recursion=depth, explicit_retained_bootstrap_token=bool(owner))
        return owner, depth

    def record_descriptor(self, uc, caller):
        ptr = uc.reg_read(REGS[0])
        raw = bytes(uc.mem_read(ptr,20))
        self.native_task_descriptors.append(dict(original_builder='0x358bf8',
            native_caller=hex(caller), descriptor=hex(ptr), running_task=hex(self.running_task or 0),
            raw_hex=raw.hex(), words=[hex(v) for v in struct.unpack('<5I',raw)],
            flag_C=raw[12], flag_D=raw[13], base_priority_E=raw[14], field_F=raw[15],
            host_modified_native_descriptor=False))

    def observe(self, uc, address, size, data):
        caller = uc.reg_read(UC_ARM_REG_LR)&~1
        if address == 0x358bf8:
            self.record_descriptor(uc,caller)
        if not self.kernel_active:
            return super().observe(uc,address,size,data)
        if self.running_task is None:
            self.running_task = self.word(0xf09090)
        if self.pending_restore is not None and address == (int(self.pending_restore['saved_PC'],16)&~1):
            row = self.pending_restore
            row['original_task_resume_destination_reached'] = True
            self.running_task = int(row['current'],16)
            self.dispatch_destinations.append(dict(address=hex(address),task=hex(self.running_task)))
            self.pending_restore = None
        task = self.running_task
        require(task in self.native_TCBs,'Running CPU task lacks observed original TCB construction')
        if address == CODE:
            require(task == self.idle and self.word(0xf09090) == self.idle,'Idle sentinel task mismatch')
            self.idle_endpoint = True
            uc.emu_stop()
            return
        if address == POST:
            target = uc.reg_read(REGS[0])
            require(target in self.native_TCBs,'Original post target lacks native TCB construction')
            self.kernel_events.append(dict(entry=hex(address),running_task=hex(task),
                ready_head=hex(self.word(0xf09090)),arguments=[hex(uc.reg_read(r))for r in REGS],
                original_post_entry_reached=True,host_fabricated_wake=False))
            self.visits[address] += 1
            return
        if address == RESTORE:
            target = self.word(0xf09090)
            require(target in self.native_TCBs,'Restore target lacks observed native TCB construction')
            frame = self.word(target+12)
            row = dict(current=hex(target),previous_running_task=hex(task),saved_context=hex(frame),
                saved_PC=hex(self.word(frame+4)),context_format=bytes(uc.mem_read(target+23,1))[0],
                original_restore_entry_reached=True,original_task_resume_destination_reached=False,
                python_CPU_context_restore=False)
            self.kernel_restores.append(row)
            self.pending_restore = row
            for wait in self.task_waits[task]:
                wait['context_restore_boundary_reached'] = True
            self.visits[address] += 1
            return

        # Native function return addresses are checked in the task that entered
        # the function, including when another task changed F09090 meanwhile.
        for pending, collection, pointer_key in [
                (self.task_releases[task],self.native_full_releases,'pointer'),
                (self.task_lower_waits[task],self.native_lower_wait_operations,'condition')]:
            if pending and address == int(pending[-1]['native_caller'],16):
                row = pending.pop()
                ptr = int(row[pointer_key],16)
                owner,depth = self.sync_counter_from_native(ptr)
                row.update(original_body_returned=True,original_return=uc.reg_read(REGS[0]),
                    native_owner_after=hex(owner),native_recursion_after=depth,
                    ready_head_after=hex(self.word(0xf09090)),running_task_after=hex(task),
                    guest_fields_written_by_original_only=True)
        waits = self.task_waits[task]
        if waits and waits[-1].get('original_return_branch_reached') and address == int(waits[-1]['native_caller'],16):
            row = waits.pop()
            ptr = int(row['mutex'],16)
            owner,depth = self.sync_counter_from_native(ptr)
            require(owner == task and self.mutexes[ptr] == 1,'Native condition returned without actual-task mutex reacquisition')
            row.update(original_wait_returned=True,original_return=uc.reg_read(REGS[0]),
                native_owner_after=hex(owner),native_reacquisition_verified=True,
                real_kernel_wait_verified=True,physical_kernel_or_IRQ_timing_verified=False)

        self.active_condition = self.task_constructors.get(task)
        if address == 0x3ec5c6:
            cond,mutex,deadline,kind = [uc.reg_read(r) for r in REGS]
            require(cond in self.native_semaphores and mutex in self.native_semaphores,
                'Condition wait uses unobserved native semaphore')
            row = dict(original_entry=hex(address),native_caller=hex(caller),condition=hex(cond),
                mutex=hex(mutex),native_argument=hex(deadline),native_kind=kind,running_task=hex(task),
                semaphore_owner_before=hex(self.word(mutex+8)),native_owner_gate_passed=False,
                original_wait_returned=False,real_kernel_wait_verified=False)
            self.native_condition_waits.append(row)
            waits.append(row)
        if address == 0x3ec5ea and waits:
            row = waits[-1]
            require(self.word(int(row['mutex'],16)+8) == task == uc.reg_read(UC_ARM_REG_R4),
                'Original condition owner gate running task mismatch')
            row['native_owner_gate_passed'] = True
        if address == 0x3ec6a0 and waits:
            require(uc.reg_read(REGS[3]) == (int(waits[-1]['native_caller'],16)|1),
                'Condition return epilogue did not restore saved LR')
            waits[-1]['original_return_branch_reached'] = True
        if address == 0x3ec498:
            row=dict(original_entry=hex(address),native_caller=hex(caller),
                condition=hex(uc.reg_read(REGS[0])),running_task=hex(task),host_fabricated_notification=False,
                original_broadcast_returned=False)
            self.condition_notifications.append(row)
            self.task_notifications[task].append(row)
        if address == 0x3ec4f8 and self.task_notifications[task]:
            row=self.task_notifications[task][-1]
            require(uc.reg_read(REGS[3])==(int(row['native_caller'],16)|1),'Broadcast native saved LR differs')
            row['original_return_branch_reached']=True
        if self.task_notifications[task] and self.task_notifications[task][-1].get('original_return_branch_reached') and address==int(self.task_notifications[task][-1]['native_caller'],16):
            self.task_notifications[task].pop()['original_broadcast_returned']=True

        if address in [0x3009a0,0x3008b0]:
            ptr = uc.reg_read(REGS[0])
            cpp = caller == (0x310408 if address == 0x3009a0 else 0x310414)
            recursive_cpp = caller == (0x46c2ae if address == 0x3009a0 else 0x46c2be)
            ctor = address == 0x3009a0 and caller == 0x3ec572 and self.active_condition is not None
            aux_wait = address == 0x3009a0 and caller == 0x3ec61c and waits and ptr == int(waits[-1]['condition'],16)+28
            reacquire = address == 0x3009a0 and caller == 0x3ec692 and waits and ptr == int(waits[-1]['mutex'],16)
            notify_aux = caller == (0x3ec4be if address == 0x3009a0 else 0x3ec4ee)
            require(cpp or recursive_cpp or ctor or aux_wait or reacquire or notify_aux,
                'Native mutex caller outside explicit per-task GUI scope: '+hex(caller))
            require(self.declared_storage(ptr,24),'Native semaphore outside declared guarded storage')
            if cpp:
                require(self.word(ptr-4)==0xc1b5dc and self.word(ptr+16)==0x31041c,'Native C++ mutex vtable/tag mismatch')
            if recursive_cpp:
                require(self.word(ptr-28)==0xc1b5c4 and self.word(ptr+16)==0x46c2c8,'Native recursive C++ mutex vtable/tag mismatch')
            if notify_aux:
                require(self.task_notifications[task] and ptr==int(self.task_notifications[task][-1]['condition'],16)+28,
                    'Broadcast auxiliary mutex does not belong to active native condition')
            if ctor:
                require(ptr == int(self.active_condition['pointer'],16) and
                    self.word(ptr+24)==self.native_condition_magic and bytes(uc.mem_read(ptr,24))==b'\0'*24 and
                    bytes(uc.mem_read(ptr+28,24))==b'\0'*24 and ptr not in self.dispatcher_condition_tokens,
                    'Original condition constructor token storage differs')
            if ptr not in self.native_semaphores:
                self.register_native_semaphore(ptr)
            if ctor:
                self.native_semaphores[ptr]['retained_condition_token'] = True
            scope = ('Cpp_mutex' if cpp else 'recursive_Cpp_mutex') if (cpp or recursive_cpp) else ('condition_constructor' if ctor else
                ('condition_reacquisition' if reacquire else 'condition_auxiliary'))
            row = dict(original_entry=hex(address),pointer=hex(ptr),native_caller=hex(caller),
                operation='lock' if address==0x3009a0 else 'unlock',scope=scope,running_task=hex(task),
                entry_SP=hex(uc.reg_read(UC_ARM_REG_SP)),entry_LR=hex(uc.reg_read(UC_ARM_REG_LR)),
                before_words=[hex(self.word(ptr+4*n))for n in range(6)],native_body_returned=False,
                semaphore_fields_written_by_original_only=True,host_CPU_context_restore=False)
            self.native_mutex_runs.append(row)
            self.task_mutex_ops[task].append(row)
            if reacquire:
                waits[-1]['original_reacquire_entry_reached'] = True
            self.visits[address] += 1
            return
        if address in [0x300a0a,0x30092a]:
            pending = self.task_mutex_ops[task]
            require(pending,'Mutex epilogue has no pending operation for actual running task')
            row = pending.pop()
            require(address == (0x300a0a if row['operation']=='lock' else 0x30092a) and
                uc.reg_read(REGS[3])==(int(row['native_caller'],16)|1),'Native mutex task/caller epilogue mismatch')
            ptr = int(row['pointer'],16)
            owner,depth = self.sync_counter_from_native(ptr)
            native_result=uc.reg_read(REGS[0])
            if row['operation']=='lock' and native_result==0:
                require(owner==task,'Native lock returned0 without ownership by originating task')
            if row['scope'] == 'condition_constructor':
                require(owner==task and depth==0 and self.active_condition is not None,'Retained condition token native owner mismatch')
                self.active_condition.update(bootstrap_token_retained=True,
                    original_mutex_lock_and_owner_store_executed=True,native_owner=hex(owner))
                self.dispatcher_condition_tokens[ptr]=dict(pointer=hex(ptr),native_caller='0x3ec572',
                    explicit_retained_bootstrap_token=1,original_native_owner_store=True,native_owner=hex(owner),
                    ordinary_mutex_counter_not_incremented_or_swept=True,safe_lifetime_verified=False)
            row.update(native_body_returned=True,original_return_branch_reached=True,
                after_words=[hex(self.word(ptr+4*n))for n in range(6)],native_owner=hex(owner),
                original_return=native_result,native_lock_acquired_by_originating_task=(owner==task if row['operation']=='lock' else None),
                native_recursion_count=depth,thread_owned_list_head=hex(self.word(task+32)),
                ready_head_at_epilogue=hex(self.word(0xf09090)))
        if address == 0x300bb8:
            ptr = uc.reg_read(REGS[0])
            require(ptr in self.native_semaphores and self.word(ptr+8)==task,
                'Original full release lacks current native ownership')
            require(caller in [0x3ec642,0x3ec648,0x30090a],
                'Original full release caller outside observed GUI scope: '+hex(caller))
            row = dict(original_entry=hex(address),pointer=hex(ptr),native_caller=hex(caller),
                running_task=hex(task),native_owner_before=hex(self.word(ptr+8)),
                native_waiter_head_before=hex(self.word(ptr+12)),original_body_returned=False,
                host_wrote_owner_or_links=False)
            self.native_full_releases.append(row)
            self.task_releases[task].append(row)
        if address == 0x300a14:
            ptr = uc.reg_read(REGS[0])
            require(waits and caller in [0x3ec664,0x3ec674] and ptr==int(waits[-1]['condition'],16),
                'Lower wait outside per-task condition scope')
            row = dict(original_entry=hex(address),condition=hex(ptr),native_caller=hex(caller),
                running_task=hex(task),original_arguments=[hex(uc.reg_read(r))for r in REGS],
                native_owner_before=hex(self.word(ptr+8)),original_body_returned=False,
                original_wait_not_replaced_with_success=True,
                observed_condition_owner_equals_running_task=self.word(ptr+8)==task)
            self.native_lower_wait_operations.append(row)
            self.task_lower_waits[task].append(row)
        if address == 0x300d08:
            ptr = uc.reg_read(REGS[0])
            self.contention_entries.append(dict(original_entry=hex(address),native_caller=hex(caller),
                semaphore=hex(ptr),running_task=hex(task),ready_head=hex(self.word(0xf09090)),
                native_owner=hex(self.word(ptr+8)),SP=hex(uc.reg_read(UC_ARM_REG_SP)),
                native_waiter_links_and_priority_and_scheduler_not_replaced=True))
        if address == 0x3ec57e and self.active_condition is not None:
            ptr=int(self.active_condition['pointer'],16)
            owner,depth=self.sync_counter_from_native(ptr)
            self.native_condition_owner_transfers.append(dict(condition=hex(ptr),original_transfer='0x300ae4',
                native_owner_after_transfer=hex(owner),owner_matches_timer=owner==self.timer_task,
                original_timer_TCB=hex(self.timer_task),running_task=hex(task)))

        # Deliberately bypass only frozen single-owner bookkeeping, while
        # preserving DispatcherVM native zero-init/constructor and every lower
        # loader, C++/GUI storage, I/O, fatal and code observation guard.
        value = DispatcherVM.observe(self,uc,address,size,data)
        if self.active_condition is None:
            self.task_constructors.pop(task,None)
        else:
            self.task_constructors[task]=self.active_condition
        return value

def main():
    require(unicorn.__version__=='2.1.4'and unicorn.uc_version()==(2,1,33621247),'Use isolated Unicorn2.1.4')
    STAGE.mkdir(exist_ok=True)
    source=Path(__file__).resolve()
    target=STAGE/'task-mutex-runtime-development-probe.json'
    require(not target.exists(),'Preserve previous terminal runtime artifact before another run')
    vm=NativeTaskMutexVM(NativeImage(),json.loads((ROOT/BUILD).read_text()))
    result=dict(updated_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256_before_run=hashlib.sha256(source.read_bytes()).hexdigest(),
        full_scoped_final_guards_passed=False,device_io=False,sounds_emitted=False,
        host_wrote_guest_mutex_owner_waiter_links_or_context_restore=False)
    try:
        result['load']=vm.load()
        vm.uc.reg_write(UC_ARM_REG_CPSR,(vm.uc.reg_read(UC_ARM_REG_CPSR)&~31)|31)
        result['kernel_inventory']=vm.configure_native_kernel_inventory()
        vm.kernel_invoke(POST,(vm.timer_task,0x10))
        require(vm.returned and vm.running_task==vm.controller,'Original timer did not resume controller')
        vm.kernel_invoke(0x5d2f7d,())
        require(vm.returned,'Original GUI bootstrap did not return')
        result['phase']='original_singleton_with_per_actual_task_native_mutex_wait_bookkeeping'
        print(json.dumps(dict(phase=result['phase'])),flush=True)
        value=vm.kernel_invoke(0x5d2131,())
        result.update(completed=bool(vm.returned),singleton=hex(value)if vm.returned else None,
            original_singleton_returned=bool(vm.returned),idle_sentinel_reached=vm.idle_endpoint)
        if not vm.returned:
            result['error']='Original singleton remained blocked and native kernel reached explicit idle sentinel'
        if vm.returned:
            require(vm.running_task==vm.controller and vm.word(0xf09090)==vm.controller,
                'Shared return sentinel did not resume original controller task')
            for ptr,entry in vm.raw_allocations.items():vm.verify_guard(ptr,entry)
            vm.verify_descriptor_guards()
            result['scoped_allocation_descriptor_guards_passed']=True
            # Whole-code/voice/GUI-region/lifetime checks remain separate.  A
            # development return is not automatically a complete proof.
    except Exception as error:
        result.update(completed=False,error=str(error),original_singleton_returned=False)
    result.update(recent=list(vm.recent),invalid_accesses=vm.invalid_accesses,native_fatal_entries=vm.native_fatal_entries,
        registers={name:hex(vm.uc.reg_read(reg))for name,reg in zip(
            ['r0','r1','r2','r3','lr','pc','sp'],REGS+(UC_ARM_REG_LR,UC_ARM_REG_PC,UC_ARM_REG_SP))},
        running_task=hex(vm.running_task or 0),ready_head=hex(vm.word(0xf09090)),
        native_all_task_insertions=vm.native_all_task_insertions,known_native_TCBs=[hex(n)for n in sorted(vm.native_TCBs)],
        native_task_descriptors=vm.native_task_descriptors,kernel_events=vm.kernel_events,
        kernel_restores=vm.kernel_restores,kernel_calls=vm.kernel_calls,
        original_task_resume_destinations=vm.dispatch_destinations,native_mutex_operations=vm.native_mutex_runs,
        native_condition_waits=vm.native_condition_waits,native_condition_owner_transfers=vm.native_condition_owner_transfers,
        native_condition_constructor_runs=vm.condition_constructor_runs,native_full_releases=vm.native_full_releases,
        native_lower_wait_operations=vm.native_lower_wait_operations,native_contention_entries=vm.contention_entries,
        native_condition_notifications=vm.condition_notifications,
        pending_mutex_ops={hex(t):rows for t,rows in vm.task_mutex_ops.items()if rows},
        pending_condition_waits={hex(t):rows for t,rows in vm.task_waits.items()if rows},
        pending_releases={hex(t):rows for t,rows in vm.task_releases.items()if rows},
        pending_lower_waits={hex(t):rows for t,rows in vm.task_lower_waits.items()if rows},
        mutex_inventory={hex(p):n for p,n in vm.mutexes.items()},audio_requests=vm.audio,
        actual_foreground_device_App_direct_phone_music_or_safe_lifetime_verified=False)
    vm.db.close()
    target.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result.get(k)for k in ['phase','completed','error','singleton','running_task','ready_head']},ensure_ascii=False),flush=True)
    if not result.get('completed'):sys.exit(1)

if __name__=='__main__':main()
