#!/usr/bin/env python3
"""Original wait-release-reacquire, without replacing native owner stores."""
from unicorn.arm_const import UC_ARM_REG_LR
from probe_native_dispatcher_owner import DispatcherOwnerVM
from emulate_native_vpm_filesystem import REGS,require

class ReacquireVM(DispatcherOwnerVM):
    def __init__(self,stock,build):
        self.active_wait=None;self.active_native_release=None;self.native_full_releases=[]
        self.native_lower_wait_operations=[];self.active_lower_wait=None
        super().__init__(stock,build)

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.active_native_release is not None and address==int(self.active_native_release['native_caller'],16):
            row=self.active_native_release;ptr=int(row['pointer'],16)
            require(self.word(ptr+8)==0 and int.from_bytes(uc.mem_read(ptr+20,2),'little')==0,
                'Original no-waiter full release did not clear owner/recursion')
            self.mutexes[ptr]=0 # Reflect this specific observed original release; do not sweep counters.
            row.update(original_body_returned=True,native_owner_after=0,observed_counter_after=0,
                thread_owned_list_head=hex(self.word(self.owner_thread+32)))
            self.active_native_release=None
        if self.active_lower_wait is not None and address==int(self.active_lower_wait['native_caller'],16):
            row=self.active_lower_wait;ptr=int(row['condition'],16)
            row.update(original_body_returned=True,original_return=uc.reg_read(REGS[0]),
                native_owner_after=hex(self.word(ptr+8)),
                native_recursion_after=int.from_bytes(uc.mem_read(ptr+20,2),'little'))
            self.active_lower_wait=None
        if self.active_wait is not None and self.active_wait.get('original_return_branch_reached') and address==int(self.active_wait['native_caller'],16):
            row=self.active_wait;ptr=int(row['mutex'],16)
            require(self.word(ptr+8)==self.owner_thread and self.mutexes[ptr]==1,
                'Original condition wait returned without native mutex reacquisition')
            row.update(original_wait_returned=True,original_return=uc.reg_read(REGS[0]),
                native_owner_after=hex(self.word(ptr+8)),native_reacquisition_verified=True,
                real_kernel_wait_verified=False)
            self.active_wait=None
        if address==0x3ec5c6 and self.owner_thread is not None:
            require(self.active_wait is None,'Unsupported nested original condition wait')
            value=super().observe(uc,address,size,data)
            self.active_wait=self.native_condition_waits[-1]
            return value
        if address==0x300bb8 and self.active_wait is not None:
            ptr=uc.reg_read(REGS[0]);wait=self.active_wait
            expected=(int(wait['condition'],16)+28 if caller==0x3ec642 else int(wait['mutex'],16))
            require(caller in [0x3ec642,0x3ec648]and ptr==expected and ptr in self.native_semaphores and
                self.word(ptr+8)==self.owner_thread and self.word(ptr+12)==0 and self.active_native_release is None,
                'Original full release outside exact no-waiter condition scope')
            row=dict(original_entry='0x300bb8',pointer=hex(ptr),native_caller=hex(caller),
                native_owner_before=hex(self.word(ptr+8)),observed_counter_before=self.mutexes[ptr],
                original_body_returned=False,host_wrote_owner_or_links=False,no_waiters_inventory=True)
            self.native_full_releases.append(row);self.active_native_release=row
        if address==0x300a14 and self.active_wait is not None:
            ptr=uc.reg_read(REGS[0]);wait=self.active_wait
            require(caller in [0x3ec664,0x3ec674]and ptr==int(wait['condition'],16)and self.active_lower_wait is None,
                'Original lower condition wait outside scoped call')
            row=dict(original_entry='0x300a14',condition=hex(ptr),native_caller=hex(caller),
                original_arguments=[hex(uc.reg_read(r))for r in REGS],native_owner_before=hex(self.word(ptr+8)),
                native_recursion_before=int.from_bytes(uc.mem_read(ptr+20,2),'little'),original_body_returned=False,
                original_wait_not_replaced_with_success=True,
                same_fictional_constructor_owner_and_current_thread=True,actual_event_delivery_verified=False)
            self.native_lower_wait_operations.append(row);self.active_lower_wait=row
        if address==0x3009a0 and caller==0x3ec692 and self.active_wait is not None:
            ptr=uc.reg_read(REGS[0]);wait=self.active_wait
            require(ptr==int(wait['mutex'],16)and ptr in self.native_semaphores and self.word(ptr+8)==0 and
                self.mutexes[ptr]==0 and self.native_lock_run is None and self.word(0xf09090)==self.owner_thread,
                'Original reacquire did not follow observed full release')
            row=dict(original_entry='0x3009a0',pointer=hex(ptr),native_caller=hex(caller),operation='lock',
                before_words=[hex(self.word(ptr+4*n))for n in range(6)],fixture_thread=hex(self.owner_thread),
                native_body_returned=False,semaphore_fields_written_by_original_only=True,
                real_kernel_scheduler_verified=False,scope='original_condition_mutex_reacquisition')
            self.native_mutex_runs.append(row);self.native_lock_run=row;self.visits[address]+=1
            wait['original_reacquire_entry_reached']=True
            return
        if address==0x3ec6a0 and self.active_wait is not None:
            require(uc.reg_read(REGS[3])==(int(self.active_wait['native_caller'],16)|1),
                'Original wait epilogue did not restore original LR')
            self.active_wait['original_return_branch_reached']=True
        return super().observe(uc,address,size,data)
