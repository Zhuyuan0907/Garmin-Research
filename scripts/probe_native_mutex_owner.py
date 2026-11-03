#!/usr/bin/env python3
"""Scoped original immediate mutex operations on explicit thread/storage fixtures."""
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_LR, UC_ARM_REG_SP
from probe_native_dispatcher_condition import DispatcherVM
from emulate_native_vpm_filesystem import REGS, require, STACK, RETURN

class OwnerVM(DispatcherVM):
    def __init__(self,stock,build):
        self.owner_thread=None;self.native_semaphores={};self.native_lock_run=None
        self.native_mutex_runs=[];self.fixture_thread_inventory=None
        super().__init__(stock,build)

    def configure_thread_fixture(self):
        require(self.owner_thread is None and not any(self.mutexes.values()),'Thread fixture configured twice or locks held')
        original={hex(a):self.word(a)for a in [0xf09090,0xf090a0]}
        ptr=self.invoke(0x3954cc,(96,))
        # Explicit input TCB inventory, not recovered real scheduler state.
        self.uc.mem_write(ptr,b'\0'*96)
        self.put(0xf09090,ptr);self.put(0xf090a0,ptr);self.owner_thread=ptr
        self.fixture_thread_inventory=dict(pointer=hex(ptr),bytes=96,original_global_words=original,
            fixture_ready_head_and_constructor_thread_pointer_equal=True,
            host_seeded_semaphore_owner_or_list_links=False,real_boot_task_context_verified=False)
        return ptr

    def register_native_semaphore(self,ptr):
        require(self.declared_storage(ptr,24)and ptr not in self.native_semaphores,
            'Unknown native semaphore storage or duplicate scope')
        self.native_semaphores[ptr]=dict(pointer=hex(ptr),bytes=24,retained_condition_token=False)

    def invoke_mutex_control(self,address,args,expected_counts):
        require(address in [0x3008a1,0x3009a1,0x3008b1,0x3ec541], 'Unsupported original mutex-control entry')
        self.returned=False
        for reg,value in zip(REGS,args):self.uc.reg_write(reg,value)
        self.uc.reg_write(UC_ARM_REG_SP,STACK);self.uc.reg_write(UC_ARM_REG_LR,RETURN|1)
        self.allow_direct_backend_control=address==0x3008a1
        try:self.uc.emu_start(address,RETURN+2,count=100000,timeout=1000000)
        finally:self.allow_direct_backend_control=False
        require(self.returned and self.native_lock_run is None,'Original immediate mutex control did not return')
        require({p:n for p,n in self.mutexes.items()if n}==expected_counts,'Native/fixture mutex inventory differs')
        return self.uc.reg_read(REGS[0])

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if address in [0x3009a0,0x3008b0]and self.owner_thread is not None:
            ptr=uc.reg_read(REGS[0])
            condition=(address==0x3009a0 and caller==0x3ec572 and self.active_condition is not None)
            if condition:
                require(ptr==int(self.active_condition['pointer'],16),'Native condition token pointer differs')
                self.register_native_semaphore(ptr)
                self.native_semaphores[ptr]['retained_condition_token']=True
            allowed=ptr in self.native_semaphores and (caller==RETURN or condition)
            if allowed:
                require(self.native_lock_run is None and self.word(0xf09090)==self.owner_thread,
                    'Nested native semaphore op or changed fixture task identity')
                row=dict(original_entry=hex(address),pointer=hex(ptr),native_caller=hex(caller),
                    operation='lock'if address==0x3009a0 else'unlock',
                    before_words=[hex(self.word(ptr+4*n))for n in range(6)],
                    fixture_thread=hex(self.owner_thread),native_body_returned=False,
                    semaphore_fields_written_by_original_only=True,real_kernel_scheduler_verified=False)
                self.native_mutex_runs.append(row);self.native_lock_run=row;self.visits[address]+=1
                return # Execute unchanged mixed ARM/Thumb native body, no inherited counter-only replacement.
        if self.native_lock_run is not None and address in [0x300a0a,0x30092a]:
            row=self.native_lock_run;ptr=int(row['pointer'],16);entry=self.native_semaphores[ptr]
            require(uc.reg_read(REGS[3])==(int(row['native_caller'],16)|1),'Original mutex epilogue did not restore LR')
            owner=self.word(ptr+8);depth=int.from_bytes(uc.mem_read(ptr+20,2),'little')
            require(owner in [0,self.owner_thread],'Original mutex has undeclared owner')
            actual_count=1+depth if owner else 0
            if entry['retained_condition_token']and row['operation']=='lock':
                require(actual_count==1 and self.active_condition is not None,'Original retained condition token missing')
                self.active_condition.update(bootstrap_token_retained=True,
                    original_mutex_lock_and_owner_store_executed=True,native_owner=hex(owner))
                self.dispatcher_condition_tokens[ptr]=dict(pointer=hex(ptr),native_caller='0x3ec572',
                    explicit_retained_bootstrap_token=1,original_native_owner_store=True,
                    native_owner=hex(owner),ordinary_mutex_counter_not_incremented_or_swept=True,
                    real_kernel_owner_wait_and_safe_lifetime_verified=False)
                self.mutexes[ptr]=0
            else:
                self.mutexes[ptr]=actual_count
                if entry['retained_condition_token']and owner==0:
                    self.dispatcher_condition_tokens[ptr].update(explicit_retained_bootstrap_token=0,
                        released_by_original_unlock_control=True)
            row.update(native_body_returned=True,original_return_branch_reached=True,
                after_words=[hex(self.word(ptr+4*n))for n in range(6)],
                native_owner=hex(owner),native_recursion_count=depth,
                thread_owned_list_head=hex(self.word(self.owner_thread+32)))
            self.native_lock_run=None
        if address in [0x300d08,0x358ec4]and self.native_lock_run is not None:
            raise ValueError('Native mutex reached contention/scheduler outside immediate single-thread scope')
        return super().observe(uc,address,size,data)
