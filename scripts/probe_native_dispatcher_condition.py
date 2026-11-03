#!/usr/bin/env python3
"""Original bounded semaphore zero-init and explicit retained condition token.

No mutation of frozen VMs, fabricated real owner, counter sweep or safe
condition scheduling/unload claim. Native3008A0 body replaces a scoped noop.
"""
import unicorn
from unicorn.arm_const import UC_ARM_REG_PC,UC_ARM_REG_LR
from probe_native_gui_runtime_bootstrap import BootstrapVM
from emulate_native_vpm_filesystem import REGS,require,RETURN

class DispatcherVM(BootstrapVM):
    def __init__(self,stock,build):
        self.backend_initializations=[];self.active_backend=None
        self.condition_constructor_runs=[];self.active_condition=None;self.dispatcher_condition_tokens={}
        self.allow_direct_backend_control=False;self.stock_zero_ranges=stock.zeros
        self.native_condition_magic=stock.word(0x3ec6b0)
        super().__init__(stock,build)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_WRITE,self.observe_backend_write)

    def declared_storage(self,pointer,length):
        if any(row['runtime_start']<=pointer and pointer+length<=row['runtime_end']for row in self.stock_zero_ranges):return 'original_zero_BSS'
        for p,entry in self.raw_allocations.items():
            if not entry['freed']and p<=pointer and pointer+length<=p+entry['length']:return 'guarded_raw_allocation'
        for entry in self.handles.values():
            if not entry['freed']and entry['pointer']<=pointer and pointer+length<=entry['pointer']+entry['length']:
                return 'guarded_opaque_handle_payload'
        return None

    def observe_backend_write(self,uc,access,address,size,value,data):
        pc=uc.reg_read(UC_ARM_REG_PC)
        if pc in range(0x3008a2,0x3008ae,2):
            row=self.active_backend
            require(row is not None and address==int(row['pointer'],16)+2*(pc-0x3008a2)and size==4 and value==0,
                'Original semaphore initializer wrote outside exact24-byte body')
            row['native_zero_writes'].append(dict(PC=hex(pc),address=hex(address),size=size,value=value))

    def observe(self,uc,address,size,data):
        caller=uc.reg_read(UC_ARM_REG_LR)&~1
        if self.active_condition is not None:
            row=self.active_condition
            if row.get('original_return_branch_reached') and address==int(row['native_caller'],16):
                row['native_constructor_returned']=True
                self.condition_constructor_runs.append(row);self.active_condition=None
        if address==0x3008a0:
            pointer=uc.reg_read(REGS[0]);storage=self.declared_storage(pointer,24)
            allowed=caller in [0x3103e6,0x46c286,0x358c82,0x358c8a,0x3ec562,0x3ec56a]or(
                caller==RETURN and self.allow_direct_backend_control)
            if allowed and storage:
                require(self.active_backend is None and len(self.backend_initializations)<8192,'Nested or exhausted native backend scope')
                row=dict(original_entry='0x3008a0',pointer=hex(pointer),native_caller=hex(caller),bytes=24,
                    storage_boundary=storage,before_hex=bytes(uc.mem_read(pointer,24)).hex(),native_zero_writes=[],
                    original_body_executed=False,host_seeded_backend_bytes=False)
                self.backend_initializations.append(row);self.active_backend=row;self.visits[address]+=1
                # Skip only inherited OuterVM's noop at3008A0. Leave all
                # registers, PC/SP/LR intact, executing the native MOV/STRe6.
                return
        if address==0x3008ae and self.active_backend is not None:
            row=self.active_backend;require(len(row['native_zero_writes'])==6 and
                bytes(uc.mem_read(int(row['pointer'],16),24))==b'\0'*24,'Native backend six zero stores incomplete')
            row.update(original_body_executed=True,after_hex=bytes(uc.mem_read(int(row['pointer'],16),24)).hex())
            self.active_backend=None
        if address==0x3ec540:
            pointer=uc.reg_read(REGS[0]);storage=self.declared_storage(pointer,52)
            if storage:
                require(self.active_condition is None,'Unsupported reentrant native condition constructor')
                self.active_condition=dict(original_entry='0x3ec540',pointer=hex(pointer),native_caller=hex(caller),
                    storage_boundary=storage,bootstrap_token_retained=False,native_constructor_returned=False)
        if address==0x3009a0 and caller==0x3ec572 and self.active_condition is not None:
            pointer=uc.reg_read(REGS[0]);row=self.active_condition
            require(pointer==int(row['pointer'],16)and pointer not in self.dispatcher_condition_tokens and
                self.word(pointer+24)==self.native_condition_magic and bytes(uc.mem_read(pointer,24))==b'\0'*24 and
                bytes(uc.mem_read(pointer+28,24))==b'\0'*24 and self.mutexes[pointer]==0,
                'Original condition storage/init or retained bootstrap token differs')
            row['bootstrap_token_retained']=True
            token=dict(pointer=hex(pointer),native_caller='0x3ec572',explicit_retained_bootstrap_token=1,
                ordinary_mutex_counter_not_incremented_or_swept=True,real_kernel_owner_wait_and_safe_lifetime_verified=False)
            self.dispatcher_condition_tokens[pointer]=token
            self.visits[address]+=1;self.ret(0);return
        if address==0x3ec57e and self.active_condition is not None:
            row=self.active_condition;require(row['bootstrap_token_retained'],'Native condition returned without declared token')
            row.update(original_IRQ_restore_call_reached=True,original_owner_transfer_300AE4_body_executed=True,
                real_thread_owner_or_condition_wait_verified=False)
        if address==0x3ec582 and self.active_condition is not None:
            self.active_condition['original_IRQ_restore_call_completed']=True
        if address==0x3ec586 and self.active_condition is not None:
            row=self.active_condition
            require(row.get('original_IRQ_restore_call_completed')and
                uc.reg_read(REGS[3])==(int(row['native_caller'],16)|1),
                'Original condition IRQ restore or LR-return epilogue incomplete')
            row['original_return_branch_reached']=True
        return super().observe(uc,address,size,data)
