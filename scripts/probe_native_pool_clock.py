#!/usr/bin/env python3
"""Exact native clock-plus1000 request before declared absent-pool failure.

Keep frozen fixed-clock VMs unchanged. Original caller, read, addition, stack
store/load, lookup scan, failure branch and unlock execute without patches.
Only the inherited unavailable kernel wait is a scoped failure boundary.
"""
from collections import deque
import unicorn
from unicorn.arm_const import UC_ARM_REG_LR,UC_ARM_REG_SP,UC_ARM_REG_R4
from probe_native_mainmenu_controller import ControllerVM
from emulate_native_mainmenu_constructor import ConstructorVM
from emulate_native_vpm_filesystem import REGS,require

class PoolClockVM(ControllerVM):
    def __init__(self,stock,build):
        self.pool_native_runs=[];self.pool_wait_failures=[];self.pool_context=None
        self.scripted_pool_clock_inputs=None
        super().__init__(stock,build)

    def set_pool_clock_inputs(self,words):
        require(self.pool_context is None,'Cannot change input during native pool call')
        require(words is None or all(0<=n<=0xffffffff for n in words),'Invalid explicit u32 clock input')
        self.scripted_pool_clock_inputs=None if words is None else deque(words)

    def observe(self,uc,address,size,data):
        if address==0x3b4ba8:
            require(self.pool_context is None,'Unsupported reentrant native pool call')
            self.pool_context=dict(original_entry='0x3b4ba8',native_caller=hex(uc.reg_read(UC_ARM_REG_LR)&~1),
                scanned_indices=[],clock_result=None,native_calculated_argument=None,wait_seen=False)
        if address==0x353a9c and self.scripted_pool_clock_inputs is not None:
            require((uc.reg_read(UC_ARM_REG_LR)&~1)==0x3b4bb0 and self.pool_context is not None,
                'Explicit pool clock used by an unrelated caller')
            require(self.scripted_pool_clock_inputs,'Finite explicit clock inputs exhausted')
            word=self.scripted_pool_clock_inputs.popleft()
            self.virtual_clock_milliseconds=word;self.put(0xf09098,word)
            self.virtual_clock_ticks.append(dict(original_entry=hex(address),word='0xf09098',
                supplied_virtual_clock_word=word,exact_native_pool_caller='0x3b4bb0',
                original_read_still_executed=True,real_kernel_time_units_and_scheduler_verified=False))
            return ConstructorVM.observe(self,uc,address,size,data)
        if address==0x3b4bb0:
            require(self.pool_context is not None,'Original clock return lacks native pool context')
            value=uc.reg_read(REGS[0]);require(value==self.word(0xf09098),'Original clock read differs from supplied word')
            self.pool_context['clock_result']=value
        if address==0x3b4bc0:
            ctx=self.pool_context;require(ctx is not None and ctx['clock_result']is not None,
                'Native plus1000 calculation lacks original clock result')
            value=uc.reg_read(REGS[0]);require(value==(ctx['clock_result']+1000)&0xffffffff,
                'Original pool addition differs from clock+1000 modulo u32')
            ctx['native_calculated_argument']=value
        if address==0x3b4bc6:
            require(self.pool_context is not None,'Original pool scan lacks context')
            self.pool_context['scanned_indices'].append(uc.reg_read(UC_ARM_REG_R4))
        if address==0x3b4c10:
            ctx=self.pool_context;require(ctx is not None and ctx['native_calculated_argument']is not None,
                'Original wait call lacks calculated argument')
            require(uc.reg_read(REGS[2])==ctx['native_calculated_argument']==self.word(uc.reg_read(UC_ARM_REG_SP)+4),
                'Original stack store/load did not retain computed wait argument')
        if address==0x3ec6aa and (uc.reg_read(UC_ARM_REG_LR)&~1)==0x3b4c14:
            args=[uc.reg_read(r)for r in REGS];ctx=self.pool_context
            require(ctx is not None and ctx['scanned_indices']==list(range(7)) and not ctx['wait_seen'],
                'Original unavailable pool did not scan all seven indices exactly once')
            require(args[:2]==[0x35e0308,0x35e02f0] and args[2]==ctx['native_calculated_argument'] and
                args[2]==(ctx['clock_result']+1000)&0xffffffff and self.mutexes[args[1]]==1,
                'Unexpected exact absent-pool caller/argument or held mutex')
            ctx['wait_seen']=True
            row=dict(entry=hex(address),caller='0x3b4c14',condition=hex(args[0]),mutex=hex(args[1]),
                original_clock_result=ctx['clock_result'],native_wait_argument=args[2],
                native_stack_store_load_and_u32_addition_verified=True,fixture_mutex_count_before=1,
                explicit_lower_wait_failure=1,host_changed_wait_argument=False,
                real_kernel_condition_owner_or_wait_schedule_verified=False)
            self.pool_wait_failures.append(row)
            self.visits[address]+=1;self.ret(1);return
        if address==0x3b4c2e:
            ctx=self.pool_context
            require(ctx is not None and ctx['wait_seen'] and uc.reg_read(UC_ARM_REG_R4)==255 and
                self.mutexes[0x35e02f0]==0,'Original unavailable-pool rejection/unlock differs')
            ctx.update(original_pool_index=255,fixture_mutex_count_after=0,
                native_failure_branch_and_unlock_executed=True,host_supplied_final_pool_index=False)
            self.pool_native_runs.append(ctx);self.pool_context=None
        return super().observe(uc,address,size,data)
