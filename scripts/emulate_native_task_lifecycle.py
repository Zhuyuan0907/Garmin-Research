#!/usr/bin/env python3
"""Exercise original task context restore and kernel self-exit, offline only.

Task creation uses the existing controlled allocator/wake harness. Restore,
VFP disabling, mutex lock/unlock, priority changes, exit notification, timed
wait removal, task-list unlinking and successor context restore are original
instructions. Ready queues and optional wait/listener nodes are synthetic.
This does not run a live scheduler or reclaim the wrapper's allocations.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
import unicorn
from unicorn import UC_HOOK_CODE
from unicorn.arm_const import (
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
    UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
    UC_ARM_REG_CPSR, UC_ARM_REG_FPEXC,
)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from emulate_native_task_creation import (
    TaskMachine, DIRECT, GENERIC, ENTRY, CALLBACK, RESULT, NAME, RETURN,
    CALL_STACK,
)

RESTORE = 0x358ec4  # ARM entry; switches to Thumb, then back to ARM.
EXIT_SHIM = 0x358fa4
ALL_TASKS = 0xf0908c
READY_TASKS = 0xf09090
TIMED_WAITS = 0xf0909c
EXIT_LIST = 0x2d226b4
NEXT_STACK = 0x8400000
NEXT_ENTRY = CALLBACK+0x40
LISTENER = CALLBACK+0x80
RAW_DESCRIPTOR = CALLBACK+0xa00
WAIT_NODES = CALLBACK+0xb00
LISTENER_NODE = CALLBACK+0xc00
REGISTERS = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
             UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
             UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
             UC_ARM_REG_R12)
STAGES = {RESTORE, 0x358ecc, 0x358ee0, 0x20ebd8, 0x358ef8, 0x358f08,
          ENTRY, CALLBACK, EXIT_SHIM, 0x1c06a4, 0x1c070c, 0x1c0714,
          0x1c0730, NEXT_ENTRY, LISTENER}


class LifecycleMachine(TaskMachine):
    def __init__(self, stock, stack, occupied=0):
        super().__init__(stock, stack, occupied)
        for page in (0x20b000, 0x20e000, 0x1c0000, 0x353000,
                     0x3cc000, 0x427000):
            self.uc.mem_map(page, 4096)
            self.uc.mem_write(page, stock.read(page, 4096))
        self.uc.mem_map(EXIT_LIST & ~4095, 4096)
        self.uc.mem_map(NEXT_STACK, 0x4000)
        self.uc.mem_write(NEXT_STACK, b'\xa5'*0x4000)
        self.uc.mem_write(LISTENER, struct.pack('<4HI',
                                              0x4a01, 0x6010, 0x6051, 0x4770,
                                              RESULT+8))
        self.observing_restore = False
        self.stages = []
        self.executed = []
        self.executed_keys = set()
        self.arm_md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        self.thumb_md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.uc.hook_add(UC_HOOK_CODE, self.observe_lifecycle)

    def put(self, address, value):
        self.uc.mem_write(address, struct.pack('<I', value))

    def snapshot(self, address=None):
        return {'pc': hex(address if address is not None else self.uc.reg_read(UC_ARM_REG_PC)),
                'cpsr': hex(self.uc.reg_read(UC_ARM_REG_CPSR)),
                'sp': hex(self.uc.reg_read(UC_ARM_REG_SP)),
                'lr': hex(self.uc.reg_read(UC_ARM_REG_LR)),
                'ready_task_list_head': hex(self.word(READY_TASKS)),
                'all_task_list_head': hex(self.word(ALL_TASKS)),
                'registers_r0_r12': [hex(self.uc.reg_read(r)) for r in REGISTERS]}

    def observe_lifecycle(self, uc, address, size, user_data):
        if not self.observing_restore:
            return
        thumb = bool(uc.reg_read(UC_ARM_REG_CPSR) & 0x20)
        key = (address, thumb)
        if key not in self.executed_keys:
            self.executed_keys.add(key)
            md = self.thumb_md if thumb else self.arm_md
            instruction = next(md.disasm(bytes(uc.mem_read(address, size)), address, count=1))
            self.executed.append({'pc': hex(address), 'mode': 'Thumb' if thumb else 'ARM',
                                  'instruction': instruction.mnemonic+' '+instruction.op_str})
        if address in STAGES:
            self.stages.append(self.snapshot(address))

    def create(self, stack, priority, argument, generic=False):
        if generic:
            handle = self.call(GENERIC, (0, CALLBACK | 1, argument, stack),
                               (priority, NAME, 0))
        else:
            handle = self.call(DIRECT, (CALLBACK | 1, argument, stack, priority), (NAME,))
        tcb = self.word(handle+48)
        self.put(READY_TASKS, tcb)
        self.put(0xf09094, 0)
        return handle, tcb

    def resume(self, stop):
        # Seed both banked stacks and old registers; the original restore must
        # use its saved context rather than retain the caller's state.
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x13)
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK-0x1000)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x1f)
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        for index, reg in enumerate(REGISTERS):
            self.uc.reg_write(reg, 0xde000000+index)
        self.uc.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        self.observing_restore = True
        self.uc.emu_start(RESTORE, stop, timeout=1000000, count=10000)
        self.observing_restore = False
        if self.uc.reg_read(UC_ARM_REG_PC) != stop:
            raise ValueError('Original task lifecycle did not reach observation endpoint')
        if self.uc.reg_read(UC_ARM_REG_FPEXC) != 0:
            raise ValueError('Original VFP disable helper did not clear FPEXC')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def restore_created(stock, stack, priority, argument, occupied, generic):
    m = LifecycleMachine(stock, stack, occupied)
    handle, tcb = m.create(stack, priority, argument, generic)
    context = m.word(tcb+12)
    frame = struct.unpack('<13I', m.uc.mem_read(context, 52))
    require(frame == (0x3f, ENTRY | 1, *([0]*9), tcb, EXIT_SHIM | 1),
            'Original initial context does not match observed 13-word layout')
    require(bytes(m.uc.mem_read(tcb+23, 1)) == b'\0', 'Unexpected initial context flag')
    m.resume(EXIT_SHIM)
    entry = next(stage for stage in m.stages if stage['pc'] == hex(ENTRY))
    require((entry['cpsr'], entry['sp'], entry['lr']) ==
            ('0x3f', hex(tcb), hex(EXIT_SHIM | 1)), 'Saved mode/stack/return was not restored')
    require(entry['registers_r0_r12'][4:] == ['0x0']*9,
            'Original initial context did not restore r4-r12')
    require(m.callback_calls == 1 and m.word(RESULT) == argument,
            'Original dispatch did not forward its saved user argument')
    require({RESTORE, 0x358ecc, 0x358ee0, 0x20ebd8, 0x358f08, ENTRY}.issubset(m.visited),
            'Original mixed-mode restore path was skipped')
    require(bytes(m.uc.mem_read(m.stack_base-32, 32)) == b'\xa5'*32,
            'Task allocation leading guard changed')
    return {'case': 'initial_created_context', 'interface': 'generic' if generic else 'direct',
            'requested_stack_bytes': stack, 'logical_priority': priority,
            'occupied_slots': occupied, 'argument': hex(argument),
            'wrapper_handle': hex(handle), 'kernel_tcb': hex(tcb),
            'original_context_words': [hex(v) for v in frame],
            'original_context_builder_executed': True, 'context_format_flag': 0,
            'entry_called_explicitly': False, 'original_restore_executed': True,
            'original_vfp_disable_executed': True, 'original_dispatch_argument_preserved': True,
            'returned_to_original_exit_shim': True, 'exit_shim_executed': False,
            'stages': m.stages, 'endpoint': m.snapshot(),
            'instructions': m.executed, 'creation_hooks': m.events, 'passed': True}


def restore_extended(stock):
    m = LifecycleMachine(stock, 4096)
    argument = 0x90abcdef
    _, tcb = m.create(4096, 12, argument)
    # Test the other restore format with a deliberately synthetic suspended
    # frame. No claim is made that the initial builder creates this format.
    registers = [0x12340000+index for index in range(13)]
    cpsr = 0xa000003f
    context = tcb-68
    frame = [cpsr, ENTRY | 1, *registers, tcb, EXIT_SHIM | 1]
    m.uc.mem_write(context, struct.pack('<17I', *frame))
    m.put(tcb+12, context)
    m.uc.mem_write(tcb+23, b'\x01')
    m.resume(EXIT_SHIM)
    entry = next(stage for stage in m.stages if stage['pc'] == hex(ENTRY))
    require(entry['registers_r0_r12'] == [hex(r) for r in registers],
            'Extended restore did not recover all r0-r12 registers')
    require((entry['cpsr'], entry['sp'], entry['lr']) ==
            (hex(cpsr), hex(tcb), hex(EXIT_SHIM | 1)), 'Extended CPU context differs')
    require(m.callback_calls == 1 and m.word(RESULT) == argument,
            'Extended restore changed original user callback argument')
    return {'case': 'synthetic_extended_saved_context', 'context_format_flag': 1,
            'saved_context_words': [hex(v) for v in frame],
            'suspended_context_created_by_stock_save_routine': False,
            'original_restore_executed': True, 'all_r0_r12_and_cpsr_restored': True,
            'original_dispatch_argument_preserved': True,
            'returned_to_original_exit_shim': True, 'stages': m.stages,
            'instructions': m.executed, 'passed': True}


def self_exit(stock, with_listener_and_waiters):
    m = LifecycleMachine(stock, 4096)
    # Build the successor through the original raw kernel builder first. This
    # makes the all-task list contain two real constructed TCBs; a singleton
    # synthetic list is insufficient for the tested kernel exit routine.
    m.uc.mem_write(RAW_DESCRIPTOR, struct.pack('<5I',
                                             NEXT_ENTRY | 1, 0, NEXT_STACK+0x4000,
                                             0x01f00000, 0))
    next_tcb = m.call(0x358bf8, (RAW_DESCRIPTOR,))
    handle, tcb = m.create(4096, 12, 0x10203040)
    require(m.word(ALL_TASKS) == tcb and m.word(tcb+40) == next_tcb and
            m.word(next_tcb+44) == tcb+40,
            'Original builder did not link two TCBs into the all-task list')
    # Wake is a controlled hook in the creation harness. Supply a two-task
    # ready list explicitly; this does not prove live wake/queue insertion.
    m.uc.mem_write(tcb+22, b'\x01')
    m.uc.mem_write(next_tcb+22, b'\x01')
    m.put(tcb, next_tcb)
    m.put(next_tcb, 0)
    m.put(TIMED_WAITS, 0)
    m.put(EXIT_LIST, 0)
    m.call(0x3008a0, (EXIT_LIST+4,))
    registration = None
    if with_listener_and_waiters:
        # Two timed waits belong to the exiting task; one belongs to successor.
        for index, owner in enumerate((tcb, next_tcb, tcb)):
            m.uc.mem_write(WAIT_NODES+index*8,
                           struct.pack('<2I', WAIT_NODES+(index+1)*8 if index < 2 else 0,
                                       owner))
        m.put(TIMED_WAITS, WAIT_NODES)
        m.observing_restore = True
        registered = m.call(0x3cc5c2, (EXIT_LIST, LISTENER_NODE, 0, LISTENER | 1),
                            (0xaabbccdd,))
        duplicate = m.call(0x3cc5c2, (EXIT_LIST, LISTENER_NODE, 1, LISTENER | 1),
                           (0x55667788,))
        m.observing_restore = False
        require(registered == 0 and duplicate == 0xffffffff,
                'Original listener registration/duplicate guard differs')
        require(m.word(EXIT_LIST) == LISTENER_NODE and
                m.word(LISTENER_NODE+12) == 0xaabbccdd,
                'Duplicate registration changed the original listener argument')
        registration = {'register_return': registered, 'duplicate_return': hex(duplicate),
                        'duplicate_kept_original_argument': True}
    prior_hooks = len(m.events)
    m.resume(NEXT_ENTRY)
    require(m.word(READY_TASKS) == next_tcb and m.word(ALL_TASKS) == next_tcb,
            'Self exit failed to unlink the current task from both lists')
    require(m.word(next_tcb+44) == ALL_TASKS, 'All-task predecessor link was not repaired')
    require(bytes(m.uc.mem_read(tcb+22, 1)) == b'\x80', 'Original exit did not set state0x80')
    require(m.callback_calls == 1 and m.word(RESULT) == 0x10203040,
            'Current task callback did not finish once')
    require(m.word(handle+48) == tcb, 'Unexpected wrapper-slot release on tested kernel path')
    require(len(m.events) == prior_hooks,
            'Self exit unexpectedly required an allocator/bookkeeping/diagnostic hook')
    require(m.uc.reg_read(UC_ARM_REG_SP) == next_tcb and
            m.uc.reg_read(UC_ARM_REG_LR) == EXIT_SHIM | 1 and
            m.uc.reg_read(UC_ARM_REG_CPSR) == 0x3f,
            'Successor context was not restored by original kernel instructions')
    for address in (EXIT_SHIM, 0x1c06a4, 0x3009a0, 0x3008b0, 0x358e18,
                    0x3cc594, 0x300c2c, 0x353df4, 0x1c0730):
        require(address in m.visited, 'Original exit path was skipped: '+hex(address))
    if with_listener_and_waiters:
        require(m.word(RESULT+8) == tcb and m.word(RESULT+12) == 0xaabbccdd,
                'Original exit notification did not pass TCB and listener argument')
        require(m.word(TIMED_WAITS) == WAIT_NODES+8 and m.word(WAIT_NODES+8) == 0,
                'Original timed-wait cleanup failed to preserve unrelated waiter')
        require(len([stage for stage in m.stages if stage['pc'] == hex(LISTENER)]) == 1,
                'Registered exit listener was not called exactly once')
        listener = next(stage for stage in m.stages if stage['pc'] == hex(LISTENER))
        require(listener['ready_task_list_head'] == hex(tcb) and
                listener['all_task_list_head'] == hex(tcb) and
                m.stack_base <= int(listener['sp'], 16) < tcb,
                'Exit listener did not run before unlink on the exiting stack')
    else:
        require(m.word(TIMED_WAITS) == 0, 'Empty timed-wait list changed')
    require(bytes(m.uc.mem_read(m.stack_base-32, 32)) == b'\xa5'*32 and
            bytes(m.uc.mem_read(NEXT_STACK, 32)) == b'\xa5'*32,
            'Task lifecycle changed stack leading guards')
    endpoint = m.snapshot()
    if with_listener_and_waiters:
        # Remove the module's callback after the exiting task is already gone.
        # Concurrent callbacks/unloading are not exercised by this serial case.
        m.observing_restore = True
        unregistered = m.call(0x3cc624, (EXIT_LIST, LISTENER_NODE))
        missing = m.call(0x3cc624, (EXIT_LIST, LISTENER_NODE))
        m.observing_restore = False
        require(unregistered == 0 and missing == 0xffffffff and m.word(EXIT_LIST) == 0,
                'Original listener removal/missing-node guard differs')
        registration.update(unregister_return=unregistered, missing_return=hex(missing),
                            node_unlinked=True)
    return {'case': 'self_exit_with_listener_and_waiters' if with_listener_and_waiters
            else 'self_exit_empty_listener_and_wait_lists',
            'original_context_builders_executed': 2, 'kernel_tcb': hex(tcb),
            'successor_tcb': hex(next_tcb), 'all_task_list_from_original_builders': True,
            'ready_list_manually_supplied': True, 'original_exit_shim_executed': True,
            'original_mutex_and_priority_operations_executed': True,
            'contended_mutex_tested': False, 'original_kernel_self_exit_executed': True,
            'exit_state': '0x80', 'all_and_ready_task_lists_unlinked': True,
            'successor_context_restored': True, 'successor_entry_executed': False,
            'exit_listener_node_storage_synthetic': with_listener_and_waiters,
            'original_listener_register_and_remove_executed': with_listener_and_waiters,
            'listener_registration': registration,
            'exit_listener_calls': 1 if with_listener_and_waiters else 0,
            'listener_runs_before_unlink_on_exiting_stack': with_listener_and_waiters,
            'timed_wait_nodes_synthetic': with_listener_and_waiters,
            'matching_timed_waits_removed': 2 if with_listener_and_waiters else 0,
            'unrelated_timed_wait_preserved': with_listener_and_waiters,
            'wrapper_slot_released': False, 'wrapper_handle_still_points_to_tcb': hex(handle),
            'stack_and_descriptor_freed': False,
            'no_hooks_during_restore_and_self_exit': True, 'stages': m.stages,
            'endpoint': endpoint, 'instructions': m.executed, 'passed': True}


def main():
    stock = NativeImage()
    # Assert exact mixed-mode entry and the original VFP helper, never patch it.
    require(stock.read(RESTORE, 8) == bytes.fromhex('01c08fe21cff2fe1'),
            'Original ARM-to-Thumb restore entry changed')
    require(stock.word(0x358f10) == READY_TASKS and stock.word(0x358d10) == ALL_TASKS,
            'Original task-list literals differ')
    restored = [restore_created(stock, 2048, 0, 0x10203040, 0, False),
                restore_created(stock, 4096, 12, 0x50607080, 7, True),
                restore_created(stock, 8192, 15, 0, 14, True), restore_extended(stock)]
    exits = [self_exit(stock, False), self_exit(stock, True)]
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED, 'unicorn_version': unicorn.__version__,
              'cpu_model': 'ARM1176',
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'dependencies_sha256': {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
                                     for name in ('scripts/emulate_native_task_creation.py',
                                                  'scripts/analyze_native_sections.py')},
              'restore_entry': hex(RESTORE), 'restore_entry_mode': 'ARM',
              'exit_shim': hex(EXIT_SHIM), 'kernel_self_exit': '0x1c06a4',
              'exit_listener_register': '0x3cc5c2', 'exit_listener_remove': '0x3cc624',
              'exit_listener_registration_abi': ['list', 'node', 'order', 'callback',
                                                  'stack:argument'],
              'all_task_list': hex(ALL_TASKS), 'ready_task_list': hex(READY_TASKS),
              'runtime_restore_cases': restored, 'kernel_self_exit_cases': exits,
              'all_passed': True, 'device_io': False, 'device_install_candidate': False,
              'original_context_restore_executed': True,
              'original_kernel_self_exit_executed': True,
              'live_scheduler_or_interrupt_timing_verified': False,
              'cross_task_cancellation_verified': False,
              'wrapper_slot_and_allocation_reclamation_verified': False,
              'real_exit_listener_registration_verified': False,
              'exit_listener_is_safe_immediate_stack_or_module_free_point': False,
              'limitations': 'Offline exact-firmware execution only. Allocation, creation bookkeeping and wake remain the prior explicit hooks; restore and self-exit require no additional hooks. Initial contexts are built by original code; the flag1 suspended frame is deliberately synthetic. Ready-list membership and timed-wait nodes are synthetic; the optional listener uses synthetic storage but is registered/removed by original code, including duplicate/missing-node guards. Successor context restoration occurs through original exit code, but no IRQ clock, live wakeup/priority policy, concurrent locking, preemption workload or physical task is tested. Kernel self-exit leaves the wrapper slot pointing at its TCB in both observed paths; safe wrapper/heap/module reclamation and cancellation remain unverified. No queue, real Bluetooth endpoint, loaded App or speaker playback is provided.'}
    path = ROOT/'evidence/firmware-analysis/native-task-lifecycle-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'restore_cases': len(restored),
                      'self_exit_cases': len(exits), 'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
