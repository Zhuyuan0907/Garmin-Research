#!/usr/bin/env python3
"""Verify stock Garmin OS20 task construction/entry ABI, offline only.

Original wrappers, lookup, interrupt save/restore, kernel context builder,
mutex initialization, descriptor registry and current-task query execute.
Allocators, diagnostic bookkeeping and wake requests are controlled hooks.
The task entry is invoked explicitly; no actual scheduling is claimed.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

import unicorn
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_CODE, UcError
from unicorn.arm_const import (UC_CPU_ARM_1176, UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                               UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_CPSR)
from analyze_native_sections import NativeImage, ROOT, EXPECTED
from analyze_sdp_activation import trace

DIRECT = 0x521e5e
GENERIC = 0x521f16
ENTRY = 0x521e44
LOOKUP = 0x521d7c
TABLE = 0x3a1b294
PRIORITIES = 0xb6ff30
DESCRIPTOR = 0x8000000+4096-100
STACK_AREA = 0x8100000
STACK_END = STACK_AREA+0x4000
CALLBACK = 0x8200000
RESULT = CALLBACK+0x800
NAME = CALLBACK+0x900
RETURN = 0x10000
CALL_STACK = 0x900f000


class TaskMachine:
    def __init__(self, stock, requested_stack, occupied=0, fail_calloc=False):
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        self.uc.ctl_set_cpu_model(UC_CPU_ARM_1176)
        self.uc.reg_write(UC_ARM_REG_CPSR, 0x1f)
        for page in (0x521000, 0x522000, 0x358000, 0x300000, 0x21b000,
                     0x2fb000, 0x2fc000, 0x395000, 0xf5000, 0x23d000, 0xb6f000):
            self.uc.mem_map(page, 4096)
            self.uc.mem_write(page, stock.read(page, 4096))
        self.uc.mem_map(0xf00000, 0x73000)
        self.uc.mem_write(0xf00000, stock.read(0xcb1980, 0x7224c))
        for page, size in ((TABLE & ~4095, 4096), (0x14b3000, 4096),
                           (DESCRIPTOR & ~4095, 4096), (STACK_AREA, 0x4000),
                           (CALLBACK, 4096), (RETURN, 4096), (0x9000000, 0x10000)):
            self.uc.mem_map(page, size)
        self.uc.mem_write(DESCRIPTOR-32, b'\xa5'*132)
        self.stack_bytes = requested_stack+152
        self.stack_base = STACK_END-self.stack_bytes
        self.uc.mem_write(self.stack_base-32, b'\xa5'*(32+self.stack_bytes))
        self.uc.mem_write(CALLBACK, struct.pack('<4HI', 0x4901, 0x6008, 0x2000, 0x4770, RESULT))
        self.uc.mem_write(RESULT, b'\xa5'*4)
        self.uc.mem_write(NAME, b'GarminMediaWorker\0')
        # The current kernel descriptor registry is controlled, already ready.
        self.uc.mem_write(0xf071cc, b'\x01'+bytes(7))
        self.uc.mem_write(0xf090a8, bytes(4))
        for slot in range(occupied):
            self.uc.mem_write(TABLE+slot*64+48, struct.pack('<I', 0x7000000+slot*0x100))
        self.hooks = {0x395440: 'calloc', 0x39544c: 'malloc',
                      0x2fcd0a: 'diagnostic_task_metadata',
                      0xf5030: 'kernel_bookkeeping', 0x2fcf44: 'wake_request',
                      0x23d6e8: 'diagnostic'}
        for address in self.hooks:
            self.uc.mem_write(address, struct.pack('<I', 0xe12fff1e)
                              if address in (0x395440, 0x39544c, 0x2fcf44) else b'\x70\x47')
        self.events = []
        self.visited = set()
        self.callback_calls = 0
        self.fail_calloc = fail_calloc
        self.uc.hook_add(UC_HOOK_CODE, self.observe)

    def observe(self, uc, address, size, user_data):
        self.visited.add(address)
        if address == CALLBACK: self.callback_calls += 1
        if address not in self.hooks: return
        args = [uc.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1,
                                            UC_ARM_REG_R2, UC_ARM_REG_R3)]
        name = self.hooks[address]
        self.events.append({'hook': name, 'args': [hex(value) for value in args]})
        if name == 'calloc':
            if args[:2] != [1, 100]: raise ValueError('Stock task descriptor allocation changed')
            if not self.fail_calloc: uc.mem_write(DESCRIPTOR, bytes(100))
            uc.reg_write(UC_ARM_REG_R0, 0 if self.fail_calloc else DESCRIPTOR)
        elif name == 'malloc':
            if args[0] != self.stack_bytes: raise ValueError('Stock task stack allocation changed')
            uc.reg_write(UC_ARM_REG_R0, self.stack_base)
        else:
            uc.reg_write(UC_ARM_REG_R0, 0)

    def call(self, address, args=(), extras=()):
        self.uc.reg_write(UC_ARM_REG_SP, CALL_STACK)
        self.uc.reg_write(UC_ARM_REG_LR, RETURN | 1)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1,
                               UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.uc.reg_write(reg, value)
        if extras: self.uc.mem_write(CALL_STACK, struct.pack('<'+'I'*len(extras), *extras))
        self.uc.emu_start(address | 1, RETURN, timeout=1000000, count=10000)
        if self.uc.reg_read(UC_ARM_REG_PC) != RETURN:
            raise ValueError('Task wrapper did not return within observation bounds')
        return self.uc.reg_read(UC_ARM_REG_R0)

    def word(self, address):
        return struct.unpack('<I', self.uc.mem_read(address, 4))[0]


def construction(stock, stack, priority, argument, occupied, generic):
    m = TaskMachine(stock, stack, occupied)
    if generic:
        handle = m.call(GENERIC, (0x11223344, CALLBACK | 1, argument, stack),
                        (priority, NAME, 0))
    else:
        handle = m.call(DIRECT, (CALLBACK | 1, argument, stack, priority), (NAME,))
    wanted = TABLE+occupied*64
    if handle != wanted: raise ValueError('Stock wrapper chose unexpected free task slot')
    tcb = m.word(handle+48)
    if tcb != ((STACK_END-108) & ~7):
        raise ValueError('Stock kernel task control block placement differs')
    if m.word(DESCRIPTOR) != ENTRY | 1:
        raise ValueError('Kernel task descriptor did not use original dispatch entry')
    if (m.word(handle+12), m.word(handle+16), m.word(handle+8)) != (CALLBACK | 1, argument, priority):
        raise ValueError('Wrapper did not retain original callback/argument/logical priority')
    mapped_priority = stock.read(PRIORITIES+priority, 1)[0]
    if bytes(m.uc.mem_read(tcb+16, 2)) != bytes([mapped_priority])*2:
        raise ValueError('Kernel task priority mapping differs')
    context = m.word(tcb+12)
    frame = struct.unpack('<13I', m.uc.mem_read(context, 52))
    if (context != tcb-52 or frame[0] != 0x3f or frame[1] != ENTRY | 1
            or frame[-2] != tcb or frame[-1] != 0x358fa5):
        raise ValueError('Original ARM/Thumb task context construction differs')
    wake = [e for e in m.events if e['hook'] == 'wake_request']
    if len(wake) != 1 or wake[0]['args'][:2] != [hex(tcb), '0x8']:
        raise ValueError('Stock task creation did not request the observed wake event')
    if m.word(0x14b3ad0) != DESCRIPTOR or m.word(0xf071d0) != 1:
        raise ValueError('Original task descriptor registry was not used')
    if bytes(m.uc.mem_read(DESCRIPTOR-32, 32)) != b'\xa5'*32:
        raise ValueError('Stock creator changed descriptor leading guard')
    if bytes(m.uc.mem_read(m.stack_base-32, 32)) != b'\xa5'*32:
        raise ValueError('Stock creator changed allocation leading guard')
    # Current-task query and slot lookup run their original instructions.
    m.uc.mem_write(0xf09090, struct.pack('<I', tcb))
    m.uc.mem_write(0xf09094, bytes(4))
    m.call(ENTRY)
    if m.callback_calls != 1 or m.word(RESULT) != argument:
        raise ValueError('Original dispatch did not call user entry with its argument')
    for address in (0x358bf8, 0x358c2c, 0x358c40, 0x3008a0, 0x21b6cc,
                    0x21b6dc, 0x2fbbbe, 0x358d24, LOOKUP):
        if address not in m.visited: raise ValueError('Required stock path skipped: '+hex(address))
    return {'interface': 'generic' if generic else 'direct', 'requested_stack_bytes': stack,
            'allocated_stack_bytes': m.stack_bytes, 'logical_priority': priority,
            'kernel_priority_byte': mapped_priority, 'argument': hex(argument),
            'occupied_slots': occupied, 'wrapper_handle': hex(handle), 'kernel_tcb': hex(tcb),
            'saved_context': [hex(v) for v in frame], 'original_dispatch_entry': hex(ENTRY | 1),
            'user_callback_calls': 1, 'user_argument_preserved': True,
            'kernel_context_builder_executed': True, 'actual_scheduling_verified': False,
            'hooks': m.events, 'passed': True}


def main():
    stock = NativeImage()
    cases = [construction(stock, 2048, 0, 0x10203040, 0, False),
             construction(stock, 4096, 12, 0x50607080, 7, True),
             construction(stock, 8192, 15, 0, 14, True)]
    exhausted = TaskMachine(stock, 2048, occupied=15)
    if exhausted.call(LOOKUP, (0,)) != 0:
        raise ValueError('Exhausted task lookup unexpectedly returned a slot')
    if len([e for e in exhausted.events if e['hook'] == 'diagnostic']) != 1:
        raise ValueError('Stock exhausted-slot diagnostic path did not execute')
    failed = TaskMachine(stock, 2048, fail_calloc=True)
    try:
        failed.call(DIRECT, (CALLBACK | 1, 0, 2048, 0), (NAME,))
    except UcError as error:
        if error.errno != unicorn.UC_ERR_WRITE_UNMAPPED or failed.uc.reg_read(UC_ARM_REG_PC) != 0x521e98:
            raise
        failure = {'case': 'null_descriptor_allocation', 'unmapped_write_fault': error.errno,
                   'fault_pc': hex(failed.uc.reg_read(UC_ARM_REG_PC)),
                   'stock_creator_checks_null_allocation': False, 'passed': True}
    else:
        raise ValueError('Stock creator unexpectedly accepted a null descriptor')
    report = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED, 'unicorn_version': unicorn.__version__,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'direct_creator': hex(DIRECT), 'generic_creator': hex(GENERIC),
              'task_dispatch_entry': hex(ENTRY), 'kernel_context_builder': '0x358bf8',
              'direct_abi': ['entry', 'argument', 'stack_bytes', 'logical_priority', 'stack:name'],
              'generic_abi': ['unused_first_argument_observed', 'entry', 'argument', 'stack_bytes',
                              'stack:logical_priority', 'stack:name', 'stack:unused_last_argument_observed'],
              'task_table': {'base': hex(TABLE), 'slots': 15, 'stride': 64,
                             'callback_offset': 12, 'argument_offset': 16, 'kernel_tcb_offset': 48},
              'creation_cases': cases, 'exhausted_lookup': {'occupied_slots': 15, 'return': 0, 'passed': True},
              'null_allocation_case': failure, 'all_passed': True,
              'actual_worker_created_on_device': False, 'actual_scheduling_verified': False,
              'cancellation_and_task_exit_verified': False, 'device_io': False,
              'creator_instructions': trace(stock, DIRECT, 180),
              'generic_instructions': trace(stock, GENERIC, 60),
              'dispatcher_instructions': trace(stock, ENTRY, 60),
              'limitations': 'Stock wrapper and ARM/Thumb kernel context builder execute in synthetic RAM. Allocators, metadata/bookkeeping, wake and diagnostic reporting are hooks. Dispatch is explicitly invoked with a controlled current TCB; no kernel scheduling/IRQ timing, lifetime/cleanup/cancellation, queue synchronization or physical device is exercised. Only logical priorities0/12/15 and stack sizes2048/4096/8192 are tested; the full valid priority domain and creator reachability in the active device are unverified. Exhaustion is tested through lookup alone; calling the unchecked creator on exhaustion is unsafe. Null allocation produces an original-code write fault. This is an ABI experiment, not an installed App or functioning audio worker.'}
    path = ROOT/'evidence/firmware-analysis/native-task-creation-emulation.json'
    path.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'creation_cases': len(cases),
                      'all_passed': True, 'device_io': False}))


if __name__ == '__main__':
    main()
