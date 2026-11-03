#!/usr/bin/env python3
"""Exact-firmware task and output-command inventory; static, no device I/O.

This follows verified literal references and the computed Thumb dispatch
table. It does not boot driver/controller tasks or infer physical DAC format.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM
from analyze_native_sections import NativeImage, ROOT, EXPECTED


def descriptor(stock, pointer, global_handle, initializer):
    raw = stock.read(pointer, 20)
    words = struct.unpack('<5I', raw)
    return {'readonly_descriptor': hex(pointer), 'raw_hex': raw.hex(),
            'entry': hex(words[0]), 'message_storage': hex(words[1]), 'stack_end': hex(words[2]),
            'message_bytes': raw[12], 'message_slots': raw[13], 'kernel_priority': raw[14],
            'descriptor_byte15': raw[15], 'argument_field': hex(words[4]),
            'runtime_handle_global': hex(global_handle), 'initializer': hex(initializer),
            'task_executed_here': False}


def instructions(stock, address, size):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    return [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
            for i in md.disasm(stock.read(address, size), address)]


def main():
    stock = NativeImage()
    driver = descriptor(stock, stock.word(0x40caf0), stock.word(0x40caf4), 0x40ca80)
    controller = descriptor(stock, stock.word(0x30ee94), stock.word(0x30ee90), 0x30ee62)
    notifier = descriptor(stock, stock.word(0x30ee98), stock.word(0x30ee9c), 0x30ee62)
    assert (driver['entry'], driver['message_bytes'], driver['message_slots'], driver['kernel_priority']) == \
           ('0x436c65', 56, 20, 22)
    assert (controller['entry'], controller['message_bytes'], controller['message_slots'],
            controller['kernel_priority']) == ('0x3ba037', 12, 15, 92)
    assert (notifier['entry'], notifier['message_bytes'], notifier['message_slots'],
            notifier['kernel_priority']) == ('0x455c43', 20, 30, 93)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    dispatch = list(md.disasm(stock.read(0x1d9096, 12), 0x1d9096))
    assert [(i.address, i.mnemonic) for i in dispatch] == [
        (0x1d9096, 'cmp'), (0x1d9098, 'bhs'), (0x1d909a, 'adr'),
        (0x1d909c, 'ldrb'), (0x1d909e, 'adds'), (0x1d90a0, 'add')]
    assert dispatch[0].operands[1].imm == 11
    assert dispatch[-1].op_str == 'pc, r3'
    table = stock.read(0x1d90a4, 11)
    commands = []
    expected_calls = {1:0x1d8de2, 2:0x1d903e, 3:0x1d8f2c, 4:0x1d8d24,
                      7:0x30ed10, 8:0x1d8e26, 9:0x1d8cf4, 10:0x1d8cd8}
    for op, offset in enumerate(table):
        target = 0x1d90a4+2*offset
        code = list(md.disasm(stock.read(target, 10), target))
        calls = [i.operands[0].imm for i in code if i.mnemonic == 'bl' and
                 i.operands[0].type == ARM_OP_IMM]
        if op in expected_calls:
            assert expected_calls[op] in calls
        else:
            assert target == 0x1d9104
        commands.append({'opcode': op, 'table_offset': offset, 'dispatch_target': hex(target),
                         'direct_calls_in_first10_bytes': [hex(p) for p in calls],
                         'instructions': instructions(stock, target, 10),
                         'semantics_not_fully_executed_or_proved': True})
    # Driver outcome messages11/12 are sent to the central source controller,
    #not to the per-channel mixer task. Follow the literal at each wrapper.
    outcome_global = stock.word(0x1d91a0)
    assert outcome_global == int(controller['runtime_handle_global'], 16)
    assert stock.read(0x1d9148, 2) == bytes.fromhex('0b20')
    assert stock.read(0x1d9168, 2) == bytes.fromhex('0c20')
    result = {'updated_utc': datetime.now(timezone.utc).isoformat(), 'stock_sha256': EXPECTED,
              'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'dependency_sha256': {'scripts/analyze_native_sections.py': hashlib.sha256(
                  (ROOT/'scripts/analyze_native_sections.py').read_bytes()).hexdigest()},
              'static_only': True, 'tasks': {'output_driver': driver, 'source_controller': controller,
                                           'notice_dispatcher': notifier},
              'driver_channel_table': {'runtime_base': hex(stock.word(0x1d8f74)),
                                       'stride_bytes': 84, 'slots': 19},
              'driver_command_request': '0x1d8c60', 'driver_command_dispatcher': '0x1d9084',
              'driver_command_table': '0x1d90a4', 'driver_command_table_hex': table.hex(),
              'driver_command_cases': commands,
              'driver_outcomes': {'wrapper11': '0x1d9140', 'wrapper12': '0x1d9160',
                                  'target_handle_global': hex(outcome_global),
                                  'target_is_central_source_controller_not_per_channel_mixer': True,
                                  'native_controller_requests': '0x30edfe'},
              'controller_wait_get_loop': '0x3ba036', 'controller_message_dispatcher': '0x3b9f84',
              'traces': {'driver_initializer': instructions(stock, 0x40ca80, 92),
                         'controller_notifier_initializer': instructions(stock, 0x30ee62, 34),
                         'controller_wait_get_loop': instructions(stock, 0x3ba036, 74),
                         'driver_outcome_wrappers': instructions(stock, 0x1d9140, 64)},
              'all_checks_passed': True, 'device_io': False, 'device_install_candidate': False,
              'limitations': 'Static exact HWID1352/software8.00 MAIN only. Descriptor pointer literals/fields, initializer/kernel-create call sites, computed Thumb command table and outcome target literal decoded. Physical BSS/TCBs are not read and none of these driver/controller/notifier tasks execute here. Generic source-controller requests, priority changes, shared pool/list exclusion, actual driver allocation/format/mixing/start/end/DMA and completion lifetime still require execution. Default ROM priorities22/92/93 do not prove all live priorities or mutual exclusion. Driver outcomes11/12 target central controller global0xF29360, not mixer START14 directly; meaning and follow-up must be traced before automatic adapter design. No driver/SBC integration, real navigation/phone/UI/SEP/loading/speaker/Google Maps or install candidate.'}
    p = ROOT/'evidence/firmware-analysis/native-output-driver-inventory.json'
    p.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'output': str(p), 'static_checks': 'passed', 'device_io': False}))


if __name__ == '__main__':
    main()
