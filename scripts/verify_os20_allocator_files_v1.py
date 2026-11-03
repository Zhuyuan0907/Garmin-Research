#!/usr/bin/env python3
"""FILE review of completed allocator scopes: no guest execution.

Check every original store's effective address and register value, byte
preimage replay, whole zones and actual helper return states. Synthetic
software table/storage inputs are not proof of physical page translation.
"""
import gzip
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path
from datetime import datetime, timezone

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from capstone.arm import *

BASE = ROOT / 'staging/native-os20-allocator-v2'
OUT = BASE / 'ROOT_FILE-proof-v1.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gp(instruction, register, values):
    name = instruction.reg_name(register)
    if name.startswith('r') and name[1:].isdigit():
        return values[int(name[1:])]
    index = {'sb': 9, 'sl': 10, 'fp': 11, 'ip': 12, 'sp': 13, 'lr': 14, 'pc': 15}[name]
    return values[index]


def condition(cc, cpsr):
    n, z, c, v = [(cpsr >> bit) & 1 for bit in (31, 30, 29, 28)]
    return {ARM_CC_INVALID: True, ARM_CC_AL: True, ARM_CC_EQ: z == 1,
            ARM_CC_NE: z == 0, ARM_CC_HS: c == 1, ARM_CC_LO: c == 0,
            ARM_CC_MI: n == 1, ARM_CC_PL: n == 0, ARM_CC_VS: v == 1,
            ARM_CC_VC: v == 0, ARM_CC_HI: c == 1 and z == 0,
            ARM_CC_LS: c == 0 or z == 1, ARM_CC_GE: n == v,
            ARM_CC_LT: n != v, ARM_CC_GT: z == 0 and n == v,
            ARM_CC_LE: z == 1 or n != v}[cc]


def stores_for(instruction, trace):
    values, cpsr = trace['GP16'], trace['CPSR']
    if not condition(instruction.cc, cpsr):
        return []
    if instruction.id == ARM_INS_PUSH:
        registers = [x.reg for x in instruction.operands]
        start = values[13] - 4 * len(registers)
        return [(start + 4 * index, 4, gp(instruction, register, values))
                for index, register in enumerate(registers)]
    if instruction.id in (ARM_INS_STM, ARM_INS_STMDB, ARM_INS_STMIB, ARM_INS_STMDA):
        base = gp(instruction, instruction.operands[0].reg, values)
        registers = [x.reg for x in instruction.operands[1:]]
        start = {ARM_INS_STM: base, ARM_INS_STMDB: base - 4 * len(registers),
                 ARM_INS_STMIB: base + 4, ARM_INS_STMDA: base - 4 * (len(registers) - 1)}[instruction.id]
        return [(start + 4 * index, 4, gp(instruction, register, values))
                for index, register in enumerate(registers)]
    if instruction.id in (ARM_INS_STR, ARM_INS_STRB, ARM_INS_STRH):
        source, memory = instruction.operands[:2]
        address = gp(instruction, memory.mem.base, values) + memory.mem.disp
        if memory.mem.index:
            index = gp(instruction, memory.mem.index, values)
            if memory.shift.type:
                assert memory.shift.type == ARM_SFT_LSL
                index = (index << memory.shift.value) & 0xffffffff
            address += memory.mem.scale * index
        size = {ARM_INS_STR: 4, ARM_INS_STRB: 1, ARM_INS_STRH: 2}[instruction.id]
        value = gp(instruction, source.reg, values) & ((1 << (size * 8)) - 1)
        return [(address & 0xffffffff, size, value)]
    assert not instruction.mnemonic.startswith(('str', 'stm', 'push', 'swp')), instruction.mnemonic
    return []


def main():
    assert not OUT.exists()
    guest = json.loads((BASE / 'guest-proof.json').read_text())
    assert guest['all_passed'] and guest['case_count'] == 3
    sources = dict(guest['source_sha256'])
    for path, h in sources.items():
        assert sha(ROOT / path) == h, path
    for relative, code in [('staging/native-os20-allocator-v1/terminal-tool-receipt.json', 1),
                           ('staging/native-os20-allocator-v2/terminal-tool-receipt.json', 0)]:
        result = json.loads((ROOT / relative).read_text())['actual_terminal_result']
        assert result['exit_code'] == code and 'session_id' not in result
        sources[relative] = sha(ROOT / relative)
    n = NativeImage()
    decoders = {False: Cs(CS_ARCH_ARM, CS_MODE_ARM), True: Cs(CS_ARCH_ARM, CS_MODE_THUMB)}
    for decoder in decoders.values():
        decoder.detail = True
    totals, cases = Counter(), []
    try:
        for row in guest['cases']:
            path = ROOT / row['path']
            assert sha(path) == row['sha256']
            sources[row['path']] = row['sha256']
            data = json.load(gzip.open(path, 'rt'))
            assert data['all_passed'] and data['MMU_translation_disabled']
            assert data['no_WORK_or_free_page_heads_seeded']
            assert not data['actual_task_created_or_callback_or_physical_heap_verified']
            journals = data['CPU_stores']
            replay = {zone['name']: bytearray.fromhex(data['whole_zones_before'][zone['name']])
                      for zone in data['zones']}
            by_name = {zone['name']: zone for zone in data['zones']}
            count, stack_arg_applied = 0, False
            before_states, after_states = [], []
            for trace in data['original_instruction_trace']:
                pc, cpsr = trace['PC'], trace['CPSR']
                raw = bytes.fromhex(trace['opcode_hex'])
                assert n.read(pc, len(raw)) == raw
                instruction = next(decoders[bool(cpsr & 32)].disasm(raw, pc, count=1))
                assert instruction.size == trace['size'] and instruction.bytes == raw
                before_states.append((pc, trace['GP16'], cpsr))
                if trace['phase'] == 'original_OS20_create_prefix' and not stack_arg_applied:
                    argument = next(x for x in data['original_constructor_calls']
                                    if x.get('kind') == 'caller_stack_arg5_input')
                    stack = replay['stack']
                    offset = argument['address'] - by_name['stack']['start']
                    assert stack[offset:offset + 4].hex() == argument['before_hex']
                    stack[offset:offset + 4] = bytes.fromhex(argument['after_hex'])
                    stack_arg_applied = True
                for address, size, value in stores_for(instruction, trace):
                    store = journals[count]
                    assert (store['PC'], store['address'], store['size'], store['value']) == (
                        pc, address, size, value), (row['name'], hex(pc), count)
                    assert store['phase'] == trace['phase'] and store['CPSR'] == cpsr
                    assert store['opcode_hex'] == raw.hex()
                    zone = by_name[store['zone']]
                    offset = address - zone['start']
                    assert 0 <= offset and offset + size <= zone['size']
                    assert replay[zone['name']][offset:offset + size].hex() == store['before_hex']
                    replay[zone['name']][offset:offset + size] = value.to_bytes(size, 'little')
                    count += 1
            assert count == len(journals)
            for name, content in replay.items():
                assert content.hex() == data['whole_zones_after'][name]
            for returned in data['native_full_returns']:
                before, after = returned['before'], returned['after']
                assert returned['full_ABI_return']
                assert (returned['entry'], before['GP16'], before['CPSR']) in before_states
                assert (returned['return_PC'], after['GP16'], after['CPSR']) in before_states
                assert before['GP16'][4:12] == after['GP16'][4:12]
                assert before['GP16'][13] == after['GP16'][13]
                assert (before['CPSR'] ^ after['CPSR']) & 0xdf == 0
            if data['payloads']:
                payloads = data['payloads']
                public = replay['public_extent_and_guards']
                start = by_name['public_extent_and_guards']['start']
                offset = payloads['descriptor'] - start
                assert public[offset:offset + 100] == bytes(100)
                offset = payloads['workspace'] - start
                assert public[offset:offset + 4248] == b'\xcc' * 4248
                assert data['boundary']['PC'] == 0x521e90
                assert not data['unreturned_native_frames']
                assert replay['current_TCB_fixture'][32:36] == bytes(4)
                work_start = 0x03a7f170 - by_name['WORK_page']['start']
                work = replay['WORK_page'][work_start:work_start + 96]
                assert struct.unpack_from('<I', work, 36)[0] == 0, 'Heap lock owner not released'
                page_returns = [r for r in data['native_full_returns'] if r['entry'] == 0x38806c]
                assert [r['after']['GP16'][0] for r in page_returns] == [0x18302000, 0x18303000, 0x18304000]
                mapping = [r for r in data['native_full_returns'] if r['entry'] == 0x221d34]
                assert [(r['before']['GP16'][0], r['before']['GP16'][1]) for r in mapping] == [
                    (0x18310000, 0x18303000), (0x18311000, 0x18304000)]
                table_stores = [s for s in journals if s['zone'].startswith('L')]
                assert [(s['PC'], s['address'], s['value']) for s in table_stores] == [
                    (0x221dae, 0x03f00040, 0x80000152), (0x221dbc, 0x03f00040, 0x18303152),
                    (0x221dae, 0x03f00044, 0x80000152), (0x221dbc, 0x03f00044, 0x18304152)]
                for entry in (0x21b6cc, 0x3275a4, 0x6f012c, 0x33e664,
                              0x6f0250, 0x33e678, 0x6f040c, 0x21b6dc):
                    assert sum(t['PC'] == entry for t in data['original_instruction_trace']) == 2
                assert data['boundary']['state']['GP16'][1:3] == [0x4e4, 40]
                assert data['boundary']['state']['GP16'][3] == payloads['descriptor'] + 60
            else:
                assert data['boundary']['PC'] == 0x23d6e8
                want = 0x388501 if data['input_public_bytes'] == 0 else 0x388c65
                assert data['boundary']['state']['GP16'][14] == want
            totals.update(CPU_stores=count, store_effective_addresses=count,
                          whole_zones=len(replay), instructions=len(before_states),
                          native_full_returns=len(data['native_full_returns']), boundaries=1)
            cases.append(dict(name=row['name'], passed=True, complete_CPU_store_EA_and_value_replay=True,
                              entire_mutable_zones_replayed=True, native_full_ABI_returns_checked=True,
                              synthetic_input_scope_only=True, guest_rerun=False))
        sources[str(Path(__file__).resolve().relative_to(ROOT))] = sha(Path(__file__).resolve())
        sources[str((BASE / 'guest-proof.json').relative_to(ROOT))] = sha(BASE / 'guest-proof.json')
        proof = dict(all_passed=True, case_count=3, cases=cases, totals=dict(totals), source_sha256=sources,
                     exact_store_effective_addresses_and_values_from_original_instruction_registers=True,
                     diagnostic_bodies_not_executed=True, actual_two_OS20_allocations_full_returns=True,
                     original_task_object_constructor_or_native_task_create_not_executed=True,
                     full_nonstore_semantic_replay=False, new_independent_agent_review=False,
                     physical_CPU_MMU_backing_or_native_App_not_verified=True, device_IO=False,
                     updated_utc=datetime.now(timezone.utc).isoformat())
        with OUT.open('x') as stream:
            json.dump(proof, stream, indent=2)
            stream.write('\n')
        print(json.dumps(dict(all_passed=True, totals=dict(totals), cases=3)), flush=True)
    except BaseException as error:
        import traceback
        with (BASE / 'FILE-v1-failure.json').open('x') as stream:
            json.dump(dict(error=str(error), traceback=traceback.format_exc(), completed_cases=cases,
                           partial_totals=dict(totals), guest_rerun=False), stream, indent=2)
        raise


if __name__ == '__main__':
    main()
