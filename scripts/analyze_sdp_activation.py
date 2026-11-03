#!/usr/bin/env python3
"""Reconstruct SDP initialization and bounded service-enable callers.

Never writes firmware, sends Bluetooth packets, or reads live device memory.
"""
import array
import json
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC
from analyze_native_sections import NativeImage, ROOT, BASE, EXPECTED

CONTROL = 0x3a7c108
ENABLE = 0x607f9c
DISABLE = 0x62d3bc
INITIALIZE = 0x5d7588
LOOKUP = 0x5d767c
BRANCHES = {'b', 'beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl',
            'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble'}


def describe(image, i):
    result = {'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
    if i.mnemonic == 'ldr' and len(i.operands) == 2:
        op = i.operands[1]
        if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
            literal = ((i.address+4) & ~3)+op.mem.disp
            result.update(literal_address=hex(literal), literal_value=hex(image.word(literal)))
    if i.mnemonic == 'adr':
        address = ((i.address+4) & ~3)+i.operands[1].imm
        raw = image.read(address, 160).split(b'\0', 1)[0]
        result['address_value'] = hex(address)
        if raw and all(32 <= b < 127 or b in (10, 13) for b in raw):
            result['string'] = raw.decode('ascii')
    if i.mnemonic in ('bl', 'blx') and i.operands[0].type == ARM_OP_IMM:
        result['direct_call'] = hex(i.operands[0].imm)
    return result


def trace(image, start, limit=1000):
    pending, seen, records, exits = [start], set(), [], []
    while pending and len(seen) < limit:
        address = pending.pop()
        while start <= address < start+0x3000 and address not in seen and len(seen) < limit:
            i = next(image.md.disasm(image.read(address, 4), address, count=1), None)
            if i is None:
                exits.append({'address': hex(address), 'reason': 'Undecodable instruction'})
                break
            seen.add(address)
            records.append(describe(image, i))
            if i.mnemonic == 'bx' or (i.mnemonic == 'pop' and 'pc' in i.op_str):
                break
            if i.mnemonic in BRANCHES:
                if i.operands[0].type != ARM_OP_IMM:
                    exits.append({'address': hex(address), 'reason': 'Indirect branch'})
                    break
                target = i.operands[0].imm
                if start <= target < start+0x3000:
                    pending.append(target)
                else:
                    exits.append({'address': hex(address), 'target': hex(target), 'reason': 'External branch'})
                if i.mnemonic == 'b':
                    break
            if i.mnemonic in ('add', 'mov') and i.operands[0].type != ARM_OP_IMM and i.reg_name(i.operands[0].reg) == 'pc':
                exits.append({'address': hex(address), 'reason': 'Computed PC; needs switch analysis'})
                break
            address += i.size
    return {'instructions': sorted(records, key=lambda r: int(r['address'], 16)),
            'unresolved_exits': exits, 'instruction_limit_reached': len(seen) >= limit}


def initialization(image, templates):
    regs, memory, instructions = {}, {}, []
    for i in image.instructions(INITIALIZE, 0x5d767c):
        instructions.append(describe(image, i))
        name = i.mnemonic
        if name in ('push', 'pop', 'bx'):
            continue
        dest = i.reg_name(i.operands[0].reg)
        if name == 'movs':
            source = i.operands[1]
            regs[dest] = source.imm if source.type == ARM_OP_IMM else regs[i.reg_name(source.reg)]
        elif name == 'ldr':
            operand = i.operands[1]
            if operand.type != ARM_OP_MEM or operand.mem.base != ARM_REG_PC:
                raise ValueError('Unexpected nonliteral load in SDP initializer')
            regs[dest] = image.word(((i.address+4) & ~3)+operand.mem.disp)
        elif name == 'adds':
            left, right = i.operands[1:3]
            regs[dest] = regs[i.reg_name(left.reg)] + (right.imm if right.type == ARM_OP_IMM else regs[i.reg_name(right.reg)])
        elif name in ('str', 'strh'):
            mem = i.operands[1].mem
            if mem.index:
                raise ValueError('Unexpected indexed store')
            address = regs[i.reg_name(mem.base)]+mem.disp
            size = 4 if name == 'str' else 2
            value = regs[dest]
            for j, b in enumerate(value.to_bytes(size, 'little')):
                memory[address+j] = b
        else:
            raise ValueError(f'Unsupported initialization operation: {name}')
    records = []
    for r in templates['records']:
        address = CONTROL+r['index']*12
        raw = bytes(memory[address+i] for i in range(12))
        handle, active, uuid_field, count, first = struct.unpack('<IHHHH', raw)
        expected_first = (int(r['descriptor_start'], 16)-int(templates['attribute_table_load_start'], 16))//8
        if handle != int(r['handle'], 16) or count != len(r['attributes']) or first != expected_first:
            raise ValueError('Initializer does not match parsed SDP attribute records')
        records.append({'index': r['index'], 'service_name': r['service_name'],
                        'runtime_control_address': hex(address), 'handle': hex(handle),
                        'initial_active_field': active, 'field_6_unassigned': uuid_field,
                        'attribute_count': count, 'first_attribute_index': first})
    count = int.from_bytes(bytes(memory[0xf42e3c+j] for j in range(2)), 'little')
    if count != len(records):
        raise ValueError('Record count mismatch')
    return records, instructions


def main():
    image = NativeImage()
    templates = json.loads((ROOT/'evidence/firmware-analysis/sdp-service-templates.json').read_text())
    initialized, init_trace = initialization(image, templates)
    words = array.array('H', image.read(BASE, 0xcb179c-BASE))
    targets = {ENABLE, DISABLE, INITIALIZE, LOOKUP}
    callers = {hex(t): [] for t in targets}
    for index in range(len(words)-1):
        a, b = words[index], words[index+1]
        if a & 0xf800 == 0xf000 and b & 0xf800 == 0xf800:
            offset = ((a & 0x7ff) << 12) | ((b & 0x7ff) << 1)
            if offset & 0x400000:
                offset -= 0x800000
            address = BASE+index*2
            target = address+4+offset
            if target in targets:
                # Verify the encoding with Capstone, since literal bytes may
                # accidentally resemble BL instructions.
                ins = next(image.md.disasm(image.read(address, 4), address, count=1), None)
                if ins and ins.mnemonic == 'bl' and ins.operands[0].imm == target:
                    callers[hex(target)].append(hex(address))
    # These function starts are checked from coherent PUSH entry / return flow.
    starts = [0x607f9c, 0x62d3bc, 0x3ae10c, 0x4cb5ee, 0x542d44, 0x62f46c, 0x4ce16c]
    functions = {hex(start): trace(image, start) for start in starts}
    # Check interworking calls from ARM code too; this image contains both
    # ARM and Thumb functions (for example the BTM database decoder).
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm.detail = True
    arm_calls = {hex(t): [] for t in targets}
    for index, word in enumerate(array.array('I', image.read(BASE, 0xcb179c-BASE))):
        if word & 0xfe000000 == 0xfa000000:
            offset = (word & 0xffffff) << 2
            if offset & 0x2000000:
                offset -= 0x4000000
            address = BASE+index*4
            target = address+8+offset+((word >> 24) & 1)*2
            if target in targets:
                ins = next(arm.disasm(image.read(address, 4), address, count=1), None)
                if ins and ins.mnemonic == 'blx' and ins.operands[0].imm == target:
                    arm_calls[hex(target)].append(hex(address))
    # The lookup function contains an inline byte-offset dispatch table. Decode
    # it separately, rather than treating the table as executable instructions.
    lookup = []
    for index, byte in enumerate(image.read(0x5d7698, 13)):
        target = 0x5d7698+byte*2
        lookup.append({'profile_index': index, 'branch_target': hex(target),
                       'instructions': [describe(image, i) for i in image.instructions(target, target+4)]})
    activation_paths = [
        {'entry': '0x3ae10c', 'lookup_call': '0x3ae124', 'lookup_profile_index': 4,
         'enable_call': '0x3ae15c', 'record_handle': '0x90005', 'service': 'Handsfree'},
        {'entry': '0x4cb5ee', 'lookup_call': '0x4cb5f6', 'lookup_profile_index': 1,
         'lookup_variant': 0, 'enable_call': '0x4cb5fc', 'record_handle': '0x90001', 'service': 'Serial Port COM5'},
        {'entry': '0x542d44', 'lookup_call': '0x542d4e', 'lookup_profile_index': 10,
         'enable_call': '0x54317e', 'record_handle': '0x9000b', 'service': 'Phonebook Access PCE'},
        {'entry': '0x62f46c', 'lookup_call': '0x62f50a', 'lookup_profile_index': 10,
         'enable_call': '0x62f556', 'record_handle': '0x9000b', 'service': 'Phonebook Access PCE'},
    ]
    for path in activation_paths:
        calls = {i['address'] for i in functions[path['entry']]['instructions'] if 'direct_call' in i}
        if path['lookup_call'] not in calls or path['enable_call'] not in calls:
            raise ValueError('Resolved activation path not reached in bounded flow')
    out = {'stock_sha256': EXPECTED, 'control_table': hex(CONTROL), 'stride': 12,
           'initializer': hex(INITIALIZE), 'initial_records': initialized,
           'initializer_instructions': init_trace, 'record_enable_function': hex(ENABLE),
           'record_disable_function': hex(DISABLE), 'lookup_dispatch': lookup,
           'direct_thumb_bl_candidates': callers, 'direct_arm_blx_candidates': arm_calls,
           'resolved_direct_activation_paths': activation_paths, 'functions': functions,
           'observations': ['Initializer sets only SDP Server record active; A2DP Sink and all application-profile templates initially inactive.',
                            'Enable writes 1 to the selected record status field; disable writes 0. SDP search and attribute retrieval test this field.',
                            'The four direct enable paths resolve to SPP COM5, Handsfree and PBAP PCE, matching previously observed live SDP. No direct Audio Sink enabling path established.',
                            'Normal code scanning found no additional direct ARM BLX callers of these Thumb entry points.'],
           'limitations': 'Static analysis only. Direct BL/BLX scanning cannot exclude indirect calls, other ARM veneers or computed activation. Initial values differ from final runtime values. Enabling an SDP template alone does not implement AVDTP endpoints, SBC decoding or playback.'}
    path = ROOT/'evidence/firmware-analysis/sdp-activation.json'
    path.write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'initial_active_records': [r['index'] for r in initialized if r['initial_active_field']],
                      'direct_enable_callers': callers[hex(ENABLE)],
                      'function_instruction_counts': {k:len(v['instructions']) for k,v in functions.items()}}))


if __name__ == '__main__':
    main()
