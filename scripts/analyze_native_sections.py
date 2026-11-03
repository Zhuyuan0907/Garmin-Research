#!/usr/bin/env python3
"""Recover startup copy/zero ranges from the verified Taiwan 2565RT MAIN.

This reads a backup image only. Load addresses in the file are not necessarily
the addresses used by initialized data at runtime.
"""
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x50000
EXPECTED = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'


class NativeImage:
    def __init__(self):
        self.data = (ROOT / 'evidence/firmware-analysis/main_02bd.bin').read_bytes()
        if hashlib.sha256(self.data).hexdigest() != EXPECTED:
            raise ValueError('Requires exact HWID 1352 software 8.00 MAIN')
        self.md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        self.md.detail = True
        self.copies, self.zeros, self.startup_trace = self.sections()

    def read(self, load_address, length):
        offset = load_address - BASE
        if offset < 0 or offset + length > len(self.data):
            raise ValueError(f'Load range outside image: {load_address:#x}+{length:#x}')
        return self.data[offset:offset + length]

    def word(self, address):
        return struct.unpack('<I', self.read(address, 4))[0]

    def instructions(self, start, end):
        return list(self.md.disasm(self.read(start, end-start), start))

    def sections(self):
        # Startup's first conditional branch selects two optional extra copies.
        # These routines directly establish r0=destination, r1=source/fill,
        # r2=byte length. Copy uses LDM r1! / STM r0!, compares r0 with r0+r2.
        copy = self.instructions(0xebe04, 0xebe18)
        if [(i.mnemonic, i.op_str) for i in copy][2:5] != [
                ('adds', 'r2, r2, r0'), ('cmp', 'r0, r2'), ('beq', '#0xebe16')]:
            raise ValueError('Unexpected copy routine')
        if not any(i.mnemonic == 'ldm' and i.op_str == 'r1!, {r3}' for i in copy):
            raise ValueError('Source register not verified')
        if not any(i.mnemonic == 'stm' and i.op_str == 'r0!, {r3}' for i in copy):
            raise ValueError('Destination register not verified')
        zero = self.instructions(0xebe18, 0xebe50)
        if not any(i.mnemonic == 'stm' and i.op_str == 'r0!, {r1}' for i in zero):
            raise ValueError('Fill register not verified')
        if not any(i.mnemonic == 'adds' and i.op_str == 'r2, r2, r0' for i in zero):
            raise ValueError('Fill length not verified')

        regs = {}
        copies, zeros, trace = [], [], []
        for i in self.instructions(0xebd90, 0xebe02):
            item = {'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
            if i.mnemonic == 'ldr' and len(i.operands) == 2:
                operand = i.operands[1]
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    literal = ((i.address+4) & ~3)+operand.mem.disp
                    value = self.word(literal)
                    regs[i.reg_name(i.operands[0].reg)] = value
                    item.update(literal_address=hex(literal), literal_value=hex(value))
                else:
                    regs.pop(i.reg_name(i.operands[0].reg), None)
            elif i.mnemonic == 'movs' and i.operands[1].type == ARM_OP_IMM:
                regs[i.reg_name(i.operands[0].reg)] = i.operands[1].imm
            elif i.mnemonic == 'bl':
                target = i.operands[0].imm
                if target not in (0xebe04, 0xebe18):
                    raise ValueError('Unexpected startup call')
                destination, source, size = (regs[r] for r in ('r0', 'r1', 'r2'))
                if destination % 4 or size % 4:
                    raise ValueError('Word copy/fill alignment mismatch')
                record = {'call': i.address, 'runtime_start': destination,
                          'runtime_end': destination+size, 'size': size,
                          'conditional': i.address < 0xebdc4}
                if target == 0xebe04:
                    self.read(source, size)
                    record.update(load_start=source, load_end=source+size,
                                  relocation_delta=destination-source)
                    copies.append(record)
                else:
                    if source != 0:
                        raise ValueError('Expected zero fill')
                    zeros.append(record)
                item['operation'] = record
                regs.clear()
            trace.append(item)
        if len(copies) != 5 or len(zeros) != 5:
            raise ValueError('Unexpected section count')
        return copies, zeros, trace

    def runtime_to_load(self, address, length=1):
        matches = [r for r in self.copies if r['runtime_start'] <= address
                   and address+length <= r['runtime_end']]
        if len(matches) != 1:
            raise ValueError(f'Runtime address not uniquely backed by file: {address:#x}')
        return matches[0]['load_start'] + address-matches[0]['runtime_start']

    def load_to_runtime(self, address, length=1):
        matches = [r for r in self.copies if r['load_start'] <= address
                   and address+length <= r['load_end']]
        if len(matches) != 1:
            raise ValueError(f'Load address not uniquely mapped: {address:#x}')
        return matches[0]['runtime_start'] + address-matches[0]['load_start']


def main():
    img = NativeImage()
    out = {'stock_sha256': EXPECTED, 'load_base': BASE,
           'startup_thumb_entry': '0x50120', 'section_initializer': '0xebd90',
           'startup_flag_address': '0xa0007ffc',
           'copies': img.copies, 'zero_fills': img.zeros,
           'startup_instructions': img.startup_trace,
           'copy_instructions': [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
                                 for i in img.instructions(0xebe04, 0xebe18)],
           'zero_instructions': [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
                                 for i in img.instructions(0xebe18, 0xebe50)],
           'limitations': 'Static startup instructions, not live RAM. Conditional sections depend on a hardware flag. Zero-filled RAM has no file-backed contents.'}
    path = ROOT / 'evidence/firmware-analysis/native-sections.json'
    path.write_text(json.dumps(out, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'copy_ranges': len(img.copies),
                      'normal_data': next(r for r in img.copies if r['runtime_start'] == 0xf00000)}))


if __name__ == '__main__':
    main()
