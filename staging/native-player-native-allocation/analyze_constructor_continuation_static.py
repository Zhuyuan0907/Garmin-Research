#!/usr/bin/env python3
"""Read the exact stock constructor beyond the current guest boundary.

No VM is imported, initialized, or run. Bounded instruction windows are not a
complete control-flow graph and prove neither a native return nor hardware use.
"""
import hashlib
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out = Path(__file__).with_name('constructor-continuation-static.json')
    assert not out.exists(), 'Preserve completed static evidence'
    image = NativeImage()
    rows = []
    # Only these ranges are decoded. In particular, no linear disassembly
    # beyond 362A8E treats following exception/cleanup bytes as normal return.
    for begin, end in [(0x395552, 0x3955D0), (0x362A2C, 0x362A90)]:
        instructions = image.instructions(begin, end)
        assert instructions and instructions[0].address == begin
        assert instructions[-1].address + instructions[-1].size == end
        window = {'start': hex(begin), 'end': hex(end),
                  'bytes_sha256': hashlib.sha256(image.read(begin, end-begin)).hexdigest(),
                  'instructions': []}
        for instruction in instructions:
            row = {'PC': hex(instruction.address), 'opcode_hex': instruction.bytes.hex(),
                   'instruction': instruction.mnemonic+' '+instruction.op_str,
                   'Thumb': True}
            if instruction.mnemonic in ('bl', 'blx') and instruction.operands[0].type == ARM_OP_IMM:
                row['direct_call_target'] = hex(instruction.operands[0].imm)
            if instruction.mnemonic == 'ldr' and len(instruction.operands) == 2:
                operand = instruction.operands[1]
                if operand.type == ARM_OP_MEM and operand.mem.base == ARM_REG_PC:
                    address = ((instruction.address + 4) & ~3) + operand.mem.disp
                    row['literal_address'] = hex(address)
                    row['literal_word'] = hex(image.word(address))
            window['instructions'].append(row)
        rows.append(window)
    by_pc = {int(row['PC'], 16): row for window in rows for row in window['instructions']}
    expected = {
        0x395552: ('04a9', 'add r1, sp, #0x10'),
        0x39556C: ('ccf726fa', 'bl #0x3619bc'),
        0x395570: ('fbf7dbfe', 'bl #0x39132a'),
        0x395580: ('ecf728fa', 'bl #0x3819d4'),
        0x3955A2: ('cdf743fa', 'bl #0x362a2c'),
        0x362A3A: ('3c20', 'movs r0, #0x3c'),
        0x362A3C: ('32f046ed', 'blx #0x3954cc'),
        0x362A48: ('fff760fe', 'bl #0x36270c'),
        0x362A52: ('1020', 'movs r0, #0x10'),
        0x362A58: ('32f038ed', 'blx #0x3954cc'),
        0x362A70: ('f6f772f8', 'bl #0x358b58'),
        0x362A86: ('32f033fd', 'bl #0x3954f0'),
        0x362A8E: ('f0bd', 'pop {r4, r5, r6, r7, pc}'),
    }
    checks = []
    for pc, (opcode, text) in expected.items():
        assert by_pc[pc]['opcode_hex'] == opcode and by_pc[pc]['instruction'] == text
        checks.append({'PC': hex(pc), 'opcode_hex': opcode, 'passed': True})
    sources = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
               ROOT/'evidence/firmware-analysis/main_02bd.bin',
               ROOT/'staging/native-player-native-allocation/gui-static/native_allocation_observer.py']
    document = {
        'all_encoding_assertions_passed': True,
        'source_sha256': {str(path.relative_to(ROOT)): digest(path) for path in sources},
        'instruction_windows': rows, 'encoding_assertions': checks,
        'current_guest_stop_PC': '0x395552',
        'next_original_allocations_inside_362A2C': [60, 16],
        'original_normal_return_instruction': '0x362a8e',
        'next_scope_requires_original_calls': ['0x3619bc', '0x39132a', '0x3819d4',
            '0x36270c', '0x358b58', '0x3954f0'],
        'earlier_flag_dependent_branch_and_lifetime_must_be_verified': True,
        'unconditional_execution_of_every_listed_call_not_claimed': True,
        'VM_import_or_instantiation': False, 'guest_executed': False,
        'device_io': False, 'complete_CFG': False,
        'actual_native_returns_or_foreground_completion_verified': False,
        'physical_App_or_audio_verified': False,
    }
    with out.open('x') as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({'output': str(out.relative_to(ROOT)),
                      'encoding_assertions': len(checks), 'guest_executed': False}))


if __name__ == '__main__':
    main()
