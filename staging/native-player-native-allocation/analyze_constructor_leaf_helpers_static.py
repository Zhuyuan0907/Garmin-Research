#!/usr/bin/env python3
"""Exact next three leaf bodies; static evidence, no emulator or device."""
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts'))
from analyze_native_sections import NativeImage


def main():
    out = Path(__file__).with_name('constructor-leaf-helpers-static.json')
    assert not out.exists(), 'Preserve exact static leaf evidence'
    stock = NativeImage()
    expected = {
        0x3619BC: [(0x3619BC, '81b0', 'sub sp, #4'),
                   (0x3619BE, '0090', 'str r0, [sp]'),
                   (0x3619C0, '01b0', 'add sp, #4'),
                   (0x3619C2, '7047', 'bx lr')],
        0x39132A: [(0x39132A, '0020', 'movs r0, #0'),
                   (0x39132C, '7047', 'bx lr')],
        0x3819D4: [(0x3819D4, '0800', 'movs r0, r1'),
                   (0x3819D6, '7047', 'bx lr')],
    }
    rows = []
    for start, want in expected.items():
        got = stock.instructions(start, want[-1][0]+2)
        actual = [(i.address, i.bytes.hex(), i.mnemonic+' '+i.op_str) for i in got]
        assert actual == want
        rows.append({'entry': hex(start), 'Thumb': True,
                     'instructions': [{'PC': hex(p), 'opcode_hex': op, 'instruction': text}
                                      for p, op, text in actual]})
    # The original outer constructor calls these exact entries. Its MOV/add
    # establish the pointer return as caller-stack storage, not a heap result.
    calls = {0x39556C: (0x3619BC, 'ccf726fa'),
             0x395570: (0x39132A, 'fbf7dbfe'),
             0x395580: (0x3819D4, 'ecf728fa')}
    for p, (target, op) in calls.items():
        i = stock.instructions(p, p+4)[0]
        assert i.bytes.hex() == op and i.mnemonic == 'bl' and i.op_str == '#'+hex(target)
    assert stock.read(0x39554E, 2).hex() == '07af'  # r7=sp+0x1c
    assert stock.read(0x39557A, 2).hex() == '3900'  # r1=r7
    assert stock.read(0x395598, 2).hex() == 'e648'
    sources = [Path(__file__), ROOT/'scripts/analyze_native_sections.py',
               ROOT/'evidence/firmware-analysis/main_02bd.bin',
               Path(__file__).with_name('constructor-continuation-static.json')]
    result = {'all_passed': True, 'file_and_source_only': True,
              'source_sha256': {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in sources},
              'leaf_bodies': rows, 'exact_leaf_instruction_count': 8,
              'native_caller_targets': {hex(p): hex(t) for p, (t, _) in calls.items()},
              '39132A_unconditionally_returns_zero_in_original_code': True,
              '3819D4_returns_actual_caller_r1_stack_pointer': True,
              '3619BC_writes_only_actual_temporary_stack_word': True,
              'later_holder_literal_address': '0x395934',
              'later_holder_literal_word': hex(stock.word(0x395934)),
              'runtime_execution_or_native_return_verified': False,
              'guest_executed': False, 'VM_import_or_instantiation': False,
              'device_io': False,
              'next_362A2C_still_requires_native60_and16_allocations_and_holder_lifetime': True,
              'timer_semantics_at395552_not_established': True,
              'physical_App_audio_or_full_foreground_verified': False}
    with out.open('x') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({'all_passed': True, 'leaf_instructions': 8,
                      'holder_literal': result['later_holder_literal_word'],
                      'runtime_execution': False}))


if __name__ == '__main__':
    main()
