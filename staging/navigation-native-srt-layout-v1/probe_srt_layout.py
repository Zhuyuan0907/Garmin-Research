#!/usr/bin/env python3
"""Finite exact-stock SRT field extraction; no policy hooks or device I/O."""
from datetime import datetime
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'staging/navigation-firmware-sort-v1'))
from analyze_native_sections import NativeImage, EXPECTED
from probe_original_sort_units_v4 import Probe, DESC, ITER, SRT, STACK, RET
from unicorn.arm_const import (UC_ARM_REG_CPSR, UC_ARM_REG_SP, UC_ARM_REG_LR,
                              UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                              UC_ARM_REG_R3, UC_ARM_REG_PC)

REFERENCE = ROOT / 'staging/navigation-search-encoding-v1/reference'
RECEIPT = ROOT / 'staging/navigation-search-encoding-v1/source-receipt.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class LocalProbe(Probe):
    # No use of parent's failure-receipt writer; any output belongs to this scope.
    def call(self, entry, args):
        start = len(self.trace)
        self.u.reg_write(UC_ARM_REG_CPSR, 0x3f)
        self.u.reg_write(UC_ARM_REG_SP, STACK + 0x1f00)
        self.u.reg_write(UC_ARM_REG_LR, RET | 1)
        for r, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            self.u.reg_write(r, value)
        try:
            self.u.emu_start(entry | 1, RET + 2, timeout=1000000, count=20000)
        except Exception as exc:
            (OUT / 'failure-receipt.json').write_text(json.dumps({
                'entry': hex(entry), 'pc': hex(self.u.reg_read(UC_ARM_REG_PC)),
                'error': repr(exc), 'device_io': False,
                'last_instructions': self.trace[-32:]}, indent=2) + '\n')
            raise
        trace = self.trace[start:]
        if not trace or trace[-1]['pc'] != RET:
            raise ValueError('Bounded original function did not return')
        if self.u.reg_read(UC_ARM_REG_SP) != STACK + 0x1f00:
            raise ValueError('Original function did not restore caller stack')
        return self.u.reg_read(UC_ARM_REG_R0), trace


def fields(probe, descriptor, offset):
    values, instructions = [], []
    for level in range(3):
        probe.u.mem_write(ITER, struct.pack('<I', descriptor) + bytes(92))
        probe.u.mem_write(ITER + 12, bytes([level]))
        value, trace = probe.call(0x1abd44, [ITER, offset, 0, 0])
        values.append(value)
        instructions.append(len(trace))
    return values, instructions


def fixture(image, name, flags, values, layout, shape, expected):
    primary, secondary, tertiary = values
    if layout == '16/8/8':
        weight = struct.pack('<HBB', primary, secondary, tertiary)
    elif layout == '16/10/6':
        if not (0 <= primary <= 65535 and 0 <= secondary <= 1023 and 0 <= tertiary <= 63):
            raise ValueError('Record does not fit the native bit widths')
        weight = struct.pack('<HH', primary, secondary | (tertiary << 10))
    elif layout == '8/4/4':
        weight = bytes([primary, secondary | (tertiary << 4)])
    else:
        raise ValueError('Unknown fixture packing')
    payload = bytes([1]) + weight if shape == 'character' else weight
    probe = LocalProbe(image, payload + bytes(32))
    probe.u.mem_write(DESC, struct.pack('<II', SRT, 2) + bytes(100))
    probe.u.mem_write(DESC + 16, struct.pack('<I', flags))
    result, instructions = fields(probe, DESC, 1 if shape == 'character' else 0)
    if result != expected:
        raise ValueError('Actual stock field result differs: ' + name)
    return {'name': name, 'shape': shape, 'descriptor_flags': hex(flags),
            'writer_values_primary_secondary_tertiary': list(values),
            'fixture_packing': layout, 'raw_record_hex': payload.hex(),
            'actual_stock_values_primary_secondary_tertiary': result,
            'expected_values': expected, 'instructions_per_field': instructions,
            'passed': True}


def main():
    OUT.mkdir(exist_ok=True)
    image = NativeImage()
    before = {'evidence/firmware-analysis/main_02bd.bin': EXPECTED,
              str(RECEIPT.relative_to(ROOT)): sha(RECEIPT),
              'staging/navigation-firmware-sort-v1/probe_original_sort_units_v4.py':
                  sha(ROOT / 'staging/navigation-firmware-sort-v1/probe_original_sort_units_v4.py')}
    receipt = json.loads(RECEIPT.read_text())
    for item in receipt['selected']:
        if Path(item['path']).name in ('SRTFile.java', 'SRTHeader.java'):
            if sha(ROOT / item['path']) != item['sha256']:
                raise ValueError('Official source receipt does not match')
            before[item['path']] = item['sha256']

    specs = [
        ('r4924 A demonstrates mismatch', 0x6f02, (3270, 1, 5), '16/8/8', 'character', [3270, 257, 1]),
        ('r4924 a demonstrates mismatch', 0x6f02, (3270, 1, 1), '16/8/8', 'character', [3270, 257, 0]),
        ('r4924 expansion T7 demonstrates mismatch', 0x6f02, (3270, 8, 7), '16/8/8', 'expansion', [3270, 776, 1]),
        ('r4924 expansion T8 demonstrates mismatch', 0x6f02, (4039, 8, 8), '16/8/8', 'expansion', [4039, 8, 2]),
        ('builtin header flags also select 10/6', 0x6302, (3270, 1, 5), '16/8/8', 'character', [3270, 257, 1]),
        ('clear bit14 diagnostic selects 16/8/8', 0x2f02, (3270, 1, 5), '16/8/8', 'character', [3270, 1, 5]),
        ('bit14 alone overrides bit8 and bit9', 0x4000, (3270, 1, 5), '16/10/6', 'character', [3270, 1, 5]),
        ('native packing A character', 0x6f02, (3270, 1, 5), '16/10/6', 'character', [3270, 1, 5]),
        ('native packing a character', 0x6f02, (3270, 1, 1), '16/10/6', 'character', [3270, 1, 1]),
        ('native packing expansion T7', 0x6f02, (3270, 8, 7), '16/10/6', 'expansion', [3270, 8, 7]),
        ('native packing expansion T8', 0x6f02, (4039, 8, 8), '16/10/6', 'expansion', [4039, 8, 8]),
        ('native packing crosses secondary byte boundary', 0x6f02, (0x1234, 511, 31), '16/10/6', 'character', [0x1234, 511, 31]),
        ('native packing all bit widths maximal', 0x6f02, (65535, 1023, 63), '16/10/6', 'expansion', [65535, 1023, 63]),
        ('native packing all zero', 0x6f02, (0, 0, 0), '16/10/6', 'expansion', [0, 0, 0]),
        ('single byte format control remains 8/4/4', 0x2002, (127, 13, 14), '8/4/4', 'character', [127, 13, 14]),
    ]
    cases = [fixture(image, *spec) for spec in specs]

    builtin_srt = 0x878f60
    h2 = struct.unpack('<I', image.read(builtin_srt + 23, 4))[0]
    h3 = struct.unpack('<I', image.read(builtin_srt + h2 + 8, 4))[0]
    header = image.read(builtin_srt + h3, 92)
    table = builtin_srt + h3 + struct.unpack_from('<I', header, 12)[0]
    expansion = builtin_srt + h3 + struct.unpack_from('<I', header, 28)[0]
    builtin_probe = LocalProbe(image)
    originals = []
    for name, address, shape in (
        ('stock builtin A', table + (ord('A') - 1) * 5, 'character'),
        ('stock builtin a', table + (ord('a') - 1) * 5, 'character'),
        ('stock builtin expansion 10', expansion + 9 * 4, 'expansion'),
        ('stock builtin expansion 11', expansion + 10 * 4, 'expansion'),
    ):
        data = image.read(address, 5 if shape == 'character' else 4)
        weight = data[1:] if shape == 'character' else data
        packed = struct.unpack_from('<H', weight, 2)[0]
        expected = [struct.unpack_from('<H', weight)[0], packed & 1023, packed >> 10]
        offset = address - builtin_srt + (1 if shape == 'character' else 0)
        actual, instructions = fields(builtin_probe, 0x878ef4, offset)
        if actual != expected:
            raise ValueError('Actual unmodified builtin SRT mismatch')
        originals.append({'name': name, 'shape': shape,
            'runtime_record_address': hex(address), 'stock_raw_record_hex': data.hex(),
            'original_memory_reader_kind': 0, 'record_file_offset_used': offset,
            'actual_stock_fields': actual, 'expected_16_10_6_fields': expected,
            'instructions_per_field': instructions, 'passed': True})

    getter = [{'address': hex(i.address), 'bytes': bytes(i.bytes).hex(),
               'instruction': i.mnemonic + ' ' + i.op_str}
              for i in image.md.disasm(image.read(0x1abd44, 0xd6), 0x1abd44)]
    after = {path: sha(ROOT / path) for path in before}
    if before != after:
        raise ValueError('Read-only dependency changed')
    result = {
        'checked_at_local': datetime.now().astimezone().isoformat(),
        'hardware_id': 1352, 'software_version': 800, 'native_getter': '0x1abd44',
        'device_io': False, 'firmware_modified': False, 'sorting_policy_hooks': [],
        'fixture_getter_only': True, 'all_passed': True,
        'source_sha256_before': before, 'source_sha256_after': after,
        'official_source_url': receipt['source_url'],
        'original_getter_instructions': getter,
        'flag_width_semantics': {
            'default': [8, 8, 8, 8, 8],
            'bit8_set': 'field0 width becomes16 at0x1ABD68..72',
            'bit9_clear': 'fields1..4 widths become4 at0x1ABD74..84',
            'bit14_set': 'unconditionally override widths to[16,10,6,16,16] at0x1ABD8C..A0',
            'primary_secondary_tertiary_fields': [0, 1, 2]},
        'builtin_header': {'runtime_srt': hex(builtin_srt), 'header2_file_offset': h2,
            'header3_file_offset': h3, 'header3_flags': hex(struct.unpack_from('<I', header, 8)[0]),
            'original_descriptor_runtime': '0x878ef4',
            'original_descriptor_flags': hex(struct.unpack('<I', image.read(0x878ef4 + 16, 4))[0]),
            'char_record_bytes': struct.unpack_from('<H', header, 20)[0],
            'expansion_record_bytes': struct.unpack_from('<H', header, 36)[0],
            'char_table_runtime': hex(table), 'expansion_table_runtime': hex(expansion)},
        'synthetic_cases': cases, 'original_builtin_cases': originals,
        'mismatch_formula_for_r4924_8_8_payload_with_bit14':
            {'native_secondary': '(host_secondary | (host_tertiary <<8)) &1023',
             'native_tertiary': 'host_tertiary >>2'},
        'compatible_writer_fixture': {'primary': 'put2u(primary)',
            'secondary_tertiary': 'put2u(secondary | (tertiary <<10))',
            'bounds': {'primary': [0, 65535], 'secondary': [0, 1023], 'tertiary': [0, 63]},
            'character_record': 'flag8 + primary16 + secondary10 + tertiary6 =5 bytes',
            'expansion_record': 'primary16 + secondary10 + tertiary6 =4 bytes',
            'flags_unchanged': '0x6f02', 'host_sort_policy_changed': False},
        'limitations': ['Tests call original getter with synthetic iterator and memory-kind2 records, plus actual readonly builtin descriptor/table kind0.',
            'Expansion semantics, actual full string iterator/comparator, MDR indexes, IMG discovery, native UI query and hardware not exercised by this proof.',
            'Clear-bit14 case is a diagnostic alternative, not the selected writer plan or a deployment candidate.',
            'No stock/sealed fixture or source modified; no nationwide map built; no firmware or device written.'],
    }
    (OUT / 'srt-layout-evidence.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_passed': True, 'synthetic_cases': len(cases),
                      'original_builtin_cases': len(originals), 'device_io': False}))


if __name__ == '__main__':
    main()
