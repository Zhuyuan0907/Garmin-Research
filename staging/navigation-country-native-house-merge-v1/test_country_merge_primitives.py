#!/usr/bin/env python3
"""New bounded controls for country cross-street packing and preserve policy."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
OUT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('new_country_merge_under_test', OUT / 'prepare_country_house_merge.py')
m = importlib.util.module_from_spec(spec);sys.modules[spec.name] = m;spec.loader.exec_module(m)


def need(ok, reason):
    if not ok:raise AssertionError(reason)


def independent_wire(values, width):
    # Slow bounded boolean positions, independent from streaming shift accumulator.
    bits = [bool(value & (1 << k)) for value in values for k in range(width)]
    wire = bytearray((len(bits) + 7) // 8)
    for index, bit in enumerate(bits):
        if bit:wire[index // 8] |= 1 << (index % 8)
    return bytes(wire)


def main():
    need(not (OUT / 'primitive-test-proof.json').exists(), 'New primitive proof only')
    checks = []
    with tempfile.TemporaryDirectory(prefix='primitive-country-', dir=OUT) as directory:
        d = Path(directory)
        for level, width in m.STRIDES.items():
            mask = (1 << width) - 1
            values = [1, mask, (mask ^ (mask >> 1)) | 1, (1 << (width - 1)) | 1, 0x6969696969696969 & mask | 1]
            writer = m.BitAppend(m.OutputHash(d / f'packed{level}.bin'), width)
            starts = []
            for group in [values[:1], values[1:3], values[3:]]:
                starts.append(writer.bits)
                for value in group:writer.add(value)
            artifact = writer.finish(); wire = (d / artifact['path']).read_bytes()
            expected = independent_wire(values, width)
            need(wire == expected and m.packed(values, width) == expected, 'Independent tight cross-street expected wire')
            need(m.unpack(wire, 0, len(values), width) == values, 'Every significant record decoded')
            need(starts == [0, width, width * 3], 'Group offsets are bits, no group byte pad')
            need(artifact['bytes'] == (len(values) * width + 7) // 8, 'No per-record or group byte padding')
            need(not len(values) * width % 8 or wire[-1] >> (len(values) * width % 8) == 0, 'Only unused final high bits zero')
            checks.append(dict(name=f'L{level}-unaligned-cross-group-bits-independent-wire', passed=True, width=width, bit_offsets=starts))
            for shift in [0, 1, 4, 7]:
                shifted = independent_wire([0], shift) if shift else b''
                # Build independent explicit bit prefix, not byte-padded prefix.
                expected_bits = [0] * shift + [(v >> b) & 1 for v in values for b in range(width)]
                stream = bytearray((len(expected_bits) + 7) // 8)
                for index, bit in enumerate(expected_bits):stream[index // 8] |= bit << (index % 8)
                need(m.unpack(bytes(stream), shift, len(values), width) == values, 'Source group initial bit alignment')
                checks.append(dict(name=f'L{level}-source-window-startshift-{shift}', passed=True))
            old_values = values[:3]
            old_names = ['+ 交叉路口 +', '22之1號', '44號']
            new = [dict(label='6號', number=6, value=0x12345), dict(label='22號', number=22, value=0x98765),
                   dict(label='150號', number=150, value=0x12489)]
            merged, positions, ordered = m.merge_numeric(old_values, old_names, new)
            need(merged == [old_values[0], new[0]['value'], old_values[1], new[1]['value'], old_values[2], new[2]['value']], 'Expected interleave including same-base subnumber')
            keep = [v for i, v in enumerate(merged) if i not in set(positions.values())]
            need(keep == old_values, 'Original raw significant bits/flags preserved')
            checks.append(dict(name=f'L{level}-preserve-old-significant-bits-and-relative-order', passed=True))
        need(m.merge_numeric([1, 3], ['2號', '1號'], []) is None, 'Nonmonotone old bases held')
        checks.append(dict(name='nonmonotone-original-bases-held', passed=True))
        need(m.merge_numeric([1], ['無數字巷名'], []) is None, 'No numeric anchor held')
        checks.append(dict(name='original-no-numeric-anchor-held', passed=True))
        flags13_record = 1 | (13 << 69) | (123 << 39) | (5 << 60) | (1124806 << 78) | (5624212 << 102)
        merged, positions, _ = m.merge_numeric([flags13_record], ['100號'], [dict(label='6號', number=6, value=1)])
        need(merged[1] == flags13_record and (merged[1] >> 69) & 511 == 13, 'Raw flags13 and nonzero child fields not converted')
        wire = m.packed(merged, 126)
        need(m.unpack(wire, 0, 2, 126)[1] == flags13_record, 'Raw13 survives actual tight stream')
        checks.append(dict(name='L5-rawflags13-childrefs-and-coordinates-preserved-through-pack', passed=True))
    proof = dict(all_assigned_checks_passed=True, new_controls_passed=len(checks), checks=checks,
        script_sha256=hashlib.sha256((OUT / 'prepare_country_house_merge.py').read_bytes()).hexdigest(),
        tests_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), device_IO=False,
        old_closed_tests_rerun=False, evidence_scope='Small actual Python/filesystem primitive tests; no country source pass, original map or native CPU execution.')
    (OUT / 'primitive-test-proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_assigned_checks_passed=True, new_controls_passed=len(checks), device_IO=False)))


if __name__ == '__main__':main()
