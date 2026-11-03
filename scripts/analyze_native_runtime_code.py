#!/usr/bin/env python3
"""Inventory all startup-backed code regions and resolve a cross-region veneer.

This scans backed-up bytes only. Conditional runtime regions are mapped by the
startup copy instructions; the actual device's boot flag is not read.
"""
from collections import defaultdict
from datetime import datetime, timezone
import array
import hashlib
import json
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
from analyze_native_sections import NativeImage, ROOT, EXPECTED


def main():
    image = NativeImage()
    regions = []
    # f00000 is initialized data, not an additional executable scan region.
    for section in image.copies:
        if section['runtime_start'] == 0xf00000: continue
        raw = image.read(section['load_start'], section['size'])
        hits = defaultdict(list)
        for index, value in enumerate(array.array('I', raw)):
            if 0x3a88e00 <= value <= 0x3a89100:
                hits[value].append(hex(section['runtime_start']+index*4))
        regions.append({'runtime_start': hex(section['runtime_start']),
                        'runtime_end': hex(section['runtime_end']),
                        'load_start': hex(section['load_start']),
                        'load_end': hex(section['load_end']), 'bytes': len(raw),
                        'conditional_copy': section['conditional'],
                        'sha256': hashlib.sha256(raw).hexdigest(),
                        'avdtp_adjacent_aligned_pointer_literals':
                            {hex(value): refs for value, refs in sorted(hits.items())}})
    veneer = 0x4ccfac
    if image.word(veneer) != 0xe51ff004:
        raise ValueError('Expected exact ARM literal-PC veneer')
    target = image.word(veneer+4)
    runtime = target & ~1
    load = image.runtime_to_load(runtime, 128)
    thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    instructions = [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
                    for i in thumb.disasm(image.read(load, 128), runtime)]
    if instructions[0]['instruction'] != 'push {r0, r4, r5, r6, r7, lr}':
        raise ValueError('Cross-region target did not match its actual backed-up code')
    conditional = [r for r in regions if r['conditional_copy']]
    if len(conditional) != 2 or any(r['avdtp_adjacent_aligned_pointer_literals'] for r in conditional):
        raise ValueError('Expected two conditional regions without these aligned pointer literals')
    output = {'updated_utc': datetime.now(timezone.utc).isoformat(),
              'stock_sha256': EXPECTED,
              'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'code_regions': regions,
              'conditional_code_bytes': sum(r['bytes'] for r in conditional),
              'startup_flag_address': '0xa0007ffc', 'conditional_flag_mask': 1,
              'live_flag_verified': False,
              'resolved_veneer': {'entry': hex(veneer), 'target_word': hex(target),
                                  'runtime_thumb_target': hex(runtime), 'file_load_address': hex(load),
                                  'arm_instructions': [{'address': hex(i.address),
                                                       'instruction': i.mnemonic+' '+i.op_str}
                                                      for i in arm.disasm(image.read(veneer, 4), veneer)],
                                  'target_instructions': instructions,
                                  'mapping': 'Exact startup runtime_to_load range; not a constant0x4000000 subtraction'},
              'expanded_scan_located_sep_registration': False,
              'native_sep_registration_absent_proven': False,
              'device_io': False, 'firmware_modified': False,
              'limitations': 'Aligned pointer literals in a bounded AVDTP-adjacent RAM range are inventoried across all startup-backed non-data ranges, including conditional code. Absence of literals does not exclude derived pointers, passed arguments, indirect registration, unaligned data, other resources/overlays or dynamically supplied code. Runtime conditional flag/region activation is not observed on hardware. The resolved veneer demonstrates how one cross-region code target is stored; it is not an AVDTP registration function.'}
    path = ROOT/'evidence/firmware-analysis/native-runtime-code-inventory.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'regions': len(regions),
                      'conditional_code_bytes': output['conditional_code_bytes'],
                      'resolved_target': hex(target), 'device_io': False}))


if __name__ == '__main__':
    main()
