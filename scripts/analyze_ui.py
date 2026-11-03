#!/usr/bin/env python3
"""Recover selected GUI RTTI/vtable references from the verified stock MAIN image."""
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'evidence/firmware-analysis'
BASE = 0x50000
SHA256 = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'
SELECTED = {'PageAudioMixer', 'PageTestAudioList', 'PageTestBluetooth', 'PageSettingsAudio',
            'PageDiagnosticsMode', 'PageReviewHTML', 'HTMLViewer', 'PageBackupCamera'}


def references(data, address):
    needle = struct.pack('<I', address)
    start = 0
    while True:
        pos = data.find(needle, start)
        if pos < 0:
            return
        start = pos + 1
        if pos % 4 == 0:
            yield pos


def main():
    data = (OUT / 'main_02bd.bin').read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('MAIN differs from the verified Taiwan image')
    pages = []
    labels = []
    for match in re.finditer(rb'N3GUI([0-9]{1,3})([A-Za-z_][A-Za-z_0-9]*)E\x00', data):
        name = match[2].decode()
        if name not in SELECTED or len(name) != int(match[1]):
            continue
        row = {'class': name, 'type_name_address': hex(BASE+match.start()), 'rtti_candidates': []}
        for pos in references(data, BASE+match.start()):
            obj = BASE+pos-4
            candidate = {'address': hex(obj), 'vtable_candidates': []}
            for table in references(data, obj):
                if table < 4 or struct.unpack_from('<I', data, table-4)[0] != 0:
                    continue
                address = BASE+table+4
                slots = []
                for slot in range(80):
                    pointer = struct.unpack_from('<I', data, table+4+4*slot)[0]
                    # This bound only filters likely code pointers, not function semantics.
                    if not BASE <= (pointer & ~1) < 0xbd0000:
                        break
                    slots.append({'slot': slot, 'pointer': hex(pointer), 'mode': 'Thumb' if pointer & 1 else 'ARM'})
                    labels.append(f'{pointer & ~1:08x}\tGUI_{name}_vslot{slot}\t' + ('Thumb' if pointer & 1 else 'ARM'))
                if not slots:
                    continue
                candidate['vtable_candidates'].append({'address': hex(address), 'slots': slots,
                    'literal_references': [hex(BASE+x) for x in references(data, address)]})
                labels.append(f'{address:08x}\tGUI_{name}_vtable\tdata')
            if candidate['vtable_candidates']:
                row['rtti_candidates'].append(candidate)
                labels.append(f'{obj:08x}\tGUI_{name}_rtti\tdata')
        if row['rtti_candidates']:
            pages.append(row)
    evidence = {'stock_main_sha256': SHA256, 'base_address_verified': BASE,
                'method': 'Type-name references, zero-offset-to-top RTTI references, bounded virtual function pointers',
                'limitations': 'Candidate ABI mapping; slot roles, reachability and executable hooks need disassembly. Does not enable pages or install applications.',
                'reference': 'https://itanium-cxx-abi.github.io/cxx-abi/abi.html', 'classes': pages}
    (OUT / 'native-ui-map.json').write_text(json.dumps(evidence, indent=2)+'\n')
    (OUT / 'native-ui-symbols.tsv').write_text('address\tlabel\tmode\n' + '\n'.join(dict.fromkeys(labels))+'\n')
    print(json.dumps({'classes_mapped': len(pages), 'symbol_labels': len(set(labels)), 'device_modified': False}))


if __name__ == '__main__':
    main()
