#!/usr/bin/env python3
"""Finite read-only keyboard/string-reference scan of the exact stock image."""
import array
import datetime as dt
import hashlib
import json
from pathlib import Path
import struct
import sys
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
sys.path.insert(0, str(ROOT / 'scripts'))
from analyze_native_sections import NativeImage, BASE, EXPECTED
from analyze_sdp_activation import trace

OUT = Path(__file__).resolve().parent


def occurrences(data, needle):
    pos = 0
    while (pos := data.find(needle, pos)) >= 0:
        yield pos
        pos += len(needle)


def main():
    image = NativeImage()
    keyboards = []
    for path in sorted((ROOT / 'backups/20261002T154458Z/files/Keyboards').glob('*.kbd')):
        xml = ET.fromstring(path.read_bytes())
        keyboards.append(dict(file=path.name, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            lang_id=xml.findtext('header/lang_id'), code_page=xml.findtext('header/code_page'),
            predefined=sorted({k.attrib['predefined'] for k in xml.iter('keyboard') if 'predefined' in k.attrib})))
    strings = []
    value_to_strings = {}
    for name in ['code_page', 'TWN_phonetic', 'TWN_handwriting', 'TWN_cangjie',
                 'Keyboards', 'zh_TW', 'predefined', 'STR_KEYBOARD', 'SearchKeyboard']:
        for offset in occurrences(image.data, name.encode() + b'\0'):
            load = BASE + offset
            pointers = [load]
            for copy in image.copies:
                source = copy['load_start'] if 'load_start' in copy else copy.get('source')
                if source is not None and source <= load < source + copy['size']:
                    pointers.append(copy['runtime_start'] + load - source)
            row = dict(text=name, load_address=hex(load), possible_pointers=[hex(a) for a in pointers],
                       aligned_pointer_locations=[], literal_load_candidates=[])
            strings.append(row)
            for value in pointers:
                value_to_strings.setdefault(value, []).append(row)
    literal_to_strings = {}
    for offset in range(0, len(image.data) - 3, 4):
        value = struct.unpack_from('<I', image.data, offset)[0]
        if value in value_to_strings:
            address = BASE + offset
            literal_to_strings[address] = value_to_strings[value]
            for row in value_to_strings[value]:
                row['aligned_pointer_locations'].append(hex(address))
    # This is intentionally a candidate scan, not proof that arbitrary bytes
    # are reached instructions. Only bounded CFG membership strengthens it.
    code_end = 0xcb1980
    words = array.array('H', image.read(BASE, code_end - BASE))
    candidates = {}
    for index, h in enumerate(words):
        if h & 0xf800 != 0x4800:
            continue
        pc = BASE + index * 2
        literal = ((pc + 4) & ~3) + (h & 255) * 4
        rows = literal_to_strings.get(literal)
        if not rows:
            continue
        for row in rows:
            row['literal_load_candidates'].append(hex(pc))
        candidates[pc] = dict(pc=pc, literal=literal, names=sorted({r['text'] for r in rows}))
    functions = {}
    for pc, candidate in candidates.items():
        for address in range(pc, max(BASE, pc - 0x400), -2):
            h = struct.unpack_from('<H', image.data, address - BASE)[0]
            if h & 0xfe00 == 0xb400 and h & 0x100:
                start = address
                break
        else:
            continue
        if start not in functions:
            try:
                functions[start] = trace(image, start, 1500)
            except ValueError as e:
                functions[start] = dict(scan_error=str(e), instructions=[], unresolved_exits=[], instruction_limit_reached=False)
        records = functions[start]['instructions']
        candidate['nearest_push_start'] = hex(start)
        candidate['bounded_CFG_contains_candidate'] = any(int(r['address'], 16) == pc and int(r.get('literal_address', '0'), 16) == candidate['literal'] for r in records)
    used = {int(c['nearest_push_start'], 16) for c in candidates.values() if c.get('bounded_CFG_contains_candidate')}
    result = dict(checked_utc=dt.datetime.now(dt.timezone.utc).isoformat(), stock_MAIN_sha256=EXPECTED,
        scope='Exact stock keyboard metadata plus finite literal-reference and bounded Thumb CFG scan; no device input or address-search execution',
        keyboards=keyboards, strings=strings, candidates=[{**c, 'pc':hex(c['pc']), 'literal':hex(c['literal'])} for c in candidates.values()],
        bounded_functions={hex(start): functions[start] for start in used},
        keyboard_header_CP_is_not_proof_of_search_query_CP=True,
        cross_code_page_conversion_verified=False, device_search_verified=False,
        device_io=False, firmware_modified=False)
    path = OUT / 'keyboard-query-scan.json'
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(keyboards=keyboards, matched_strings=len(strings), literal_candidates=len(candidates),
        bounded_reached_candidates=sum(c.get('bounded_CFG_contains_candidate', False) for c in candidates.values()),
        bounded_functions=len(used), evidence=str(path.relative_to(ROOT))), ensure_ascii=False))


if __name__ == '__main__':
    main()
