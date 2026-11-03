#!/usr/bin/env python3
"""Inventory stock diagnostic names; strings alone do not establish USB host support."""
from datetime import datetime, timezone
import hashlib, json, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = 'evidence/firmware-analysis/main_02bd.bin'
STOCK_SHA = '10ab7e1f864f3e9b39806b7d3b7c7eb11ba597fdd8cfc0796e281f509c5a54a8'

def main():
    data = (ROOT / MAIN).read_bytes()
    assert hashlib.sha256(data).hexdigest() == STOCK_SHA
    classes = []
    for m in re.finditer(rb'N3GUI([0-9]{1,3})([A-Za-z_][A-Za-z_0-9]*)E\x00', data):
        name = m[2].decode()
        if len(name) == int(m[1]) and re.search('Test|Diagnostic|USB|Card|TV', name):
            classes.append({'name': name, 'file_offset': m.start(),
                            'image_address_before_runtime_copy': hex(0x50000 + m.start())})
    literals = []
    for name in ('Data Card Test Page', 'Audio Test Page', 'TV Test Page',
                 'Bluetooth Test Page', 'USB Test', 'INCOMPATIBLE AUDIO'):
        positions = []
        for encoding in ('ascii', 'utf-16le'):
            pattern = name.encode(encoding)
            start = 0
            while (start := data.find(pattern, start)) >= 0:
                positions.append({'encoding': encoding, 'file_offset': start,
                                  'image_address_before_runtime_copy': hex(0x50000 + start)})
                start += 1
        literals.append({'name': name, 'matches': positions})
    evidence = {
        'updated_utc': datetime.now(timezone.utc).isoformat(),
        'exact_target': {'HWID': 1352, 'software': '8.00'},
        'classes': classes, 'literal_labels': literals,
        'source_sha256': {MAIN: STOCK_SHA, str(Path(__file__).relative_to(ROOT)):
                          hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'runtime_relocation_or_vtable_callback_mapping_performed': False,
        'diagnostic_USB_host_switch_or_hub_driver_verified': False,
        'device_io': False, 'firmware_modified': False,
        'scope': 'Read-only stock byte inventory. Four literal page headings match the '
                 'user-transcribed diagnostic headings. Class names and raw pre-copy '
                 'image addresses do not establish reachability, installed hardware, '
                 'callback roles, a native App API or USB host support. Missing exact '
                 'ASCII/UTF16 literals do not prove a feature absent; localized or '
                 'generated strings and other firmware modules were not searched.'}
    out = ROOT / 'evidence/firmware-analysis/native-diagnostic-pages-survey.json'
    out.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'evidence': str(out.relative_to(ROOT)),
                      'class_names': len(classes),
                      'matched_page_headings': sum(bool(p['matches']) for p in literals[:4]),
                      'USB_host_verified': False}))

if __name__ == '__main__':
    main()
