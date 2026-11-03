#!/usr/bin/env python3
"""Decode file-backed SDP attribute templates, without touching the device."""
import json
import struct

from analyze_native_sections import NativeImage, ROOT, EXPECTED

ATTRIBUTE_NAMES = {0: 'ServiceRecordHandle', 1: 'ServiceClassIDList',
                   4: 'ProtocolDescriptorList', 5: 'BrowseGroupList',
                   6: 'LanguageBaseAttributeIDList', 9: 'BluetoothProfileDescriptorList',
                   0xd: 'AdditionalProtocolDescriptorLists',
                   0x100: 'ServiceName', 0x102: 'ProviderName', 0x311: 'SupportedFeatures'}
TYPE_NAMES = {0: 'nil', 1: 'uint', 2: 'int', 3: 'uuid', 4: 'text',
              5: 'bool', 6: 'sequence', 7: 'alternative', 8: 'url'}
CLASS_NAMES = {0x1000: 'SDP Server', 0x1101: 'Serial Port', 0x1108: 'Headset',
               0x1112: 'Headset Audio Gateway', 0x111e: 'Handsfree',
               0x111f: 'Handsfree Audio Gateway', 0x110b: 'Audio Sink',
               0x110a: 'Audio Source', 0x110e: 'AV Remote Control',
               0x110c: 'AV Remote Control Target', 0x112e: 'Phonebook Access PCE',
               0x112f: 'Phonebook Access PSE', 0x1133: 'Message Notification Server',
               0x1203: 'Generic Audio'}
SOURCES = [
    'https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/host/service-discovery-protocol--sdp--specification.html',
    'https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Assigned_Numbers/out/en/index-en.html',
]


def element(raw, offset=0, depth=0):
    if offset >= len(raw) or depth > 16:
        raise ValueError('SDP data element overrun or nesting limit')
    header = raw[offset]
    kind, size_index = header >> 3, header & 7
    if kind not in TYPE_NAMES:
        raise ValueError('Reserved SDP type')
    cursor = offset+1
    if kind == 0:
        if size_index != 0:
            raise ValueError('Invalid nil')
        size = 0
    elif size_index <= 4:
        size = 1 << size_index
    else:
        count = {5: 1, 6: 2, 7: 4}[size_index]
        if cursor+count > len(raw):
            raise ValueError('SDP size overrun')
        size = int.from_bytes(raw[cursor:cursor+count], 'big')
        cursor += count
    end = cursor+size
    if end > len(raw):
        raise ValueError('SDP value overrun')
    payload = raw[cursor:end]
    result = {'type': TYPE_NAMES[kind]}
    if kind in (1, 2, 3):
        if size_index > 4 or (kind == 3 and size not in (2, 4, 16)):
            raise ValueError('Invalid numeric/UUID size')
        value = int.from_bytes(payload, 'big', signed=kind == 2)
        result.update(value=value, hex=hex(value), width_bits=size*8)
    elif kind in (4, 8):
        if size_index < 5:
            raise ValueError('Invalid string size descriptor')
        result.update(value=payload.decode('utf-8'), trailing_nul=payload.endswith(b'\0'))
    elif kind in (6, 7):
        if size_index < 5:
            raise ValueError('Invalid container size descriptor')
        children = []
        child_offset = 0
        while child_offset < len(payload):
            child, child_offset = element(payload, child_offset, depth+1)
            children.append(child)
        result['value'] = children
    elif kind == 5:
        if size != 1 or size_index != 0:
            raise ValueError('Invalid bool')
        result['value'] = bool(payload[0])
    return result, end


def main():
    image = NativeImage()
    records, current = [], None
    start, end = 0xcf4b84, 0xcf4ed4
    for address in range(start, end, 8):
        attr, size, pointer = struct.unpack('<HHI', image.read(address, 8))
        source = image.runtime_to_load(pointer, size)
        if not (0xcf47c0 <= source and source+size <= start):
            raise ValueError('Attribute payload outside the identified SDP block')
        raw = image.read(source, size)
        decoded, consumed = element(raw)
        if consumed != size:
            raise ValueError('SDP encoded length differs from attribute descriptor')
        if attr == 0:
            if decoded['type'] != 'uint' or decoded['width_bits'] != 32:
                raise ValueError('Unexpected record handle type')
            current = {'index': len(records), 'handle': decoded['hex'],
                       'descriptor_start': hex(address), 'attributes': []}
            records.append(current)
        if current is None or attr in [a['id'] for a in current['attributes']]:
            raise ValueError('Attribute before handle, or duplicate attribute')
        current['attributes'].append({'id': attr, 'id_hex': hex(attr),
                                      'name': ATTRIBUTE_NAMES.get(attr),
                                      'descriptor_load_address': hex(address),
                                      'runtime_payload_pointer': hex(pointer),
                                      'load_payload_address': hex(source),
                                      'encoded_length': size, 'encoded_hex': raw.hex(),
                                      'decoded': decoded})
    if image.read(end, 8) != b'\0'*8:
        raise ValueError('Expected zero descriptor sentinel')
    for r in records:
        attrs = {a['id']: a['decoded'] for a in r['attributes']}
        expected_handle = 0 if r['index'] == 0 else 0x90000+r['index']
        if int(r['handle'], 16) != expected_handle:
            raise ValueError('Unexpected record handle sequence')
        classes = attrs[1]['value']
        if any(c['type'] != 'uuid' for c in classes):
            raise ValueError('Invalid service class list')
        r['classes'] = [{'uuid': c['hex'], 'name': CLASS_NAMES.get(c['value'])} for c in classes]
        r['service_name'] = attrs.get(0x100, {}).get('value', '').rstrip('\0')
        r['provider_name'] = attrs.get(0x102, {}).get('value', '').rstrip('\0')
    output = {'stock_sha256': EXPECTED, 'section_evidence': 'native-sections.json',
              'attribute_table_load_start': hex(start),
              'attribute_table_runtime_start': hex(image.load_to_runtime(start)),
              'attribute_count': sum(len(r['attributes']) for r in records),
              'record_count': len(records), 'records': records, 'sources': SOURCES,
              'limitations': 'Compiled service templates only. Does not show which records are enabled at runtime, a working SEP, SBC decoder, media UI or speaker path. No image/device changes.'}
    path = ROOT / 'evidence/firmware-analysis/sdp-service-templates.json'
    path.write_text(json.dumps(output, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'attribute_count': output['attribute_count'],
                      'services': [{k: r[k] for k in ('index', 'handle', 'service_name', 'classes')}
                                   for r in records]}, ensure_ascii=False))


if __name__ == '__main__':
    main()
