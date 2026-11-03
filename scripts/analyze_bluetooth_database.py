#!/usr/bin/env python3
"""Read-only analysis of backed-up BTM phone compatibility databases."""
from collections import Counter
import hashlib
import json
import re
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
from analyze_native_sections import NativeImage, ROOT, EXPECTED


def main():
    folder = ROOT/'backups/20261002T154458Z/files/.System/BTM'
    plain = (folder/'006-D1283-00.bin').read_bytes()
    binary = (folder/'006-D1283-01.bin').read_bytes()
    image = NativeImage()
    arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    decoder = [{'address': hex(i.address), 'instruction': i.mnemonic+' '+i.op_str}
               for i in arm.disasm(image.read(0x746fc0, 0x24), 0x746fc0)]
    if [i['instruction'] for i in decoder][2:6] != [
            'ldrblt ip, [r0, r3]', 'eorlt ip, ip, r3',
            'eorlt ip, ip, #0x69', 'strblt ip, [r1, r3]']:
        raise ValueError('Unexpected native database decoder')
    decoded = bytes(byte ^ (index & 255) ^ 0x69 for index, byte in enumerate(binary))
    count = struct.unpack_from('<I', decoded)[0]
    cursor, records = 4, []
    for index in range(count):
        begin, fields, scalar = cursor, [], None
        for field in range(11):
            size = struct.unpack_from('<I', decoded, cursor)[0]
            cursor += 4
            if field == 2:
                scalar = size
                continue
            if not 1 <= size <= 1024 or cursor+size > len(decoded):
                raise ValueError('Database string length overrun')
            raw = decoded[cursor:cursor+size]
            if not raw.endswith(b'\0'):
                raise ValueError('Database string missing terminating NUL')
            fields.append(raw[:-1].decode('latin1'))
            cursor += size
        tail = struct.unpack_from('<12I', decoded, cursor)
        cursor += 48
        records.append({'index': index, 'payload_offset': begin, 'payload_end': cursor,
                        'phone_name': fields[0], 'string_fields': fields,
                        'scalar_unassigned': scalar, 'trailing_words_unassigned': list(tail)})
    trailer = binary[cursor:]
    if trailer[4:] != b'006-D1283-01\0':
        raise ValueError('Unexpected unmasked database trailer identifier')
    if bytes(byte ^ (index & 255) ^ 0x69 for index, byte in enumerate(decoded[:cursor])) != binary[:cursor]:
        raise ValueError('Database XOR round trip mismatch')
    text = plain.decode('latin1')
    keys = Counter(re.findall(r'^([^\[\r\n=]+)=', text, re.M))
    sections = re.findall(r'^\[(.*?)\]\s*$', text, re.M)
    decoded_payload = decoded[:cursor]
    terms = {t: {'plain_count': len(re.findall(re.escape(t), text, re.I)),
                 'binary_payload_count': len(re.findall(re.escape(t.encode()), decoded_payload, re.I))}
             for t in ('A2DP', 'AVDTP', 'SBC', 'AudioSink', 'music', 'codec')}
    output = {'firmware_sha256': EXPECTED,
              'plain': {'file': str((folder/'006-D1283-00.bin').relative_to(ROOT)),
                        'sha256': hashlib.sha256(plain).hexdigest(), 'size': len(plain),
                        'sections': len(sections), 'keys': dict(keys)},
              'binary': {'file': str((folder/'006-D1283-01.bin').relative_to(ROOT)),
                         'sha256': hashlib.sha256(binary).hexdigest(), 'size': len(binary),
                         'mask': 'byte XOR (byte_offset & 255) XOR 0x69',
                         'decoder_address': '0x746fc0', 'decoder_instructions': decoder,
                         'caller': '0x747a48', 'decoder_call': '0x747b48',
                         'records': count, 'record_payload_end': cursor,
                         'round_trip_identical': True,
                         'raw_trailer_hex': trailer.hex(),
                         'raw_trailer_u32_unassigned': struct.unpack_from('<I', trailer)[0],
                         'dictionary_records': records},
              'term_counts': terms,
              'dll_name_counts': dict(Counter(r['string_fields'][6] for r in records)),
              'observations': ['Plain database contains phonebook, SMS, call-log, HF and legacy port compatibility fields.',
                               'Binary database contains 537 phone model records, length-prefixed strings and 12 unassigned trailing words per record.',
                               'Occurrences of music in the decoded binary are phone product names such as XpressMusic, not an identified media-enable setting.'],
              'limitations': 'No database edits or uploads. String fields and trailing words have not all been assigned semantics. DLL name strings do not establish native application loading; absence of named A2DP keys alone does not rule out numeric flags.'}
    path = ROOT/'evidence/firmware-analysis/bluetooth-phone-databases.json'
    path.write_text(json.dumps(output, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'output': str(path), 'phone_records': count,
                      'xor_decoder_confirmed': True, 'round_trip_identical': True,
                      'a2dp_term_counts': terms['A2DP'], 'dll_name_counts': output['dll_name_counts']}))


if __name__ == '__main__':
    main()
