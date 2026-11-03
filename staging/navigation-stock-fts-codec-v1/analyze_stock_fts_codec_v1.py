#!/usr/bin/env python3
"""Bounded, file-only reconstruction of the stock TWNJAI token codec.

No native execution, IMG scan, device access, database writes, or whole-backup
hashing. The MAIN startup mapping is inherited from its frozen section proof.
"""
import hashlib
import json
import mmap
from pathlib import Path
import sqlite3
import struct
from datetime import datetime, timezone
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
BASE = 0x50000
DELTA = 57525300
PROOF = OUT / 'stock-fts-token-codec-proof-v1.json'
FRAGMENTS = OUT / 'stock-fts-token-codec-static-fragments-v1.json'


def need(value, label):
    if not value:
        raise ValueError(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def xor_swap(state, first, second):
    # Preserve the original three sequential XOR stores, including equal-index
    # behavior; replacing this with a Python tuple swap changes that behavior.
    state[second] ^= state[first]
    state[first] ^= state[second]
    state[second] ^= state[first]


def schedule(key):
    state = list(range(256))
    second = 0
    for first in range(256):
        second = (second + state[first] + key[first & 127]) & 255
        xor_swap(state, first, second)
    return state


def transform(data, scheduled):
    # Each encoder/decoder copies the 258-byte initialized context. Its two
    # index bytes are zero. The original PRGA does not persist local indexes.
    state = scheduled.copy()
    first = second = 0
    result = bytearray(data)
    for offset in range(len(result)):
        first = (first + 1) & 255
        second = (second + state[first]) & 255
        xor_swap(state, first, second)
        result[offset] ^= state[(state[first] + state[second]) & 255]
    return bytes(result)


def encode_bytes(data, scheduled):
    need(1 <= len(data) <= 4, 'bounded UTF-8 unit length')
    encrypted = transform(data, scheduled)
    return chr(ord('q') + len(data)) + ''.join(
        chr(ord('a') + (byte >> 4)) + chr(ord('a') + (byte & 15))
        for byte in encrypted)


def encode_text(text, scheduled):
    # A host control for the selected Chinese labels. The complete native
    # iterator/normalization API is outside this proof.
    return ''.join(encode_bytes(char.encode('utf-8'), scheduled) for char in text)


def decode_text(token_string, scheduled):
    offset = 0
    decoded = bytearray()
    units = []
    while offset < len(token_string):
        length = ord(token_string[offset]) - ord('q')
        need(1 <= length <= 4, 'encoded unit prefix range')
        encoded = token_string[offset + 1:offset + 1 + 2 * length]
        need(len(encoded) == 2 * length, 'encoded unit bounds')
        need(all('a' <= letter <= 'p' for letter in encoded), 'nibble alphabet')
        encrypted = bytes((ord(encoded[n]) - 97) * 16 +
                          ord(encoded[n + 1]) - 97
                          for n in range(0, len(encoded), 2))
        plain = transform(encrypted, scheduled)
        label = plain.decode('utf-8', errors='strict')
        need(len(label) == 1, 'one decoded Unicode scalar per selected token')
        units.append({'offset': offset, 'prefix': token_string[offset],
                      'utf8_bytes': length, 'encrypted_hex': encrypted.hex(),
                      'plain_hex': plain.hex(), 'text': label,
                      'codepoint': f'U+{ord(label):04X}'})
        decoded.extend(plain)
        offset += 1 + 2 * length
    return decoded.decode('utf-8', errors='strict'), units


def main():
    need(not PROOF.exists() and not FRAGMENTS.exists(), 'new outputs only')
    section_path = ROOT / 'evidence/firmware-analysis/native-sections.json'
    sections = json.loads(section_path.read_text())
    copied = next(row for row in sections['copies']
                  if row['runtime_start'] == 0x4400000)
    need(copied['relocation_delta'] == DELTA and copied['conditional'],
         'frozen exact conditional startup mapping')
    checks = []
    fragments = {}
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    with MAIN.open('rb') as handle, mmap.mmap(handle.fileno(), 0,
                                             access=mmap.ACCESS_READ) as image:
        def read_runtime(address, length):
            need(copied['runtime_start'] <= address and
                 address + length <= copied['runtime_end'], 'fragment range')
            load = address - DELTA
            return bytes(image[load - BASE:load - BASE + length])

        ranges = {
            'byte_transform': (0x44242F4, 0x4424356),
            'token_decoder': (0x4424356, 0x44243AE),
            'token_encoder': (0x442545A, 0x44254B4),
            'text_encoder_iterator': (0x44254C0, 0x4425572),
            'key_schedule': (0x4425AE8, 0x4425B40),
            'initializer': (0x4425B40, 0x4425B8C),
        }
        instruction_map = {}
        for name, (start, end) in ranges.items():
            raw = read_runtime(start, end - start)
            decoded = list(md.disasm(raw, start))
            need(sum(ins.size for ins in decoded) == len(raw), name + ' decode coverage')
            fragments[name] = {'runtime_start': hex(start), 'runtime_end': hex(end),
                               'load_start': hex(start - DELTA), 'bytes': len(raw),
                               'sha256': digest(raw), 'raw_hex': raw.hex(),
                               'instructions': [{'address': hex(ins.address),
                                  'instruction': ins.mnemonic + ' ' + ins.op_str}
                                  for ins in decoded]}
            instruction_map.update({ins.address: (ins.mnemonic, ins.op_str)
                                    for ins in decoded})
        guards = {
            0x4424324: ('eors', 'r7, r6'),
            0x4424326: ('strb', 'r7, [r2, r3]'),
            0x442432C: ('eors', 'r6, r7'),
            0x442432E: ('strb', 'r6, [r2, r4]'),
            0x4424334: ('eors', 'r6, r7'),
            0x4424336: ('strb', 'r6, [r2, r3]'),
            0x4424346: ('eors', 'r7, r6'),
            0x442437A: ('ldrb', 'r2, [r1, #1]'),
            0x442437E: ('subs', 'r2, r2, #1'),
            0x4424382: ('subs', 'r1, #0x61'),
            0x4424398: ('adds', 'r2, #3'),
            0x44243A6: ('bl', '#0x44242f4'),
            0x442547C: ('bl', '#0x44242f4'),
            0x442548E: ('adds', 'r2, #0x61'),
            0x442549A: ('adds', 'r2, #0x61'),
            0x44254A4: ('adds', 'r1, #0x71'),
            0x4425538: ('bl', '#0x442545a'),
            0x4425B04: ('blx', '#0x448fe78'),
            0x4425B0E: ('strb', 'r1, [r0]'),
            0x4425B10: ('strb', 'r1, [r0, #1]'),
            0x4425B72: ('strb', 'r1, [r2, r1]'),
            0x4425B74: ('ldrb', 'r4, [r3, r4]'),
            0x4425B82: ('bl', '#0x4425ae8'),
        }
        for address, expected in guards.items():
            need(instruction_map.get(address) == expected,
                 'static opcode guard ' + hex(address))
        literals = {}
        for name, instruction, displacement, expected in (
                ('identity_context', 0x4425B64, 0x1C0, 0x6921D64),
                ('key128', 0x4425B66, 0x1C4, 0x457D68C),
                ('scheduled_context', 0x4425B7E, 0x1B0, 0x6921E64),
                ('decoder_context', 0x4424396, 0x3EC, 0x6921E64),
                ('encoder_context', 0x442546C, 0x4C, 0x6921E64)):
            literal = ((instruction + 4) & ~3) + displacement
            value = struct.unpack('<I', read_runtime(literal, 4))[0]
            need(value == expected, name + ' exact pointer')
            literals[name] = {'instruction': hex(instruction),
                             'literal': hex(literal), 'value': hex(value)}
        key = read_runtime(0x457D68C, 128)
        fragments['key128'] = {'runtime': '0x0457D68C', 'load': '0x00EA1258',
                               'bytes': 128, 'sha256': digest(key)}
    scheduled = schedule(key)
    checks.append({'name': 'exact static codec instructions and context literals',
                   'passed': True, 'opcode_guards': len(guards)})
    # All 256 possible one-byte inputs round-trip the host transform. This is a
    # bounded model check, not a native instruction execution or name lookup.
    need(all(transform(transform(bytes([x]), scheduled), scheduled) == bytes([x])
             for x in range(256)), 'host transform symmetric round trip')
    checks.append({'name': '256 one-byte host transform controls', 'passed': True})

    db_before = DB.stat()
    connection = sqlite3.connect(DB.resolve().as_uri() + '?mode=ro&immutable=1',
                                 uri=True)
    cities = []
    city_query = ('SELECT id,index_record,record FROM japan_addr_info '
                  'WHERE record>>28=1 ORDER BY record LIMIT 22')
    for info_id, token, record in connection.execute(city_query):
        label, units = decode_text(token, scheduled)
        need(encode_text(label, scheduled) == token, 'city token inverse match')
        cities.append({'id': info_id, 'record': record, 'record_hex': hex(record),
                       'index_record': token, 'decoded_text': label,
                       'unicode_codepoints': [f'U+{ord(c):04X}' for c in label],
                       'units': units})
    need(len(cities) == 22, 'bounded city witness count')
    city8 = next(row for row in cities if row['record'] == 0x10000008)
    need(city8['id'] == 12987 and city8['decoded_text'] == '台中市',
         'actual stock Taichung token plaintext')
    checks.append({'name': '22 bounded city token UTF-8 decode and inverse', 'passed': True})

    labels = ('台中市', '臺中市', '民權路', '民權', '民和路', '184號')
    query_results = []
    for label in labels:
        encoded = encode_text(label, scheduled)
        # Prefix phrase mirrors the observed quote + star construction in the
        # native search wrapper; complete caller normalization is unverified.
        expression = '"' + encoded + '*"'
        sql = ('SELECT index_record,record_info FROM japan_addr_index_8 '
               'WHERE index_record MATCH ? LIMIT 24')
        count = connection.execute(
            'SELECT COUNT(*) FROM japan_addr_index_8 WHERE index_record MATCH ?',
            (expression,)).fetchone()[0]
        witnesses = []
        for token, packed in connection.execute(sql, (expression,)):
            text, units = decode_text(token, scheduled)
            info_id = packed >> 8
            original = connection.execute(
                'SELECT index_record,record FROM japan_addr_info WHERE id=?',
                (info_id,)).fetchone()
            need(original is not None, 'bounded FTS info row')
            original_label, original_units = decode_text(original[0], scheduled)
            need(encode_text(original_label, scheduled) == original[0],
                 'FTS-linked name inverse match')
            need(token.endswith(encoded) or token.startswith(encoded) or encoded in token,
                 'selected FTS prefix witness contains control')
            witnesses.append({'index_record': token, 'decoded_index_text': text,
                              'record_info': packed, 'info_id': info_id,
                              'record_level_flag': (packed & 0xF0) >> 4,
                              'source_info_index_record': original[0],
                              'source_info_decoded_text': original_label,
                              'source_record': original[1],
                              'source_record_hex': hex(original[1])})
        query_results.append({'input_label': label, 'host_encoded_control': encoded,
                              'fts_expression': expression, 'matching_fts_rows': count,
                              'witness_limit': 24, 'witnesses': witnesses})
    connection.close()
    db_after = DB.stat()
    need((db_before.st_size, db_before.st_mtime_ns) ==
         (db_after.st_size, db_after.st_mtime_ns), 'read-only DB metadata preserved')
    checks.append({'name': 'six bounded immutable FTS8 host lookups with linked names',
                   'passed': True})
    fragments_payload = {'schema': 'stock-fts-codec-static-fragments/v1',
                         'scope': 'static exact MAIN bytes only; no native execution',
                         'startup_copy': copied, 'literals': literals,
                         'fragments': fragments}
    FRAGMENTS.write_text(json.dumps(fragments_payload, ensure_ascii=False, indent=2) + '\n')
    payload = {
        'schema': 'stock-fts-token-codec-proof/v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'all_bounded_checks_passed': all(row['passed'] for row in checks),
        'scope': {'FILE_ONLY': True, 'sqlite_mode_ro_immutable': True,
                  'native_execution': False, 'native_query_caller_verified': False,
                  'hardware_query_success': False, 'whole_database_decoded': False,
                  'whole_MAIN_rehashed': False, 'whole_backup_rehashed': False,
                  'AP_payload_read': False, 'candidate_or_canonical_mutated': False,
                  'stock_NT_AP_update_implementation': False},
        'inputs': {'MAIN': str(MAIN.relative_to(ROOT)),
                   'MAIN_sha256_inherited': sections['stock_sha256'],
                   'MAIN_identity_newly_rehashed': False,
                   'database': str(DB.relative_to(ROOT)),
                   'database_bytes': db_before.st_size,
                   'database_identity_from_existing_backup_verification': True,
                   'section_mapping': str(section_path.relative_to(ROOT)),
                   'source_sha256': digest(Path(__file__).read_bytes()),
                   'static_fragments_sha256': digest(FRAGMENTS.read_bytes())},
        'codec_contract': {
            'token_layout': "one prefix byte ('q'+UTF-8-byte-length), then two a..p nibble letters per encrypted byte",
            'example_three_byte_token': 't + six nibble letters; tk is not a two-byte fixed tag',
            'transform': 'original sequential-XOR-swap RC4-style KSA/PRGA, with 128-byte fixed stock key repeated to 256',
            'context': 'identity table 0x06921D64; initialized scheduled context 0x06921E64; copy258 bytes separately for each token',
            'literal_decoder_high_nibble': '(ASCII-1)<<4 modulo byte, equivalent to (ASCII-a)<<4 for a..p',
            'native_text_iterator': 'calls token encoder0x0442545A from0x044254C0; complete iterator/normalization semantics not proved',
            'plaintext_encoding_in_selected_witnesses': 'strict UTF-8, one Unicode scalar per token',
            'stock_taichung_plaintext': city8['decoded_text'],
            'stock_taichung_is_TAI_U53F0': True,
            'OSM_source_TAI_U81FA_comparison': 'source node8528998711 is 臺中市; strings differ but query normalization/address caller not verified; difference alone is not established root cause',
        },
        'checks': checks, 'city_query': city_query, 'city_witnesses': cities,
        'bounded_FTS8_host_controls': query_results,
        'limits': [
            'Host algorithm reconstructed from frozen original instructions; no original instruction execution in this task.',
            'Six host FTS8 queries do not reproduce Garmin UI or complete native caller, normalization, map-manager selection, or query ABI.',
            'Only 22 city records and selected FTS witnesses decoded; no whole NT/AP payload or database export.',
            'Record keys are existing stock indexing references; host token construction alone cannot rebuild/update the NT/AP carrier.',
            'A zero host lookup for 184號 does not establish absence of address184 from stock AP or its native house-number provider.',
        ]}
    PROOF.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'proof': str(PROOF.relative_to(ROOT)),
                      'proof_sha256': digest(PROOF.read_bytes()),
                      'source_sha256': payload['inputs']['source_sha256'],
                      'static_fragments_sha256': payload['inputs']['static_fragments_sha256'],
                      'bounded_checks': len(checks), 'cities': len(cities),
                      'queries': [{'label': row['input_label'],
                                   'matching_fts_rows': row['matching_fts_rows']}
                                  for row in query_results],
                      'native_query_caller_verified': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
