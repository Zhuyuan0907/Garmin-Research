#!/usr/bin/env python3
"""Bounded read of original AP's 120-byte provider descriptor directory."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-provider-records-v1'
MAP_PATH = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
SCHEMA = ROOT / 'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
NATIVE = ROOT / 'staging/navigation-native-MDR-provider-fields-v1/native-MDR-header-fields-proof-v1.json'
OFFSET = 0x0585C7A8
LENGTH = 120


def need(ok, message):
    if not ok:
        raise ValueError(message)


def source_reference(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def stat_signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class ReadonlyMDR:
    def __init__(self, path):
        self.path = path
        self.before = stat_signature(path)
        self.stream = path.open('rb')
        self.read_log = []
        head = self.physical_read(0, 512, 'disk_header')
        need(head[0] == 0 and head[16:23] == b'DSKIMG\0' and head[65:72] == b'GARMIN\0',
             'Unsupported/encrypted disk header')
        self.block_size = 1 << (head[97] + head[98])
        first = head[64] * 512
        entry = self.physical_read(first, 512, 'directory_extent_header')
        end = struct.unpack_from('<I', entry, 12)[0]
        need(first < end <= 131072 and end % 512 == 0, 'Unexpected directory extent')
        self.directory_extent = [first, end]
        directory = self.physical_read(first, end - first, 'IMG_public_directory')
        self.parts, self.blocks = [], []
        self.component_name = '00004171.MDR'
        for pos in range(0, len(directory), 512):
            row = directory[pos:pos + 512]
            if row[0] != 1 or row[16] == 3:
                continue
            name = row[1:9].decode('ascii').rstrip() + '.' + row[9:12].decode('ascii').rstrip()
            if name != self.component_name:
                continue
            part = struct.unpack_from('<H', row, 17)[0]
            need(part == len(self.parts), 'MDR parts out of order')
            if not part:
                self.component_bytes = struct.unpack_from('<I', row, 12)[0]
            allocated = [block for block in struct.unpack_from('<240H', row, 32) if block != 65535]
            need(all(block * self.block_size < path.stat().st_size for block in allocated), 'FAT outside map')
            self.parts.append({'part': part, 'directory_record_physical_offset': first + pos,
                               'first_logical_block_index': len(self.blocks), 'allocated_block_count': len(allocated)})
            self.blocks.extend(allocated)
        need(len(self.blocks) == (self.component_bytes + self.block_size - 1) // self.block_size,
             'MDR allocated block count differs from declared size')
        need(len(set(self.blocks)) == len(self.blocks), 'Duplicate MDR allocated blocks')

    def physical_read(self, offset, length, purpose):
        self.stream.seek(offset)
        raw = self.stream.read(length)
        need(len(raw) == length, 'Short physical read')
        self.read_log.append({'purpose': purpose, 'physical_offset': offset, 'bytes': length})
        return raw

    def logical_read(self, offset, length, purpose):
        need(0 <= offset <= offset + length <= self.component_bytes, 'Range outside MDR')
        result, mapping = bytearray(), []
        cursor = offset
        while cursor < offset + length:
            index, within = divmod(cursor, self.block_size)
            count = min(offset + length - cursor, self.block_size - within)
            block = self.blocks[index]
            physical = block * self.block_size + within
            mapping.append({'logical_offset': cursor, 'logical_offset_hex': hex(cursor),
                'logical_block_index': index, 'FAT_part': index // 240,
                'FAT_slot_in_part': index % 240, 'allocated_disk_block': block,
                'within_block': within, 'physical_offset': physical, 'bytes': count})
            result.extend(self.physical_read(physical, count, purpose))
            cursor += count
        return bytes(result), mapping

    def close(self):
        self.stream.close()
        need(stat_signature(self.path) == self.before, 'Original map stat changed during read')


def projections(raw):
    return {'u8': list(raw), 'u16_LE': list(struct.unpack('<10H', raw)),
            'u16_BE': list(struct.unpack('>10H', raw)),
            'u32_LE': list(struct.unpack('<5I', raw)),
            'u32_BE': list(struct.unpack('>5I', raw))}


def main():
    target = OUT / 'AP-provider-records-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    schema = json.loads(SCHEMA.read_text())
    need(source_reference(SCHEMA)['sha256'] == '8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d',
         'Sealed schema proof changed')
    native = json.loads(NATIVE.read_text())
    ap_case = next(c for c in native['cases'] if c['name'].endswith('/gmapprom1.img'))
    need(ap_case['success'] and ap_case['stop_reached'], 'Native parser proof incomplete')
    declared_header = next(h for h in schema['public_mdr_headers'] if h['path'].endswith('/gmapprom1.img'))
    image = ReadonlyMDR(MAP_PATH)
    try:
        header, header_mapping = image.logical_read(0, 772, 'public_MDR_header')
        need(hashlib.sha256(header).hexdigest() == declared_header['header_sha256'] == ap_case['header_sha256'],
             'Original MDR header changed')
        descriptor = list(struct.unpack_from('<4I', header, 600))
        need(descriptor == [OFFSET, LENGTH, 20, 1], 'Provider header descriptor changed')
        directory, mapping = image.logical_read(OFFSET, LENGTH, 'provider_directory_120_bytes')
        records = []
        for ordinal in range(6):
            raw = directory[ordinal * 20:ordinal * 20 + 20]
            records.append({'ordinal_zero_based': ordinal,
                'MDR_relative_offset': OFFSET + ordinal * 20, 'hex': raw.hex(), **projections(raw)})
        known_city_ids = {r['record'] & 0x0fffffff for r in schema['databases']['jai']['city_record_witnesses']}
        gaps = set(schema['databases']['jai']['third_level_missing_low28'])
        logical_records = ({0x10000000 | value for value in range(1, 23)} |
                           {0x20000000 | value for value in range(1, 344)} |
                           {0x30000000 | value for value in range(1, 47871) if value not in gaps})
        need(len(logical_records) == 48218, 'Logical record set reconstruction differs from sealed counts')
        map_ids = {5441050, 5454428}
        matches = []
        for row in records:
            for endian in ('LE', 'BE'):
                for word, value in enumerate(row['u32_' + endian]):
                    match = {'record_ordinal': row['ordinal_zero_based'], 'word_offset': word * 4,
                             'endian': endian, 'value': value,
                             'equals_stock_map_id': value in map_ids,
                             'equals_logical_jai_record': value in logical_records,
                             'within_dense_info_PK_range': 1 <= value <= 48218,
                             'equals_city_low28_ID': value in known_city_ids}
                    if any(match[k] for k in ('equals_stock_map_id', 'equals_logical_jai_record',
                                             'within_dense_info_PK_range', 'equals_city_low28_ID')):
                        matches.append(match)
        le_words = [row['u32_LE'] for row in records]
        spans = [{'ordinal': i, 'observed_word0': w[0], 'observed_word1': w[1],
                  'candidate_start': w[0], 'candidate_bytes': w[1], 'candidate_end': w[0] + w[1]}
                 for i, w in enumerate(le_words)]
        need(all(772 <= s['candidate_start'] < s['candidate_end'] <= OFFSET for s in spans),
             'Numerical span outside MDR data')
        need(spans[0]['candidate_end'] == OFFSET and
             all(spans[i]['candidate_start'] == spans[i + 1]['candidate_end'] for i in range(5)),
             'Six observed numerical spans not contiguous')
        native_slice = bytes.fromhex(ap_case['native_context_slice280_2c4'])
        context = {hex(0x280 + offset): struct.unpack_from('<I', native_slice, offset)[0]
                   for offset in range(0x28, len(native_slice) - 3, 4)}
        evidence = {
            'created_utc': datetime.now(timezone.utc).isoformat(), 'source_sha256': source_reference(Path(__file__))['sha256'],
            'scope': 'Exactly original AP 120-byte provider directory and public header; numerical observations only.',
            'source_map': {'path': str(MAP_PATH.relative_to(ROOT)), 'bytes': MAP_PATH.stat().st_size,
                'backup_verified_sha256_reference': next(m['backup_verified_sha256'] for m in schema['stock_map_metadata'] if m['path'].endswith('/gmapprom1.img')),
                'whole_map_digest_repeated': False},
            'dependencies': [source_reference(SCHEMA), source_reference(NATIVE)],
            'IMG_FAT': {'block_size': image.block_size, 'directory_extent': image.directory_extent,
                        'MDR_component': image.component_name, 'MDR_bytes': image.component_bytes,
                        'MDR_allocated_blocks': len(image.blocks), 'MDR_parts': len(image.parts),
                        'target_FAT_part': image.parts[mapping[0]['FAT_part']]},
            'provider_header_descriptor': {'MDR_header_offset': 600, 'MDR_header_offset_hex': '0x258',
                'bytes': 16, 'hex': header[600:616].hex(), 'u32_LE': descriptor,
                'native_parser_size_over_itemsize': '120/20=6',
                'field_semantics_beyond_native_guard_not_confirmed': True},
            'native_context_value_projection': context,
            'context_offset_caution': 'Value0x0585C7A8 occurs at ctx+2B4, not +2B0; store/consumer semantics still require native confirmation.',
            'provider_directory': {'MDR_relative_offset': OFFSET, 'MDR_relative_offset_hex': hex(OFFSET),
                'bytes': LENGTH, 'sha256': hashlib.sha256(directory).hexdigest(), 'hex': directory.hex(),
                'mapping': mapping, 'records': records,
                'ends_exactly_at_MDR_EOF': OFFSET + LENGTH == image.component_bytes},
            'numerical_span_observation': {'spans_if_word0_offset_word1_length': spans,
                'native_offset_and_length_semantics_confirmed': False,
                'strictly_contiguous_in_reverse_directory_order': True,
                'disjoint_combined_range': [spans[-1]['candidate_start'], OFFSET],
                'combined_bytes': sum(w[1] for w in le_words), 'large_span_contents_read': False,
                'word3_low16_identical': len({w[3] & 65535 for w in le_words}) == 1,
                'word3_common_low16_hex': hex(le_words[0][3] & 65535)},
            'JAI_value_comparison': {'method': 'Compare projected whole DWORDs with sealed city IDs, exact logical-record set and MapIDs; info PK range membership is numerical only.',
                'matches': matches,
                'any_exact_stock_map_id_match': any(m['equals_stock_map_id'] for m in matches),
                'any_exact_logical_jai_record_match': any(m['equals_logical_jai_record'] for m in matches),
                'city_or_JAI_field_semantics_confirmed': False,
                'number6_named_as_city_count': False},
            'read_log': image.read_log, 'total_actual_map_bytes_read': sum(r['bytes'] for r in image.read_log),
            'body_content_bytes_read': LENGTH, 'unlock_or_decryption_performed': False,
            'device_IO': False, 'stock_map_modified': False, 'copied_raw_map': False,
            'sealed_schema_modified': False, 'physical_query_or_routing_verified_by_this_probe': False,
            'all_bounded_read_and_link_checks_passed': True,
        }
        need(evidence['total_actual_map_bytes_read'] <= 65536, 'Read budget exceeded')
        image.close()
        evidence['source_map_stat_unchanged'] = True
        with target.open('x') as out:
            json.dump(evidence, out, ensure_ascii=False, indent=2)
            out.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
              'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
              'payload_bytes_read': LENGTH, 'total_actual_map_bytes_read': evidence['total_actual_map_bytes_read'],
              'all_bounded_read_and_link_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
