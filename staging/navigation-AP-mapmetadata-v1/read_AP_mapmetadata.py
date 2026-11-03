#!/usr/bin/env python3
"""Read original AP public map headers / one levels table and static callers.

No complete IMG/MAIN digest, decoding of protected NT data, or device I/O.
Every source read is bounded and reported. Existing evidence is immutable.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-mapmetadata-v1'
MAP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
MAIN = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
SCHEMA = ROOT / 'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
PACKED = ROOT / 'staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json'
SECTIONS = ROOT / 'evidence/firmware-analysis/native-sections.json'


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class BoundedIMG:
    def __init__(self):
        self.before = stat(MAP)
        self.stream = MAP.open('rb')
        self.log = []
        head = self.physical(0, 512, 'public_disk_header')
        need(head[0] == 0 and head[16:23] == b'DSKIMG\0' and head[65:72] == b'GARMIN\0',
             'Unrecognized or obfuscated disk header')
        self.block_size = 1 << (head[97] + head[98])
        first = head[64] * 512
        row = self.physical(first, 512, 'directory_extent_header')
        end = struct.unpack_from('<I', row, 12)[0]
        need(first < end <= 131072 and end % 512 == 0, 'Unexpected public FAT extent')
        directory = self.physical(first, end - first, 'public_directory_and_FAT')
        self.extent = [first, end]
        self.components = {}
        targets = {'00004171.MDR', 'I053061A.GMP'}
        for pos in range(0, len(directory), 512):
            row = directory[pos:pos + 512]
            if row[0] != 1 or row[16] == 3:
                continue
            name = row[1:9].decode('ascii').rstrip() + '.' + row[9:12].decode('ascii').rstrip()
            if name not in targets:
                continue
            c = self.components.setdefault(name, {'blocks': [], 'parts': []})
            part = struct.unpack_from('<H', row, 17)[0]
            need(part == len(c['parts']), 'Unexpected FAT part order')
            if not part:
                c['bytes'] = struct.unpack_from('<I', row, 12)[0]
            blocks = [v for v in struct.unpack_from('<240H', row, 32) if v != 65535]
            need(all(b * self.block_size < self.before[2] for b in blocks), 'FAT outside original file')
            c['parts'].append({'part': part, 'directory_record_physical_offset': first + pos,
                               'first_logical_block_index': len(c['blocks']), 'blocks': len(blocks)})
            c['blocks'].extend(blocks)
        need(set(self.components) == targets, 'Required public components missing')
        for c in self.components.values():
            need(len(c['blocks']) == (c['bytes'] + self.block_size - 1) // self.block_size,
                 'FAT count differs from original component length')
            need(len(set(c['blocks'])) == len(c['blocks']), 'Duplicated allocated blocks')

    def physical(self, offset, length, purpose):
        need(length >= 0 and 0 <= offset <= offset + length <= self.before[2], 'Physical range outside map')
        self.stream.seek(offset)
        raw = self.stream.read(length)
        need(len(raw) == length, 'Short source read')
        self.log.append({'purpose': purpose, 'physical_offset': offset, 'bytes': length})
        return raw

    def read(self, name, offset, length, purpose):
        c = self.components[name]
        need(0 <= offset <= offset + length <= c['bytes'], 'Logical range outside component')
        result, mappings = bytearray(), []
        cursor = offset
        while cursor < offset + length:
            index, within = divmod(cursor, self.block_size)
            count = min(offset + length - cursor, self.block_size - within)
            block = c['blocks'][index]
            physical = block * self.block_size + within
            mappings.append({'logical_offset': cursor, 'logical_block_index': index,
                'FAT_part': index // 240, 'FAT_slot': index % 240,
                'allocated_disk_block': block, 'within_block': within,
                'physical_offset': physical, 'bytes': count})
            result.extend(self.physical(physical, count, purpose))
            cursor += count
        raw = bytes(result)
        return {'component': name, 'logical_offset': offset, 'bytes': length,
                'sha256': sha(raw), 'hex': raw.hex(), 'FAT_mapping': mappings}, raw

    def close(self):
        self.stream.close()
        need(stat(MAP) == self.before, 'Original IMG changed during read')


def static_fragments():
    before = stat(MAIN)
    copies = json.loads(SECTIONS.read_text())['copies']
    # Exact control-flow ranges exclude the loader's embedded literal pool.
    ranges = [(0x359038, 54), (0x1F7814, 76),
              (0x2D057C, 282), (0x2D0834, 28),
              (0x2D0850, 0x18A), (0x44B134C, 0x3A)]
    out = []
    dis = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    with MAIN.open('rb') as f:
        for runtime, count in ranges:
            found = [c for c in copies if c['runtime_start'] <= runtime and
                     runtime + count <= c['runtime_end']]
            need(len(found) == 1, 'No unique initialized section mapping')
            c = found[0]
            load = c['load_start'] + runtime - c['runtime_start']
            f.seek(load - 0x50000)
            raw = f.read(count)
            need(len(raw) == count, 'Short MAIN fragment')
            literal = runtime == 0x2D0834
            out.append({'runtime_address': runtime, 'runtime_address_hex': hex(runtime),
                'load_address': load, 'MAIN_file_offset': load - 0x50000,
                'bytes': count, 'sha256': sha(raw), 'hex': raw.hex(),
                'kind': 'embedded_exact_TRE_literals' if literal else 'Thumb_static_code',
                'instructions': [] if literal else [{'address': i.address, 'address_hex': hex(i.address),
                    'hex': i.bytes.hex(), 'mnemonic': i.mnemonic, 'operands': i.op_str}
                    for i in dis.disasm(raw, runtime)]})
    need(stat(MAIN) == before, 'Original MAIN changed during read')
    return out


def main():
    target = OUT / 'AP-mapmetadata-evidence.json'
    need(not target.exists(), 'Refusing to overwrite existing evidence')
    need(ref(SCHEMA)['sha256'] == '8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d',
         'Sealed original schema changed')
    need(ref(PACKED)['sha256'] == 'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53',
         'Sealed native packed-reader evidence changed')
    schema = json.loads(SCHEMA.read_text())
    packed = json.loads(PACKED.read_text())
    stock = next(m for m in schema['stock_map_metadata'] if m['path'].endswith('/gmapprom1.img'))
    gmp_decl = next(c for c in stock['components'] if c['name'] == 'I053061A.GMP')
    image = BoundedIMG()
    try:
        need(image.before[2] == stock['bytes'], 'Original AP size differs from verified backup')
        mapid_record, mapid_raw = image.read('00004171.MDR', 772, 4, 'MDR_mapordinal1_ID')
        mapid = struct.unpack('<I', mapid_raw)[0]
        gmp_record, gmp = image.read('I053061A.GMP', 0, 57, 'public_GMP_header')
        need(struct.unpack_from('<H', gmp)[0] == 57 and gmp[2:12] == b'GARMIN GMP',
             'Unexpected public GMP header')
        pointer_values = list(struct.unpack_from('<7I', gmp, 25))
        tre_offset = gmp_decl['gmp_component_headers']['TRE']['offset']
        need(pointer_values[0] == tre_offset == 236, 'Original TRE subheader offset changed')
        tre_record, tre = image.read('I053061A.GMP', tre_offset, 289, 'public_TRE_header')
        need(struct.unpack_from('<H', tre)[0] == 289 and tre[2:12] == b'GARMIN TRE' and tre[13] == 0,
             'Unexpected or protected TRE public header')
        tre_mapid = struct.unpack_from('<I', tre, 116)[0] & 0x0fffffff
        need(mapid == tre_mapid == stock['mps_maps'][0]['hex_map_number'] == 5441050,
             'MDR ordinal / TRE / original MPS mapID mismatch')
        table_offset, table_bytes = struct.unpack_from('<2I', tre, 33)
        need(tre_offset + len(tre) <= table_offset <= 1048576 and
             4 <= table_bytes <= 32 and table_bytes % 4 == 0, 'Unexpected bounded TRE table range')
        table_record, table = image.read('I053061A.GMP', table_offset, table_bytes,
                                         'TRE_small_level_records_original_absolute_offset')
        records = []
        for pos in range(0, len(table), 4):
            raw = table[pos:pos + 4]
            value = struct.unpack('<I', raw)[0]
            records.append({'ordinal': pos // 4, 'GMP_logical_offset': table_offset + pos,
                'hex': raw.hex(), 'u32_LE': value, 'level_low7': value & 127,
                'bit7': (value >> 7) & 1, 'second_byte': (value >> 8) & 255,
                'upper16': value >> 16})
        minimum = min(r['level_low7'] for r in records)
        at_min = [r for r in records if r['level_low7'] == minimum]
        need(len(at_min) == 1, 'Ambiguous original minimum-level entry')
        bits = at_min[0]['second_byte']
        need(1 <= bits <= 32, 'Invalid observed original shift field')
        cases = []
        for c in packed['cases']:
            values = [c['native_unnamed_fields']['+14'], c['native_unnamed_fields']['+18']]
            shifted = [(v << (32 - bits)) & 0xffffffff for v in values]
            cases.append({'native_case': c['source_plan_case'], 'raw_fields_24bit': values,
                'observed_TRE_metadata_parameter': bits, 'predicted_original_left_shift': 32 - bits,
                'arithmetic_shifted_u32': shifted,
                'hypothesis_degrees_if_signed_32_global_circle': [
                    (v if v < 0x80000000 else v - 0x100000000) * 360 / 2**32 for v in shifted],
                'native_rescale_instructions_executed_here': False,
                'latitude_longitude_field_semantics_confirmed_here': False})
        fragments = static_fragments()
        body_bytes = 4 + 57 + 289 + table_bytes
        evidence = {'created_utc': datetime.now(timezone.utc).isoformat(),
            'source': ref(Path(__file__)), 'scope': 'Original AP MDR1 ID, GMP/TRE public headers, bounded TRE levels table; exact static metadata/rescale path.',
            'dependencies': [ref(SCHEMA), ref(PACKED), ref(SECTIONS)],
            'original_map': {'path': str(MAP.relative_to(ROOT)), 'bytes': image.before[2],
                'verified_backup_sha256_reference': stock['backup_verified_sha256'],
                'whole_map_digest_repeated': False},
            'original_MAIN': {'path': str(MAIN.relative_to(ROOT)), 'bytes': MAIN.stat().st_size,
                'verified_sha256_reference': packed['stock_MAIN_sha256'], 'whole_MAIN_digest_repeated': False,
                'conditional_copy_live_flag_verified': False},
            'MDR1_mapordinal1_record': {**mapid_record, 'u32_LE': mapid},
            'GMP_public_header': {**gmp_record, 'seven_pointer_values_at25': pointer_values},
            'TRE_public_header': {**tre_record, 'header_mapID_at116_low28': tre_mapid,
                'level_table_offset_field_at33': table_offset, 'level_table_size_field_at37': table_bytes},
            'TRE_level_table': {**table_record, 'records': records,
                'minimum_low7_level': minimum, 'second_byte_at_minimum_level': bits},
            'static_dataflow': {
                'mapordinal_to_mapID': {'entry': '0x1F7814', 'formula': 'ctx+58 start + (mapordinal-1)*u16(ctx+5C), read4 bytes',
                    'actual_MDR1_mapID_match': True, 'function_executed_here': False},
                'mapmetadata_chain': '0x0448F740 -> 0x359038 -> 0x1F7814 -> 0x1EE156 -> 0x1AF428 -> 0x2D0EE0 -> 0x2D057C',
                'live_mapregistry_lookup_or_complete_loader_verified_here': False,
                'TRE_table_read': '0x2D062E extracts header+37 length; 0x2D065A extracts header+33 offset; 0x2D068E reads original table',
                'table_store': '0x2D093C stores second byte at object+0x40+low7level+0x16; 0x2D09AE stores minimum low7level at object+0x68',
                'metadata_getter': '0x044B135C..1366 reads u8(object+u8(object+0x68)+0x56)',
                'rescale': '0x044B1374..1382 left shifts each out+14/out+18 by 32-parameter',
                'metadata_return_hook_or_guessed_parameter_used': False},
            'cases_arithmetic_only': cases, 'static_original_code_fragments': fragments,
            'original_IMG_FAT': {'block_size': image.block_size, 'directory_extent': image.extent,
                'components': {n: {'bytes': c['bytes'], 'parts': len(c['parts']), 'blocks': len(c['blocks'])}
                               for n, c in image.components.items()}},
            'actual_map_read_log': image.log, 'map_content_bytes_read': body_bytes,
            'total_map_bytes_read_including_FAT': sum(r['bytes'] for r in image.log),
            'new_original_MAIN_fragment_bytes_read': sum(r['bytes'] for r in fragments),
            'unlock_or_decryption_performed': False, 'device_IO': False,
            'stock_map_or_DB_modified': False, 'copied_raw_map_or_MAIN': False,
            'original_metadata_returns_or_query_results_faked': False,
            'full_query_or_route_executed_here': False,
            'all_bounded_source_and_static_link_checks_passed': True}
        need(body_bytes <= 382 and evidence['total_map_bytes_read_including_FAT'] < 56000,
             'IMG read budget exceeded')
        need(evidence['new_original_MAIN_fragment_bytes_read'] <= 1000, 'MAIN fragment read budget exceeded')
        image.close()
        evidence['original_map_stat_unchanged'] = True
        evidence['original_MAIN_stat_unchanged'] = True
        with target.open('x') as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': sha(target.read_bytes()), 'actual_mapID': mapid,
            'actual_TRE_level_table_hex': table.hex(), 'actual_minimum_level_second_byte': bits,
            'map_content_bytes_read': body_bytes,
            'all_bounded_source_and_static_link_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
