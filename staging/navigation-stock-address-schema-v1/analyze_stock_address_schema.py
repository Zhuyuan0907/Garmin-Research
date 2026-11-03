#!/usr/bin/env python3
"""Read stock SQLite schema/link witnesses and public MDR headers only.

No DB/IMG writes, NT unlocking, map-payload extraction, or physical device I/O.
This does not claim that logical JAI records are map/routing addresses.
"""
import collections
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-stock-address-schema-v1'
BACKUP = ROOT / 'backups/20261002T154458Z/files/.System'
DB_PATHS = {'jai': BACKUP / 'SQLite/Prefecture/TWNJAI.db',
            'hwm': BACKUP / 'SQLite/HWM/TWNHWM.db'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def safe_value(value):
    if isinstance(value, bytes):
        return {'bytes': len(value), 'head_hex': value[:96].hex(),
                'sha256': hashlib.sha256(value).hexdigest()}
    return value


def rows(conn, sql, args=()):
    cur = conn.execute(sql, args)
    keys = [item[0] for item in cur.description]
    return [{key: safe_value(value) for key, value in zip(keys, row)} for row in cur]


def signature(path):
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def inspect_db(path):
    before = signature(path)
    with path.open('rb') as stream:
        header = stream.read(4096)
    need(header[:16] == b'SQLite format 3\0', 'Not plain SQLite3')
    con = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA query_only=ON')
    schema = rows(con, 'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')
    tables = [item['name'] for item in schema if item['type'] == 'table']
    result = {
        'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size,
        'read_mode': 'sqlite mode=ro&immutable=1; PRAGMA query_only=ON',
        'header_signature': 'SQLite format 3',
        'header_4096_sha256': hashlib.sha256(header).hexdigest(),
        'pragmas': {key: con.execute('PRAGMA ' + key).fetchone()[0] for key in
                    ('page_size', 'encoding', 'user_version', 'schema_version', 'application_id', 'auto_vacuum')},
        'schema': schema,
        'table_columns': {table: rows(con, 'PRAGMA table_info("' + table + '")') for table in tables},
        'table_counts': {table: con.execute('SELECT COUNT(*) FROM "' + table + '"').fetchone()[0] for table in tables},
        'metadata': rows(con, 'SELECT * FROM garmin_metadata'),
        'quick_check': [row[0] for row in con.execute('PRAGMA quick_check')],
    }
    return con, result, before


def public_mdr_header(path):
    """Read only IMG directory and declared MDR header (no MDR contents)."""
    reads = 0
    with path.open('rb') as stream:
        def read_at(offset, count):
            nonlocal reads
            stream.seek(offset)
            data = stream.read(count)
            reads += len(data)
            need(len(data) == count, 'Short public header read')
            return data
        head = read_at(0, 512)
        need(head[0] == 0 and head[16:23] == b'DSKIMG\0' and head[65:72] == b'GARMIN\0',
             'Unsupported/encrypted disk header')
        block_size = 1 << (head[97] + head[98])
        first = head[64] * 512
        first_entry = read_at(first, 512)
        end = struct.unpack_from('<I', first_entry, 12)[0]
        need(first < end <= 131072 and end % 512 == 0, 'Unexpected public directory size')
        directory = read_at(first, end - first)
        components = {}
        for pos in range(0, len(directory), 512):
            entry = directory[pos:pos + 512]
            if not entry[0] or entry[16] == 3:
                continue
            need(entry[0] == 1, 'Unknown public directory entry')
            name = entry[1:9].decode('ascii').rstrip() + '.' + entry[9:12].decode('ascii').rstrip()
            if not name.endswith('.MDR'):
                continue
            part = struct.unpack_from('<H', entry, 17)[0]
            if not part:
                components[name] = {'bytes': struct.unpack_from('<I', entry, 12)[0], 'blocks': [], 'parts': 0}
            item = components[name]
            need(part == item['parts'], 'Nonsequential MDR allocation')
            item['blocks'] += [n for n in struct.unpack_from('<240H', entry, 32) if n != 65535]
            item['parts'] += 1
        need(len(components) == 1, 'Expected one original MDR')
        name, info = next(iter(components.items()))
        first_block = info['blocks'][0] * block_size
        declared = struct.unpack_from('<H', read_at(first_block, 2))[0]
        need(29 <= declared <= block_size, 'Public header exceeds first block')
        data = read_at(first_block, declared)
        need(data[2:12] == b'GARMIN MDR', 'MDR signature absent')
        sections = []
        pos = 29
        # Test the documented r4924 prefix, but do not assume original NT shares
        # the whole layout. Retain exact public bytes for native-parser mapping.
        for number in range(1, 31):
            descriptor_offset = pos
            start, size = struct.unpack_from('<2I', data, pos)
            pos += 8
            item_size = 0
            if number not in (10, 15, 17):
                item_size = struct.unpack_from('<H', data, pos)[0]
                pos += 2
            extra = None
            if number != 15:
                extra = struct.unpack_from('<I', data, pos)[0]
                pos += 4
            else:
                need(data[pos] == 0, 'MDR15 prefix terminator differs')
                pos += 1
            in_bounds = 0 <= start <= info['bytes'] and start + size <= info['bytes']
            sections.append({'r4924_assumed_section': number, 'header_offset': descriptor_offset,
                             'start': start, 'bytes': size, 'item_size': item_size,
                             'extra_hex': f'0x{extra:08X}' if extra is not None else None,
                             'records_if_integral': size // item_size if item_size and size % item_size == 0 else None,
                             'within_component_bounds': in_bounds,
                             'native_section_semantics_confirmed': False})
            if not in_bounds:
                break
        return {
            'path': str(path.relative_to(ROOT)), 'component_name': name,
            'component_bytes': info['bytes'], 'header_bytes': declared,
            'header_sha256': hashlib.sha256(data).hexdigest(),
            'code_page': struct.unpack_from('<H', data, 21)[0],
            'sort_ids': list(struct.unpack_from('<2H', data, 23)),
            'metadata_halfword_offset27': struct.unpack_from('<H', data, 27)[0],
            'r4924_descriptor_prefix_attempt': sections,
            'r4924_layout_matches_whole_native_header': False,
            'public_header_hex': data.hex(),
            'public_header_chunks16': [{'offset': offset, 'offset_hex': hex(offset),
                'hex': data[offset:offset + 16].hex(),
                'u32le': list(struct.unpack('<4I', data[offset:offset + 16])) if offset + 16 <= len(data) else None}
                for offset in range(0, len(data), 16)],
            'native_agent_requested_chunks16': [{'offset': offset, 'offset_hex': hex(offset),
                'hex': data[offset:offset + 16].hex(), 'u32le': list(struct.unpack_from('<4I', data, offset))}
                for offset in range(0x1B8, 0x208, 16)],
            'native_descriptor_cursor_pending': True,
            'r4924_prefix_attempt_stopped_at_byte': pos,
            'extra_header_bytes_not_interpreted': declared - pos,
            'total_actual_bytes_read': reads, 'section_contents_read': False,
        }


def main():
    target = OUT / 'stock-address-schema-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    source_inventory = ROOT / 'staging/navigation-map-layers-v1/layer-inventory.json'
    inventory = json.loads(source_inventory.read_text())
    evidence = {
        'recorded_utc': datetime.now(timezone.utc).isoformat(),
        'scope': 'Exact HWID1352 SW800 stock backup. Plain SQLite schema/data linking and public MDR headers only.',
        'device_io': False, 'stock_files_modified': False, 'nt_payload_unlocked_or_decoded': False,
        'inventory_reference': {'path': str(source_inventory.relative_to(ROOT)),
            'sha256': hashlib.sha256(source_inventory.read_bytes()).hexdigest()},
        'stock_map_metadata': [item for item in inventory['stock_maps'] if item['path'].endswith(('/gmapprom.img', '/gmapprom1.img'))],
        'stock_dependencies': inventory['verified_relationships'],
        'databases': {},
    }
    opened = []
    try:
        for key, path in DB_PATHS.items():
            con, item, before = inspect_db(path)
            opened.append((con, path, before))
            evidence['databases'][key] = item
            if key == 'jai':
                item['jai_metadata'] = rows(con, 'SELECT * FROM jai_metadata')
                item['map_ids'] = rows(con, 'SELECT * FROM jai_map_id')
                item['record_levels'] = rows(con, 'SELECT record>>28 AS high_nibble,COUNT(*) AS count,MIN(record&268435455) AS first_low28,MAX(record&268435455) AS last_low28 FROM japan_addr_info GROUP BY record>>28')
                item['city_record_witnesses'] = rows(con, 'SELECT id,index_record,record,printf("%08X",record) AS record_hex FROM japan_addr_info WHERE record>>28=1 ORDER BY record')
                item['unique_counts'] = rows(con, 'SELECT COUNT(*) AS rows,COUNT(DISTINCT record) AS unique_records,COUNT(DISTINCT index_record) AS unique_index_strings FROM japan_addr_info')[0]
                tokens = [v[0] for v in con.execute('SELECT index_record FROM japan_addr_info')]
                item['encoded_text_shape'] = {'tk_plus_5_a_to_p_rows': sum(bool(re.fullmatch(r'(?:tk[a-p]{5})+', value)) for value in tokens),
                    'nonmatching_rows': [{'id': row['id'], 'record_hex': row['record_hex'], 'index_record': row['index_record']} for row in rows(con, 'SELECT id,printf("%08X",record) AS record_hex,index_record FROM japan_addr_info') if not re.fullmatch(r'(?:tk[a-p]{5})+', row['index_record'])],
                    'literal_chinese_name_queries': {value: con.execute('SELECT COUNT(*) FROM japan_addr_info WHERE index_record LIKE ?', ('%' + value + '%',)).fetchone()[0] for value in ('民權路', '民和路', '台中', '臺中', '184')},
                    'encoder_or_decoded_name_confirmed': False,
                    'literal_zero_does_not_prove_address_absent': True}
                item['fts_links'] = []
                cities = item['city_record_witnesses']
                for ordinal in range(1, 23):
                    table = 'japan_addr_index_' + str(ordinal)
                    expected_first = cities[ordinal - 1]['id']
                    expected_last = cities[ordinal]['id'] - 1 if ordinal < 22 else 48218
                    linked = rows(con, f'SELECT COUNT(*) AS rows,SUM(i.id IS NULL) AS orphan_ids,SUM(((f.record_info&240)>>4)!=(i.record>>28)) AS level_mismatches,MIN(f.record_info>>8) AS min_info_id,MAX(f.record_info>>8) AS max_info_id FROM {table} f LEFT JOIN japan_addr_info i ON i.id=(f.record_info>>8)')[0]
                    linked.update(table=table, expected_city_low28=ordinal,
                                  info_id_range=[expected_first, expected_last])
                    need(linked['orphan_ids'] == 0 and linked['level_mismatches'] == 0 and
                         linked['min_info_id'] == expected_first and linked['max_info_id'] == expected_last,
                         'FTS linkage mismatch')
                    linked['low_byte_distribution'] = rows(con, f'SELECT record_info&255 AS low_byte,COUNT(*) AS rows FROM {table} GROUP BY record_info&255')
                    linked['sample'] = rows(con, f'SELECT f.rowid,f.index_record,f.record_info,i.id AS info_id,printf("%08X",i.record) AS logical_record_hex FROM {table} f JOIN japan_addr_info i ON i.id=f.record_info>>8 LIMIT 3')
                    item['fts_links'].append(linked)
                item['family_level_transitions'] = rows(con, 'SELECT parent_record>>28 AS parent_level,the_first_record>>28 AS first_child_level,COUNT(*) AS rows FROM japan_addr_family GROUP BY 1,2')
                item['family_first_child_not_in_info'] = rows(con, 'SELECT printf("%08X",f.parent_record) AS parent_record_hex,p.id AS parent_info_id,printf("%08X",f.the_first_record) AS first_child_record_hex FROM japan_addr_family f JOIN japan_addr_info p ON p.record=f.parent_record LEFT JOIN japan_addr_info ch ON ch.record=f.the_first_record WHERE ch.record IS NULL')
                third = {row[0] & 0x0fffffff for row in con.execute('SELECT record FROM japan_addr_info WHERE record>>28=3')}
                item['third_level_missing_low28'] = sorted(set(range(1, max(third) + 1)) - third)
                item['prefix_samples'] = rows(con, 'SELECT * FROM japan_addr_prefix ORDER BY prefix_id LIMIT 3')
                item['segment_samples'] = []
                for sid in (1, 2, 3, 4, 45, 88, 131):
                    blob = con.execute('SELECT segment FROM japan_addr_segments WHERE seg_id=?', (sid,)).fetchone()[0]
                    sample = {'seg_id': sid, 'blob': safe_value(blob), 'prefix_rows': rows(con, 'SELECT * FROM japan_addr_prefix WHERE seg_id=?', (sid,))}
                    if sid in (45, 88, 131):
                        sample['u16_pairs_observed'] = [list(pair) for pair in struct.iter_unpack('<HH', blob)]
                    if sid == 2:
                        entries, offset = [], 0
                        while True:
                            ident, flag, low_byte, next_offset = struct.unpack_from('<IBBI', blob, offset)
                            stop = next_offset or len(blob)
                            token = blob[offset + 10:stop].decode('ascii')
                            record = rows(con, 'SELECT id,index_record,printf("%08X",record) AS logical_record_hex FROM japan_addr_info WHERE id=?', (ident,))[0]
                            need(token in record['index_record'] and flag == 1 and low_byte == 0x31, 'Segment witness differs')
                            entries.append({'offset': offset, 'info_id': ident, 'flag': flag, 'low_byte': low_byte, 'next_offset': next_offset, 'ascii_suffix': token, 'info': record})
                            if not next_offset:
                                break
                            need(offset < next_offset < len(blob), 'Bad segment next pointer')
                            offset = next_offset
                        sample['bounded_linked_entry_observation'] = entries
                    item['segment_samples'].append(sample)
                item['segment_interpretation_scope'] = 'Observed selected raw u16 pairs and six linked entries only; full serialization and native use not confirmed.'
            else:
                item['map_ids'] = rows(con, 'SELECT * FROM map_ids')
                item['referenced_map_ids'] = {table: rows(con, 'SELECT DISTINCT "' + column + '" AS map_id FROM "' + table + '"') for table, column in [('roadsign_node_info','m_map_id'),('highway_exits_db','m_map_id'),('Exit_Selection_List','m_map_id'),('Entrance_Selection_List','m_map_id'),('FacilityIconList','MapId')]}
                item['road_node_samples'] = rows(con, 'SELECT * FROM roadsign_node_info LIMIT 3')
                item['exit_samples'] = rows(con, 'SELECT * FROM Exit_Selection_List LIMIT 3')
                item['minquan_name_matches'] = rows(con, 'SELECT * FROM roadsign_node_info WHERE roadsign_text LIKE ? LIMIT 3', ('%民權%',))
                item['meaning_scope'] = 'Roadsign/highway graph sidecar; does not provide the ordinary house-address table.'
        evidence['public_mdr_headers'] = [public_mdr_header(BACKUP / name) for name in ('gmapprom.img', 'gmapprom1.img')]
        evidence['confirmed_db_observations'] = [
            'Both databases have readable standard SQLite3 schema; FTS3 tables exist in stock JAI.',
            'JAI IDs bind to AP map 0x53061A; HWM graph references bind to road map 0x533A5C.',
            'All 22 FTS partitions join record_info>>8 to info.id with zero orphans; low-byte high nibble matches record high nibble.',
            'All FTS partitions cover exact contiguous info-ID ranges associated with city logical IDs 1..22.',
            'JAI has 22/343/47853 logical records at high-nibble levels 1/2/3, no direct house-number or coordinate columns.',
            'Four valid stock family first-child values are absent from info; do not invent an all-children-present requirement.',
            'AP contains no NET/NOD header; its MDR accounts for 92653600 of 96739328 disk-image bytes.',
        ]
        evidence['rebuildability_boundaries'] = {
            'schema_and_sqlite_indexes_structurally_recreatable': True,
            'tk_query_and_index_encoder_decoded': False,
            'logical_jai_record_to_native_ap_feature_reference_decoded': False,
            'native_house_number_184_witness_identified': False,
            'native_ap_house_position_storage_decoded': False,
            'native_ap_destination_to_new_osm_route_record_linkage_verified': False,
            'original_nt_can_be_updated_from_osm_proven': False,
            'new_original_format_db_or_map_written': False,
            'stock_184_absence_proven': False,
            'note': 'Schema shape is necessary but not sufficient to generate functioning native records; preserve original CN+AP pairing.'}
        for con, path, before in opened:
            con.close()
            need(signature(path) == before, 'Original DB metadata changed')
        evidence['db_stat_signatures_unchanged'] = True
        evidence['all_readonly_structural_checks_passed'] = True
        with target.open('x') as stream:
            json.dump(evidence, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
              'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
              'all_readonly_structural_checks_passed': True,
              'actual_img_bytes_read': sum(item['total_actual_bytes_read'] for item in evidence['public_mdr_headers'])}))
    finally:
        for con, _, _ in opened:
            con.close()


if __name__ == '__main__':
    main()
