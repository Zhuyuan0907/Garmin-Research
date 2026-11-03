#!/usr/bin/env python3
"""Stream Taiwan OSM address nodes and prepare stock-JAI match coverage.

Offline preparation only: source/stock files are read-only. No image writer,
native execution, device I/O, index replacement or device prefix normalization.
Floor/unit dedup groups are planning keys, never a silent location selection.
"""
import argparse
import ast
from bisect import bisect_right
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import struct
import subprocess
import unicodedata
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
SOURCE = ROOT / 'sources/maps/taiwan-latest.osm.pbf'
DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
CODEC = ROOT / 'staging/navigation-stock-fts-codec-v1/analyze_stock_fts_codec_v1.py'
FRAGMENTS = CODEC.parent / 'stock-fts-token-codec-static-fragments-v1.json'
PLAN = ROOT / 'staging/navigation-native-Minquan-append-plan-v1/Minquan-append-only-record-plan-v1.json'
LEVEL4_COUNT = 2133948
CHILD_FIRST_MAX = (1 << 22) - 1


def need(ok, message):
    if not ok:
        raise ValueError(message)


def dump(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))


def save(path, value):
    need(not path.exists(), 'Refusing overwrite: ' + str(path))
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature(path):
    st = path.stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def normalize_name(text):
    # Explicit host matching policy only; raw labels/tags are retained.
    return unicodedata.normalize('NFKC', text or '').strip().replace('臺', '台')


def house_number(raw):
    """Conservative single-house planning key; do not split multiple values."""
    text = unicodedata.normalize('NFKC', raw or '').strip()
    if not text:
        return {'class': 'missing', 'key': None}
    if re.search(r'[;,、/\\~～至]', text):
        return {'class': 'multiple_or_range', 'key': None}
    # Floors/units in separate addr:* tags are grouped separately below.
    match = re.fullmatch(r'([1-9][0-9]*)(?:之([1-9][0-9]*))?號?(?:(之)([1-9][0-9]*))?', text)
    if match:
        base, sub, after, aftersub = match.groups()
        if sub and after:
            return {'class': 'malformed', 'key': None}
        sub = sub or aftersub
        return {'class': 'single_integer' if not sub else 'single_subnumber',
                'key': str(int(base)) + ('之' + str(int(sub)) if sub else '') + '號'}
    match = re.fullmatch(r'([1-9][0-9]*(?:之[1-9][0-9]*)?號)(.+(?:樓|室|F|f).*)', text)
    if match:
        parsed = house_number(match.group(1))
        return {'class': 'single_with_embedded_floor_unit', 'key': parsed['key'],
                'embedded_floor_unit': match.group(2)}
    if re.fullmatch(r'[1-9][0-9]*-[1-9][0-9]*號?', text):
        return {'class': 'hyphen_subnumber_or_range_ambiguous', 'key': None}
    if not re.search(r'[0-9]', text):
        return {'class': 'nonnumeric', 'key': None}
    return {'class': 'malformed_or_unrecognized', 'key': None}


def codec_decoder():
    # Reuse only pure codec functions; no previous suite/module main is run.
    selected = {'xor_swap', 'schedule', 'transform', 'decode_text'}
    tree = ast.parse(CODEC.read_text())
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in selected]
    need(len(functions) == len(selected), 'Four reusable codec functions')
    namespace = {'need': need}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(CODEC), 'exec'), namespace)
    key_fragment = json.loads(FRAGMENTS.read_text())['fragments']['key128']
    with (ROOT / 'evidence/firmware-analysis/main_02bd.bin').open('rb') as stream:
        stream.seek(0xEA1258 - 0x50000)
        key = stream.read(128)
    need(hashlib.sha256(key).hexdigest() == key_fragment['sha256'], 'Frozen codec key')
    scheduled = namespace['schedule'](key)
    cache = {}
    def decode(encoded):
        if encoded not in cache:
            cache[encoded] = namespace['decode_text'](encoded, scheduled)[0]
        return cache[encoded]
    return decode


def component_range(path, name, offset, length):
    """Read a bounded logical range via IMG FAT; never copy/read full image."""
    with path.open('rb') as handle:
        header = handle.read(512)
        need(header[16:23] == b'DSKIMG\0', 'Stock IMG container')
        block_size = 1 << (header[97] + header[98])
        fat_start = header[64] * 512
        handle.seek(fat_start)
        first = handle.read(512)
        fat_end = struct.unpack_from('<I', first, 12)[0]
        blocks, total = [], None
        for position in range(fat_start, fat_end, 512):
            handle.seek(position)
            row = handle.read(512)
            if row[0] != 1 or row[16] == 3:
                continue
            entry = row[1:9].decode().rstrip() + '.' + row[9:12].decode().rstrip()
            if entry != name:
                continue
            part = struct.unpack_from('<H', row, 17)[0]
            need(part == len(blocks) // 240, 'Component FAT part order')
            if part == 0:
                total = struct.unpack_from('<I', row, 12)[0]
            blocks.extend(struct.unpack_from('<240H', row, 32))
        blocks = [block for block in blocks if block != 65535]
        need(total is not None and offset + length <= total, 'Bounded component range')
        result = bytearray()
        cursor, end = offset, offset + length
        while cursor < end:
            index, within = divmod(cursor, block_size)
            amount = min(end - cursor, block_size - within)
            handle.seek(blocks[index] * block_size + within)
            result.extend(handle.read(amount))
            cursor += amount
        need(len(result) == length, 'Complete bounded component range')
        return bytes(result)


def native_hierarchy():
    decode = codec_decoder()
    before = signature(DB)
    con = sqlite3.connect(DB.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA query_only=ON')
    info = {record: {'info_id': ident, 'record': record, 'low28_id': record & 0x0fffffff,
                     'level': record >> 28, 'raw_name': decode(encoded)}
            for ident, encoded, record in con.execute('SELECT id,index_record,record FROM japan_addr_info')}
    families = con.execute('SELECT parent_record,the_first_record FROM japan_addr_family ORDER BY the_first_record').fetchall()
    con.close()
    need(signature(DB) == before, 'Stock DB unchanged')
    firsts = [row[1] for row in families]
    need(len(firsts) == len(set(firsts)), 'Unique family lower boundaries')
    def parent(record):
        position = bisect_right(firsts, record) - 1
        need(position >= 0, 'Known family predecessor')
        value = families[position][0]
        need(value in info and info[value]['level'] < record >> 28, 'Family level decrease')
        need(firsts[position] >> 28 == record >> 28, 'Family child level match')
        return value
    table = next(row for row in json.loads(PLAN.read_text())['MDR_component_relocation_plan']['tables'] if row['level'] == 3)
    packed = component_range(AP, '00004171.MDR', table['old_start'], table['old_bytes'])
    need(table['record_bits'] == 111 and table['count'] == 47870, 'Known street table')
    cities, districts, streets = {}, defaultdict(list), defaultdict(list)
    rows = []
    for record, row in sorted(info.items()):
        if row['level'] == 1:
            row.update(city=row['raw_name'], district=None, street=None)
            cities[normalize_name(row['raw_name'])] = row
        elif row['level'] == 2:
            city = info[parent(record)]
            need(city['level'] == 1, 'District parent is city')
            row.update(city=city['raw_name'], district=row['raw_name'], street=None)
            districts[(normalize_name(row['city']), normalize_name(row['district']))].append(row)
        elif row['level'] == 3:
            par = info[parent(record)]
            city = par if par['level'] == 1 else info[parent(par['record'])]
            row.update(city=city['raw_name'], district=None if par['level'] == 1 else par['raw_name'], street=row['raw_name'])
            bit = (row['low28_id'] - 1) * 111
            byte, shift = divmod(bit, 8)
            word = int.from_bytes(packed[byte:byte + 16], 'little') >> shift
            row.update(first_child=(word >> 20) & ((1 << 22) - 1),
                       child_count=(word >> 42) & 4095,
                       child_level_and_flags=(word >> 54) & 511)
            row['next_level'] = row['child_level_and_flags'] & 7
            streets[(normalize_name(row['city']), normalize_name(row['district']), normalize_name(row['street']))].append(row)
        else:
            raise ValueError('Unexpected JAI name level')
        rows.append(row)
    need(Counter(row['level'] for row in rows) == {1: 22, 2: 343, 3: 47853}, 'Exact name row counts')
    central = streets[('台中市', '中區', '民權路')]
    need(len(central) == 1 and central[0]['low28_id'] == 16707 and central[0]['first_child'] == 904706 and central[0]['child_count'] == 84 and central[0]['next_level'] == 4, 'Known stock street witness')
    return rows, cities, districts, streets, table


def match_native(city, district, street, cities, districts, streets):
    key = tuple(map(normalize_name, (city, district, street)))
    if not city:
        return 'missing_source_city', []
    if key[0] not in cities:
        return 'missing_native_city', []
    if not district:
        direct = streets.get((key[0], '', key[2]), []) if street else []
        return ('matched_direct_city_street' if len(direct) == 1 else 'missing_source_district'), direct
    if not street:
        return 'missing_source_street', []
    exact = streets.get(key, [])
    if exact:
        return ('matched_native_street' if len(exact) == 1 else 'ambiguous_native_street'), exact
    direct = streets.get((key[0], '', key[2]), [])
    if direct:
        return ('matched_direct_city_street_district_unverified' if len(direct) == 1 else 'ambiguous_native_street'), direct
    if (key[0], key[1]) not in districts:
        return 'missing_native_district', []
    return 'missing_native_street', []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=SOURCE)
    parser.add_argument('--xml', type=Path, help='Use an existing complete filtered XML instead of scanning PBF')
    args = parser.parse_args()
    need(not (OUT / 'ingestion-summary.json').exists(), 'One new preparation run')
    rows, cities, districts, streets, table = native_hierarchy()
    with gzip.open(OUT / 'native-hierarchy.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for row in rows:
            stream.write(dump(row) + '\n')
    native_counts = Counter(row['level'] for row in rows)
    signature_before = signature(args.source)
    counts, matches, houses, coordinates = Counter(), Counter(), Counter(), Counter()
    missing = defaultdict(Counter)
    # One full planning key ignores separate floor/unit/door/level, retains all
    # source IDs in the node ledger, and rejects divergent locations below.
    groups = {}
    matched_street_groups = Counter()
    matched_street_records = {}
    source_city_counts = Counter()
    source_district_counts = Counter()
    process = None
    argv = ['osmium', 'tags-filter', '--no-progress', '-R', '-f', 'osm', str(args.source), 'n/addr:*']
    stderr_path = OUT / 'osmium-filter.stderr.txt'
    with stderr_path.open('wb') as err:
        if args.xml:
            input_stream = gzip.open(args.xml, 'rb') if str(args.xml).endswith('.gz') else args.xml.open('rb')
        else:
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err)
            input_stream = process.stdout
        try:
            with gzip.open(OUT / 'source-address-nodes.jsonl.gz', 'wt', encoding='utf-8') as target:
                events = ET.iterparse(input_stream, events=['start', 'end'])
                _, root = next(events)
                for event, element in events:
                    if event != 'end' or element.tag not in ('node', 'way', 'relation'):
                        continue
                    tags = {x.get('k'): x.get('v') for x in element.findall('tag')}
                    if element.tag != 'node' or not any(k.startswith('addr:') for k in tags):
                        counts['non_address_or_nonnode_objects'] += 1
                        root.clear()
                        continue
                    counts['address_nodes'] += 1
                    city, district, street, house = [tags.get('addr:' + k, '') for k in ('city', 'district', 'street', 'housenumber')]
                    source_city_counts[city or '<absent>'] += 1
                    source_district_counts[(city, district)] += 1
                    complete = all((city, district, street, house))
                    counts['full_city_district_street_house_nodes' if complete else 'incomplete_structured_address_nodes'] += 1
                    for field in ('city', 'district', 'street', 'housenumber'):
                        if not tags.get('addr:' + field):
                            counts['missing_addr:' + field] += 1
                    match, candidates = match_native(city, district, street, cities, districts, streets)
                    matches[match] += 1
                    parsed = house_number(house)
                    houses[parsed['class']] += 1
                    lat, lon = element.get('lat'), element.get('lon')
                    valid = bool(lat and lon) and -90 <= float(lat) <= 90 and -180 <= float(lon) < 180
                    coordinates['direct_OSM_node' if valid else 'invalid_or_missing'] += 1
                    if match.startswith('missing_native_'):
                        missing[match][(city, district, street)] += 1
                    if any(tags.get(k) for k in ('addr:floor', 'addr:unit', 'addr:door', 'level')):
                        counts['separate_floor_unit_door_level_nodes'] += 1
                    if not complete or parsed['key'] is None or not valid:
                        group_id = None
                    else:
                        key = (normalize_name(city), normalize_name(district), normalize_name(street), parsed['key'])
                        if key not in groups:
                            group_id = len(groups) + 1
                            groups[key] = {'group_id': group_id, 'source_ids': [int(element.get('id'))],
                                           'first_coordinate': [lat, lon], 'different_coordinate_nodes': 0,
                                           'raw_address': [city, district, street, house],
                                           'native_match': match,
                                           'native_street_records': [row['record'] for row in candidates],
                                           'embedded_floor_unit': bool(parsed.get('embedded_floor_unit')),
                                           'separate_floor_unit_nodes': int(any(tags.get(k) for k in ('addr:floor', 'addr:unit', 'addr:door', 'level')))}
                            if match == 'matched_native_street':
                                matched_street_groups[candidates[0]['record']] += 1
                                matched_street_records[candidates[0]['record']] = candidates[0]
                        else:
                            group = groups[key]
                            group_id = group['group_id']
                            group['source_ids'].append(int(element.get('id')))
                            group['different_coordinate_nodes'] += int(group['first_coordinate'] != [lat, lon])
                            group['separate_floor_unit_nodes'] += int(any(tags.get(k) for k in ('addr:floor', 'addr:unit', 'addr:door', 'level')))
                            counts['repeated_full_address_nodes_ignoring_floor_unit'] += 1
                    target.write(dump({'source_type': 'node', 'source_id': int(element.get('id')),
                                       'source_version': element.get('version'), 'source_timestamp': element.get('timestamp'),
                                       'coordinate_strings': [lat, lon], 'coordinate_provenance': 'OSM node direct; no centroid/nearest-road/admin inference',
                                       'addr_tags': {k: v for k, v in tags.items() if k.startswith('addr:')},
                                       'entrance': tags.get('entrance'), 'level': tags.get('level'),
                                       'native_match': match, 'native_street_records': [row['record'] for row in candidates],
                                       'house': parsed, 'planning_group_id': group_id}) + '\n')
                    root.clear()
        finally:
            input_stream.close()
        if process:
            code = process.wait()
            need(code == 0, 'osmium filter failed, exit ' + str(code))
    need(signature_before == signature(args.source), 'Source PBF metadata unchanged')
    # Different-coordinate repeats remain quarantined: no silently chosen
    # entrance or averaged coordinate. Dedup does not imply official validity.
    dedup = Counter()
    with gzip.open(OUT / 'address-planning-groups.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for key, group in groups.items():
            group['normalized_planning_key'] = list(key)
            group['source_node_count'] = len(group['source_ids'])
            group['coordinate_selection_ready'] = group['different_coordinate_nodes'] == 0
            group['needs_coordinate_review'] = not group['coordinate_selection_ready']
            dedup['groups'] += 1
            dedup['multi_node_groups'] += int(len(group['source_ids']) > 1)
            dedup['different_coordinate_groups'] += int(group['different_coordinate_nodes'] > 0)
            dedup['same_coordinate_multi_node_groups'] += int(len(group['source_ids']) > 1 and group['different_coordinate_nodes'] == 0)
            dedup['groups_with_floor_unit_tags'] += int(group['separate_floor_unit_nodes'] > 0)
            dedup['groups_with_embedded_floor_unit'] += int(group['embedded_floor_unit'])
            stream.write(dump(group) + '\n')
    missing_rows = [{'classification': classification, 'raw_city': key[0], 'raw_district': key[1],
                     'raw_street': key[2], 'source_nodes': count}
                    for classification, values in missing.items() for key, count in values.items()]
    with gzip.open(OUT / 'missing-native-hierarchy.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for row in sorted(missing_rows, key=lambda row: (-row['source_nodes'], row['raw_city'], row['raw_district'], row['raw_street'])):
            stream.write(dump(row) + '\n')
    growth_rows = []
    for record, count in matched_street_groups.items():
        row = matched_street_records[record]
        level4 = row['next_level'] == 4
        growth_rows.append({'street_record': record, 'low28_id': row['low28_id'],
                            'raw_address': [row['city'], row['district'], row['street']],
                            'old_child_first': row['first_child'], 'old_child_count': row['child_count'],
                            'old_child_level': row['next_level'], 'unique_source_planning_groups': count,
                            'worst_case_appended_level4_records': row['child_count'] + count if level4 else None,
                            'all_groups_new_assumption': True,
                            'native_leaf_overlap_not_decoded': True,
                            'merged_12bit_count_fits': row['child_count'] + count <= 4095 if level4 else None})
    growth_rows.sort(key=lambda row: (-(row['worst_case_appended_level4_records'] or 0), row['street_record']))
    save(OUT / 'bounded-growth-by-matched-street.json', growth_rows)
    worst = sum(row['worst_case_appended_level4_records'] or 0 for row in growth_rows)
    capacity = {'stock_level4_count': LEVEL4_COUNT, 'first_child_22bit_max': CHILD_FIRST_MAX,
                'numerical_remaining_level4_ids': CHILD_FIRST_MAX - LEVEL4_COUNT,
                'clone_entire_old_level4_then_new_total': 2 * LEVEL4_COUNT,
                'clone_entire_old_level4_overflows_before_new_addresses_by': 2 * LEVEL4_COUNT - CHILD_FIRST_MAX,
                'matched_native_streets_with_parseable_complete_source_groups': len(growth_rows),
                'matched_streets_with_other_child_level': sum(row['old_child_level'] != 4 for row in growth_rows),
                'matched_level4_street_old_records_to_clone': sum(row['old_child_count'] for row in growth_rows if row['old_child_level'] == 4),
                'matched_level4_source_groups_assumed_all_new': sum(row['unique_source_planning_groups'] for row in growth_rows if row['old_child_level'] == 4),
                'selective_append_worst_case_records': worst,
                'selective_append_worst_case_final_count': LEVEL4_COUNT + worst,
                'selective_append_numerical_capacity_fits': LEVEL4_COUNT + worst <= CHILD_FIRST_MAX,
                'streets_exceeding_12bit_merged_child_count': [row for row in growth_rows if row['merged_12bit_count_fits'] is False],
                'caution': 'Arithmetic planning bound only. Source/native leaf overlap, node coordinate conflicts, flags/order, old incoming references, new labels, higher-level additions, carrier FAT/component capacity and native JAI rebuild remain unresolved.'}
    source_download = json.loads((ROOT / 'sources/maps/taiwan-download.json').read_text())
    summary = {'schema': 'taiwan-native-address-ingestion-preparation/v1', 'created_utc': datetime.now(timezone.utc).isoformat(),
               'scope': {'offline_source_preparation_only': True, 'all_tagged_address_nodes_one_source_pass': args.xml is None,
                         'no_native_or_device_execution': True, 'source_and_stock_unmodified': True,
                         'native_full_Taiwan_2026_update_complete': False},
               'source': {'path': str(args.source.relative_to(ROOT)), 'bytes': args.source.stat().st_size,
                          'snapshot_utc': '2026-10-01T20:22:06Z', 'sha256_inherited_not_rehashed': source_download['sha256'],
                          'license': 'OpenStreetMap contributors, ODbL; downloaded Geofabrik Taiwan extract',
                          'filter_command': argv, 'stderr_bytes': stderr_path.stat().st_size,
                          'source_node_address_tags_only': True, 'address_ways_relations_not_counted': True},
               'native': {'database': str(DB.relative_to(ROOT)), 'city_rows': native_counts[1], 'district_rows': native_counts[2],
                          'named_street_rows': native_counts[3], 'street_AP_slots': table['count'],
                          'street_AP_holes_without_JAI_name': table['count'] - native_counts[3],
                          'city_names': [row['raw_name'] for row in rows if row['level'] == 1],
                          'direct_city_street_rows': sum(row['level'] == 3 and row['district'] is None for row in rows),
                          'stock_street_table_bytes_newly_read': table['old_bytes'],
                          'stock_street_child_level_distribution': dict(Counter(row['next_level'] for row in rows if row['level'] == 3))},
               'offline_matching_policy': 'NFKC, strip surrounding whitespace, 臺→台 in host matching keys only; raw tags and native names preserved; no comparator, prefix or keyboard change',
               'house_policy': 'Conservative integer/之 subnumber; embedded explicit 號+floor/unit grouping retained; semicolon/comma/slash/ranges and ambiguous hyphen values quarantined; no automatic splitting or expanding',
               'coordinate_policy': 'Keep source node lat/lon strings, version and timestamp. No centroid, nearest-road, admin guessing or silent conflicting-location selection.',
               'counts': dict(counts), 'native_match_counts': dict(matches), 'house_number_classes': dict(houses),
               'coordinate_provenance_counts': dict(coordinates), 'floor_unit_dedup_counts': dict(dedup),
               'raw_source_city_counts': dict(source_city_counts.most_common()),
               'raw_source_city_district_pairs': [{'city': key[0], 'district': key[1], 'nodes': value} for key, value in source_district_counts.most_common()],
               'missing_native_hierarchy_unique_triples': len(missing_rows),
               'missing_native_hierarchy_top30': sorted(missing_rows, key=lambda row: -row['source_nodes'])[:30],
               'incremental_level4_capacity': capacity,
               'required_next_work': ['Decode existing level4 leaf labels for matched streets and compare actual house overlap before additions.',
                                      'Resolve full-key coordinate conflicts and malformed/multiple/subnumber addresses with source provenance.',
                                      'Resolve missing native streets/admin and direct-city street district association without guessing.',
                                      'Preserve contiguous child ranges, old records and incoming references; validate native order/flags and 12-/22-bit limits.',
                                      'Allocate labels and rebuild required native JAI family/FTS/segments together with AP/road support; test bounded candidates before a full deployment.',
                                      'Quantify OSM coverage gaps including address ways/relations, inferred admin and official untagged addresses; this node extract is not comprehensive official Taiwan addresses.']}
    save(OUT / 'ingestion-summary.json', summary)
    print(dump({'summary': str((OUT / 'ingestion-summary.json').relative_to(ROOT)),
                'source_nodes': counts['address_nodes'], 'full_nodes': counts['full_city_district_street_house_nodes'],
                'unique_planning_groups': dedup['groups'], 'match_counts': dict(matches), 'capacity': capacity}))


if __name__ == '__main__':
    main()
