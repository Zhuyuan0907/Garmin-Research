#!/usr/bin/env python3
"""Six exact immutable-DB street/family witnesses and AP numerical bounds.

No codec suite rerun, packed-body reads, native execution, DB writes or USB I/O.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import struct

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-JAI-AP-link-samples-v1'
DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'
CODEC = ROOT / 'staging/navigation-stock-fts-codec-v1/stock-fts-token-codec-proof-v1.json'
FAMILIES = ROOT / 'staging/navigation-stock-fts-codec-v1/stock-taichung-FTS-family-links-v2.json'
SCHEMA = ROOT / 'staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json'
DIRECTORY = ROOT / 'staging/navigation-AP-provider-records-v1/AP-provider-records-evidence.json'
PINNED = {CODEC: '09ca38fcbdc88e4bc4bb87e226945d4e2567ace057b0cfd358d93f0f134c5ca9',
          FAMILIES: '9525c2cb5d1a3e991f0c8cdcb25468bae4c6848eec9262d36b4ca13980765c1c',
          SCHEMA: '8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d',
          DIRECTORY: '32aae3c125bc21ae71d81997d4b7d481cd08686e4b42683b51501adc8b7121dd'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def reference(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def stat_signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def key_projection(value):
    return {'u32': value, 'hex': hex(value), 'u32_LE_hex': struct.pack('<I', value).hex(),
            'level_high_nibble': value >> 28, 'low28_ID': value & 0x0fffffff}


def main():
    target = OUT / 'JAI-AP-link-samples-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    deps = [reference(path) for path in PINNED]
    need(all(item['sha256'] == PINNED[ROOT / item['path']] for item in deps), 'Sealed dependency changed')
    families = json.loads(FAMILIES.read_text())
    schema = json.loads(SCHEMA.read_text())
    directory = json.loads(DIRECTORY.read_text())
    expected = [w for w in families['selected_street_family_witnesses'] if w['child']['decoded_text'] == '民權路']
    need(len(expected) == 6, 'Expected six frozen Minquan street witnesses')
    gaps = set(schema['databases']['jai']['third_level_missing_low28'])
    descriptors = []
    for row in directory['provider_directory']['records']:
        w = row['u32_LE']
        count, remainder = divmod(w[1] * 8, w[2])
        descriptors.append({'ordinal': row['ordinal_zero_based'], 'raw_words_u32_LE': w,
            'start_value': w[0], 'size_value': w[1], 'scalar_value': w[2],
            'floor_size8_over_scalar': count, 'residual_bits': remainder,
            'word3_6bit_projections': {str(shift): (w[3] >> shift) & 63 for shift in (18,24,12,6,0)},
            'word3_bit30': (w[3] >> 30) & 1, 'word3_bit31': (w[3] >> 31) & 1,
            'word4_6bit_projections': {str(shift): (w[4] >> shift) & 63 for shift in (0,11,17)},
            'native_consumer_executed_by_this_script': False})
    level_counts = []
    for level in (1,2,3):
        original = next(r for r in schema['databases']['jai']['record_levels'] if r['high_nibble'] == level)
        desc = descriptors[level - 1]
        maxid = original['last_low28']
        need(desc['floor_size8_over_scalar'] == maxid, 'Maximum logical-ID / capacity mismatch')
        level_counts.append({'level': level, 'candidate_directory_ordinal': level - 1,
            'JAI_info_rows': original['count'], 'JAI_first_low28': original['first_low28'],
            'JAI_last_low28': maxid, 'AP_numerical_capacity': desc['floor_size8_over_scalar'],
            'capacity_equals_max_low28_ID': True, 'native_level_to_descriptor_selector_verified': False,
            'max_ID_as_zero_based_bit_end': (maxid + 1) * desc['scalar_value'],
            'max_ID_minus_one_as_bit_end': maxid * desc['scalar_value'],
            'span_bit_size': desc['size_value'] * 8,
            'zero_based_direct_ID_hypothesis_fits_max_ID': (maxid + 1) * desc['scalar_value'] <= desc['size_value'] * 8,
            'one_based_ID_minus_one_hypothesis_fits_max_ID': maxid * desc['scalar_value'] <= desc['size_value'] * 8})
    before = stat_signature(DB)
    con = sqlite3.connect(DB.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA query_only=ON')
    query_log = []
    def select(sql, args):
        query_log.append({'sql': sql, 'parameters': list(args)})
        cur = con.execute(sql, args)
        keys = [item[0] for item in cur.description]
        return [dict(zip(keys, row)) for row in cur]
    def info(record):
        result = select('SELECT id,index_record,record FROM japan_addr_info WHERE record=? LIMIT 2', (record,))
        need(len(result) == 1, 'Exact info logical record missing or ambiguous')
        row = result[0]
        return {**row, 'key': key_projection(row['record'])}
    def numerical_index(key, info_id):
        level, low_id = key >> 28, key & 0x0fffffff
        desc = descriptors[level - 1]
        relative_bit = (low_id - 1) * desc['scalar_value']
        relative_byte, bit_in_byte = divmod(relative_bit, 8)
        covered = (bit_in_byte + desc['scalar_value'] + 7) // 8
        return {'assumption': 'Unverified level→ordinal(level-1), 1-based low28 ID→record_index(ID-1).',
            'candidate_directory_ordinal': level - 1, 'candidate_zero_based_index': low_id - 1,
            'candidate_bit_offset_in_span': relative_bit, 'candidate_bit_in_start_byte': bit_in_byte,
            'candidate_MDR_byte_offset': desc['start_value'] + relative_byte,
            'candidate_cover_bytes': covered,
            'ID_minus_one_candidate_fits_span': relative_bit + desc['scalar_value'] <= desc['size_value'] * 8,
            'alternative_info_PK_as_zero_based_index_fits_span': (info_id + 1) * desc['scalar_value'] <= desc['size_value'] * 8,
            'alternative_info_PK_minus_one_fits_span': info_id * desc['scalar_value'] <= desc['size_value'] * 8,
            'candidate_body_bytes_read': False, 'native_getter_or_selector_verified': False}
    samples = []
    try:
        for frozen in expected:
            child = info(frozen['child']['record'])
            need(child['id'] == frozen['child']['info_id'] and child['index_record'] == frozen['child']['index_record'],
                 'Exact child differs from frozen decoded witness')
            fts_value = frozen['prior_FTS_record_info']
            fts = select('SELECT rowid,index_record,record_info FROM japan_addr_index_8 WHERE record_info=? AND index_record=? LIMIT 16',
                         (fts_value, child['index_record']))
            need(len(fts) == 1 and (fts_value >> 8) == child['id'], 'Selected frozen full-name FTS row differs')
            sample = {'name_from_frozen_codec': '民權路', 'host_hierarchy_from_frozen_proof': frozen['host_hierarchy'],
                'child_raw_info': child,
                'FTS_exact_full_name_rows': fts,
                'FTS_record_info_projection': {'value': fts_value, 'hex': hex(fts_value),
                    'info_ID_from_shift8': fts_value >> 8, 'low_byte': fts_value & 255,
                    'level_bits4to7': (fts_value >> 4) & 15, 'low4_flags': fts_value & 15,
                    'low4_flag_semantics_confirmed': False},
                'candidate_AP_index': numerical_index(child['record'], child['id']), 'family_links': []}
            current = child
            for frozen_link in frozen['family_links']:
                family = select('SELECT parent_record,the_first_record FROM japan_addr_family WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 1', (current['record'],))
                need(len(family) == 1, 'Preceding family missing')
                entry = family[0]
                following = select('SELECT parent_record,the_first_record FROM japan_addr_family WHERE the_first_record>? ORDER BY the_first_record LIMIT 1', (entry['the_first_record'],))
                need(len(following) == 1, 'Expected next family boundary')
                parent = info(entry['parent_record'])
                upper = following[0]['the_first_record']
                need(entry['parent_record'] == frozen_link['parent_record'] and
                     entry['the_first_record'] == frozen_link['the_first_record'] and
                     upper == frozen_link['next_family_first'] and
                     entry['the_first_record'] <= current['record'] < upper, 'Frozen family interval differs')
                first_info = select('SELECT id,index_record,record FROM japan_addr_info WHERE record=? LIMIT 2', (entry['the_first_record'],))
                link = {'child_key': current['key'], 'raw_family_row': entry,
                    'parent_raw_info': parent,
                    'parent_decoded_name_from_frozen_proof': frozen_link['decoded_parent']['decoded_text'],
                    'next_family_row': following[0], 'next_boundary_key': key_projection(upper),
                    'first_child_key': key_projection(entry['the_first_record']),
                    'half_open_interval_contains_child': True, 'first_info_rows': first_info,
                    'third_level_known_gap_IDs_in_interval': sorted(value for value in gaps if
                        current['key']['level_high_nibble'] == 3 and
                        (entry['the_first_record'] & 0x0fffffff) <= value < (upper & 0x0fffffff)),
                    'candidate_parent_AP_index': numerical_index(parent['record'], parent['id']),
                    'native_family_consumer_verified': False}
                sample['family_links'].append(link)
                current = parent
            need(current['record'] == 0x10000008, 'Selected street did not link to expected city')
            samples.append(sample)
        con.close()
        need(stat_signature(DB) == before, 'Stock DB metadata changed')
        central = next(s for s in samples if s['child_raw_info']['record'] == 0x30004143)
        evidence = {'created_utc': datetime.now(timezone.utc).isoformat(),
            'source_sha256': reference(Path(__file__))['sha256'], 'dependencies': deps,
            'scope': 'Six Minquan exact DB/FTS rows and predecessor family intervals; frozen AP directory numerical bounds only.',
            'DB_path': str(DB.relative_to(ROOT)), 'DB_readonly_immutable': True,
            'bounded_SQL_statement_count': len(query_log), 'queries': query_log,
            'AP_directory_numerical_projections': descriptors,
            'JAI_level_capacity_comparison': level_counts,
            'samples': samples, 'central_district_selected_sample': central,
            'confirmed_by_this_probe': [
                'Exact stock rows and FTS integer/flag values match previously decoded six name witnesses.',
                'Exact predecessor/next family rows match frozen host relationships and include the target record.',
                'AP first three numerical capacities equal JAI first/second/third max low28 IDs.',
                'Under the candidate level-to-span mapping, direct zero-based lowID fails at each maximum; lowID-1 fits.',
                'Using SQLite info PK as a uniform packed index fails city/district capacities; it is not the same number space.'
            ],
            'limits': {'native_level_to_span_selector_verified': False,
                'native_one_based_packed_index_verified': False, 'packed_record_contents_read': False,
                'AP_body_or_original_map_read': False, 'codec_or_prior22FTS_suite_rerun': False,
                'packed_field_or_position_semantics_named': False, 'native_house184_record_identified': False,
                'native_family_consumer_executed': False, 'DB_writer': False, 'device_IO': False,
                'canonical_or_report_modified': False, 'physical_search_or_routing_verified': False},
            'DB_stat_unchanged': True, 'all_bounded_DB_and_numerical_checks_passed': True}
        with target.open('x') as out:
            json.dump(evidence, out, ensure_ascii=False, indent=2)
            out.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'SQL_statements': len(query_log),
            'AP_map_bytes_read': 0, 'all_bounded_DB_and_numerical_checks_passed': True,
            'central_candidate_index': central['candidate_AP_index']}))
    finally:
        con.close()


if __name__ == '__main__':
    main()
