#!/usr/bin/env python3
"""New bounded continuation: selected Taichung stock FTS -> family links.

Consumes the completed token proof without rerunning its city/query suite.
"""
import ast
import hashlib
import json
import mmap
from pathlib import Path
import sqlite3
import struct
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
TARGET = OUT / 'stock-taichung-FTS-family-links-v2.json'
CODEC = OUT / 'analyze_stock_fts_codec_v1.py'
PROOF = OUT / 'stock-fts-token-codec-proof-v1.json'
DB = ROOT / 'backups/20261002T154458Z/files/.System/SQLite/Prefecture/TWNJAI.db'


def need(value, label):
    if not value:
        raise ValueError(label)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    need(not TARGET.exists(), 'new output only')
    prior = json.loads(PROOF.read_text())
    need(prior['all_bounded_checks_passed'], 'prior completed file proof')
    need(sha(CODEC) == prior['inputs']['source_sha256'], 'frozen codec source')
    # Only the six pure host functions are extracted. No module/main, queries,
    # native image object, emulator, or prior suite is instantiated/executed.
    tree = ast.parse(CODEC.read_text())
    selected = {'xor_swap', 'schedule', 'transform', 'encode_bytes',
                'encode_text', 'decode_text'}
    functions = [node for node in tree.body
                 if isinstance(node, ast.FunctionDef) and node.name in selected]
    need(len(functions) == len(selected), 'six pure host codec functions')
    namespace = {'need': need}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(CODEC), 'exec'),
         namespace)
    main_path = ROOT / 'evidence/firmware-analysis/main_02bd.bin'
    with main_path.open('rb') as handle, mmap.mmap(handle.fileno(), 0,
                                                access=mmap.ACCESS_READ) as image:
        key = bytes(image[0xEA1258 - 0x50000:0xEA1258 - 0x50000 + 128])
    fragments = json.loads((OUT / 'stock-fts-token-codec-static-fragments-v1.json').read_text())
    need(hashlib.sha256(key).hexdigest() == fragments['fragments']['key128']['sha256'],
         'same frozen key128 fragment')
    scheduled = namespace['schedule'](key)
    decode = lambda text: namespace['decode_text'](text, scheduled)[0]
    connection = sqlite3.connect(DB.resolve().as_uri() + '?mode=ro&immutable=1', uri=True)
    observations = []
    selected_witnesses = [w for q in prior['bounded_FTS8_host_controls']
                          if q['input_label'] in ('民權路', '民和路')
                          for w in q['witnesses']]

    def record_info(record):
        rows = connection.execute(
            'SELECT id,index_record,record FROM japan_addr_info WHERE record=? LIMIT 2',
            (record,)).fetchall()
        need(len(rows) == 1, 'selected unique exact info.record')
        info_id, encoded, actual = rows[0]
        return {'info_id': info_id, 'record': actual, 'record_hex': hex(actual),
                'logical_record_u32_le': struct.pack('<I', actual).hex(),
                'level_high_nibble': actual >> 28,
                'low28_id': actual & 0x0FFFFFFF,
                'index_record': encoded, 'decoded_text': decode(encoded)}

    for witness in selected_witnesses:
        child = record_info(witness['source_record'])
        need(child['info_id'] == witness['info_id'] and
             child['decoded_text'] == witness['source_info_decoded_text'],
             'prior FTS witness exact child')
        current = child['record']
        links = []
        for depth in range(2):
            row = connection.execute(
                'SELECT parent_record,the_first_record FROM japan_addr_family '
                'WHERE the_first_record<=? ORDER BY the_first_record DESC LIMIT 1',
                (current,)).fetchone()
            need(row is not None, 'bounded selected predecessor family')
            parent, first = row
            next_row = connection.execute(
                'SELECT parent_record,the_first_record FROM japan_addr_family '
                'WHERE the_first_record>? ORDER BY the_first_record LIMIT 1',
                (first,)).fetchone()
            need(first <= current and
                 (next_row is None or current < next_row[1]), 'selected interval bounds')
            need((parent >> 28) < (current >> 28), 'selected family level decreases')
            decoded_parent = record_info(parent)
            first_info = connection.execute(
                'SELECT id FROM japan_addr_info WHERE record=? LIMIT 2', (first,)).fetchall()
            links.append({'child_record': current, 'child_record_hex': hex(current),
                          'parent_record': parent, 'parent_record_hex': hex(parent),
                          'parent_u32_le': struct.pack('<I', parent).hex(),
                          'the_first_record': first, 'the_first_record_hex': hex(first),
                          'first_u32_le': struct.pack('<I', first).hex(),
                          'next_family_first': next_row[1] if next_row else None,
                          'next_family_first_hex': hex(next_row[1]) if next_row else None,
                          'selected_interval_contains_child': True,
                          'first_has_exact_info_row': bool(first_info),
                          'first_info_rows_observed': len(first_info),
                          'decoded_parent': decoded_parent,
                          'interpretation': 'host predecessor interval using exact stock SQL; native family consumer unexecuted'})
            current = parent
            if parent >> 28 == 1:
                break
        need(current == 0x10000008, 'selected FTS8 family chain reaches stock city8')
        observations.append({'prior_FTS_record_info': witness['record_info'],
                             'prior_FTS_info_id': witness['info_id'],
                             'child': child, 'family_links': links,
                             'host_hierarchy': ' → '.join(
                                 [links[-1]['decoded_parent']['decoded_text']] +
                                 [x['decoded_parent']['decoded_text'] for x in links[:-1][::-1]] +
                                 [child['decoded_text']])})
    # A bounded district list uses the level2 parent's first-level family
    # interval, not arbitrary city-name assumptions or whole-database decoding.
    city_child_range = connection.execute(
        'SELECT the_first_record FROM japan_addr_family WHERE parent_record=? '
        'ORDER BY the_first_record LIMIT 2', (0x10000008,)).fetchall()
    need(len(city_child_range) == 1, 'selected city has one family range')
    lower = city_child_range[0][0]
    upper_row = connection.execute(
        'SELECT the_first_record FROM japan_addr_family WHERE the_first_record>? '
        'AND parent_record>>28=1 ORDER BY the_first_record LIMIT 1', (lower,)).fetchone()
    need(upper_row is not None, 'bounded city next level-one range')
    upper = upper_row[0]
    district_rows = connection.execute(
        'SELECT id,index_record,record FROM japan_addr_info '
        'WHERE record>=? AND record<? AND record>>28=2 ORDER BY record LIMIT 40',
        (lower, upper)).fetchall()
    districts = [{'info_id': row[0], 'record_hex': hex(row[2]),
                  'index_record': row[1], 'decoded_text': decode(row[1])}
                 for row in district_rows]
    connection.close()
    central = [row for row in observations if row['child']['decoded_text'] == '民權路'
               and row['family_links'][0]['decoded_parent']['decoded_text'] == '中區']
    need(len(central) == 1 and central[0]['child']['record'] == 0x30004143,
         'unique bounded stock central district Minquan witness')
    payload = {
        'schema': 'stock-taichung-FTS-family-links/v2',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'all_bounded_checks_passed': True,
        'source_sha256': sha(Path(__file__)),
        'inputs': {'completed_codec_proof': str(PROOF.relative_to(ROOT)),
                   'completed_codec_proof_sha256': sha(PROOF),
                   'codec_source': str(CODEC.relative_to(ROOT)),
                   'codec_source_sha256': sha(CODEC),
                   'database': str(DB.relative_to(ROOT))},
        'scope': {'FILE_ONLY': True, 'prior_city_FTS_suite_rerun': False,
                  'selected_original_FTS_witnesses': len(selected_witnesses),
                  'whole_DB_decoded': False, 'native_family_consumer_executed': False,
                  'Garmin_UI_query_reproduced': False, 'query_codepage_confirmed': False,
                  'address184_house_provider_decoded': False,
                  'NT_AP_payload_read': False, 'map_or_DB_writer': False},
        'record_key_contract': {
            'observed': 'u32 logical key = high-nibble level1/2/3 and low28 recordID',
            'byte_hex_note': 'u32_le hex is a logical scalar rendering, not an AP payload offset or a copy of SQLite on-disk varint encoding',
            'family_query': 'SELECT parent_record FROM japan_addr_family WHERE the_first_record <= ? ORDER BY the_first_record DESC LIMIT 0,1',
            'boundary_caution': 'candidate links use predecessor interval and explicit next boundary; whole-stock family gaps remain legal and unmodified',
            'FTS_link': 'record_info>>8 is info.id; selected record-level nibble comes from bits4..7; low4 flag semantics unverified',
        },
        'selected_city': {'record_hex': '0x10000008', 'info_id': 12987,
                          'decoded_text': '台中市', 'initial_char': 'U+53F0'},
        'district_interval': {'first_record_hex': hex(lower),
                              'next_city_first_record_hex': hex(upper),
                              'district_count': len(districts), 'witness_limit': 40,
                              'districts': districts},
        'selected_street_family_witnesses': observations,
        'central_district_Minquan_candidate': central[0],
        'address184_limit': {
            'JAI_name_levels': 'observed city/district/street; selected city8 FTS host control184號 had zero rows',
            'not_absence_proof': True,
            'source_OSM_city': '臺中市', 'source_OSM_street': '民權路',
            'source_OSM_housenumber': '184號', 'source_node': 8528998711,
            'stock_candidate': '台中市 → 中區 → 民權路; record0x30004143',
            'remaining': 'native AP/NT house-number provider and exact184 payload must be linked separately; token/family proof does not select or decode house184',
        },
        'normalization_limit': 'Selected decrypted DB bytes are strict UTF-8. Native query input conversion, complete normalization/keyboard encoding and caller reachability remain unverified; do not assume CP950 or treat 台/臺 difference alone as root cause.'}
    TARGET.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'proof': str(TARGET.relative_to(ROOT)), 'sha256': sha(TARGET),
                      'source_sha256': payload['source_sha256'],
                      'districts': len(districts), 'streets': len(observations),
                      'hierarchies': [row['host_hierarchy'] for row in observations],
                      'central_candidate': '0x30004143',
                      'native_query_caller_verified': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
