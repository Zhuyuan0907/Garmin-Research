#!/usr/bin/env python3
"""Find label184 within the newly authorized82 middle original AP records.

Exact native-tested bit order/sentinel model; host extraction only. Reuse
frozen boundary records and label bytes, read no old headers/body records.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-MinQuan184-witness-v1'
HELPER = ROOT / 'staging/navigation-AP-mapmetadata-v1/read_AP_mapmetadata.py'
HEADER = ROOT / 'staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json'
NATIVE = ROOT / 'staging/navigation-native-AP-level4-records-v1/original-level4-boundary-records-proof-v3.json'
OLD3 = ROOT / 'staging/navigation-AP-LBL-target-strings-v1/AP-target-label-windows-evidence.json'
OLD2 = ROOT / 'staging/navigation-AP-level4-label-windows-v1/level4-label-window-source-proof-v1.json'
EXPECTED = {
    HELPER: '31c9ec231ab862ab6477c5399b5a79139e7536284120a9f23629e16935cf8ffb',
    HEADER: 'dd14408a357d5587d8a4c4d72f4eb3f70b21296c1022bc95e35ad6afba606a7e',
    NATIVE: '10a9036cf74be7c26c4b724665c128914db0cef0d492bd8433d7147938f1a19a',
    OLD3: '2ed1ad21962955ade1f9cd2b84bfdc02604930f4d0dc7aacb34b72d2b508f414',
    OLD2: 'a3462f19b5cdd701ef09946e1778e3e32e6073a5495c910e6b036dcc097adc6c',
}
FIELD_ORDER = [('+08', 1), ('+1c', 19), ('+10', 19), ('+00', 22),
               ('+0c', 10), ('+04', 9), ('+14', 24), ('+18', 24)]
NEW_FIRST_ID, NEW_LAST_ID = 904707, 904788
NEW_MDR_START, NEW_RECORD_BYTES = 72315844, 1312
CONTENT_CAP = 10240


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def decode(raw):
    need(len(raw) == 16, 'Wrong128-bit record size')
    scalar, position, fields, extraction = int.from_bytes(raw, 'little'), 0, {}, []
    for name, width in FIELD_ORDER:
        value = (scalar >> position) & ((1 << width) - 1)
        sentinel = name in ('+1c', '+10') and value == (1 << width) - 1
        fields[name] = 0xffffffff if sentinel else value
        extraction.append({'field': name, 'start_bit': position, 'bits': width,
                           'raw_unsigned_value': value, 'reference_allones_to_FFFFFFFF': sentinel})
        position += width
    need(position == 128, 'Native frozen field widths do not cover128bits')
    return fields, extraction


def main():
    target = OUT / 'stock-MinQuan184-bounded-source-proof-v1.json'
    need(not target.exists(), 'Refusing to overwrite proof')
    for path, expected in EXPECTED.items():
        need(ref(path)['sha256'] == expected, 'Frozen dependency changed: ' + str(path))
    header = json.loads(HEADER.read_text())
    native = json.loads(NATIVE.read_text())
    old3, old2 = json.loads(OLD3.read_text()), json.loads(OLD2.read_text())
    need(native['all_cases_passed'], 'Original boundary native evidence incomplete')
    obs = header['public_LBL_header']['field_observations']
    start, size, shift = obs['u32_LE_at21'], obs['u32_LE_at25'], obs['u8_at29']
    need((start, size, shift, obs['u8_at30'], obs['u16_LE_at170']) == (6566, 3805432, 3, 10, 950),
         'Frozen LBL contract differs')
    boundary_controls = []
    for c in native['cases']:
        raw = bytes.fromhex(c['original_readonly_payload_hex'])
        fields, extraction = decode(raw)
        need(fields == c['native_fields'], 'Host decoder differs from frozen original boundary outputs')
        need([(v['output_offset'], v['width']) for v in c['conditional_read_sequence']] == FIELD_ORDER,
             'Original tested width/order differs')
        boundary_controls.append({'frozen_case': c['name'], 'source_lowID': c['explicit_low28_ID'],
            'host_fields_equal_frozen_native_fields': True, 'new_original_native_execution': False})
    need(native['cases'][0]['explicit_low28_ID'] + 1 == NEW_FIRST_ID and
         native['cases'][1]['explicit_low28_ID'] - 1 == NEW_LAST_ID and
         native['cases'][0]['MDRrelative_byte_offset'] + 16 == NEW_MDR_START and
         NEW_MDR_START + NEW_RECORD_BYTES == native['cases'][1]['MDRrelative_byte_offset'],
         'New bounded records do not exclusively cover the82 middle records')
    cache, cached_sources = {}, []
    for dependency, evidence in [(OLD3, old3), (OLD2, old2)]:
        for c in evidence['cases']:
            offset, raw = c['GMP_logical_offset'], bytes.fromhex(c['hex'])
            for n, byte in enumerate(raw):
                need(offset + n not in cache or cache[offset + n] == byte, 'Frozen overlapping bytes disagree')
                cache[offset + n] = byte
            cached_sources.append({'path': str(dependency.relative_to(ROOT)), 'GMP_offset': offset,
                                   'bytes': len(raw), 'sha256': sha(raw)})
    module = types.ModuleType('frozen_bounded_IMG_reader')
    module.__dict__['__file__'] = str(HELPER)
    exec(compile(HELPER.read_text(), str(HELPER), 'exec'), module.__dict__)
    image = module.BoundedIMG()
    new_label_reads, reused_windows = [], []
    content_read = NEW_RECORD_BYTES
    try:
        source_records, body = image.read('00004171.MDR', NEW_MDR_START, NEW_RECORD_BYTES,
                                         'new82_middle_level4_records')
        need(len(body) == (NEW_LAST_ID - NEW_FIRST_ID + 1) * 16, 'Bounded source length differs')
        all_rows = []
        # Frozen endpoints are included solely as cited inputs, never reread.
        for c in native['cases']:
            all_rows.append({'source': 'frozen_boundary', 'lowID': c['explicit_low28_ID'],
                'MDR_relative_offset': c['MDRrelative_byte_offset'],
                'record_hex': c['original_readonly_payload_hex'], 'host_fields': c['native_fields'],
                'host_decoded_new_record': False})
        for n, lowID in enumerate(range(NEW_FIRST_ID, NEW_LAST_ID + 1)):
            raw = body[n * 16:(n + 1) * 16]
            fields, _ = decode(raw)
            all_rows.append({'source': 'new82_middle_records', 'lowID': lowID,
                'MDR_relative_offset': NEW_MDR_START + n * 16, 'record_hex': raw.hex(),
                'record_sha256': sha(raw), 'host_fields': fields, 'host_decoded_new_record': True})
        all_rows.sort(key=lambda r: r['lowID'])
        need([r['lowID'] for r in all_rows] == list(range(904706, 904790)), 'Combined bounded recordIDs differ')
        unique_refs = sorted({r['host_fields']['+10'] for r in all_rows if r['host_fields']['+10'] != 0xffffffff})
        labels = {}
        for labelref in unique_refs:
            need(labelref >= 0 and labelref <= 0x3fffff, 'Unexpected positive reference size')
            offset = start + ((labelref & 0x3fffff) << shift)
            need(start <= offset <= offset + 64 <= start + size, 'Reference window outside original label bounds')
            missing, cursor = [], offset
            while cursor < offset + 64:
                if cursor in cache:
                    cursor += 1
                    continue
                first = cursor
                while cursor < offset + 64 and cursor not in cache:
                    cursor += 1
                missing.append((first, cursor - first))
            for first, length in missing:
                need(content_read + length <= CONTENT_CAP, 'New source content would exceed10KiB cap')
                source, raw = image.read('I053061A.GMP', first, length, 'missing_reference_' + str(labelref) + '_window_bytes')
                new_label_reads.append({**source, 'requested_reference': labelref})
                for n, byte in enumerate(raw):
                    need(first + n not in cache, 'Attempted reread of already sourced label byte')
                    cache[first + n] = byte
                content_read += length
            raw = bytes(cache[p] for p in range(offset, offset + 64))
            terminator = raw.find(b'\0')
            need(terminator >= 0, 'NUL absent within bounded64-byte reference window')
            text = raw[:terminator].decode('cp950', errors='strict')
            labels[labelref] = {'reference': labelref, 'GMP_logical_offset': offset, 'window_upper_bound': 64,
                'window_hex': raw.hex(), 'window_sha256': sha(raw), 'first_NUL_relative_offset': terminator,
                'first_NUL_absolute_GMP_offset': offset + terminator, 'first_NUL_bytes_hex': raw[:terminator].hex(),
                'host_strict_CP950_text': text, 'new_bytes_read_for_this_window': sum(n for _, n in missing),
                'reused_cached_bytes_for_this_window': 64 - sum(n for _, n in missing),
                'host_display_not_native_DBCS_result': True}
            if not missing:
                reused_windows.append(labelref)
        for r in all_rows:
            fields = r['host_fields']
            label = labels.get(fields['+10'])
            r.update({'primary_reference': fields['+10'], 'alternate_reference': fields['+1c'],
                'label': None if label is None else label['host_strict_CP950_text'],
                'mapordinal': fields['+08'], 'raw_flags_field': fields['+04'],
                'child_level_low3': fields['+04'] & 7, 'first_child_ID': fields['+00'], 'child_count': fields['+0c'],
                'last_child_inclusive_if_nonempty': fields['+00'] + fields['+0c'] - 1 if fields['+0c'] else None,
                'raw24_fields_out14_out18': [fields['+14'], fields['+18']],
                'exact_184_label_match': label is not None and label['host_strict_CP950_text'] == '184號',
                'contains_184_digits': label is not None and '184' in label['host_strict_CP950_text']})
        strict = [r for r in all_rows if r['exact_184_label_match']]
        related = [r for r in all_rows if r['contains_184_digits']]
        need(content_read <= CONTENT_CAP, 'Actual content cap exceeded')
        image.close()
        proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
            'scope': 'Only82 previously unread records within stock Minquan street level4 range, plus bounded missing primary-label bytes.',
            'dependencies': [ref(path) for path in EXPECTED], 'source_map': {**header['source_map'], 'stat_unchanged': True},
            'source_record_range': {**source_records, 'first_lowID': NEW_FIRST_ID, 'last_inclusive_lowID': NEW_LAST_ID,
                'new_records': 82, 'record_stride_bytes': 16, 'old_first_last_reread': False},
            'frozen_native_bitfield_contract': {'LSB_first_within_little_endian_128bit_scalar': True,
                'ordered_fields': [{'output_offset': field, 'width': width} for field, width in FIELD_ORDER],
                'sentinel': 'For+10/+1C only, all-width-bits1 becomes0xFFFFFFFF',
                'matches_frozen_boundary_native_values': boundary_controls,
                'new_original_native_execution_for82records': False},
            'reused_frozen_LBL_contract': {'labelStart': start, 'labelSize': size, 'shift': shift, 'codepage': 950,
                'positive_reference_formula': 'labelStart + ((reference & 0x3FFFFF) << shift)', 'header_reread': False},
            'reused_frozen_label_windows': cached_sources, 'entire_window_cached_references': reused_windows,
            'new_label_source_fragments': new_label_reads, 'unique_primary_reference_labels': list(labels.values()),
            'all84_rows_with_frozen_boundaries': all_rows, 'strict_184_matches': strict, 'related184_string_matches': related,
            'strict_184_match_count': len(strict), 'related184_string_match_count': len(related),
            'actual_map_read_log': image.log, 'new_MDR_record_bytes_read': NEW_RECORD_BYTES,
            'new_unique_label_payload_bytes_read': content_read - NEW_RECORD_BYTES,
            'actual_new_content_bytes_read': content_read, 'maximum_authorized_content_bytes': CONTENT_CAP,
            'total_map_bytes_read_including_FAT': sum(r['bytes'] for r in image.log),
            'old5_reference_payload_bytes_reread': False, 'old3_or_header_or_boundary_reads_rerun': False,
            'alternate_label_references_read': False, 'level6_or_other_child_tables_read': False,
            'whole_map_digest_repeated': False, 'whole_AP_or_NT_decoded': False,
            'stock_map_or_DB_modified': False, 'unlock_or_decryption_performed': False, 'device_IO': False,
            'full_native_query_or_route_executed': False, 'physical_search_or_routing_verified_here': False,
            'all_level4_rows_named_houses': False, 'strict_match_equated_with_OSM_source_node': False,
            'all_bounded_source_and_host_decode_checks_passed': True}
        with target.open('x') as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': sha(target.read_bytes()), 'new_record_bytes': NEW_RECORD_BYTES,
            'new_label_bytes': content_read - NEW_RECORD_BYTES, 'actual_new_content_bytes_read': content_read,
            'strict_184_matches': strict, 'related184_string_match_count': len(related),
            'unique_label_count': len(labels), 'all_bounded_source_and_host_decode_checks_passed': True}, ensure_ascii=False))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
