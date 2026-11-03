#!/usr/bin/env python3
"""Bounded saved-capture source gate, ordinary files only; zero IMG/native I/O."""
import hashlib
import json
import re
import zlib
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-v2-one-family-lane-delta-plan-v1'
CAP = ROOT / 'staging/navigation-beitun-source-capture-corrected-v1/missing-source-groups.jsonl.gz'
STOCK = ROOT / 'staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json'


def stat(p):
    s = p.stat()
    return {'device': s.st_dev, 'inode': s.st_ino, 'bytes': s.st_size,
            'mtime_ns': s.st_mtime_ns, 'ctime_ns': s.st_ctime_ns,
            'mode_octal': oct(s.st_mode & 0o777)}


def write(name, d):
    (OUT / name).write_text(json.dumps(d, ensure_ascii=False, indent=2) + '\n')


def find_prepared(obj):
    matches = []
    if isinstance(obj, dict):
        if obj.get('group_id') == 172188 and 'raw_address' in obj and 'source_ids' in obj:
            matches.append(obj)
        for value in obj.values():
            matches.extend(find_prepared(value))
    elif isinstance(obj, list):
        for value in obj:
            matches.extend(find_prepared(value))
    return matches


def main():
    cb, sb = stat(CAP), stat(STOCK)
    compressed = CAP.read_bytes()
    assert len(compressed) == 18867
    assert hashlib.sha256(compressed).hexdigest() == '937cfd4cd38ee374e99bdbb08d0a2546b6d9a40e6ea71bdd47408d309dfdc221'
    z = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = z.decompress(compressed, 512 * 1024)
    assert z.eof and not z.unconsumed_tail and not z.unused_data
    assert len(plain) == 383921
    assert hashlib.sha256(plain).hexdigest() == '784bca17b70321b36a084b7a987849207a66fe34733b7b9ae28fcfb9ad24d031'
    # zlib reaches the stored gzip footer and validates its CRC32/ISIZE.
    records = [json.loads(line) for line in plain.splitlines()]
    assert len(records) == 102
    saved = []
    for line, rec in enumerate(records, 1):
        found = find_prepared(rec)
        if found:
            # More than one copied occurrence must still represent the exact same group.
            assert all(x == found[0] for x in found)
            saved.append((line, rec, found[0]))
    assert len(saved) == 1
    line, rec, prepared = saved[0]
    assert line == 87
    assert prepared['raw_address'][2:] == ['昌平路二段50之6巷2弄', '39號']
    assert prepared['raw_address'][0] in ['台中市', '臺中市']
    assert prepared['raw_address'][1] == '北屯區'
    data = STOCK.read_bytes()
    assert hashlib.sha256(data).hexdigest() == '929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6'
    snapshot = json.loads(data)
    names = {x['label']: x for x in snapshot['old_info_rows']}
    assert len(names) == 441
    shape = re.fullmatch(r'(?P<parent>昌平路二段)(?P<lane>50之6巷)(?P<alley>2弄)', prepared['raw_address'][2])
    assert shape and shape['parent'] in names
    parent = names[shape['parent']]
    ids = prepared['source_ids']
    IDs_ready = (isinstance(ids, list) and len(ids) > 0 and len(set(ids)) == len(ids)
                 and all(type(x) is int and x > 0 for x in ids)
                 and prepared['source_node_count'] == len(ids))
    coords_ready = (prepared['coordinate_selection_ready'] is True
                    and prepared['needs_coordinate_review'] is False
                    and prepared['different_coordinate_nodes'] == 0)
    no_floor = (prepared['embedded_floor_unit'] is False
                and prepared['separate_floor_unit_nodes'] == 0)
    gates = {'complete_source_ID_metadata': IDs_ready,
             'coordinate_selection_ready_no_conflict': coords_ready,
             'floor_unit_absent': no_floor,
             'exact_stock_parent_literal': True}
    holds = [k for k, v in gates.items() if not v]
    original_point = prepared['first_coordinate']
    assert len(original_point) == 2
    native24 = [int((Decimal(x) * Decimal(2 ** 24) / Decimal(360)).quantize(Decimal(1), rounding=ROUND_HALF_UP)) for x in original_point]
    write('selected-original-source.json', {'capture_line': line, 'complete_saved_record': rec,
        'complete_original_prepared_group': prepared, 'original_raw_address': prepared['raw_address'],
        'source_node_IDs': ids, 'sourcepoint_decimal_strings': original_point,
        'native24': native24, 'native24_rule': 'Decimal nearest ROUND_HALF_UP; stock rounding unknown',
        'raw_parent': shape['parent'], 'raw_lane_suffix': shape['lane'], 'raw_alley_suffix': shape['alley'],
        'original_house_literal': prepared['raw_address'][3],
        'source_group_not_renamed_or_normalized': True,
        'full_per_node_tags_not_available_from_prepared_capture': True})
    write('stock-parent-exact-match.json', {'parent_literal': shape['parent'], 'original_stock_entry': parent,
        'snapshot_city': snapshot['city'], 'snapshot_district': snapshot['district'],
        'street_original_literal_reconstruction': shape['parent'] + shape['lane'] + shape['alley'],
        'stock_snapshot_reference_only_not_actual_IMG_parent_read': True,
        'alias_or_nearest_matching_used': False})
    ca, sa = stat(CAP), stat(STOCK)
    assert cb == ca and sb == sa
    pins = [{'path': str(CAP.relative_to(ROOT)), 'compressed_bytes_read': len(compressed),
        'SHA256': hashlib.sha256(compressed).hexdigest(), 'decompressed_bytes': len(plain),
        'decompressed_SHA256': hashlib.sha256(plain).hexdigest(), 'saved_capture_rows': len(records),
        'gzip_footer_CRC32_ISIZE_verified': True, 'stat_before': cb, 'stat_after': ca},
        {'path': str(STOCK.relative_to(ROOT)), 'bytes_read': len(data), 'SHA256': hashlib.sha256(data).hexdigest(),
         'stat_before': sb, 'stat_after': sa}]
    write('source-pins.json', {'inputs': pins})
    proof = {'schema': 'one_exact_lane_source_gate_before_v2_family_delta/v1',
        'assigned_source_metadata_check_completed': True, 'source_group': 172188, 'capture_line': 87,
        'original_full_street': prepared['raw_address'][2], 'original_raw_house': prepared['raw_address'][3],
        'sourcepoint': original_point, 'native24': native24, 'source_node_IDs': ids,
        'original_complete_metadata': prepared, 'exact_stock_parent': parent,
        'gates': gates, 'failed_gate_holds': holds, 'status': 'held_before_IMG_family_planning' if holds else 'source_ready_pending_exact_actual_v3_tree',
        'source_ready_for_requested_family_plan': not holds,
        'actual_v2_v3_IMG_reads_attempted': False,
        'actual_v3_same_coordinates_house_found': None,
        'exact_street_ID_parent_child_ranges_from_actual_IMG': None,
        'new_counts_remap_payload_bitwidth_bounds_or_IMG_capacity_plan': None,
        'reason_for_not_advancing': 'User instruction requires held/seal when source floor, coordinates or IDs are not ready.' if holds else None,
        'read_counters': {'saved_capture_compressed_bytes': len(compressed), 'saved_capture_decompressed_bytes': len(plain),
            'stock_snapshot_bytes': len(data), 'original_137MB_source_gzip_bytes': 0, 'PBF_or_fullnodeledger_bytes': 0,
            'actual_IMG_bytes': 0, 'actual_IMG_budget': 2 * 1024 * 1024,
            'selected_L4_records_traversed': 0, 'selected_L4_limit': 4095,
            'native_CPU_instructions': 0, 'audio_or_device_IO': 0},
        'new_IMG_package_or_installation_created': False, 'native_lane_format_absent_claimed': False,
        'flags': {k: False for k in ['source_released', 'formal_address_accepted', 'family_delta_plan_completed',
            'v3_road_disappearance_fixed', 'installable', 'device_verified', 'fullTaiwan_complete',
            'App_complete', 'native_backend_owner', 'STOP_DONE', 'direct_phone_A2DP_complete', 'speaker_complete']}}
    write('proof.json', proof)
    print(json.dumps({'status': proof['status'], 'group_id': 172188, 'capture_line': line,
        'original_complete_metadata': prepared, 'exact_stock_parent': parent,
        'failed_gates': holds, 'actual_IMG_bytes': 0, 'saved_capture_compressed_bytes': len(compressed),
        'native_CPU_instructions': 0}, ensure_ascii=False))


if __name__ == '__main__':
    main()
