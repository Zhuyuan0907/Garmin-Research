#!/usr/bin/env python3
"""Finite arithmetic plan from sealed JSON metadata; never opens an IMG or DB."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
INPUTS = {
    'coverage': ('staging/navigation-MinQuan-source-coverage-v1/coverage-summary-v1.json', '4474a5689efb9861f0fbb24e4717e4836bbeac77650f7efb5a1fc23cf625b97b'),
    'coverage_seal': ('staging/navigation-MinQuan-source-coverage-v1/source-file-seal.json', '63ddf0100ba8f14ea632d3e19f4f517514a2f98887ab5e7da4795fd2e9c2b9b0'),
    'old84': ('staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json', '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774'),
    'old84_seal': ('staging/navigation-AP-MinQuan184-witness-v1/source-file-seal.json', 'e8babb717bf395b66f6955147aa79fb9d6b6a20d863fd562b022526ef6fa1e36'),
    'directory_source': ('staging/navigation-AP-provider-records-v1/AP-provider-records-evidence.json', '32aae3c125bc21ae71d81997d4b7d481cd08686e4b42683b51501adc8b7121dd'),
    'directory_native': ('staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json', '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60'),
    'street_native': ('staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json', 'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53'),
    'mapmetadata': ('staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json', '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753'),
    'LBL_header': ('staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json', 'dd14408a357d5587d8a4c4d72f4eb3f70b21296c1022bc95e35ad6afba606a7e'),
    'schema': ('staging/navigation-stock-address-schema-v1/stock-address-schema-evidence.json', '8111d750106255d91becf7254e8a8ead8c4ad1c2562cf83df3ddd64cafeef21d'),
    'JAI_family': ('staging/navigation-stock-fts-codec-v1/stock-taichung-FTS-family-links-v2.json', '9525c2cb5d1a3e991f0c8cdcb25468bae4c6848eec9262d36b4ca13980765c1c'),
}
CHECKS: list[dict] = []


def check(name: str, condition: bool, detail=None):
    CHECKS.append({'check': name, 'passed': bool(condition), 'detail': detail})
    if not condition:
        raise AssertionError(name)


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def signature(path: Path):
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def load_inputs():
    data, dependencies, signatures = {}, [], {}
    for key, (name, expected) in INPUTS.items():
        path = ROOT / name
        check('bounded_JSON_input_' + key, path.suffix == '.json' and path.stat().st_size < 2_000_000)
        signatures[name] = signature(path)
        raw = path.read_bytes()
        actual = digest(raw)
        check('sealed_input_hash_' + key, actual == expected)
        data[key] = json.loads(raw)
        dependencies.append({'path': name, 'bytes': len(raw), 'sha256': actual,
                             'fresh_check_scope': 'this small frozen JSON only; no original IMG/DB or old suite rehash'})
    return data, dependencies, signatures


def raw_point(lat: str, lon: str):
    factor = Decimal(1 << 24) / Decimal(360)
    result = [int((Decimal(v) * factor).to_integral_value(rounding=ROUND_HALF_UP)) for v in (lat, lon)]
    check('prospective_24bit_point_bounds_' + lat + '_' + lon,
          all(-(1 << 23) <= n < (1 << 23) for n in result))
    return [n & ((1 << 24) - 1) for n in result]


def prepare():
    proof_path = OUT / 'Minquan-append-only-record-plan-v1.json'
    note_path = OUT / 'APPEND-PLAN-v1.txt'
    check('new_outputs_absent', not proof_path.exists() and not note_path.exists())
    d, dependencies, signatures = load_inputs()
    rows = d['old84']['all84_rows_with_frozen_boundaries']
    check('all84_contiguous_original_IDs', [r['lowID'] for r in rows] == list(range(904706, 904790)))
    old84_raw = b''.join(bytes.fromhex(r['record_hex']) for r in rows)
    check('old84_exact_fixed_records', len(old84_raw) == 84 * 16 and all(len(bytes.fromhex(r['record_hex'])) == 16 for r in rows))
    check('old84_mapordinal_preserved', {r['mapordinal'] for r in rows} == {1})
    check('old84_source_checks_passed', d['old84']['all_bounded_source_and_host_decode_checks_passed'])
    candidates = sorted(d['coverage']['nine_simple_house_source_candidates_complete_tags'],
                        key=lambda r: int(re.fullmatch(r'(\d+)號', r['raw_housenumber']).group(1)))
    names = [r['raw_housenumber'] for r in candidates]
    check('nine_exact_candidate_names', names == ['6號', '8號', '138號', '140號', '142號', '144號', '146號', '148號', '150號'])
    check('nine_independent_explicit_source_nodes', len({r['id'] for r in candidates}) == 9 and all(
        r['type'] == 'node' and r['tags'].get('addr:city') == '臺中市' and r['tags'].get('addr:district') == '中區'
        and r['tags'].get('addr:street') == '民權路' and not r['additional_floor_or_unit_tags']
        and r['primary_label_status'] == 'not_observed_in_old84' for r in candidates))
    check('coverage_summary_projection_passed', d['coverage']['all_summary_projection_checks_passed'])
    street = next(c for c in d['street_native']['cases'] if c['explicit_level'] == 3 and c['explicit_low28_ID'] == 16707)
    sf = street['native_unnamed_fields']
    check('street_actual_84_range', [sf['+00'], sf['+0c'], sf['+04'], sf['+08'], sf['+10']] == [904706, 84, 4, 1, 206])
    native = d['directory_native']['cases'][0]['decoded_records']
    source = d['directory_source']['provider_directory']['records']
    check('six_source_directory_rows', len(native) == len(source) == 6)
    tables = []
    for i, (n, s) in enumerate(zip(native, source), 1):
        raw = s['u32_LE']
        width = n['six_bit_values_at_record_offsets_10_to_17']
        check('directory_source_native_agree_level_' + str(i), raw[:3] == [n['span_start'], n['span_bytes'], n['third_scalar']]
              and raw[3:] == [int(n['original_raw_words'][3], 16), n['original_raw_words'][4]])
        check('native_span_count_level_' + str(i), raw[1] * 8 // raw[2] == n['native_floor_spanbits_div_scalar'])
        tables.append({'level': i, 'old_start': raw[0], 'old_bytes': raw[1], 'record_bits': raw[2],
                       'count': n['native_floor_spanbits_div_scalar'], 'widths': width,
                       'condition_flags': n['flags_at_record_offsets_18_19'], 'raw_words': raw,
                       'residual_bits': n['span_bits_division_remainder']})
    l4 = tables[3]
    check('level4_baseline', [l4['count'], l4['old_start'], l4['old_bytes'], l4['record_bits']] == [2133948, 57840548, 34143168, 128])
    check('actual_street_count_width12_level4_descendant_width10', tables[2]['widths'][5] == 12 and l4['widths'][5] == 10)
    for previous, following in zip(reversed(tables), list(reversed(tables))[1:]):
        check('contiguous_levels_' + str(previous['level']) + '_' + str(following['level']),
              previous['old_start'] + previous['old_bytes'] == following['old_start'])
    descriptor = d['directory_source']['provider_header_descriptor']['u32_LE']
    old_size = d['directory_source']['IMG_FAT']['MDR_bytes']
    check('directory_at_component_end', tables[0]['old_start'] + tables[0]['old_bytes'] == descriptor[0]
          and descriptor == [92653480, 120, 20, 1] and descriptor[0] + 120 == old_size)
    added_records, inserted_bytes = 84 + len(candidates), (84 + len(candidates)) * 16
    new_first = l4['count'] + 1
    new_count = l4['count'] + added_records
    check('append_math', [new_first, new_count, inserted_bytes] == [2133949, 2134041, 1488])
    check('street22bit_firstchild_and12bit_count', new_first < (1 << tables[2]['widths'][0]) and added_records < (1 << tables[2]['widths'][5]))
    check('level4_22bit_ID_bound', new_count < (1 << l4['widths'][0]))
    child_rows = [r for r in rows if r['child_count']]
    for r in rows:
        check('old84_preserved_field_bounds_' + str(r['lowID']), 0 <= r['raw_flags_field'] < 512
              and r['child_count'] < 1024 and r['first_child_ID'] < (1 << 22)
              and all(x == 0xffffffff or 0 <= x < ((1 << 19) - 1) for x in [r['primary_reference'], r['alternate_reference']]))
        if r['child_count']:
            level = r['child_level_low3']
            check('known_child_range_stays_valid_' + str(r['lowID']), level in (5, 6)
                  and r['first_child_ID'] >= 1 and r['first_child_ID'] + r['child_count'] - 1 <= tables[level - 1]['count'])
    shift_start = l4['old_start'] + l4['old_bytes']
    table_plan = []
    for t in tables:
        updated = t['raw_words'][:]
        if t['level'] <= 3:
            updated[0] += inserted_bytes
        if t['level'] == 4:
            updated[1] += inserted_bytes
        table_plan.append({**t, 'proposed_start': updated[0], 'proposed_bytes': updated[1],
                           'proposed_count': updated[1] * 8 // updated[2],
                           'old_directory_metadata_hex': struct.pack('<5I', *t['raw_words']).hex(),
                           'proposed_directory_metadata_hex': struct.pack('<5I', *updated).hex(),
                           'logical_IDs_of_existing_records_change': False})
    new_descriptor = [descriptor[0] + inserted_bytes, *descriptor[1:]]
    mdr = d['mapmetadata']['original_IMG_FAT']['components']['00004171.MDR']
    block_size = d['mapmetadata']['original_IMG_FAT']['block_size']
    capacity = mdr['blocks'] * block_size
    new_mdr_size = old_size + inserted_bytes
    check('MDR_conditional_existing_block_capacity', capacity - old_size == 2016 and capacity - new_mdr_size == 528
          and (new_mdr_size + block_size - 1) // block_size == mdr['blocks'])
    lbl = d['LBL_header']['public_LBL_header']['field_observations']
    pool_start, pool_bytes, shift = lbl['u32_LE_at21'], lbl['u32_LE_at25'], lbl['u8_at29']
    pool_end = pool_start + pool_bytes
    gmp = d['mapmetadata']['original_IMG_FAT']['components']['I053061A.GMP']
    check('actual_LBL_contract', [pool_start, pool_bytes, shift, lbl['u8_at30'], lbl['u16_LE_at170']] == [6566, 3805432, 3, 10, 950]
          and pool_bytes % (1 << shift) == 0)
    check('GMP_tail_not_free_padding', gmp['bytes'] - pool_end == 826)
    label_total = 0
    proposed_sources = []
    for i, r in enumerate(candidates):
        encoded = r['raw_housenumber'].encode('cp950', errors='strict') + b'\0'
        padded_bytes = ((len(encoded) + 7) // 8) * 8
        provisional_ref = (pool_bytes + label_total) >> shift
        check('provisional_new_reference_bounds_' + r['raw_housenumber'], provisional_ref < ((1 << 19) - 1))
        proposed_sources.append({'label': r['raw_housenumber'], 'OSM_type': r['type'], 'OSM_id': r['id'],
                                 'source_coordinate_strings': [r['attributes']['lat'], r['attributes']['lon']],
                                 'explicit_source_city_district_street': [r['tags']['addr:city'], r['tags']['addr:district'], r['tags']['addr:street']],
                                 'source_tags_reference': INPUTS['coverage'][0],
                                 'provisional_leaf_ID_in_old84_then_new9_order': new_first + 84 + i,
                                 'provisional_CP950_bytes_through_NUL_hex': encoded.hex(),
                                 'provisional_padded_label_bytes': padded_bytes,
                                 'provisional_primary_reference_if_pool_tail_inserted': provisional_ref,
                                 'provisional_GMP_label_offset': pool_start + (provisional_ref << shift),
                                 'prospective_raw24_point_host_nearest_policy': raw_point(r['attributes']['lat'], r['attributes']['lon']),
                                 'native_label_allocation_or_new_record_encoded': False})
        label_total += padded_bytes
    check('nine_provisional_labels72_bytes', label_total == 72)
    gmp_capacity = gmp['blocks'] * block_size
    check('GMP_conditional_existing_block_capacity', gmp_capacity - gmp['bytes'] == 552
          and gmp_capacity - (gmp['bytes'] + label_total) == 480)
    old_numeric = [int(re.match(r'\d+', r['label']).group()) for r in rows[1:]]
    check('observed_old_primary_number_order', all(a <= b for a, b in zip(old_numeric, old_numeric[1:])))
    trial = old_numeric + [int(re.match(r'\d+', name).group()) for name in names]
    inversions = [(a, b) for a, b in zip(trial, trial[1:]) if a > b]
    check('literal_copy_then_append_has_numeric_inversion', inversions == [(216, 6)])
    family = d['JAI_family']['central_district_Minquan_candidate']
    check('existing_street_JAI_identity_unchanged', family['child']['low28_id'] == 16707 and family['child']['info_id'] == 16786
          and family['child']['decoded_text'] == '民權路' and family['child']['record'] == 0x30004143)
    jai_levels = d['schema']['databases']['jai']['record_levels']
    check('observed_JAI_only_levels123', [r['high_nibble'] for r in jai_levels] == [1, 2, 3])
    for name, before in signatures.items():
        check('small_frozen_input_stat_unchanged_' + name, signature(ROOT / name) == before)

    plan = {
        'schema': 'Minquan-existing-street-append-plan/v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'source': {'path': str(Path(__file__).relative_to(ROOT)), 'sha256': digest(Path(__file__).read_bytes())},
        'scope': 'Offline arithmetic/record/metadata plan for one existing stock AP street; no carrier or label writer.',
        'dependencies': dependencies,
        'complete_coverage_proof_inherited_reference': d['coverage']['complete_source_proof'],
        'target_identity': {'device': 'Taiwan nuvi 2565RT HWID1352 SW8.00', 'mapordinal': 1, 'mapID': 5441050,
                            'JAI_city': '0x10000008', 'JAI_district': '0x20000058', 'JAI_street': '0x30004143',
                            'street_level': 3, 'street_lowID': 16707, 'street_primary_ref': 206,
                            'JAI_info_id': 16786, 'unchanged_street_FTS_token': family['child']['index_record']},
        'answer': {'record_ID_and_field_capacity_feasible': True, 'physical_suffix_relocation_required': True,
                   'MDR_catalog_block_capacity_sufficient_for1488': True, 'LBL_catalog_block_capacity_sufficient_for72': True,
                   'catalog_capacity_is_proven_writable_free_space': False,
                   'new_93_range_is_93_houses': False, 'old84_plus9_are_mixed_children_with9_proposed_houses': True,
                   'ready_for_full_candidate_or_installation': False, 'whole_Taiwan_2026_update_complete': False},
        'record_ID_plan': {'old_level4_count': l4['count'], 'new_level4_count': new_count,
                           'old_street_range': [904706, 904789], 'new_street_range': [new_first, new_count],
                           'new_street_count': added_records, 'extra_records': added_records,
                           'extra_bytes': inserted_bytes, 'old84_original_slots_remain_unchanged': True,
                           'other_street_IDs_remain_unchanged_by_this_append_arithmetic': True,
                           'simple_copy_order_mapping': 'copied ID = 2133949 + (oldID - 904706), for oldID904706..904789',
                           'simple_copy_order_copied84_range': [new_first, new_first + 83],
                           'simple_copy_order_new9_range': [new_first + 84, new_count],
                           'mapping_or_order_finalized': False,
                           'reason': 'Literal old84 then new9 has216->6 numeric inversion; actual native house ordering and flag8 adjacency semantics are not yet verified.'},
        'street_patch_plan': {'old_MDR_byte_offset': street['MDRrelative_byte_offset'],
                              'proposed_MDR_byte_offset_after_suffix_shift': street['MDRrelative_byte_offset'] + inserted_bytes,
                              'initial_bit_offset': street['initial_bit_offset'], 'record_used_bits': 111,
                              'only_changed_fields': {'+00': {'old': sf['+00'], 'proposed': new_first, 'width': 22,
                                                              'window_bit_start': 26, 'window_bit_end_exclusive': 48},
                                                      '+0C': {'old': 84, 'proposed': 93, 'width': 12,
                                                              'window_bit_start': 48, 'window_bit_end_exclusive': 60}},
                              'complete_raw_child_level_and_flags_preserved': sf['+04'],
                              'derived_nextlevel': sf['+04'] & 7,
                              'all_other_fields_and_neighbor_bits_preserved': True,
                              'record_patch_executed_or_payload_emitted': False,
                              'count_width_caution': 'Street L3 count is12 bits. L4 descendant count is10 bits; do not substitute one width for the other.'},
        'old84_preservation': {'source_record_stream_bytes': len(old84_raw), 'source_record_stream_sha256': digest(old84_raw),
                               'preservation_rule': 'Copy each source16-byte record verbatim; retain original slots and all existing firstchild/count/raw9flags/primary/secondary/mapordinal/raw24 values.',
                               'raw_flags_distribution': {str(k): v for k, v in sorted(Counter(r['raw_flags_field'] for r in rows).items())},
                               'child_bearing_records': [{'oldID': r['lowID'], 'label': r['label'], 'firstchild': r['first_child_ID'],
                                                          'count': r['child_count'], 'nextlevel': r['child_level_low3'],
                                                          'raw_child_level_and_flags': r['raw_flags_field']}
                                                         for r in child_rows],
                               'level5_and_level6_spans_or_IDs_change': False,
                               'child_range_referential_math_passed': True,
                               'unknown_flags8_or_other_incoming_backreferences_checked': False,
                               'all_original_subtree_contents_reread': False},
        'nine_new_source_candidates': proposed_sources,
        'new_leaf_format_proposal_only': {'basis': 'Actual original184 leaf source template, not a whole new-door constructor proof.',
                                          'mapordinal': 1, 'primary_reference': 'unallocated; conditional values listed per source',
                                          'secondary_reference': '0xFFFFFFFF(native sentinel; stored19-bit all ones)',
                                          'firstchild': 0, 'count': 0, 'complete_raw_child_level_and_flags': 0,
                                          'record_bits': 128, 'record_bytes': 16,
                                          'new_flags0_sufficient_for_actual_house_search': 'unknown',
                                          'coordinate_quantization': 'Host signed24 global-circle nearest with ties away from zero; native source-backed raw24/rescale shape, stock geographic rounding/query not claimed.'},
        'MDR_component_relocation_plan': {'logical_insert_at_old_level4_end': shift_start,
                                         'new1488_bytes': '93 planned records; no bytes written',
                                         'move_old_suffix': {'old_start': shift_start, 'old_end_exclusive': old_size,
                                                             'bytes': old_size - shift_start, 'new_start': shift_start + inserted_bytes,
                                                             'new_end_exclusive': new_mdr_size},
                                         'tables': table_plan,
                                         'header600_descriptor': {'offset': 600, 'bytes': 16, 'old_u32': descriptor,
                                                                   'proposed_u32': new_descriptor,
                                                                   'old_hex': struct.pack('<4I', *descriptor).hex(),
                                                                   'proposed_hex': struct.pack('<4I', *new_descriptor).hex()},
                                         'component_bytes': {'old': old_size, 'proposed': new_mdr_size},
                                         'FAT_part0_component_length_field_offset': 12,
                                         'other_MDR_header_tail_pointer_fields_fully_classified': False,
                                         'other_absolute_or_checksum_fields_may_need_updates': True,
                                         'whole_MDR_suffix_read_or_relocated': False},
        'conditional_carrier_capacity': {'block_size': block_size,
                                          'MDR': {'allocated_blocks': mdr['blocks'], 'capacity': capacity,
                                                  'old_last_block_padding_bytes_by_catalog': capacity - old_size,
                                                  'proposed_last_block_padding_bytes_by_catalog': capacity - new_mdr_size,
                                                  'last_allocated_disk_block_source': 22635,
                                                  'oldEOF_in_last_block': old_size % block_size,
                                                  'proposedEOF_in_last_block': new_mdr_size % block_size,
                                                  'extra_FAT_blocks_needed_if_catalog_and_padding_valid': 0},
                                          'GMP': {'allocated_blocks': gmp['blocks'], 'capacity': gmp_capacity,
                                                  'old_bytes': gmp['bytes'], 'conditional_proposed_bytes': gmp['bytes'] + label_total,
                                                  'old_padding_bytes_by_catalog': gmp_capacity - gmp['bytes'],
                                                  'conditional_proposed_padding_bytes_by_catalog': gmp_capacity - gmp['bytes'] - label_total,
                                                  'extra_FAT_blocks_needed_if_catalog_and_padding_valid': 0},
                                          'IMG_bytes_change_needed_if_both_allocations_confirmed': False,
                                          'spare_padding_contents_ownership_and_checksums_verified': False},
        'conditional_LBL_pool_plan': {'map_component': 'I053061A.GMP', 'LBL_header_offset': 874,
                                      'label_pool_start_GMP': pool_start, 'old_label_pool_bytes': pool_bytes,
                                      'old_label_pool_end_GMP': pool_end, 'shift': shift, 'encoding_type': 10, 'codepage': 950,
                                      'packed_reference_bits': 19, 'native_getter_positive_mask_bits': 22,
                                      'stored_sentinel': (1 << 19) - 1, 'maximum_non_sentinel_reference': (1 << 19) - 2,
                                      'nine_labels72_bytes_is_host_conditional_arithmetic_only': True,
                                      'pool_tail_insert_bytes': label_total, 'conditional_new_pool_bytes': pool_bytes + label_total,
                                      'conditional_new_pool_end_GMP': pool_end + label_total,
                                      'move_unclassified_GMP_tail': {'old_start': pool_end, 'old_end_exclusive': gmp['bytes'],
                                                                    'bytes': gmp['bytes'] - pool_end,
                                                                    'conditional_new_start': pool_end + label_total,
                                                                    'conditional_new_end_exclusive': gmp['bytes'] + label_total},
                                      'tail826_bytes_are_proven_padding': False,
                                      'existing_label_references_or_label_start_change': False,
                                      'native_allocation_serializer_and_all_tail_pointer_fields_verified': False,
                                      'provisional_references_assigned_to_actual_map': False,
                                      'same_text_existing_elsewhere_in_original_LBL_pool_checked': False},
        'ordering_and_flags': {'old_primary_numeric_bases_monotone_observed': True,
                               'old84_then_new9_observed_numeric_inversions': inversions,
                               'numeric_order_equals_full_original_native_house_comparator': False,
                               'old_rawflags8_count': sum(r['raw_flags_field'] == 8 for r in rows),
                               'rawflags8_adjacency_semantics': 'unknown; preserve complete old values and do not assume sorted insertion leaves semantics unchanged',
                               'alternative': 'A new93 range can merge new houses while preserving relative order and rawbytes of old84, without changing any preexisting table IDs; finalize only after native order/flag consumers are source-backed.'},
        'JAI_index_assessment': {'observed_info_record_levels': jai_levels, 'existing_name_token_and_logical_key_preserved': True,
                                 'existing_city_district_street_FTS_and_family_rewrite_proposed': False,
                                 'evidence_based_inference': 'This same-street child augmentation need not create a new city/district/street name entry because the proven JAI key and family lookup still reach street16707. No JAI level4 info rows observed.',
                                 'complete_native_house_query_or_hidden_auxiliary_index_requirements_verified': False,
                                 'no_JAI_or_other_index_change_ever_needed_claimed': False},
        'next_exact_evidence_ranges_before_carrier_writer': [
            {'source': 'already sealed JSON', 'range': 'MDR public header[0,772), header600[600,616), sixdirectory[92653480,92653600)',
             'action': 'Reuse bytes; classify all native tail-referencing descriptors and checksum/length fields. No repeat IMG read required for these sealed bytes.'},
            {'source': 'original IMG public FAT/header', 'physical_ranges': [[0, 512], [4096, 57344]],
             'action': 'If immutable full directory bytes are unavailable, one bounded read to retain exact MDR part0 size field, all95 blocklists, GMP4 part blocklists, cross-component disjoint allocation and IMG declared lengths/checksum fields. Do not hash/copy whole IMG.'},
            {'source': 'original MDR last allocated block', 'logical_range': [old_size, capacity],
             'physical_range_from_frozen_last_block_mapping': [22635 * block_size + old_size % block_size, (22635 + 1) * block_size],
             'bytes': capacity - old_size,
             'action': 'Read2016 existing allocated-tail bytes once; establish padding/reserved/checksum ownership before treating1488 as writable.'},
            {'source': 'already sealed JSON', 'range': 'GMP header[0,57), TREheader[236,525), LBLheader[874,1535)',
             'action': 'Reuse exact headers to classify every tail section pointer/size and any component checksum; preserve TRE/RGN/mapID/encoding/sort identities.'},
            {'source': 'original GMP logical tail', 'logical_range': [pool_end, gmp['bytes']], 'bytes': gmp['bytes'] - pool_end,
             'action': 'Read826 tail bytes once and correlate nonlabel sections; never erase or repurpose as padding.'},
            {'source': 'original GMP allocated EOF slack', 'logical_range': [gmp['bytes'], gmp_capacity],
             'bytes': gmp_capacity - gmp['bytes'], 'physical_range': 'derive from exact last GMP FAT block; not inferred contiguous physical placement',
             'action': 'Read552 allocated-tail bytes once to determine reservations/checksums before conditional72-byte growth.'},
        ],
        'remaining_non_read_requirements': [
            'Source-back native house comparator/search and rawflags8 semantics; determine final93 ordering and whether copied-record IDs need any incoming/backreference mapping.',
            'Verify actual new-label8-byte alignment/padding and all LBL/GMP tail-offset fields; label values above are provisional host CP950 math, not allocation proof.',
            'Close native full house selection/provider/registry and new-coordinate route association on a complete fresh candidate before meaningful physical acceptance.',
            'Plan one isolated complete candidate retaining stock maps/licensing/metadata and explicit rollback; this plan does not create that candidate.',
        ],
        'scope_limits': {'original_IMG_MAIN_DB_or_source_XML_opened': False, 'old_native_writer_or_UI_suites_rerun': False,
                         'new_record_or_label_payload_binary_emitted': False, 'original_map_USB_canonical_or_daemon_modified': False,
                         'whole_backup_or_IMG_digest_repeated': False, 'new_ZIP_or_installer_created': False,
                         'full_query_UI_hardware_or_route_executed': False,
                         'nine_absent_primary_labels_equal_whole_Garmin_absence_or_post2016_new_construction': False,
                         'proposed9_additions_equal_whole_Taiwan_update': False,
                         '184_meter_shift_physical_test_requested': False},
        'checks': CHECKS,
        'all_bounded_input_and_mathematical_checks_passed': all(c['passed'] for c in CHECKS),
        'native_full_candidate_validation_passed': False,
    }
    raw = (json.dumps(plan, ensure_ascii=False, indent=2) + '\n').encode()
    with proof_path.open('xb') as f:
        f.write(raw)
    text = '''同一既有民權路 append-only 門牌計畫（離線，未產候選）

原街道16707仍沿用原城市/中區/民權路 JAI、primaryref206、mapordinal1。
可在level4表末尾建立新93筆子項範圍2133949..2134041，複製舊84筆並增9筆來源門牌；原84筆的舊位置和其他街道ID保持。84筆含交叉路口及巷道，不能叫93個門牌。
street的firstchild22 bits/count12 bits足夠；level4各記錄的子孫count才10 bits。完整9-bit flags必須保留，包括未知高bit8。

MDR新增93×16=1488 bytes，將669884-byte舊suffix移後1488：L3起點91985204、L2起點92649401、L1起點92654632、目錄92654968、MDR大小92655088。header600的16-byte descriptor為[92654968,120,20,1]；其他尾指標/校驗尚須分類。
既有MDR22621個4096-byte blocks的容量算術剩528 bytes；原末塊2016 bytes內容/保留用途未驗，不能當可寫空間。

九個來源門牌為6、8、138、140、142、144、146、148、150號。只證未觀測於該街舊84個primary labels，不證整原廠不存在/2016後新建。16,18多門牌way排除。
若每個新CP950 label按原8-byte參照粒度配置，條件計算共72 bytes，refs475679..475687符合19-bit（524287保留sentinel）。LBL pool尾部另826 bytes非label區不能覆寫；須搬移並修所有真實指標。GMP既有blocks的條件容量剩480 bytes；現未分配任何label。

舊84的primary數值12..216單調；把九筆直接排在舊84後會有216→6倒序。尚未證原門牌比較/搜尋是否要求該排序，也未證flag8相鄰語義，因此93筆順序尚未定案。可研究新範圍中交織9筆、保留舊84相對順序/完整bytes，但不能先叫原生相容。
同街道名稱及其JAI key/family不變，现有level1..3 FTS名稱索引可保持；完整house-query及隱藏輔助索引需求仍未證，不宣稱JAI永遠不用改。

精確下一步來源範圍和阻塞條件見同名JSON；本輪只讀sealed小JSON，不讀原IMG/DB，不寫USB/canonical，不重跑舊native/writer，不產ZIP或安裝器，不要求184幾公尺位移測試。
這是9筆單街增補方案，完整2026全台地址更新仍未完成。
'''
    with note_path.open('x', encoding='utf-8') as f:
        f.write(text)
    print(json.dumps({'all_bounded_input_and_mathematical_checks_passed': True, 'checks': len(CHECKS),
                      'proof': str(proof_path.relative_to(ROOT)), 'proof_bytes': len(raw), 'proof_sha256': digest(raw),
                      'note': str(note_path.relative_to(ROOT)), 'note_sha256': digest(text.encode()),
                      'native_full_candidate_validation_passed': False, 'original_map_or_USB_modified': False}, ensure_ascii=False))


if __name__ == '__main__':
    prepare()
