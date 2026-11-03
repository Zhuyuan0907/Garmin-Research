#!/usr/bin/env python3
"""New host writer/source cross-checks and one explicit modern street prototype."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from native_address_records import AddressRecord, RecordLayout, encode_record, quantize_point24


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def need(ok, label):
    if not ok:
        raise ValueError(label)


def record_from_output(raw):
    first, flags, ordinal, count, primary, a, b, secondary = struct.unpack('<8I', raw)
    return AddressRecord(ordinal, None if primary == 0xFFFFFFFF else primary,
                         None if secondary == 0xFFFFFFFF else secondary,
                         first, count, flags, a, b)


def main():
    proof_path = OUT / 'native-record-writer-source-crosscheck-proof-v1.json'
    prototype_path = OUT / 'modern-Minquan-street-point-prototype-v1.json'
    payload_path = OUT / 'modern-Minquan-street-point-payload-v1.bin'
    need(not any(p.exists() for p in (proof_path, prototype_path, payload_path)), 'new outputs only')
    dependency_specs = [
        ('staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
         '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60'),
        ('staging/navigation-native-AP-packed-records-v1/original-packed-records-proof-v2.json',
         'd56e53bf77fa604597d670a61df108f3331e4404df8e2f167395dae6b2d2bc53'),
        ('staging/navigation-native-AP-level4-records-v1/original-level4-boundary-records-proof-v3.json', None),
        ('staging/navigation-house184-v1/source-address184-proof.json', None),
        ('staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json',
         '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753'),
        ('staging/navigation-native-AP-child-range-v1/original-child-range-and-level4-plans-proof-v1.json', None),
    ]
    dependencies, data = [], []
    for path, expected in dependency_specs:
        raw = (ROOT / path).read_bytes()
        if expected:
            need(sha(raw) == expected, 'sealed dependency ' + path)
        data.append(json.loads(raw))
        dependencies.append({'path': path, 'bytes': len(raw), 'sha256': sha(raw), 'old_scope_not_replayed': True})
    consumer, packed, level4, osm, metadata, childproof = data
    need(consumer['all_cases_passed'] and packed['all_cases_passed'] and level4['all_cases_passed'] and
         childproof['all_cases_passed'], 'completed native source dependencies')
    profiles = consumer['cases'][0]['decoded_records']
    crosschecks = []
    for case in packed['cases'] + level4['cases']:
        level, low_id = case['explicit_level'], case['explicit_low28_ID']
        descriptor = profiles[level - 1]
        layout = RecordLayout(tuple(descriptor['six_bit_values_at_record_offsets_10_to_17']),
                              tuple(descriptor['flags_at_record_offsets_18_19']), descriptor['third_scalar'])
        values = bytes.fromhex(case['native_32byte_output_hex'])
        record = record_from_output(values)
        source = bytes.fromhex(case['original_readonly_payload_hex'])
        initial = case['initial_bit_offset']
        encoded = encode_record(layout, record, initial_bit_offset=initial, pad_to_bytes=16)
        mask = ((1 << encoded.used_bits) - 1) << initial
        source_used = int.from_bytes(source, 'little') & mask
        encoded_used = int.from_bytes(encoded.payload, 'little') & mask
        need(source_used == encoded_used, 'byte-exact original source used-bit witness')
        native_sequence = case['conditional_read_sequence']
        need(len(native_sequence) == len(encoded.field_plan) == 8, 'eight native field boundaries')
        for actual, written in zip(native_sequence, encoded.field_plan):
            need(actual['output_offset'] == written['output_offset'] and actual['width'] == written['width'] and
                 actual['conditional_enabled'] == written['enabled'] and
                 actual['cumulative_record_bits_consumed'] == written['record_bits_consumed'],
                 'writer field order/conditional consumption matches completed original bitreader')
        crosschecks.append({'level': level, 'one_based_lowID': low_id,
            'original_MDR_relative_offset': case['MDRrelative_byte_offset'], 'initial_bit_offset': initial,
            'used_bits': encoded.used_bits, 'source_readonly_16bytes_hex': source.hex(),
            'serialized_zero_padded_16bytes_hex': encoded.payload.hex(),
            'used_bit_mask_16bytes_hex': mask.to_bytes(16, 'little').hex(),
            'byte_exact_original_used_bits': True,
            'neighbor_bits_outside_record_compared': False,
            'complete_child_level_and_flags_preserved': record.child_level_and_flags,
            'derived_next_level_low3': record.next_level,
            'field_plan': encoded.field_plan})
    street_case = packed['cases'][2]
    street_descriptor = profiles[2]
    street_layout = RecordLayout(tuple(street_descriptor['six_bit_values_at_record_offsets_10_to_17']),
                                 tuple(street_descriptor['flags_at_record_offsets_18_19']),
                                 street_descriptor['third_scalar'])
    street = record_from_output(bytes.fromhex(street_case['native_32byte_output_hex']))
    controls = [
        ('unverified_width_slot6', replace(street_layout, widths=street_layout.widths[:6] + (1, 0)), street),
        ('unverified_width_slot7', replace(street_layout, widths=street_layout.widths[:7] + (1,)), street),
        ('unverified_layout', replace(street_layout, record_bits=112), street),
        ('reference_overflow', street_layout, replace(street, primary_ref=1 << 19)),
        ('reserved_reference_collision', street_layout, replace(street, primary_ref=(1 << 19) - 1)),
        ('negative_reference', street_layout, replace(street, primary_ref=-1)),
        ('disabled_secondary_reference', street_layout, replace(street, secondary_ref=1)),
        ('raw24_overflow', street_layout, replace(street, raw_location_a=1 << 24)),
        ('child_count_overflow', street_layout, replace(street, child_count=1 << 12)),
        ('complete_child_flags_overflow', street_layout, replace(street, child_level_and_flags=1 << 9 | 4)),
        ('unknown_next_level7', street_layout, replace(street, child_level_and_flags=7)),
        ('unverified_mapordinal', street_layout, replace(street, mapordinal=2)),
    ]
    rejected = []
    for label, layout, record in controls:
        try:
            encode_record(layout, record)
        except ValueError as exc:
            rejected.append({'case': label, 'rejected': True, 'reason': str(exc)})
        else:
            raise ValueError('required rejection accepted: ' + label)
    node = next(x for x in osm['house184_prefix_matches'] if x['type'] == 'node' and x['id'] == '8528998711')
    need(node['coordinate'] == [24.1425658, 120.6748857] and node['tags']['addr:street'] == '民權路' and
         node['tags']['addr:city'] == '臺中市', 'actual modern source node')
    # Actual TRE metadata in the existing source proof is24; native local
    # rescale is raw<<8. No complete coordinate getter is replayed here.
    need(metadata['TRE_level_table']['second_byte_at_minimum_level'] == 24,
         'source-backed actual AP resolution input')
    point = quantize_point24(*node['coordinate'])
    modern = replace(street, raw_location_a=point['latitude']['wire_u24'],
                     raw_location_b=point['longitude']['wire_u24'])
    encoded = encode_record(street_layout, modern, initial_bit_offset=street_case['initial_bit_offset'],
                            pad_to_bytes=16)
    expected_output = struct.pack('<8I', modern.first_child, modern.child_level_and_flags,
        modern.mapordinal, modern.child_count, modern.primary_ref, modern.raw_location_a,
        modern.raw_location_b, 0xFFFFFFFF)
    now = datetime.now(timezone.utc).isoformat()
    module = ROOT / 'scripts/native_address_records.py'
    payload_path.write_bytes(encoded.payload)
    prototype = {'schema': 'modern-Minquan-street-point-format-prototype/v1', 'created_utc': now,
        'source_node': node, 'point_quantization': point,
        'record_semantics': 'Existing source-proved level3 民權路 representative-point template; only the two raw24 point fields replaced with explicit modern OSM node data.',
        'explicit_reader_level': 3, 'explicit_one_based_lowID_fixture': 16707,
        'MDR_relative_offset_fixture': street_case['MDRrelative_byte_offset'],
        'initial_bit_offset': encoded.initial_bit_offset, 'used_bits': encoded.used_bits,
        'original_native_directory_record_hex': street_descriptor['native_decoded_record_hex'],
        'original_native_directory_output_hex_dependency': consumer['cases'][0]['output_hex'],
        'layout': {'widths': street_layout.widths, 'reference_flags': street_layout.reference_flags,
                   'record_bits': street_layout.record_bits},
        'record': {'mapordinal': modern.mapordinal, 'primary_ref': modern.primary_ref,
                   'secondary_ref': None, 'first_child': modern.first_child, 'child_count': modern.child_count,
                   'child_level_and_flags': modern.child_level_and_flags, 'derived_next_level': modern.next_level,
                   'raw_location_a': modern.raw_location_a, 'raw_location_b': modern.raw_location_b},
        'payload': str(payload_path.relative_to(ROOT)), 'payload_bytes': len(encoded.payload),
        'payload_sha256': sha(encoded.payload), 'payload_hex': encoded.payload.hex(),
        'expected_native_output_32bytes_hex': expected_output.hex(), 'field_plan': encoded.field_plan,
        'source_dependencies': dependencies,
        'producer_source_sha256': sha(Path(__file__).read_bytes()), 'module_sha256': sha(module.read_bytes()),
        'independent_original_native_reader_executed': False,
        'actual_original_house184_record_identity': False, 'new_house_label_allocated': False,
        'whole_original_format_map_or_MDR_or_JAI_rebuilt': False, 'installable': False,
        'stock_MAP_DB_USB_canonical_writes': False,
        'limits': ['This is a street representative-point format experiment, not a new/replaced native house184 record.',
                   'Original names/refs/child metadata remain the original 民權路 template; modern point provenance is the OSM node.',
                   'Native independent new payload decode is pending; no full query/registry/installer or2026stock-address update claim.']}
    prototype_path.write_text(json.dumps(prototype, ensure_ascii=False, indent=2) + '\n')
    proof = {'schema': 'native-record-writer-source-crosscheck/v1', 'created_utc': now,
        'all_bounded_host_checks_passed': True, 'source_sha256': sha(Path(__file__).read_bytes()),
        'module_path': str(module.relative_to(ROOT)), 'module_sha256': sha(module.read_bytes()),
        'dependencies': dependencies, 'original_native_source_cases': crosschecks,
        'required_rejection_controls': rejected,
        'totals': {'original_source_used_bit_crosschecks': len(crosschecks),
                   'original_source_used_bits': sum(x['used_bits'] for x in crosschecks),
                   'rejected_invalid_inputs': len(rejected), 'fresh_prototype_payload_bytes': len(encoded.payload)},
        'prototype': str(prototype_path.relative_to(ROOT)), 'prototype_sha256': sha(prototype_path.read_bytes()),
        'native_CPU_execution_here': False, 'actual_IMG_MAIN_DB_USB_reads_here': False,
        'old_VM_or_codec_or_MDR_suites_replayed': False, 'same_function_roundtrip_claim': False,
        'whole_original_format_or2026stock_address_update': False,
        'limits': ['Five direct used-bit comparisons against actual original source slices and original native output, not encoder/decoder roundtrips.',
                   'Bits before/after each used record belong to neighboring records and are deliberately excluded.',
                   'Widths6/7 refer to descriptor slots6/7; nonzero values rejected because their meaning is unverified.',
                   'Complete +04raw9bit value is retained; only low3bits denote next level; high flags remain unnamed.',
                   'Only exact decoded directory layout profiles and source-proved ordinal1 are supported.']}
    proof_path.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'proof': str(proof_path.relative_to(ROOT)), 'proof_sha256': sha(proof_path.read_bytes()),
        'prototype': str(prototype_path.relative_to(ROOT)), 'prototype_sha256': sha(prototype_path.read_bytes()),
        'payload': str(payload_path.relative_to(ROOT)), 'payload_sha256': sha(encoded.payload),
        'payload_hex': encoded.payload.hex(), 'record': prototype['record'], 'point': point,
        'module_sha256': proof['module_sha256'], 'source_sha256': proof['source_sha256'],
        'totals': proof['totals']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
