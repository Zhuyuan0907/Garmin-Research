#!/usr/bin/env python3
"""One new source-backed184 template payload; no old writer suites rerun."""
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


def main():
    output = OUT / 'modern-source-native-house184-point-prototype-v1.json'
    payload = OUT / 'modern-source-native-house184-point-payload-v1.bin'
    need(not output.exists() and not payload.exists(), 'new isolated outputs only')
    module = ROOT / 'scripts/native_address_records.py'
    need(sha(module.read_bytes()) == '8dfec0a03795e29fc223fbd06f0418536b6f3969024083b5023e25620319eb33',
         'completed frozen pure writer module')
    paths = [
        ('staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json',
         '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774'),
        ('staging/navigation-native-AP-provider-consumer-v1/original-AP-directory-consumer-proof-v1.json',
         '2b7e7caf26284461c097e9d2bf7fb8d4a9b319058ee4f1dca220df91d8b66e60'),
        ('staging/navigation-house184-v1/source-address184-proof.json', None),
        ('staging/navigation-native-record-writer-v1/native-record-writer-file-seal-v1.json',
         'a69e3b666c8be1843a8d85839eed5116bc4979637d191c6e5eb2459860a1e19c'),
        ('staging/navigation-AP-MinQuan184-witness-v1/source-file-seal.json',
         'e8babb717bf395b66f6955147aa79fb9d6b6a20d863fd562b022526ef6fa1e36'),
    ]
    deps, data = [], []
    for path, expected in paths:
        raw = (ROOT / path).read_bytes()
        if expected:
            need(sha(raw) == expected, 'selected frozen dependency')
        data.append(json.loads(raw))
        deps.append({'path': path, 'sha256': sha(raw), 'old_scope_not_replayed': True})
    witness, consumer, osm, oldseal, witnessseal = data
    need(witnessseal['all_files_immutable_after_seal'], 'sealed source184 dependency')
    need(witness['all_bounded_source_and_host_decode_checks_passed'] and witness['strict_184_match_count'] == 1,
         'actual bounded source184 witness')
    old = witness['strict_184_matches'][0]
    need(old['lowID'] == 904780 and old['MDR_relative_offset'] == 72317012 and
         old['primary_reference'] == 808 and old['label'] == '184號' and old['mapordinal'] == 1,
         'exact original184 host-source template')
    profile = consumer['cases'][0]['decoded_records'][3]
    layout = RecordLayout(tuple(profile['six_bit_values_at_record_offsets_10_to_17']),
                          tuple(profile['flags_at_record_offsets_18_19']), profile['third_scalar'])
    fields = old['host_fields']
    original = AddressRecord(fields['+08'], fields['+10'], None,
                             fields['+00'], fields['+0c'], fields['+04'], fields['+14'], fields['+18'])
    source = bytes.fromhex(old['record_hex'])
    encoded_old = encode_record(layout, original, pad_to_bytes=16)
    need(encoded_old.used_bits == 128 and len(source) == 16 and encoded_old.payload == source,
         'one fresh original184 source128bit exact crosscheck')
    node = next(x for x in osm['house184_prefix_matches'] if x['type'] == 'node' and x['id'] == '8528998711')
    need(node['coordinate'] == [24.1425658, 120.6748857], 'actual modern source node coordinates')
    quantization = quantize_point24(*node['coordinate'])
    modern = replace(original, raw_location_a=quantization['latitude']['wire_u24'],
                     raw_location_b=quantization['longitude']['wire_u24'])
    encoded = encode_record(layout, modern, pad_to_bytes=16)
    prefix_bits = 80
    need(int.from_bytes(encoded.payload, 'little') & ((1 << prefix_bits) - 1) ==
         int.from_bytes(source, 'little') & ((1 << prefix_bits) - 1),
         'all original reference/map/child/flag bits retained')
    expected = struct.pack('<8I', modern.first_child, modern.child_level_and_flags, modern.mapordinal,
        modern.child_count, modern.primary_ref, modern.raw_location_a, modern.raw_location_b, 0xFFFFFFFF)
    payload.write_bytes(encoded.payload)
    result = {'schema': 'modern-source-native-house184-point-prototype/v1',
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'all_new_bounded_host_checks_passed': True,
        'source_sha256': sha(Path(__file__).read_bytes()), 'module_sha256': sha(module.read_bytes()),
        'dependencies': deps, 'source_original184_host_witness': old,
        'one_new_original_source_crosscheck': {'source_payload_hex': source.hex(),
            'serialized_original_payload_hex': encoded_old.payload.hex(), 'source_used_bits': 128,
            'byte_exact': True, 'no_old5_cases_or12_controls_rerun': True},
        'modern_OSM_node': node, 'point_quantization': quantization,
        'explicit_reader_level': 4, 'explicit_one_based_lowID_fixture': 904780,
        'MDR_relative_offset_fixture': 72317012, 'initial_bit_offset': 0, 'used_bits': 128,
        'original_native_directory_record_hex': profile['native_decoded_record_hex'],
        'original_native_directory_output_hex_dependency': consumer['cases'][0]['output_hex'],
        'layout': {'widths': layout.widths, 'reference_flags': layout.reference_flags, 'record_bits': 128},
        'record': {'mapordinal': modern.mapordinal, 'primary_ref': modern.primary_ref,
            'secondary_ref': None, 'first_child': modern.first_child, 'child_count': modern.child_count,
            'child_level_and_flags': modern.child_level_and_flags, 'derived_next_level': modern.next_level,
            'raw_location_a': modern.raw_location_a, 'raw_location_b': modern.raw_location_b},
        'raw24_delta_from_original': [modern.raw_location_a - original.raw_location_a,
                                      modern.raw_location_b - original.raw_location_b],
        'payload': str(payload.relative_to(ROOT)), 'payload_bytes': len(encoded.payload),
        'payload_hex': encoded.payload.hex(), 'payload_sha256': sha(encoded.payload),
        'field_plan': encoded.field_plan, 'expected_native_output_32bytes_hex': expected.hex(),
        'retained_original_label_reference': 'AP ordinal1/ref808→source CP950184號; no new label allocation.',
        'independent_original_native_reader_new_payload_executed': False,
        'original184_native_CPU_identity_verified_here': False,
        'OSM_node_equated_with_stock_record_identity': False,
        'fresh_geographic_point_is_explicit_host_data': True, 'whole2026stock_update': False,
        'whole_IMG_MDR_JAI_writer_or_installer': False, 'installable': False,
        'new_IMG_MAIN_DB_USB_reads_here': False, 'old_scope_or_source_or_canonical_writes': False,
        'limits': ['Exact existing184號 label/template is a bounded host-source witness; original native selected-record proof is a separate scope.',
                   'Only two raw24 fields changed; all names/refs/child/flags and stock files remain unchanged.',
                   'Modern node coordinates use explicit nearest-grid quantization, not a claim about the stock compiler rounding.',
                   'No complete native query/getter/provider/city/street writer, installed map, route acceptance or2026fullstock update.']}
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'prototype': str(output.relative_to(ROOT)), 'prototype_sha256': sha(output.read_bytes()),
        'payload': str(payload.relative_to(ROOT)), 'payload_sha256': sha(encoded.payload),
        'payload_hex': encoded.payload.hex(), 'record': result['record'],
        'raw24_delta_from_original': result['raw24_delta_from_original'],
        'source_sha256': result['source_sha256'], 'original_source_crosschecks': 1,
        'native_new_payload_verified': False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
