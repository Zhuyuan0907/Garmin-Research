#!/usr/bin/env python3
"""Finite read-only AP8K metadata comparison; no firmware or device execution."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
PINS = {
    'staging/navigation-country-native-lane-cpu-v3/strict_ap8k_reader.py':
        'fe76a3b33b361d02518f7045b8437db9819b34dffeafd77a0bfb9058af1100ec',
    'staging/navigation-country-native-lane-candidate-v3/proof.json':
        'b5baf538981a60aceb2b8cbb2c31ce3e8159363a719909791e31ef0ca0cb58d0',
    'staging/navigation-country-native-lane-candidate-v3/actual-output-layout.json':
        '4abdc75c4af78dbfcdae421d68e838042e1756f978bff0f342c793bc4d411a9a',
    'staging/navigation-img-capacity-header-comparison-v1/stock-header-comparison.json':
        '0e8a7782717e9c5b3ff6b2bbaf2805ee462b628899c13d50f7720414db35b3ec',
    'staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json':
        '0cae70cbeef21afa1c04786b122b19dd40781539377dc513447eb951e88a2753',
    'staging/navigation-rendering-review-v1/header-inventory.json':
        '6e3d0275b14baa86adc987a8291c02211c0f705952903e24901d9da69bfc41ff',
}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(path, expected=None):
    p = ROOT/path
    raw = p.read_bytes()
    need(expected is None or sha(raw) == expected, 'Dependency digest mismatch: '+path)
    return raw, {'path': path, 'bytes': len(raw), 'sha256': sha(raw)}


def main():
    dependencies = []
    loaded = {}
    for path, expected in PINS.items():
        raw, receipt = pin(path, expected)
        dependencies.append(receipt)
        if path.endswith('.json'):
            loaded[path] = json.loads(raw)
    for path in ['sources/maps/format-reference/ImgHeader.java',
                 'sources/maps/format-reference/TREHeader.java',
                 'staging/navigation-native-address-supplement-v1/manifest.json',
                 'staging/navigation-country-native-candidate-v2/proof.json']:
        raw, receipt = pin(path)
        dependencies.append(receipt)
        if path.endswith('.json'):
            loaded[path] = json.loads(raw)
    module_path = ROOT/'staging/navigation-country-native-lane-cpu-v3/strict_ap8k_reader.py'
    spec = importlib.util.spec_from_file_location('map_disappearance_strict8k', module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    layout = loaded['staging/navigation-country-native-lane-candidate-v3/actual-output-layout.json']
    prior = loaded['staging/navigation-country-native-lane-candidate-v3/proof.json']
    closed_headers = loaded['staging/navigation-img-capacity-header-comparison-v1/stock-header-comparison.json']['headers']
    old = next(x for x in closed_headers if x['source'].endswith('/gmapprom1.img'))
    stock_header = bytes.fromhex(old['header_hex'])
    need(sha(stock_header) == old['header_sha256'], 'Closed stock header digest')
    candidate = ROOT/'staging/navigation-country-native-lane-candidate-v3/gmapprom1.img'
    fresh_stat = module.stat(candidate)
    mapper = module.Candidate8K(candidate, layout, fresh_stat)
    new_header = bytes.fromhex(mapper.header_hex)
    actual = []
    closed = loaded['staging/navigation-AP-mapmetadata-v1/AP-mapmetadata-evidence.json']
    try:
        for key in ['GMP_public_header', 'TRE_public_header', 'TRE_level_table']:
            reference = closed[key]
            receipt, raw = mapper.read(reference['component'], reference['logical_offset'],
                                       reference['bytes'], 'fresh_'+key)
            need(sha(bytes.fromhex(reference['hex'])) == reference['sha256'], 'Closed '+key+' digest')
            need(raw == bytes.fromhex(reference['hex']), 'Fresh v3 differs from original '+key)
            actual.append({'purpose': key, 'equal_to_closed_original_bytes': True, **receipt})
        change_offsets = [i for i, (a, b) in enumerate(zip(stock_header, new_header)) if a != b]
        need(change_offsets == [15, 24, 95, 98, 460], 'Unexpected AP header changes')
        v2 = loaded['staging/navigation-country-native-candidate-v2/proof.json']
        nine = loaded['staging/navigation-native-address-supplement-v1/manifest.json']
        new_components = prior['complete_actual_component_checks']
        old_components = {x['name']: x for x in v2['component_checks']}
        for item in new_components:
            if item['name'].endswith('.MDR'):
                continue
            old_item = old_components[item['name']]
            need(item['all_actual_component_bytes_readback'] and item['unchanged'] and
                 old_item['unchanged_from_stock'] and item['bytes'] == old_item['bytes'] and
                 item['sha256'] == old_item['sha256'], 'Closed complete component preservation chain')
        need(nine['GMP_and_other_components_unchanged'], 'Nine-house closed display preservation claim')
        summaries = []
        for name, component in mapper.components.items():
            blocks = component['blocks']
            summaries.append({'name': name, 'logical_bytes': component['bytes'],
                              'allocated_8K_blocks': len(blocks),
                              'continuation_rows': len(component['parts']),
                              'first_allocated_block': blocks[0], 'last_allocated_block': blocks[-1],
                              'tail_padding_bytes': len(blocks)*8192-component['bytes'],
                              'first_row_nonallocation_0_to_32_hex': component['parts'][0]['row_hex'][:64]})
        read_log = list(mapper.log)
        mapper.close()
    except BaseException:
        mapper.stream.close()
        raise
    tre = bytes.fromhex(actual[1]['hex'])
    inventory = loaded['staging/navigation-rendering-review-v1/header-inventory.json']['headers']
    osm = next(x for x in inventory if x['path'].endswith('/70530020.img'))['TRE_headers'][0]
    proof = {
        'schema': 'garmin-map-disappearance-metadata/v1',
        'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'scope': 'Fresh finite completed v3 AP8K FAT/header/GMP/TRE reads against closed original public bytes; no rendering firmware/device execution.',
        'source': {'path': str(Path(__file__).relative_to(ROOT)), 'sha256': sha(Path(__file__).read_bytes())},
        'dependencies': dependencies,
        'candidate': {'path': str(candidate.relative_to(ROOT)), 'bytes': fresh_stat[2],
                      'sha256_inherited_from_closed_full_readback': prior['candidate_sha256'],
                      'whole_candidate_hash_repeated': False, 'fresh_stat_before_and_after': fresh_stat,
                      'handle_closed': mapper.stream.closed},
        'actual_candidate_bytes_read': sum(x['bytes'] for x in read_log),
        'actual_read_log': read_log,
        'strict_8K_FAT_validation_passed': True,
        'metadata_prefix_sha256': mapper.metadata_sha256,
        'directory_extent': mapper.extent,
        'components': summaries,
        'header_change_offsets_decimal': change_offsets,
        'header_changes': [{'offset_decimal': i, 'offset_hex': hex(i),
                            'stock': stock_header[i], 'v3': new_header[i]} for i in change_offsets],
        'requested_header_fields': [
            {'offset_decimal': i, 'offset_hex': hex(i), 'stock': stock_header[i],
             'v3': new_header[i], 'unchanged': stock_header[i] == new_header[i]}
            for i in sorted(set([32,39,40,41,0x32,0x39,0x40,0x41]))],
        'new_header_hex': new_header.hex(),
        'public_GMP_TRE_level_readback': actual,
        'all_five_non_MDR_component_bytes_unchanged_closed_proof_chain': True,
        'nine_house_GMP_preservation_closed_manifest_claim': True,
        'TRE_raw_fields': {'header_bytes': len(tre), 'flags_byte13': tre[13],
                           'poi_flags_byte63': tre[63],
                           'priority_u24_at64': int.from_bytes(tre[64:67], 'little'),
                           'transparent_bit_under_mkgmap_convention': bool(tre[63] & 2),
                           'map_ID_low28_at116': struct.unpack_from('<I',tre,116)[0] & 0xfffffff,
                           'all_equal_to_original_AP': True},
        'closed_OSM_representative_TRE': {'path': 'staging/navigation-repair-v2/compiled/70530020.img',
                                         'header_length': osm['header_length'],
                                         'poi_flags': osm['poi_flags'],
                                         'display_priority': osm['display_priority'],
                                         'new_OSM_reads_performed': False},
        'primary_source_interpretation_limits': [
            'ImgHeader.java is mkgmap filesystem format source, not the Garmin drawing dispatcher.',
            'TREHeader.java defines bit0x2 transparency and the generic three-byte priority field; vendor 289-byte AP rendering semantics are not executed here.',
            'No new transparency or priority byte was introduced by the v3 MDR/container change.',
            'Strict FAT and original public-header equality do not establish actual Garmin drawing acceptance.',
            'Header checksum byte15 algorithm remains unknown; zero is a deliberate writer choice, not a verified original checksum.',
            'The original CN image on this unit also uses 8K blocks, but that alone does not establish AP8K renderer compatibility.',
        ],
        'parent_reported_physical_observations_not_new_device_IO': [
            'Search v2 alone displays roads; adding installed v3 AP removes that drawing.',
            'Enabling stock CN together with AP and Search v2 restores the displayed map.',
        ],
        'least_change_temporary_configuration': 'Keep the already physically confirmed CN+AP+Search v2 selection while diagnosis is pending.',
        'minimal_discriminating_next_test': 'Use the existing exact-stock AP rollback, then at the same place/zoom test original AP+Search v2 with CN off. If it still disappears, original AP/OSM coexistence semantics suffice; if it restores, the v3 MDR/container combination is implicated but 8K alone is not yet isolated.',
        'not_a_proved_fix': True,
        'drawing_dispatcher_ABI_verified': False,
        'device_IO': False,
        'firmware_or_map_modified': False,
        'performance_branch_reopened': False,
        'all_assigned_metadata_comparisons_passed': True,
    }
    target = OUT/'proof.json'
    need(not target.exists(), 'Do not overwrite emitted diagnostic proof')
    target.write_text(json.dumps(proof, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'all_assigned_metadata_comparisons_passed': True,
                      'candidate_bytes_read': proof['actual_candidate_bytes_read'],
                      'candidate_handle_closed': mapper.stream.closed,
                      'header_changes': change_offsets,
                      'proof_sha256': sha(target.read_bytes())}))


if __name__ == '__main__':
    main()
