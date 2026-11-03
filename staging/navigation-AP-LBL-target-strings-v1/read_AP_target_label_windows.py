#!/usr/bin/env python3
"""Read three native-selected CP950 references via actual LBL header fields."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import struct
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-LBL-target-strings-v1'
HELPER = ROOT / 'staging/navigation-AP-mapmetadata-v1/read_AP_mapmetadata.py'
HEADER = ROOT / 'staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json'
NATIVE = ROOT / 'staging/navigation-native-AP-text-reference-v1/original-text-reference-consumer-proof-v1.json'


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'AP-target-label-windows-evidence.json'
    need(not target.exists(), 'Refusing to overwrite source evidence')
    need(ref(HELPER)['sha256'] == '31c9ec231ab862ab6477c5399b5a79139e7536284120a9f23629e16935cf8ffb',
         'Frozen bounded IMG reader changed')
    need(ref(HEADER)['sha256'] == 'dd14408a357d5587d8a4c4d72f4eb3f70b21296c1022bc95e35ad6afba606a7e',
         'Frozen original LBL header changed')
    need(ref(NATIVE)['sha256'] == '64087eb40410d38f630c8da85b0e8377bd1e67c643d1c8f7112d83b00da5b480',
         'Frozen original reference consumer changed')
    header = json.loads(HEADER.read_text())
    native = json.loads(NATIVE.read_text())
    need(native['all_cases_passed'], 'Native reference consumer incomplete')
    obs = header['public_LBL_header']['field_observations']
    start, size, shift = obs['u32_LE_at21'], obs['u32_LE_at25'], obs['u8_at29']
    need((start, size, shift, obs['u8_at30'], obs['u16_LE_at170']) == (6566, 3805432, 3, 10, 950),
         'Actual original header contract changed')
    selected = [c for c in native['actual_original_fragment_cases'] if c['scope'] == 'stock_CP950']
    need([(c['parent_explicit_level'], c['parent_lowID'], c['original_pregetter_call']['selected_reference'])
          for c in selected] == [(1, 8, 12), (2, 88, 14), (3, 16707, 206)], 'Native source references differ')
    planned = []
    for c in selected:
        call = c['original_pregetter_call']
        need(call['mapordinal'] == 1, 'Unexpected map ordinal')
        reference = call['selected_reference'] & 0x3fffff
        offset = start + (reference << shift)
        need(start <= offset <= offset + 32 <= start + size, 'Reference window outside LBL string bounds')
        planned.append({'parent_explicit_level': c['parent_explicit_level'], 'parent_lowID': c['parent_lowID'],
            'mapordinal': 1, 'selected_reference': call['selected_reference'],
            'masked_22bit_reference': reference, 'GMP_logical_offset': offset, 'window_bytes': 32})
    # First two 32-byte windows overlap by16. Read their48-byte union once.
    need(planned[0]['GMP_logical_offset'] == 6662 and planned[1]['GMP_logical_offset'] == 6678 and
         planned[2]['GMP_logical_offset'] == 8214, 'Unexpected bounded target windows')
    module = types.ModuleType('frozen_bounded_IMG_reader')
    module.__dict__['__file__'] = str(HELPER)
    exec(compile(HELPER.read_text(), str(HELPER), 'exec'), module.__dict__)
    image = module.BoundedIMG()
    try:
        cluster, cluster_raw = image.read('I053061A.GMP', 6662, 48, 'city_district_overlapping_window_union')
        street, street_raw = image.read('I053061A.GMP', 8214, 32, 'street_reference206_window')
        windows = [cluster_raw[:32], cluster_raw[16:48], street_raw]
        outputs = []
        for plan, raw in zip(planned, windows):
            terminator = raw.find(b'\0')
            text_bytes = raw[:terminator] if terminator >= 0 else raw
            try:
                text, error = text_bytes.decode('cp950', errors='strict'), None
            except UnicodeDecodeError as exc:
                text, error = None, str(exc)
            outputs.append({**plan, 'hex': raw.hex(), 'sha256': hashlib.sha256(raw).hexdigest(),
                'first_zero_byte_relative_offset': terminator if terminator >= 0 else None,
                'first_zero_terminated_bytes_hex': text_bytes.hex(), 'host_strict_CP950_display': text,
                'host_strict_CP950_display_error': error,
                'original_DBCS_parser_executed_here': False,
                'first_zero_terminated_bytes_equal_native_full_text_not_proven_here': True})
        need(sum(r['bytes'] for r in image.log) == 54352, 'Unexpected actual source read budget')
        image.close()
        proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
            'scope': 'Three original CP950-selected city/district/street label windows; only80 distinct source bytes.',
            'dependencies': [ref(HELPER), ref(HEADER), ref(NATIVE)], 'source_map': header['source_map'],
            'reference_mapping_contract': {'public_header_start': start, 'public_header_size': size,
                'public_header_shift': shift, 'reference_mask': '0x3FFFFF',
                'formula': 'GMP_absolute_offset = labelStart + ((positive_reference & 0x3FFFFF) << shift)',
                'original_static_caller': '0x1AFB82..9C mask22bits then 0x2BF5F4(kind5)',
                'original_static_reader': '0x044C0ED6..0EFA reference<<object_shift plus object_labelStart',
                'original_static_parser': '0x2CF43A reads LBLbase+21/10bytes then 0x2CF44A..45A stores fields',
                'original_instruction_ABI_executed_in_separate_peer_scope': True,
                'complete_registry_or_native_metadata_function_executed_here': False},
            'actual_read_unions': [cluster, street], 'cases': outputs,
            'actual_map_read_log': image.log, 'actual_unique_label_payload_bytes_read': 80,
            'logical_reference_window_bytes': 96, 'overlapping_window_bytes_saved': 16,
            'total_map_bytes_read_including_FAT': 54352, 'original_map_stat_unchanged': True,
            'whole_map_digest_repeated': False, 'label_reference_is_bare_file_offset': False,
            'original_native_DBCS_or_query_executed_here': False,
            'names_or_CP950_conversion_inferred_from_strings_only': False,
            'stock_map_or_DB_modified': False, 'unlock_or_decryption_performed': False,
            'device_IO': False, 'physical_search_or_routing_verified_here': False,
            'all_bounded_source_and_reference_checks_passed': True}
        with target.open('x') as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'actual_unique_label_payload_bytes_read': 80,
            'labels': [{'ref': c['selected_reference'], 'offset': c['GMP_logical_offset'],
                        'window_hex': c['hex'], 'host_CP950_display': c['host_strict_CP950_display']} for c in outputs],
            'all_bounded_source_and_reference_checks_passed': True}, ensure_ascii=False))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
