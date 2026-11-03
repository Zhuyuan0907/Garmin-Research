#!/usr/bin/env python3
"""Two true AP LBL windows for original level4 boundary references only."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-level4-label-windows-v1'
HELPER = ROOT / 'staging/navigation-AP-mapmetadata-v1/read_AP_mapmetadata.py'
HEADER = ROOT / 'staging/navigation-AP-LBL-header-v1/AP-LBL-header-evidence.json'
LEVEL4 = ROOT / 'staging/navigation-native-AP-level4-records-v1/original-level4-boundary-records-proof-v3.json'
TEXTCHOICE = ROOT / 'staging/navigation-native-AP-text-reference-v1/original-text-reference-consumer-proof-v1.json'


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'level4-label-window-source-proof-v1.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    for path, expected in [(HELPER, '31c9ec231ab862ab6477c5399b5a79139e7536284120a9f23629e16935cf8ffb'),
                           (HEADER, 'dd14408a357d5587d8a4c4d72f4eb3f70b21296c1022bc95e35ad6afba606a7e'),
                           (LEVEL4, '10a9036cf74be7c26c4b724665c128914db0cef0d492bd8433d7147938f1a19a'),
                           (TEXTCHOICE, '64087eb40410d38f630c8da85b0e8377bd1e67c643d1c8f7112d83b00da5b480')]:
        need(ref(path)['sha256'] == expected, 'Frozen dependency changed: ' + str(path))
    header = json.loads(HEADER.read_text())
    decoded = json.loads(LEVEL4.read_text())
    choice = json.loads(TEXTCHOICE.read_text())
    need(decoded['all_cases_passed'] and choice['all_cases_passed'], 'Native frozen proofs incomplete')
    obs = header['public_LBL_header']['field_observations']
    start, size, shift = obs['u32_LE_at21'], obs['u32_LE_at25'], obs['u8_at29']
    need((start, size, shift, obs['u8_at30'], obs['u16_LE_at170']) == (6566, 3805432, 3, 10, 950),
         'Original header contract differs')
    cases = decoded['cases']
    need(len(cases) == 2, 'Unexpected level4 case count')
    inputs = []
    for c, expected in zip(cases, [('selected_street_child_first', 904706, 179, 7998),
                                 ('selected_street_child_last', 904789, 834, 13238)]):
        name, lowID, labelref, offset = expected
        fields = c['native_fields']
        need(c['name'] == name and c['explicit_level'] == 4 and c['explicit_low28_ID'] == lowID and
             fields['+08'] == 1 and fields['+10'] == labelref, 'Original selected reference differs')
        computed = start + ((labelref & 0x3fffff) << shift)
        need(computed == offset and start <= offset <= offset + 64 <= start + size,
             'Computed reference outside original label bounds')
        inputs.append({'name': name, 'explicit_source_level': 4, 'explicit_source_lowID': lowID,
                       'mapordinal': 1, 'selected_CP950_primary_reference': labelref,
                       'alternate_reference': fields['+1c'], 'GMP_logical_offset': offset})
    module = types.ModuleType('frozen_bounded_IMG_reader')
    module.__dict__['__file__'] = str(HELPER)
    exec(compile(HELPER.read_text(), str(HELPER), 'exec'), module.__dict__)
    image = module.BoundedIMG()
    try:
        outputs = []
        for inp in inputs:
            source, raw = image.read('I053061A.GMP', inp['GMP_logical_offset'], 64, inp['name'] + '_label_window')
            boundary = raw.find(b'\0')
            need(boundary >= 0, 'No NUL within bounded label window')
            first = raw[:boundary]
            host_text = first.decode('cp950', errors='strict')
            outputs.append({**inp, **source, 'window_read_upper_bound': 64,
                'first_NUL_relative_offset': boundary, 'first_NUL_GMP_logical_offset': inp['GMP_logical_offset'] + boundary,
                'first_NUL_terminated_bytes_hex': first.hex(), 'host_strict_CP950_display': host_text,
                'host_strict_CP950_roundtrip_matches': host_text.encode('cp950', errors='strict') == first,
                'original_DBCS_or_getter_executed_here': False,
                'record_level_meaning_named_here': False})
            need(outputs[-1]['host_strict_CP950_roundtrip_matches'], 'Strict CP950 roundtrip differs')
        need(sum(r['bytes'] for r in image.log) == 54400, 'Actual read budget differs')
        image.close()
        proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
            'scope': 'Only original AP CP950 primary refs179/834 for two original level4 boundary records.',
            'dependencies': [ref(HELPER), ref(HEADER), ref(LEVEL4), ref(TEXTCHOICE)],
            'source_map': {**header['source_map'], 'stat_unchanged': True},
            'frozen_public_LBL_parameters_reused': {'labelStart': start, 'labelSize': size, 'shift': shift,
                'encoding': 10, 'codepage': 950, 'header_not_reread': True},
            'positive_reference_formula': 'GMP_absolute_offset = labelStart + ((reference & 0x3FFFFF) << shift)',
            'CP950_source_field_choice': 'native output +10 primary, frozen original generic CP950 choice; +1C alternate not read',
            'cases': outputs, 'actual_map_read_log': image.log, 'new_label_payload_bytes_read': 128,
            'total_map_bytes_read_including_FAT': 54400, 'previous_three_references_or_header_reread': False,
            'other_level4_records_or_level6_body_read': False, 'whole_map_digest_repeated': False,
            'host_display_is_not_original_native_DBCS_execution': True,
            'new_IMG_source_body_only_not_whole_NT_decoding': True,
            'record_level_meaning_named_here': False, 'full_native_query_or_route_executed': False,
            'stock_map_or_DB_modified': False, 'unlock_or_decryption_performed': False,
            'device_IO': False, 'all_bounded_source_and_strict_CP950_checks_passed': True}
        with target.open('x') as f:
            json.dump(proof, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'new_label_payload_bytes_read': 128,
            'cases': [{'reference': c['selected_CP950_primary_reference'], 'GMP_offset': c['GMP_logical_offset'],
                       'NUL_offset': c['first_NUL_relative_offset'], 'bytes_before_NUL_hex': c['first_NUL_terminated_bytes_hex'],
                       'host_strict_CP950_display': c['host_strict_CP950_display']} for c in outputs],
            'all_bounded_source_and_strict_CP950_checks_passed': True}, ensure_ascii=False))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
