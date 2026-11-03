#!/usr/bin/env python3
"""Exactly two original level4 records selected by the original child reader."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-level4-boundary-bytes-v1'
READER = ROOT / 'staging/navigation-AP-provider-records-v1/read_AP_provider_records.py'
PLAN = ROOT / 'staging/navigation-native-AP-child-range-v1/original-child-range-and-level4-plans-proof-v1.json'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'level4-boundary-bytes-evidence.json'
    need(not target.exists(), 'Refusing to overwrite output')
    need(ref(READER)['sha256'] == 'e1844c7ab21e7804e151b865dff5db271eca2a501f31c46d54b72f5b492e3e4e',
         'Frozen bounded FAT reader changed')
    need(ref(PLAN)['sha256'] == 'a3cbaf0bb87b16c39d59f2078b283bad7d0fbadec3ebb6ec1eabfe996620a4d9',
         'Frozen native child range / original read-plan proof changed')
    plan = json.loads(PLAN.read_text())
    need(plan['all_cases_passed'] and plan['new_IMG_payload_bytes_read'] == 0,
         'Native original plans incomplete')
    cases = plan['newly_executed_child_reader_plans']
    need(len(cases) == 2, 'Unexpected plan count')
    expected = [('selected_street_child_first', 904706, 72315828),
                ('selected_street_child_last', 904789, 72317156)]
    for c, (name, lowID, offset) in zip(cases, expected):
        r = c['original_planned_read']
        need(c['name'] == name and c['explicit_level'] == 4 and
             c['explicit_low28_ID'] == lowID and c['required_body_bytes'] == 16 and
             r['r2_MDR_relative_byte_offset'] == offset and r['r3_initial_bit_offset'] == 0,
             'Bounded plan inputs differ')
    module = types.ModuleType('frozen_bounded_MDR_reader')
    module.__dict__['__file__'] = str(READER)
    exec(compile(READER.read_text(), str(READER), 'exec'), module.__dict__)
    image = module.ReadonlyMDR(module.MAP_PATH)
    try:
        outputs = []
        for c in cases:
            offset = c['original_planned_read']['r2_MDR_relative_byte_offset']
            raw, mapping = image.logical_read(offset, 16, c['name'])
            outputs.append({'name': c['name'], 'explicit_level': c['explicit_level'],
                'explicit_low28_ID': c['explicit_low28_ID'], 'MDRrelative_byte_offset': offset,
                'initial_bit_offset': 0, 'bytes': 16, 'hex': raw.hex(),
                'sha256': hashlib.sha256(raw).hexdigest(), 'FAT_mapping': mapping,
                'record_field_semantics_decoded_or_named_here': False})
        need(sum(r['bytes'] for r in image.read_log) == 54304, 'Unexpected source read budget')
        image.close()
        evidence = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
            'scope': 'Only first and last original level4 child records for selected stock Minquan street; no intervening records.',
            'dependencies': [ref(READER), ref(PLAN)],
            'source_map': {'path': str(module.MAP_PATH.relative_to(ROOT)),
                'bytes': module.MAP_PATH.stat().st_size,
                'verified_backup_sha256_reference': '864d128f8d4660570d443b2e14772c9c5356ebdf0bbb6a5891f3318b836053c2',
                'whole_map_digest_repeated': False, 'stat_unchanged': True},
            'selected_child_range': {'explicit_level': 4, 'first_ID': 904706,
                'last_inclusive_ID': 904789, 'record_count': 84, 'entire_range_read': False},
            'cases': outputs, 'actual_source_read_log': image.read_log,
            'body_bytes_read': 32, 'total_map_bytes_read_including_FAT': 54304,
            'stock_record_field_semantics_confirmed_here': False,
            'children_named_houses_here': False, 'original_native_reader_executed_here': False,
            'stock_map_or_DB_modified': False, 'whole_AP_decoded': False,
            'unlock_or_decryption_performed': False, 'device_IO': False,
            'physical_query_or_routing_verified_by_this_probe': False,
            'old_checks_or_reads_replayed': False, 'all_bounded_source_checks_passed': True}
        with target.open('x') as f:
            json.dump(evidence, f, ensure_ascii=False, indent=2)
            f.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'body_bytes_read': 32,
            'cases': [{'name': c['name'], 'MDRrelative_byte_offset': c['MDRrelative_byte_offset'],
                       'hex': c['hex']} for c in outputs], 'all_bounded_source_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
