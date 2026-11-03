#!/usr/bin/env python3
"""Read three exact original-AP 16-byte ranges planned by stock instructions."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import types

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-AP-target-packed-bytes-v1'
READER = ROOT / 'staging/navigation-AP-provider-records-v1/read_AP_provider_records.py'
PLAN = ROOT / 'staging/navigation-native-AP-packed-reader-v1/original-packed-reader-plan-proof-v1.json'
DIRECTORY = ROOT / 'staging/navigation-AP-provider-records-v1/AP-provider-records-evidence.json'
LINKS = ROOT / 'staging/navigation-JAI-AP-link-samples-v1/JAI-AP-link-samples-evidence.json'
CASES = [('JAI_city_lowID8', 1, 8, 92653250, 6, 16),
         ('JAI_district_lowID88', 2, 88, 92649239, 6, 16),
         ('JAI_central_Minquan_street_lowID16707', 3, 16707, 92215511, 6, 15)]
PINS = {READER: 'e1844c7ab21e7804e151b865dff5db271eca2a501f31c46d54b72f5b492e3e4e',
        PLAN: 'ef3c9b8373aa8fd1471843ef9c08a33c62f39659fd204cb76380921e06de7042',
        DIRECTORY: '32aae3c125bc21ae71d81997d4b7d481cd08686e4b42683b51501adc8b7121dd',
        LINKS: 'a3a5d041d53deadc418dfca52d518f8d7a84cf21eb116616c9e5fb790976998c'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


def main():
    target = OUT / 'target-packed-bytes-evidence.json'
    need(not target.exists(), 'Refusing to overwrite evidence')
    dependencies = [ref(path) for path in PINS]
    need(all(item['sha256'] == PINS[ROOT / item['path']] for item in dependencies), 'Sealed source/proof changed')
    plan = json.loads(PLAN.read_text())
    need(plan['all_cases_passed'] is True and plan['body_bytes_read'] == 0, 'Original read-plan proof mismatch')
    # Validate every case name before opening the IMG or reading any body bytes.
    for name, level, ident, offset, bit, cover in CASES:
        need(len([case for case in plan['cases'] if case['name'] == name]) == 1,
             'Exact stock planner case missing')
    directory = json.loads(DIRECTORY.read_text())
    module = types.ModuleType('sealed_AP_readonly_reader')
    module.__file__ = str(READER)
    exec(compile(READER.read_text(), str(READER), 'exec'), module.__dict__)
    image = module.ReadonlyMDR(ROOT / directory['source_map']['path'])
    before_payload = len(image.read_log)
    rows = []
    try:
        for name, level, ident, offset, bit, cover in CASES:
            matches = [case for case in plan['cases'] if case['name'] == name]
            need(len(matches) == 1, 'Exact stock planner case missing')
            case = matches[0]
            need(case['synthetic_explicit_recordID'] == ident and case['synthetic_explicit_tablelevel'] == level,
                 'Explicit ID/level differs')
            reads = case['original_planned_read']
            need(len(reads) == 1, 'Planner does not describe one exact read')
            original = reads[0]
            need(original['r2_MDR_relative_byte_offset'] == offset and
                 original['r3_initial_bit_offset'] == bit and
                 original['body_bytes_covering_this_one_record'] == cover and
                 original['actual_selected_directory_ordinal_zero_based'] == level - 1,
                 'Actual original planned offset/coverage differs')
            span_start = original['original_directory_span_start']
            span_end = span_start + original['original_directory_span_bytes']
            need(span_start <= offset < offset + 16 <= span_end, 'Initial 16-byte fetch exceeds span')
            data, mapping = image.logical_read(offset, 16, 'target_level' + str(level) + '_ID' + str(ident))
            rows.append({'original_plan_case': name, 'explicit_level': level, 'explicit_low28_ID': ident,
                'logical_key_from_separate_JAI_witness': hex((level << 28) | ident),
                'MDR_relative_offset': offset, 'MDR_relative_offset_hex': hex(offset),
                'initial_bit_offset': bit, 'native_record_cover_bytes': cover,
                'actual_source_read_bytes': 16,
                'reason_16bytes': 'Original bitreader initial filesystem fetch is fixed up to16 bytes; street record needs15 but original fetch requests16.',
                'hex': data.hex(), 'sha256': hashlib.sha256(data).hexdigest(), 'u8': list(data),
                'FAT_mapping': mapping, 'original_plan_observation': original,
                'synthetic_padding_used': False, 'packed_fields_or_positions_decoded': False})
        payload_reads = image.read_log[before_payload:]
        need(sum(r['bytes'] for r in payload_reads) == 48 and len(rows) == 3, 'Bounded body-read budget differs')
        evidence = {'created_utc': datetime.now(timezone.utc).isoformat(),
            'source_sha256': ref(Path(__file__))['sha256'], 'dependencies': dependencies,
            'scope': 'Three exact original-AP 16-byte filesystem ranges for original bitreader; no field decoding.',
            'source_map': directory['source_map'], 'MDR_component': image.component_name,
            'MDR_component_bytes': image.component_bytes, 'records': rows,
            'body_bytes_read': 48, 'read_log': image.read_log,
            'total_actual_map_bytes_read': sum(r['bytes'] for r in image.read_log),
            'new_DB_query_or_codec_suite_rerun': False,
            'original_bitreader_executed_by_this_source_reader': False,
            'JAI_UI_key_to_explicit_level_ID_caller_verified': False,
            'native_fields_house184_label_position_or_route_decoded': False,
            'synthetic_padding_used': False, 'unlock_or_decryption_attempted': False,
            'raw_map_copy': False, 'stock_map_modified': False, 'DB_modified': False, 'device_IO': False,
            'old_proofs_or_canonical_modified': False, 'all_exact_range_and_dependency_checks_passed': True}
        image.close()
        evidence['source_map_stat_unchanged'] = True
        with target.open('x') as stream:
            json.dump(evidence, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
        print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
            'sha256': hashlib.sha256(target.read_bytes()).hexdigest(), 'body_bytes_read': 48,
            'total_actual_map_bytes_read': evidence['total_actual_map_bytes_read'],
            'records': [{'level': r['explicit_level'], 'ID': r['explicit_low28_ID'],
                         'offset': r['MDR_relative_offset'], 'bit': r['initial_bit_offset'],
                         'bytes': 16, 'hex': r['hex']} for r in rows],
            'all_exact_range_and_dependency_checks_passed': True}))
    finally:
        image.stream.close()


if __name__ == '__main__':
    main()
