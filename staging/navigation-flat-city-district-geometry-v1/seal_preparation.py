#!/usr/bin/env python3
"""Record actual completed executions; seal this narrow geometry/API scope."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def stat_key(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    assert not (HERE / 'actual-receipts.json').exists()
    proof = json.loads((HERE / 'proof.json').read_text())
    tests = json.loads((HERE / 'membership-test-proof.json').read_text())
    assert proof['all_assigned_preparation_checks_passed'] and tests['all_assigned_new_wrapper_controls_passed']
    assert sha((HERE / 'prepare_flat_city_districts.py').read_bytes()) == proof['script_sha256']
    assert sha((HERE / 'test_source_district_membership.py').read_bytes()) == tests['script_sha256']
    assert sha((HERE / 'source_district_membership.py').read_bytes()) == tests['API_sha256']
    assert sha((HERE / 'dataset-pins.json').read_bytes()) == tests['dataset_pins_sha256']
    pins = json.loads((HERE / 'dataset-pins.json').read_text())
    for name, expected in pins['files'].items():
        payload = (HERE / name).read_bytes()
        assert len(payload) == expected['bytes'] and sha(payload) == expected['sha256']
    immutable = []
    for item in proof['source_inputs']:
        current = stat_key(ROOT / item['path'])
        assert current == item['stat_before'] == item['stat_after']
        immutable.append({'path': item['path'], 'bytes': item['bytes'],
                          'sha256_from_completed_preparation_pass': item['sha256'],
                          'stat_at_seal': current, 'unchanged_from_preparation': True})
    assert not (HERE / 'ephemeral-single-district.osm.pbf').exists()
    assert not (HERE / 'ephemeral-single-district.osm.pbf').is_symlink()
    assert not list(HERE.glob('new-wrapper-identity-controls-*'))
    receipt = {
        'schema': 'flat-native-city-source-district-actual-receipts/v1',
        'sealed_utc': datetime.now(timezone.utc).isoformat(),
        'preparation': {
            'command': 'python3 staging/navigation-flat-city-district-geometry-v1/prepare_flat_city_districts.py',
            'initial_exec_chunk_id': 'fe5540', 'session_id': 13237,
            'terminal_write_stdin_chunk_id': 'dc7077', 'actual_exit_code': 0,
            'started_utc': proof['started_utc'], 'finished_utc': proof['finished_utc'],
            'max_RSS_KiB': proof['max_RSS_KiB'],
            'explicit_source_district_relations': proof['source_district_count'],
            'observed_counts_by_source_city': proof['source_district_counts_by_city'],
            'vertices': proof['vertices'], 'native_district_records': 0,
            'osmium_commands_count': len(proof['commands']),
            'osmium_all_actual_exit_codes_zero': all(c['actual_exit_code'] == 0 for c in proof['commands']),
            'osmium_command_stdout_bytes_total': sum(c['stdout_bytes'] for c in proof['commands']),
            'command_receipts': 'proof.json commands plus export_relation_receipts',
            'assigned_input_content_bytes_hashed': sum(c['bytes'] for c in proof['source_inputs']),
            'external_osmium_total_disk_IO_bytes_observed': False,
            'small_source_PBF_bytes': 4349834,
            'small_source_PBF_hash_passes_in_preparation': 1,
            'single_relation_ephemeral_memfd_exports': 24,
            'all_memfds_closed_and_temporary_PBF_symlink_removed': True,
            'complete_original_327MB_PBF_read': False,
            'proof_sha256': sha((HERE / 'proof.json').read_bytes())},
        'new_API_controls': {
            'command': 'python3 staging/navigation-flat-city-district-geometry-v1/test_source_district_membership.py',
            'actual_exec_chunk_id': '944f7b', 'actual_exit_code': 0,
            'started_utc': tests['started_utc'], 'finished_utc': tests['finished_utc'],
            'counts': tests['counts'], 'guard_controls': len(tests['new_guard_controls']),
            'identity_tamper_controls': len(tests['input_identity_tamper_rejections']),
            'temporary_identity_fixtures_removed': True,
            'membership_test_proof_sha256': sha((HERE / 'membership-test-proof.json').read_bytes()),
            'boundary_quantization_rejections_are_address_source_statistics': False},
        'all_existing_source_stats_unchanged_at_seal': True,
        'source_immutability': immutable,
        'native_district_verified': False,
        'closed_Kaohsiung_21city_country_review_suites_rerun': False,
        'address_ready_full_group_node_ledgers_read': False,
        'new_native_records_JAI_IMG_USB_canonical_report_ZIP': False,
        'full_Taiwan_update_complete': False,
        'scope': '24 explicit source district geometries for four originally flat native cities; source/native-grid containment prerequisite API only.'}
    (HERE / 'actual-receipts.json').write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + '\n')
    handoff = """Four native flat cities: explicit source district geometry prerequisite

Source counts: 臺北市 12, 基隆市 7, 新竹市 3, 嘉義市 2. All 24 actual city
subarea relations have complete referenced ways/nodes and closed outer/inner
rings. Each relation was separately exported from the existing 4,349,834-byte
admin PBF, with referenced-object tags removed; duplicate district names across
cities cannot determine feature identity. No source city union was produced.
24 district geometries, 17,912 vertices, district-geometries.json 476,977 bytes.

Original decoded JAI roster evidence: one L1 and zero L2 rows for each city;
district=null L3 named streets are 基隆 251 / 台北 889 / 新竹 500 / 嘉義 458.
This preparation adds source district evidence and does not create or validate
a native district record. native_district_record=null and native_district_verified
false remain explicit in the dataset and every API decision.

API: source_district_membership.py, class SourceDistrictMembership().
assess(city, district, source_latitude, source_longitude) checks the declared
source district. Exact city names are supported, plus the explicitly bound
native literal 台北市 for source 臺北市. All district names must match literally.
No other glyph/name/whitespace aliases or automatic district assignment occur.
assess_source_and_raw24(city, district, source_latitude, source_longitude,
                       [latitude_uint24, longitude_uint24]) requires both points
inside that same declared source district and raw24 exactly rounded from source.
Native-grid containment uses exact rational cross-products, without rounding the
quantized point to seven decimal digits. Boundaries are covered; this does not
resolve shared-boundary or cross-group address conflicts.

An eligible=true result is only a geometry prerequisite; native_merge_eligible
is always false. A future flat-city writer still requires a unique native
city/street record, global (nativeStreetID, house_label) collision guard across
all districts/groups, original house overlap/order/branch checks and numeric
label encoding. Keep the original city→street structure and source district
provenance; do not represent these source districts as existing JAI L2 records.

New controls passed: all 24 geometry-derived source/native pairs; 264 source
signed-winding comparisons; 189 exact rational native-grid comparisons; 24
actual boundary checks; 21 input guards; 5 dataset/engine identity tamper
rejections; 9 rational hole/boundary controls. Twenty-one boundary-derived test
points reject their quantized position: these are new control cases, not
statistics or evidence from any address ledger. All source data remained
unchanged, temporary memfd links and identity fixtures were removed.

Existing sealed general geometry engine and Kaohsiung controls are referenced
by fixed hashes. Their closed suites, the 21-city suite and country review were
not rerun. No address-ready/full source ledger, original 327MB PBF, native map,
JAI or device was read or changed. No new address records or ZIP were produced.
The full Taiwan native address update remains incomplete.

proof.json / membership-test-proof.json retain source hash/stat and new control
evidence. actual-receipts.json records preparation session 13237 / dc7077 EXIT0
and new wrapper controls 944f7b EXIT0. sealed-files.json pins these artifacts.
"""
    (HERE / 'HANDOFF.txt').write_text(handoff)
    filenames = ['prepare_flat_city_districts.py', 'source_district_membership.py',
                 'test_source_district_membership.py', 'seal_preparation.py',
                 'source-membership.json', 'district-geometries.json', 'proof.json',
                 'dataset-pins.json', 'membership-test-proof.json', 'actual-receipts.json', 'HANDOFF.txt']
    files = []
    for filename in filenames:
        payload = (HERE / filename).read_bytes()
        files.append({'path': filename, 'bytes': len(payload), 'sha256': sha(payload)})
    seal = {'schema': 'flat-native-city-source-district-file-seal/v1',
            'sealed_utc': receipt['sealed_utc'], 'all_actual_executions_terminal': True,
            'all_assigned_preparation_and_new_wrapper_checks_passed': True,
            'source_districts': 24, 'native_district_records': 0,
            'native_district_verified': False, 'files': files,
            'full_Taiwan_update_complete': False}
    (HERE / 'sealed-files.json').write_text(json.dumps(seal, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'scope_sealed': True, 'all_source_stats_unchanged': True,
          'source_districts': 24, 'native_district_records': 0,
          'geometry_sha256': next(x['sha256'] for x in files if x['path'] == 'district-geometries.json'),
          'proof_sha256': next(x['sha256'] for x in files if x['path'] == 'proof.json'),
          'seal_sha256': sha((HERE / 'sealed-files.json').read_bytes())}, ensure_ascii=False))


if __name__ == '__main__':
    main()
