#!/usr/bin/env python3
"""Prepare source district geometry for four native city→street layouts only."""
from collections import Counter
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
PINS = {
    'staging/navigation-repair-v1/taiwan-admin-selected-from-source.osm.pbf':
        (4349834, '5b8cd8d1de51a55446abc2d42164244c909e1bc70cadc55fe20fd9808e949c7d'),
    'staging/navigation-road-coverage-v1/native-all-city-closure-proof.json':
        (143946, 'e28ce491a3463c3aebb6662b304270aae02596240de8d40ce092af13d77f438a'),
    'staging/navigation-road-coverage-v1/native-taiwan-admin-roots.json':
        (45537, '4a66ad7483723dd2f6935f96697f4482829c4e29581da438a90dfec21b0d52c4'),
    'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz':
        (1210093, '45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776'),
    'scripts/prepare_taichung_city_geometry_v1.py':
        (5776, '2fff38c613a41017553f8a59978b85811fce6b118b6db87cfc07fe1e17d74101'),
    'staging/navigation-kaohsiung-district-geometry-v1/district_membership.py':
        (6731, 'c99ba1ad496356ca389f0bd8a8f1c7b00929a216066b7ed05a6c100359d0e998'),
    'staging/navigation-kaohsiung-district-geometry-v1/sealed-files.json':
        (1932, '3cffbeb8246e8f87428ce1fe376f1b2de1922f37d6386575be993a7c56095541'),
    'staging/navigation-kaohsiung-district-geometry-v1/membership-test-proof.json':
        (9031, '21b7de4d24627719668b71925fdd4e75c7d32e86b0bb0c1f49eeefe47dfd79bf'),
    'staging/navigation-country-city-geometry-v1/proof.json':
        (1740, 'de9a7dc37f8506fe137480b1d79dd4235e4ac721356586c5e3db17a5a20033f3'),
}
CITY_BINDINGS = {
    '臺北市': {'native_city': '台北市', 'relation_id': 1293250},
    '基隆市': {'native_city': '基隆市', 'relation_id': 1296154},
    '新竹市': {'native_city': '新竹市', 'relation_id': 2849488},
    '嘉義市': {'native_city': '嘉義市', 'relation_id': 2790418},
}
SOURCE = ROOT / next(iter(PINS))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def tags(relation):
    return {item.attrib['k']: item.attrib['v'] for item in relation.findall('tag')}


def save(name, value):
    with (OUT / name).open('xb') as handle:
        handle.write(canonical(value) + b'\n')
        handle.flush()
        os.fsync(handle.fileno())


def main():
    assert not (OUT / 'proof.json').exists(), 'New preparation scope only'
    started = datetime.now(timezone.utc).isoformat()
    snapshots = {}
    inputs = []
    data = {}
    for relative, (size, digest) in PINS.items():
        path = ROOT / relative
        before = signature(path)
        payload = path.read_bytes()
        assert len(payload) == size and sha(payload) == digest, relative
        assert before == signature(path)
        snapshots[relative] = before
        inputs.append({'path': relative, 'bytes': size, 'sha256': digest,
                       'stat_before': before, 'stat_after': before, 'stat_unchanged': True})
        if not relative.endswith('.pbf'):
            data[relative] = payload
    engine_relative = 'scripts/prepare_taichung_city_geometry_v1.py'
    spec = importlib.util.spec_from_file_location('flat_city_pinned_membership_engine', ROOT / engine_relative)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    inherited_tests = json.loads(data['staging/navigation-kaohsiung-district-geometry-v1/membership-test-proof.json'])
    assert inherited_tests['all_assigned_new_controls_passed']
    inherited_seal = json.loads(data['staging/navigation-kaohsiung-district-geometry-v1/sealed-files.json'])
    assert inherited_seal['all_actual_handles_terminal']
    for filename, relative in [('district_membership.py', 'staging/navigation-kaohsiung-district-geometry-v1/district_membership.py'),
                               ('membership-test-proof.json', 'staging/navigation-kaohsiung-district-geometry-v1/membership-test-proof.json')]:
        item = next(x for x in inherited_seal['files'] if x['path'] == filename)
        assert (item['bytes'], item['sha256']) == PINS[relative]
    city_proof = json.loads(data['staging/navigation-country-city-geometry-v1/proof.json'])
    assert city_proof['all_assigned_checks_passed']
    closure_data = json.loads(data['staging/navigation-road-coverage-v1/native-all-city-closure-proof.json'])
    closures = {r['id']: r for r in closure_data['roots']}
    assert len(closures) == len(closure_data['roots'])
    roots = json.loads(data['staging/navigation-road-coverage-v1/native-taiwan-admin-roots.json'])
    root_rows = {r['name']: r for r in roots['municipality_city_roots']}
    native_counts = {b['native_city']: Counter() for b in CITY_BINDINGS.values()}
    native_roots = {}
    native_street_ranges = {}
    roster = data['staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz']
    hierarchy_rows = 0
    for line in gzip.decompress(roster).splitlines():
        r = json.loads(line)
        hierarchy_rows += 1
        city = r.get('city')
        if city not in native_counts:
            continue
        native_counts[city][r['level']] += 1
        if r['level'] == 1:
            assert city not in native_roots and r['raw_name'] == city
            native_roots[city] = r
        elif r['level'] == 3:
            assert r['district'] is None and r['street'] == r['raw_name']
            native_street_ranges.setdefault(city, []).append(r['record'])
        else:
            raise AssertionError('Unexpected native district under flat city')
    assert len(native_roots) == 4
    for city, counts in native_counts.items():
        assert counts[1] == 1 and counts[2] == 0 and counts[3] > 0
    commands = []

    def run(command, **kwargs):
        r = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, **kwargs)
        commands.append({'argv': command, 'actual_exit_code': r.returncode,
                         'stdout_bytes': len(r.stdout), 'stdout_sha256': sha(r.stdout),
                         'stderr_bytes': len(r.stderr), 'stderr_text': r.stderr.decode(errors='replace')})
        assert r.returncode == 0, commands[-1]
        return r.stdout

    parent_ids = [b['relation_id'] for b in CITY_BINDINGS.values()]
    parent_xml = run(['osmium', 'getid', '-f', 'osm', str(SOURCE), *['r' + str(i) for i in parent_ids]])
    parents = {int(r.attrib['id']): r for r in ET.fromstring(parent_xml).findall('relation')}
    assert set(parents) == set(parent_ids)
    subarea_to_city = {}
    parent_memberships = {}
    for source_city, binding in CITY_BINDINGS.items():
        relation_id = binding['relation_id']
        parent = parents[relation_id]
        t = tags(parent)
        assert t['name'] == source_city and t['type'] == 'boundary'
        assert t['boundary'] == 'administrative' and t['admin_level'] == '4'
        assert root_rows[source_city]['id'] == relation_id
        assert closures[relation_id]['name'] == source_city
        assert closures[relation_id]['complete_reference_closed_geometry']
        subareas = [m for m in parent.findall('member') if m.attrib['role'] == 'subarea']
        assert subareas and all(m.attrib['type'] == 'relation' for m in subareas)
        ids = [int(m.attrib['ref']) for m in subareas]
        assert len(ids) == len(set(ids))
        for child_id in ids:
            assert child_id not in subarea_to_city
            subarea_to_city[child_id] = source_city
        city = binding['native_city']
        parent_memberships[source_city] = {
            'source_city': source_city, 'source_parent_relation_id': relation_id,
            'source_parent_tags': t, 'source_parent_closure': closures[relation_id],
            'source_subarea_relation_ids': sorted(ids), 'source_subarea_count': len(ids),
            'native_city': city, 'native_city_row': native_roots[city],
            'native_level_counts': dict(native_counts[city]),
            'native_named_street_records': len(native_street_ranges[city]),
            'native_street_record_min': min(native_street_ranges[city]),
            'native_street_record_max': max(native_street_ranges[city]),
            'native_district_records': 0, 'native_city_to_street_layout': True,
            'city_name_binding': 'Literal names joined by the explicit existing 臺/台 host policy only.'
        }
    child_xml = run(['osmium', 'getid', '-f', 'osm', str(SOURCE),
                     *['r' + str(i) for i in sorted(subarea_to_city)]])
    children = {int(r.attrib['id']): r for r in ET.fromstring(child_xml).findall('relation')}
    assert set(children) == set(subarea_to_city)
    rows = []
    for relation_id, source_city in sorted(subarea_to_city.items()):
        t = tags(children[relation_id])
        assert t['type'] == 'boundary' and t['boundary'] == 'administrative' and t['admin_level'] == '7'
        name = t['name']
        cl = closures[relation_id]
        assert name == cl['name'] and cl['complete_reference_closed_geometry']
        assert not cl['missing_way_ids'] and not cl['missing_node_ids']
        assert all(not role['open_chains'] for role in cl['roles'].values())
        binding = CITY_BINDINGS[source_city]
        rows.append({'source_city': source_city, 'district': name,
                     'source_parent_relation_id': binding['relation_id'], 'source_relation_id': relation_id,
                     'source_relation_tags': t, 'source_admin_level': t['admin_level'],
                     'parent_subarea_membership_verified': True, 'closure': cl,
                     'native_city': binding['native_city'], 'native_city_record': native_roots[binding['native_city']]['record'],
                     'native_district_record': None, 'native_district_verified': False})
    assert len({(r['source_city'], r['district']) for r in rows}) == len(rows)
    assert len(rows) == 24 and {c: p['source_subarea_count'] for c, p in parent_memberships.items()} == {
        '臺北市': 12, '基隆市': 7, '新竹市': 3, '嘉義市': 2}, 'Observed counts differ from expected; inspect before continuing'
    save('source-membership.json', {'schema': 'flat-native-city-explicit-source-district-membership/v1',
         'source_cities': parent_memberships, 'districts': rows,
         'actual_parent_subarea_count': len(rows), 'native_district_records_total': 0,
         'source_membership_authority': 'Actual named source-city relation subarea members in pinned 4.35MB admin PBF.',
         'native_hierarchy_evidence': 'Pinned decoded original JAI roster: one L1, no L2 and only district=null L3 rows for each of four cities.',
         'native_district_membership_proved': False, 'source_to_native_city_policy': 'Explicit native/source root identity; only 臺/台 spelling difference for Taipei.'})
    geometries = {city: {} for city in CITY_BINDINGS}
    vertices = 0
    subsets = []
    for row in rows:
        relation_id = row['source_relation_id']
        # One explicit relation per export prevents duplicate district names in
        # different cities being joined by name alone. Referenced objects lose tags.
        subset = run(['osmium', 'getid', '-r', '-t', '-f', 'pbf', str(SOURCE), 'r' + str(relation_id)])
        assert 0 < len(subset) <= PINS[next(iter(PINS))][0]
        fd = os.memfd_create('flat-city-district-' + str(relation_id), flags=0)
        link = OUT / 'ephemeral-single-district.osm.pbf'
        assert not link.exists() and not link.is_symlink()
        try:
            with os.fdopen(os.dup(fd), 'wb') as memory:
                memory.write(subset)
                memory.flush()
            os.lseek(fd, 0, os.SEEK_SET)
            link.symlink_to('/proc/self/fd/' + str(fd))
            exported = run(['osmium', 'export', '-F', 'pbf', '--geometry-types=polygon', '-u', 'type_id',
                            '--stop-on-error', '-f', 'geojsonseq', str(link)], pass_fds=(fd,))
        finally:
            if link.is_symlink():
                link.unlink()
            os.close(fd)
        features = [json.loads(line.lstrip(b'\x1e')) for line in exported.splitlines() if line.lstrip(b'\x1e').strip()]
        assert len(features) == 1, (relation_id, row['district'], len(features))
        f = features[0]
        props = f['properties']
        assert props['name'] == row['district'] and str(props['admin_level']) == '7'
        assert props['boundary'] == 'administrative'
        geometry = f['geometry']
        if geometry['type'] == 'Polygon':
            geometry = {'type': 'MultiPolygon', 'coordinates': [geometry['coordinates']]}
        assert geometry['type'] == 'MultiPolygon' and geometry['coordinates']
        assert len(geometry['coordinates']) == row['closure']['roles']['outer']['closed_rings']
        assert sum(len(p) - 1 for p in geometry['coordinates']) == row['closure']['roles']['inner']['closed_rings']
        for polygon in geometry['coordinates']:
            assert polygon
            for ring in polygon:
                assert len(ring) >= 4 and ring[0] == ring[-1]
                vertices += len(ring)
                for lon, lat in ring:
                    assert -180 <= lon <= 180 and -90 <= lat <= 90
                    engine.integer_coordinate(lon)
                    engine.integer_coordinate(lat)
        engine.CityGeometry(geometry)
        geometries[row['source_city']][row['district']] = dict(row, geometry_sha256=sha(canonical(geometry)),
            geometry=geometry, export_area_id=f['id'], export_identity_method='Single explicitly tagged relation export; no area-id→relation formula or name-only cross-city join.')
        subsets.append({'source_relation_id': relation_id, 'subset_bytes': len(subset),
                        'subset_sha256': sha(subset), 'export_bytes': len(exported),
                        'export_sha256': sha(exported), 'export_features': 1,
                        'ephemeral_memfd_closed_and_link_removed': True})
    save('district-geometries.json', {'schema': 'flat-native-city-explicit-source-district-geometries/v1',
        'source_cities': geometries, 'district_count': len(rows), 'native_district_records_total': 0,
        'source_district_membership_only': True, 'native_district_membership_proved': False,
        'city_union_created': False})
    for relative, before in snapshots.items():
        assert signature(ROOT / relative) == before, relative
    output_bindings = {}
    for filename in ('source-membership.json', 'district-geometries.json'):
        payload = (OUT / filename).read_bytes()
        output_bindings[filename] = {'bytes': len(payload), 'sha256': sha(payload)}
    save('proof.json', {'schema': 'flat-native-city-source-district-preparation-proof/v1',
        'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'all_assigned_preparation_checks_passed': True, 'source_inputs': inputs,
        'all_source_stats_unchanged': True, 'commands': commands, 'export_relation_receipts': subsets,
        'script_sha256': sha(Path(__file__).read_bytes()), 'output_bindings': output_bindings,
        'native_layouts': parent_memberships, 'native_hierarchy_rows_streamed': hierarchy_rows,
        'source_district_count': len(rows), 'source_district_counts_by_city': {c: len(d) for c, d in geometries.items()},
        'source_districts': {c: sorted(d) for c, d in geometries.items()},
        'all_districts_complete_reference_closed': True, 'vertices': vertices,
        'source_parent_complete_city_geometries_already_prepared': True,
        'existing_21_city_and_Kaohsiung_suite_rerun': False,
        'general_membership_engine_path': engine_relative, 'general_membership_engine_sha256': PINS[engine_relative][1],
        'existing_membership_engine_controls_inherited': 'Pinned sealed Kaohsiung membership-test-proof.json; no test rerun.',
        'native_district_records_total': 0, 'native_district_membership_verified': False,
        'membership_API_final_merge_authorization': False,
        'future_merge_required_guards': [
            'Exact declared source city/district relation; no inferred or assigned district.',
            'Unique native city/street record, original flat city→street layout retained.',
            'Complete global (nativeStreetID, house_label) collision guard across all source districts/groups.',
            'Finite source coordinates and exact encoded raw24 coordinates both inside the same declared source district.',
            'Existing numeric label ref, original branch profile and true old-house overlap/order checks.'
        ], 'max_RSS_KiB': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        'all_ephemeral_subset_files_removed': not (OUT / 'ephemeral-single-district.osm.pbf').is_symlink(),
        'whole_Taiwan_PBF_or_address_ready_or_group_ledgers_read': False,
        'native_IMG_JAI_records_device_or_canonical_modified': False,
        'full_Taiwan_update_complete': False})
    for filename in ('proof.json',):
        payload = (OUT / filename).read_bytes()
        output_bindings[filename] = {'bytes': len(payload), 'sha256': sha(payload)}
    save('dataset-pins.json', {'schema': 'flat-source-district-dataset-pins/v1',
         'files': output_bindings, 'engine_path': engine_relative,
         'engine_bytes': PINS[engine_relative][0], 'engine_sha256': PINS[engine_relative][1]})
    wrapper = OUT / 'source_district_membership.py'
    code = wrapper.read_text()
    assert code.count('__DATASET_PINS_SHA256__') == 1
    wrapper.write_text(code.replace('__DATASET_PINS_SHA256__', sha((OUT / 'dataset-pins.json').read_bytes())))
    print(json.dumps({'all_preparation_checks_passed': True, 'source_districts': len(rows),
          'source_district_counts_by_city': {c: len(d) for c, d in geometries.items()},
          'native_district_records': 0, 'vertices': vertices, 'max_RSS_KiB': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
          'geometry_bytes': output_bindings['district-geometries.json']['bytes']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
