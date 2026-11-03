#!/usr/bin/env python3
"""Prepare explicit, complete Kaohsiung district polygons from the existing admin extract.

No house ledger, whole Taiwan PBF, map writer, USB or city-union fallback is used.
"""
import gzip
import hashlib
import importlib.util
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
CITY = '高雄市'
PARENT = 2127079
HELD = 2106668
PINS = {
    'staging/navigation-repair-v1/taiwan-admin-selected-from-source.osm.pbf':
        (4349834, '5b8cd8d1de51a55446abc2d42164244c909e1bc70cadc55fe20fd9808e949c7d'),
    'staging/navigation-road-coverage-v1/native-all-city-closure-proof.json':
        (143946, 'e28ce491a3463c3aebb6662b304270aae02596240de8d40ce092af13d77f438a'),
    'staging/navigation-road-coverage-v1/selected-admin.json':
        (37388, '84c8199dfa8cd1a98b723adec47104f90a043a6783ea26e1502722c7fa0b0cde'),
    'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz':
        (1210093, '45333390cec4996db40b4a4a987eb421641fec352203bb318aedfd6a6fce2776'),
    'scripts/prepare_taichung_city_geometry_v1.py':
        (5776, '2fff38c613a41017553f8a59978b85811fce6b118b6db87cfc07fe1e17d74101'),
    'staging/navigation-country-city-geometry-v1/city-geometries.json':
        (3112627, 'cd44ea3aba74357480487ab83cf228232bdf0fc99821d7bf39fd58bbcd50cfc5'),
}
SOURCE = ROOT / next(iter(PINS))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(name, value):
    payload = canonical(value) + b'\n'
    path = OUT / name
    if path.exists():
        # Resume the first attempt's completed membership evidence, verbatim.
        assert name == 'source-membership.json' and path.read_bytes() == payload
        return
    with path.open('xb') as file:
        file.write(payload)
        file.flush()
        os.fsync(file.fileno())


def tags(relation):
    return {node.attrib['k']: node.attrib['v'] for node in relation.findall('tag')}


def stat_key(path):
    s = path.stat()
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def main():
    snapshots = {}
    inputs = {}
    for relative, (size, digest) in PINS.items():
        path = ROOT / relative
        snapshots[relative] = stat_key(path)
        payload = path.read_bytes()
        assert len(payload) == size and sha(payload) == digest, relative
        inputs[relative] = {'bytes': size, 'sha256': digest}
    engine_spec = importlib.util.spec_from_file_location('verified_geometry_engine', ROOT / 'scripts/prepare_taichung_city_geometry_v1.py')
    engine = importlib.util.module_from_spec(engine_spec)
    engine_spec.loader.exec_module(engine)
    closure_data = json.loads((ROOT / 'staging/navigation-road-coverage-v1/native-all-city-closure-proof.json').read_text())
    closure = {row['id']: row for row in closure_data['roots']}
    assert len(closure) == len(closure_data['roots'])
    commands = []

    def run(command, **kwargs):
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, **kwargs)
        commands.append({'argv': command, 'exit_code': result.returncode, 'stdout_bytes': len(result.stdout),
                         'stdout_sha256': sha(result.stdout), 'stderr': result.stderr.decode(errors='replace')})
        assert result.returncode == 0, commands[-1]
        return result.stdout

    parent_xml = run(['osmium', 'getid', '-f', 'osm', str(SOURCE), 'r' + str(PARENT)])
    parent_relations = ET.fromstring(parent_xml).findall('relation')
    assert len(parent_relations) == 1 and int(parent_relations[0].attrib['id']) == PARENT
    parent = parent_relations[0]
    pt = tags(parent)
    assert pt['name'] == CITY and pt['admin_level'] == '4' and pt['boundary'] == 'administrative' and pt['type'] == 'boundary'
    subareas = [int(m.attrib['ref']) for m in parent.findall('member') if m.attrib['role'] == 'subarea' and m.attrib['type'] == 'relation']
    all_subareas = [m for m in parent.findall('member') if m.attrib['role'] == 'subarea']
    assert len(subareas) == len(all_subareas) == len(set(subareas)) == 38
    children_xml = run(['osmium', 'getid', '-f', 'osm', str(SOURCE), *['r' + str(i) for i in sorted(subareas)]])
    children = {int(r.attrib['id']): r for r in ET.fromstring(children_xml).findall('relation')}
    assert set(children) == set(subareas)
    native_city = []
    native_districts = {}
    hierarchy_rows = 0
    with gzip.open(ROOT / 'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz', 'rt') as stream:
        for line in stream:
            hierarchy_rows += 1
            row = json.loads(line)
            if row.get('city') != CITY:
                continue
            if row['level'] == 1:
                native_city.append(row)
            elif row['level'] == 2:
                name = row['district']
                assert name == row['raw_name'] and name not in native_districts
                native_districts[name] = row
    assert len(native_city) == 1 and native_city[0]['raw_name'] == CITY
    assert len(native_districts) == 38
    rows = []
    for relation_id in sorted(subareas):
        ct = tags(children[relation_id])
        assert ct['admin_level'] == '7' and ct['type'] == 'boundary' and ct['boundary'] == 'administrative'
        name = ct['name']
        assert name in native_districts and name == closure[relation_id]['name']
        cl = closure[relation_id]
        complete = cl['complete_reference_closed_geometry']
        if complete:
            assert not cl['missing_way_ids'] and not cl['missing_node_ids']
            assert all(not role['open_chains'] for role in cl['roles'].values())
        else:
            assert relation_id == HELD and name == '旗津區'
            assert cl['missing_way_ids'] == [284788564, 654482084] and not cl['missing_node_ids']
        native = native_districts[name]
        rows.append({'city': CITY, 'district': name, 'source_parent_relation_id': PARENT,
                     'source_relation_id': relation_id, 'parent_subarea_membership_verified': True,
                     'source_admin_level': ct['admin_level'], 'source_relation_tags': ct,
                     'native_city_record': native_city[0]['record'], 'native_district_record': native['record'],
                     'native_district_low28_id': native['low28_id'], 'native_names_exact': True,
                     'closure': cl})
    assert {r['district'] for r in rows} == set(native_districts)
    complete_rows = [r for r in rows if r['closure']['complete_reference_closed_geometry']]
    held_rows = [r for r in rows if not r['closure']['complete_reference_closed_geometry']]
    assert len(complete_rows) == 37 and len(held_rows) == 1
    assert not closure[PARENT]['complete_reference_closed_geometry']
    assert closure[PARENT]['missing_way_ids'] == held_rows[0]['closure']['missing_way_ids']
    selected_admin = json.loads((ROOT / 'staging/navigation-road-coverage-v1/selected-admin.json').read_text())
    selected_ids = [r['id'] for r in selected_admin]
    assert PARENT not in selected_ids
    save('source-membership.json', {'schema': 'garmin-kaohsiung-subarea-membership/v1',
                                    'parent_relation_id': PARENT, 'parent_tags': pt,
                                    'parent_closure': closure[PARENT], 'native_city': native_city[0],
                                    'source_subarea_count': 38, 'districts': rows,
                                    'selected_admin_root_ids': selected_ids,
                                    'selected_admin_contains_kaohsiung': False,
                                    'membership_authority': 'actual parent subarea relation members in pinned admin PBF'})
    # Only explicitly requested complete relations keep tags. Referenced subareas,
    # ways and nodes lose tags, so export cannot yield village or parent polygons.
    requested = ['r' + str(r['source_relation_id']) for r in complete_rows]
    subset = run(['osmium', 'getid', '-r', '-t', '-f', 'pbf', str(SOURCE), *requested])
    assert 0 < len(subset) <= 4349834
    fd = os.memfd_create('kaohsiung-complete-district-admin', flags=0)
    temporary_link = OUT / 'complete-districts-input.osm.pbf'
    try:
        with os.fdopen(os.dup(fd), 'wb') as memory_file:
            memory_file.write(subset)
            memory_file.flush()
        os.lseek(fd, 0, os.SEEK_SET)
        # Osmium's second export reader redetects the filename format. A PBF
        # suffix lets both readers use this same inherited, seekable memfd.
        temporary_link.symlink_to('/proc/self/fd/' + str(fd))
        exported = run(['osmium', 'export', '-F', 'pbf', '--geometry-types=polygon', '-u', 'type_id',
                        '--stop-on-error', '-f', 'geojsonseq', str(temporary_link)], pass_fds=(fd,))
    finally:
        if temporary_link.is_symlink():
            temporary_link.unlink()
        os.close(fd)
    features = [json.loads(line.lstrip(b'\x1e')) for line in exported.splitlines() if line.lstrip(b'\x1e').strip()]
    # Export type_id is the assembled AREA identifier, not the relation ID.
    # All references had their tags removed; only the explicit 37 relations
    # retain names. Match these unique names to their actual source relations.
    by_name = {feature['properties']['name']: feature for feature in features}
    assert len(features) == len(by_name) == 37
    assert set(by_name) == {row['district'] for row in complete_rows}
    geometries = {}
    vertices = 0
    for row in complete_rows:
        relation_id = row['source_relation_id']
        feature = by_name[row['district']]
        props = feature['properties']
        assert props['name'] == row['district'] and str(props['admin_level']) == '7'
        assert props['boundary'] == 'administrative'
        geometry = feature['geometry']
        if geometry['type'] == 'Polygon':
            geometry = {'type': 'MultiPolygon', 'coordinates': [geometry['coordinates']]}
        assert geometry['type'] == 'MultiPolygon' and geometry['coordinates']
        outer_count = len(geometry['coordinates'])
        inner_count = sum(len(poly) - 1 for poly in geometry['coordinates'])
        assert outer_count == row['closure']['roles']['outer']['closed_rings']
        assert inner_count == row['closure']['roles']['inner']['closed_rings']
        for polygon in geometry['coordinates']:
            assert polygon
            for ring in polygon:
                assert len(ring) >= 4 and ring[0] == ring[-1]
                vertices += len(ring)
                for lon, lat in ring:
                    assert -180 <= lon <= 180 and -90 <= lat <= 90
                    engine.integer_coordinate(lat)
                    engine.integer_coordinate(lon)
        # Constructing the existing, sealed engine also checks all closed rings.
        engine.CityGeometry(geometry)
        geometries[row['district']] = {'city': CITY, 'district': row['district'],
            'source_relation_id': relation_id, 'source_parent_relation_id': PARENT,
            'native_city_record': row['native_city_record'], 'native_district_record': row['native_district_record'],
            'native_district_low28_id': row['native_district_low28_id'],
            'export_area_id': feature['id'],
            'complete_reference_closed_geometry': True, 'closure': row['closure'],
            'geometry_sha256': sha(canonical(geometry)), 'geometry': geometry}
    save('district-geometries.json', {'schema': 'garmin-explicit-kaohsiung-district-geometries/v1',
         'city': CITY, 'parent_relation_id': PARENT, 'full_city_geometry_complete': False,
         'union_is_city_geometry': False, 'districts': geometries,
         'held_districts': {r['district']: {'source_relation_id': r['source_relation_id'], 'closure': r['closure']} for r in held_rows}})
    for relative, before in snapshots.items():
        assert stat_key(ROOT / relative) == before, relative
    geometry_bytes = (OUT / 'district-geometries.json').read_bytes()
    membership_bytes = (OUT / 'source-membership.json').read_bytes()
    save('proof.json', {'schema': 'garmin-kaohsiung-district-preparation-proof/v1',
         'created_utc': datetime.now(timezone.utc).isoformat(), 'all_assigned_preparation_checks_passed': True,
         'source_inputs': inputs, 'all_pinned_source_stats_unchanged': True, 'commands': commands,
         'actual_parent_subareas': 38, 'native_exact_district_matches': 38,
         'complete_districts_exported': 37, 'held_districts_count': 1, 'held_districts': held_rows,
         'selected_admin_root_ids': selected_ids, 'selected_admin_contains_kaohsiung': False,
         'native_hierarchy_lines_streamed': hierarchy_rows, 'parent_geometry_complete': False,
         'export_features_actual_count': len(features), 'total_geometry_vertices': vertices,
         'ephemeral_subset_pbf_bytes': len(subset), 'ephemeral_subset_pbf_persisted': False,
         'district_geometry_file': {'bytes': len(geometry_bytes), 'sha256': sha(geometry_bytes)},
         'source_membership_file': {'bytes': len(membership_bytes), 'sha256': sha(membership_bytes)},
         'reference_closed_rings_match_export_for_all_complete_districts': True,
         'city_union_created': False, 'original_21_city_dataset_unchanged': True,
         'house_or_address_ledgers_read': False, 'whole_taiwan_pbf_read': False,
         'network_used': False, 'IMG_created': False, 'device_IO': False,
         'scope': 'Explicit district membership geometry only. Parent city and 旗津 remain held. No address merge, device or navigation acceptance.'})
    print(json.dumps({'complete_districts': 37, 'held_districts': 1, 'parent_city_complete': False,
                      'vertices': vertices, 'geometry_bytes': len(geometry_bytes), 'all_preparation_checks_passed': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
