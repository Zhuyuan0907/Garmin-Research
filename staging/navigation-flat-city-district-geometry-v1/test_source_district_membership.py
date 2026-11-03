#!/usr/bin/env python3
"""New wrapper/geometry identity and exact native-grid integration controls only."""
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile

HERE = Path(__file__).resolve().parent


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def load_api():
    spec = importlib.util.spec_from_file_location('flat_source_district_api', HERE / 'source_district_membership.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def exact_vertices(geometry):
    return [[[(int(Decimal(str(x)) * 10000000), int(Decimal(str(y)) * 10000000))
               for x, y in ring] for ring in polygon] for polygon in geometry['coordinates']]


def winding(ring, x, y, den=1):
    """Independent signed winding over all edges; no imported bucket/ray code."""
    value = 0
    for (ax, ay), (bx, by) in zip(ring, ring[1:]):
        turn = (bx - ax) * (y - ay * den) - (by - ay) * (x - ax * den)
        if turn == 0 and min(ax, bx) * den <= x <= max(ax, bx) * den \
                and min(ay, by) * den <= y <= max(ay, by) * den:
            return 2
        if ay * den <= y < by * den and turn > 0:
            value += 1
        elif by * den <= y < ay * den and turn < 0:
            value -= 1
    return int(value != 0)


def reference(polygons, x, y, den=1):
    for rings in polygons:
        hit = winding(rings[0], x, y, den)
        if hit == 2:
            return True
        if not hit:
            continue
        hole_inside = False
        for ring in rings[1:]:
            inner = winding(ring, x, y, den)
            if inner == 2:
                return True
            if inner:
                hole_inside = True
                break
        if not hole_inside:
            return True
    return False


def native24(lat, lon):
    # Independent Decimal half-up rounding, versus API exact Fraction rounding.
    return [int((Decimal(v) * (1 << 24) / 360).quantize(Decimal(1), rounding=ROUND_HALF_UP)) & 0xffffff
            for v in (lat, lon)]


def native_reference(polygons, words):
    signed = [x if x < 0x800000 else x - 0x1000000 for x in words]
    return reference(polygons, signed[1] * 3515625, signed[0] * 3515625, 16384)


def strings(x, y):
    return [str(Decimal(y) / 10000000), str(Decimal(x) / 10000000)]


def inside_pair(polygons):
    # A geometry-derived control point, not an address or assigned district.
    for rings in sorted(polygons, key=lambda p: len(p[0]), reverse=True):
        outer = rings[0]
        lo_x, hi_x = min(x for x, y in outer), max(x for x, y in outer)
        lo_y, hi_y = min(y for x, y in outer), max(y for x, y in outer)
        for parts in (8, 24, 64):
            for i in range(1, parts):
                x = lo_x + (hi_x - lo_x) * i // parts
                for j in range(1, parts):
                    y = lo_y + (hi_y - lo_y) * j // parts
                    if reference(polygons, x, y):
                        coords = strings(x, y)
                        words = native24(*coords)
                        if native_reference(polygons, words):
                            return coords, words
    raise AssertionError('No bounded interior native-grid control point')


def main():
    assert not (HERE / 'membership-test-proof.json').exists()
    started = datetime.now(timezone.utc).isoformat()
    module = load_api()
    api = module.SourceDistrictMembership()
    data = api.dataset
    counts = Counter()
    representatives = []
    safe_points = {}
    for city, districts in data['source_cities'].items():
        for district, item in districts.items():
            geometry = item['geometry']
            polygons = exact_vertices(geometry)
            coords, words = inside_pair(polygons)
            safe_points[(city, district)] = (coords, words)
            accepted = api.assess_source_and_raw24(city, district, *coords, words)
            assert accepted['eligible'] and accepted['source_point_inside'] and accepted['quantized_point_inside']
            assert accepted['native_district_verified'] is False and accepted['native_district_record'] is None
            assert accepted['native_merge_eligible'] is False
            assert accepted['source_relation_id'] == item['source_relation_id']
            representatives.append({'source_city': city, 'district': district,
                 'source_relation_id': item['source_relation_id'], 'source_parent_relation_id': item['source_parent_relation_id'],
                 'geometry_derived_control_point': coords, 'raw24': words,
                 'both_inside_declared_source_district': True, 'native_district_verified': False})
            counts['districts_with_positive_source_and_native_pair'] += 1
            flat = [xy for polygon in polygons for ring in polygon for xy in ring]
            lo_x, hi_x = min(x for x, y in flat), max(x for x, y in flat)
            lo_y, hi_y = min(y for x, y in flat), max(y for x, y in flat)
            control_points = [(lo_x + (hi_x - lo_x) * i // 4,
                               lo_y + (hi_y - lo_y) * j // 4) for i in range(1, 4) for j in range(1, 4)]
            control_points += [polygons[0][0][0], (lo_x - 10000, lo_y - 10000)]
            for x, y in control_points:
                coords = strings(x, y)
                expected_source = reference(polygons, x, y)
                assessment = api.assess(city, district, *coords)
                assert assessment['eligible'] == expected_source
                assert assessment['native_district_verified'] is False and assessment['native_merge_eligible'] is False
                counts['source_signed_winding_comparisons'] += 1
                counts['source_inside' if expected_source else 'source_outside'] += 1
                words = native24(*coords)
                pair = api.assess_source_and_raw24(city, district, *coords, words)
                expected_native = native_reference(polygons, words)
                assert pair['eligible'] == (expected_source and expected_native)
                assert pair['source_point_inside'] == expected_source
                if expected_source:
                    assert pair['quantized_point_inside'] == expected_native
                    counts['exact_rational_native_grid_comparisons'] += 1
                    if not expected_native:
                        assert pair['status'] == 'quantized_point_outside_declared_source_district'
                        counts['actual_source_boundary_quantization_rejections'] += 1
            # Source outer boundary is covered; it does not assign among neighbors.
            x, y = polygons[0][0][0]
            assert api.covers(city, district, *strings(x, y))
            counts['actual_geometry_boundary_controls'] += 1
    assert counts['districts_with_positive_source_and_native_pair'] == 24
    assert len(api.geometries) == 24 and len(api.city_aliases) == 5
    guards = []
    city, district = '臺北市', '中正區'
    coords, words = safe_points[(city, district)]

    def guard(name, value, status):
        assert value['eligible'] is False and value['status'] == status, (name, value)
        assert value['native_merge_eligible'] is False and value['native_district_verified'] is False
        guards.append({'control': name, 'actual_status': value['status'], 'eligible': False})

    guard('unlisted_city', api.assess('新北市', district, *coords), 'unsupported_city')
    guard('unverified_city_glyph', api.assess('臺北巿', district, *coords), 'unsupported_city')
    guard('city_whitespace_is_not_alias', api.assess('臺北市 ', district, *coords), 'unsupported_city')
    guard('district_whitespace_is_not_alias', api.assess(city, district + ' ', *coords), 'source_district_unknown')
    guard('unknown_district', api.assess(city, '西區', *coords), 'source_district_unknown')
    guard('missing_district', api.assess(city, None, *coords), 'source_district_unknown')
    guard('boolean_latitude', api.assess(city, district, True, coords[1]), 'invalid_coordinate')
    guard('missing_latitude', api.assess(city, district, None, coords[1]), 'invalid_coordinate')
    for name, latitude, longitude in [('NaN', 'NaN', coords[1]), ('infinity', coords[0], 'Infinity'),
                                     ('latitude_range', '91', coords[1]), ('longitude_range', coords[0], '181')]:
        guard(name, api.assess(city, district, latitude, longitude), 'invalid_global_coordinate')
    guard('unsupported_coordinate_precision', api.assess(city, district, coords[0] + '00000001', coords[1]),
          'coordinate_exceeds_source_precision')
    for name, bad in [('missing_raw24', None), ('short_raw24', words[:1]), ('boolean_raw24', [True, words[1]]),
                      ('negative_raw24', [-1, words[1]]), ('overflow_raw24', [1 << 24, words[1]])]:
        guard(name, api.assess_source_and_raw24(city, district, *coords, bad), 'invalid_raw24')
    guard('native_grid_not_from_source', api.assess_source_and_raw24(city, district, *coords, [words[0] + 1, words[1]]),
          'raw24_does_not_match_source_rounding')
    guard('same_name_different_source_city', api.assess('基隆市', district, *coords), 'outside_declared_source_district')
    guard('same_name_East_different_source_city',
          api.assess('嘉義市', '東區', *safe_points[('新竹市', '東區')][0]), 'outside_declared_source_district')
    alias = api.assess_source_and_raw24('台北市', district, *coords, words)
    assert alias['eligible'] and alias['source_city'] == '臺北市' and alias['native_city'] == '台北市'
    assert alias['native_district_record'] is None and alias['native_district_verified'] is False
    counts['literal_source_native_Taipei_binding_control'] += 1
    # Newly added rational integration is checked on hole/boundary/half-grid cases.
    engine_path = Path('/root/garmin/scripts/prepare_taichung_city_geometry_v1.py')
    spec = importlib.util.spec_from_file_location('flat_rational_control_engine', engine_path)
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    artificial = {'type': 'MultiPolygon', 'coordinates': [[
        [[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]],
        [[1, 1], [1, 3], [3, 3], [3, 1], [1, 1]]]]}
    g = engine.CityGeometry(artificial)
    polygons = exact_vertices(artificial)
    rational_cases = [(1, 1, 2), (3, 3, 2), (1, 2, 1), (0, 2, 1), (5, 2, 1),
                      (7, 7, 2), (-1, 1, 2), (2, 2, 1), (4, 4, 1)]
    for x, y, den in rational_cases:
        value = module._rational_covers(g, x * 10000000, y * 10000000, den)
        assert value == reference(polygons, x * 10000000, y * 10000000, den)
    counts['new_rational_hole_boundary_controls'] = len(rational_cases)
    cached = {name: (HERE / name).read_bytes() for name in
              ('dataset-pins.json', 'district-geometries.json', 'source-membership.json', 'proof.json')}
    identity_rejections = []
    with tempfile.TemporaryDirectory(prefix='new-wrapper-identity-controls-', dir=HERE) as temporary:
        directory = Path(temporary)
        for mutate in cached:
            for name, payload in cached.items():
                (directory / name).write_bytes(payload + b' ' if name == mutate else payload)
            try:
                module.SourceDistrictMembership(data_dir=directory)
            except ValueError:
                identity_rejections.append({'tampered_file': mutate, 'rejected': True})
            else:
                raise AssertionError('Unpinned geometry/metadata identity accepted')
        for name, payload in cached.items():
            (directory / name).write_bytes(payload)
        modified_engine = directory / 'modified-engine.py'
        modified_engine.write_bytes(engine_path.read_bytes() + b'\n')
        try:
            module.SourceDistrictMembership(data_dir=directory, engine_path=modified_engine)
        except ValueError:
            identity_rejections.append({'tampered_file': 'original_general_membership_engine', 'rejected': True})
        else:
            raise AssertionError('Unpinned general membership engine accepted')
    result = {'schema': 'flat-city-source-district-new-wrapper-controls/v1',
        'started_utc': started, 'finished_utc': datetime.now(timezone.utc).isoformat(),
        'all_assigned_new_wrapper_controls_passed': True,
        'script_sha256': sha(Path(__file__).read_bytes()),
        'API_sha256': sha((HERE / 'source_district_membership.py').read_bytes()),
        'dataset_pins_sha256': module.PINS_SHA256,
        'source_district_counts_by_city': {c: len(d) for c, d in data['source_cities'].items()},
        'counts': dict(counts), 'new_guard_controls': guards,
        'input_identity_tamper_rejections': identity_rejections,
        'geometry_derived_positive_pair_controls': representatives,
        'independent_reference': 'Signed winding over all original edges with exact rational cross-products; API uses inherited parity-ray buckets.',
        'rational_rounding_reference': 'Decimal ROUND_HALF_UP versus API Fraction integer division.',
        'temporary_identity_fixture_removed': not directory.exists(),
        'source_geometry_derived_points_are_address_evidence': False,
        'native_district_verified': False, 'address_ready_group_or_PBF_read': False,
        'closed_Kaohsiung_21city_country_review_suites_rerun': False,
        'new_IMG_JAI_records_or_device_IO': False, 'full_Taiwan_update_complete': False}
    (HERE / 'membership-test-proof.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_new_wrapper_controls_passed': True, 'districts': 24, 'counts': dict(counts),
                     'guard_controls': len(guards), 'identity_controls': len(identity_rejections),
                     'test_proof_sha256': sha((HERE / 'membership-test-proof.json').read_bytes())}, ensure_ascii=False))


if __name__ == '__main__':
    main()
