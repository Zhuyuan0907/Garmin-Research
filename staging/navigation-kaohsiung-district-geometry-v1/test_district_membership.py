#!/usr/bin/env python3
"""New district integration controls and independent, unbucketed rational readback."""
import hashlib
import importlib.util
import json
import os
import tempfile
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def integer(value):
    coordinate = Decimal(str(value)) * 10000000
    if coordinate != coordinate.to_integral_value():
        raise ValueError('not source precision')
    return int(coordinate)


def reference_ring(ring, latitude, longitude):
    """Unbucketed exact rational rightward ray; independent of reused engine."""
    x, y = integer(longitude), integer(latitude)
    points = [(integer(lon), integer(lat)) for lon, lat in ring]
    crossings = 0
    for (ax, ay), (bx, by) in zip(points, points[1:]):
        if (x - ax) * (by - ay) == (y - ay) * (bx - ax):
            if min(ax, bx) <= x <= max(ax, bx) and min(ay, by) <= y <= max(ay, by):
                return 2
        if ay <= y < by or by <= y < ay:
            intersection = Fraction(ax) + Fraction((y - ay) * (bx - ax), by - ay)
            if intersection > x:
                crossings += 1
    return crossings % 2


def reference_covers(geometry, latitude, longitude):
    for rings in geometry['coordinates']:
        outer = reference_ring(rings[0], latitude, longitude)
        if outer == 2:
            return True
        if outer == 0:
            continue
        holes = [reference_ring(ring, latitude, longitude) for ring in rings[1:]]
        if 2 in holes:
            return True
        if 1 not in holes:
            return True
    return False


def grid_coordinate(low, high, ordinal):
    # Include two samples outside the bounding box, as well as three within.
    value = Decimal(str(low)) + (Decimal(str(high)) - Decimal(str(low))) * Decimal(ordinal) / 2
    return value.quantize(Decimal('0.0000001'), rounding=ROUND_HALF_UP)


def main():
    api = load(HERE / 'district_membership.py', 'tested_district_membership')
    validator = api.DistrictMembership()
    dataset_bytes = (HERE / 'district-geometries.json').read_bytes()
    dataset = json.loads(dataset_bytes)
    comparisons = []
    point_count = 0
    inside_count = 0
    outside_count = 0
    boundary_count = 0
    for district, row in sorted(dataset['districts'].items()):
        geometry = row['geometry']
        all_points = [point for polygon in geometry['coordinates'] for ring in polygon for point in ring]
        low_lon, high_lon = min(p[0] for p in all_points), max(p[0] for p in all_points)
        low_lat, high_lat = min(p[1] for p in all_points), max(p[1] for p in all_points)
        local_inside = local_outside = local_boundaries = 0
        for latitude_index in (-1, 0, 1, 2, 3):
            for longitude_index in (-1, 0, 1, 2, 3):
                lat = grid_coordinate(low_lat, high_lat, latitude_index)
                lon = grid_coordinate(low_lon, high_lon, longitude_index)
                expected = reference_covers(geometry, lat, lon)
                actual = validator.covers('高雄市', district, lat, lon)
                assert actual == expected, (district, str(lat), str(lon), actual, expected)
                point_count += 1
                if actual:
                    inside_count += 1
                    local_inside += 1
                else:
                    outside_count += 1
                    local_outside += 1
        for polygon in geometry['coordinates']:
            for ring in polygon:
                for ordinal in {0, (len(ring) - 1) // 2}:
                    lon, lat = ring[ordinal]
                    assert reference_covers(geometry, lat, lon)
                    assert validator.covers('高雄市', district, lat, lon)
                    assert not validator.covers('臺南市', district, lat, lon)
                    boundary_count += 1
                    local_boundaries += 1
        assert local_outside and local_boundaries
        comparisons.append({'district': district, 'source_relation_id': row['source_relation_id'],
                            'interior_or_boundary_grid_cases': local_inside, 'outside_grid_cases': local_outside,
                            'actual_vertex_boundary_cases': local_boundaries, 'all_equal_to_independent_reader': True})
    controls = []

    def control(label, city, district, latitude, longitude, expected):
        result = validator.assess(city, district, latitude, longitude)
        assert result['status'] == expected and result['eligible'] is False, (label, result)
        controls.append({'name': label, 'status': result['status'], 'passed': True})

    control('incomplete_旗津_never_city_fallback', '高雄市', '旗津區', '22.6', '120.3', 'district_geometry_incomplete_held')
    control('missing_district_no_city_union', '高雄市', '', '22.6', '120.3', 'district_unknown')
    control('unknown_district_no_nearest_search', '高雄市', '未知區', '22.6', '120.3', 'district_unknown')
    control('whitespace_name_not_normalized', '高雄市', '三民區 ', '22.6', '120.3', 'district_unknown')
    control('incorrect_city_not_accepted', '高雄縣', '三民區', '22.6', '120.3', 'unsupported_city')
    control('nullable_district', '高雄市', None, '22.6', '120.3', 'district_unknown')
    control('unhashable_district', '高雄市', [], '22.6', '120.3', 'district_unknown')
    control('Taipei_point_outside_三民', '高雄市', '三民區', '25.033', '121.5654', 'outside_verified_district')
    control('nonfinite_coordinate', '高雄市', '三民區', 'NaN', '120.3', 'invalid_global_coordinate')
    control('infinite_coordinate', '高雄市', '三民區', '22.6', 'Infinity', 'invalid_global_coordinate')
    control('out_of_global_latitude', '高雄市', '三民區', '90.01', '120.3', 'invalid_global_coordinate')
    control('out_of_global_longitude', '高雄市', '三民區', '22.6', '180.01', 'invalid_global_coordinate')
    control('malformed_coordinate', '高雄市', '三民區', 'bad', '120.3', 'invalid_coordinate')
    control('boolean_coordinate', '高雄市', '三民區', True, '120.3', 'invalid_coordinate')
    control('beyond_source_coordinate_precision', '高雄市', '三民區', '22.60000001', '120.3', 'coordinate_exceeds_source_precision')
    with tempfile.TemporaryDirectory(prefix='kh-geometry-guard-', dir=HERE) as temporary:
        target = Path(temporary)
        # Validate fail-closed pinning without constructing additional engine
        # instances or using any device fixture.
        for name in api.PINS:
            (target / name).write_bytes((HERE / name).read_bytes())
        altered = bytearray((target / 'district-geometries.json').read_bytes())
        altered[len(altered) // 2] ^= 1
        (target / 'district-geometries.json').write_bytes(altered)
        try:
            api.DistrictMembership(data_dir=target)
        except ValueError as error:
            assert 'district-geometries.json' in str(error)
        else:
            raise AssertionError('Altered geometry was accepted')
        controls.append({'name': 'one_byte_geometry_corruption_rejected', 'passed': True})
        (target / 'district-geometries.json').write_bytes(dataset_bytes)
        (target / 'source-membership.json').write_bytes((target / 'source-membership.json').read_bytes()[:-1])
        try:
            api.DistrictMembership(data_dir=target)
        except ValueError as error:
            assert 'source-membership.json' in str(error)
        else:
            raise AssertionError('Truncated membership was accepted')
        controls.append({'name': 'truncated_membership_rejected', 'passed': True})
    proof = {'schema': 'garmin-kaohsiung-explicit-district-membership-tests/v1',
             'all_assigned_new_controls_passed': True, 'districts_checked': len(comparisons),
             'independent_rational_grid_cases': point_count, 'inside_grid_cases': inside_count,
             'outside_grid_cases': outside_count, 'actual_geometry_boundary_cases': boundary_count,
             'wrong_city_boundary_rejections': boundary_count, 'district_comparisons': comparisons,
             'new_guard_controls': controls, 'new_guard_controls_count': len(controls),
             'geometry_file_bytes': len(dataset_bytes), 'geometry_file_sha256': hashlib.sha256(dataset_bytes).hexdigest(),
             'independent_reference': 'unbucketed full-ring exact rational ray; no CityGeometry calls in reference',
             'scope': 'New explicit-district geometry integration. No addresses, source merge, full city boundary or real-device proof.',
             'device_IO': False, 'full_Taiwan_update': False}
    with (HERE / 'membership-test-proof.json').open('x') as output:
        json.dump(proof, output, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    print(json.dumps({'districts_checked': len(comparisons), 'independent_grid_cases': point_count,
                      'geometry_boundary_cases': boundary_count, 'new_guard_controls': len(controls),
                      'all_assigned_new_controls_passed': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
