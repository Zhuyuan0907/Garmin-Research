#!/usr/bin/env python3
"""Pinned source district membership for four original native flat cities.

Results are a geometry prerequisite only: original JAI has no district records
for these four cities. No native street selection or target collision is resolved.
"""
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path('/root/garmin')
HERE = Path(__file__).resolve().parent
PINS_SHA256 = '216e155f53201f88c76ad55b751481f03154f35b046cc4041c4879db6450d400'


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _read_verified(path, expected_bytes=None, expected_sha256=None):
    payload = path.read_bytes()
    if expected_bytes is not None and len(payload) != expected_bytes:
        raise ValueError('Unverified bounded input size: ' + path.name)
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        raise ValueError('Unverified input identity: ' + path.name)
    return payload


def _round24(value):
    number = Fraction(value) * 16777216 / 360
    sign = -1 if number < 0 else 1
    number = abs(number)
    whole, remainder = divmod(number.numerator, number.denominator)
    if 2 * remainder >= number.denominator:
        whole += 1
    signed = sign * whole
    if not -(1 << 23) <= signed < (1 << 23):
        raise ValueError('Source point cannot be represented as signed raw24')
    return signed & 0xffffff


def _rational_ring(ring, x, y, denominator):
    """Reuse sealed engine edges/buckets, evaluating exact rational native grid."""
    inside = False
    for (ax, ay), (bx, by) in ring.buckets.get(y // (10000 * denominator), []):
        dy, dx = by - ay, bx - ax
        cross = (x - ax * denominator) * dy - (y - ay * denominator) * dx
        if cross == 0 and min(ax, bx) * denominator <= x <= max(ax, bx) * denominator \
                and min(ay, by) * denominator <= y <= max(ay, by) * denominator:
            return 2
        if (ay * denominator > y) != (by * denominator > y):
            if cross < 0 if dy > 0 else cross > 0:
                inside = not inside
    return int(inside)


def _rational_covers(geometry, x, y, denominator):
    for rings in geometry.polygons:
        outer = _rational_ring(rings[0], x, y, denominator)
        if outer == 2:
            return True
        if not outer:
            continue
        inside_hole = False
        for ring in rings[1:]:
            hit = _rational_ring(ring, x, y, denominator)
            if hit == 2:
                return True
            if hit:
                inside_hole = True
                break
        if not inside_hole:
            return True
    return False


class SourceDistrictMembership:
    def __init__(self, data_dir=HERE, engine_path=None):
        directory = Path(data_dir)
        pins = json.loads(_read_verified(directory / 'dataset-pins.json', expected_sha256=PINS_SHA256))
        files = {}
        for name, identity in pins['files'].items():
            files[name] = json.loads(_read_verified(directory / name, identity['bytes'], identity['sha256']))
        dataset = files['district-geometries.json']
        membership = files['source-membership.json']
        proof = files['proof.json']
        assert dataset['schema'] == 'flat-native-city-explicit-source-district-geometries/v1'
        assert membership['schema'] == 'flat-native-city-explicit-source-district-membership/v1'
        assert proof['all_assigned_preparation_checks_passed'] is True
        assert dataset['district_count'] == membership['actual_parent_subarea_count'] == proof['source_district_count'] == 24
        assert dataset['native_district_records_total'] == membership['native_district_records_total'] == 0
        assert dataset['native_district_membership_proved'] is False
        assert membership['native_district_membership_proved'] is False
        assert set(dataset['source_cities']) == {'臺北市', '基隆市', '新竹市', '嘉義市'}
        engine_path = ROOT / pins['engine_path'] if engine_path is None else Path(engine_path)
        _read_verified(engine_path, pins['engine_bytes'], pins['engine_sha256'])
        spec = importlib.util.spec_from_file_location('flat_city_verified_source_geometry_engine', engine_path)
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        rows = {(r['source_city'], r['district']): r for r in membership['districts']}
        assert len(rows) == 24
        self.geometries = {}
        self.metadata = {}
        self.city_aliases = {}
        for source_city, parent in membership['source_cities'].items():
            assert parent['source_city'] == parent['source_parent_tags']['name'] == source_city
            assert parent['native_city_to_street_layout'] and parent['native_district_records'] == 0
            assert parent['source_parent_closure']['complete_reference_closed_geometry']
            for literal in (source_city, parent['native_city']):
                assert literal not in self.city_aliases or self.city_aliases[literal] == source_city
                self.city_aliases[literal] = source_city
            for district, item in dataset['source_cities'][source_city].items():
                key = (source_city, district)
                row = rows[key]
                assert item['source_city'] == source_city and item['district'] == district
                assert item['source_relation_id'] in parent['source_subarea_relation_ids']
                assert item['source_parent_relation_id'] == parent['source_parent_relation_id']
                assert item['source_relation_id'] == row['source_relation_id']
                assert item['source_relation_tags']['name'] == district
                assert item['native_city'] == parent['native_city']
                assert item['native_city_record'] == parent['native_city_row']['record']
                assert item['native_district_record'] is None and item['native_district_verified'] is False
                assert item['parent_subarea_membership_verified']
                closure = item['closure']
                assert closure == row['closure'] and closure['complete_reference_closed_geometry']
                assert not closure['missing_way_ids'] and not closure['missing_node_ids']
                assert hashlib.sha256(_canonical(item['geometry'])).hexdigest() == item['geometry_sha256']
                self.geometries[key] = engine.CityGeometry(item['geometry'])
                self.metadata[key] = {name: item[name] for name in (
                    'source_city', 'district', 'source_relation_id', 'source_parent_relation_id',
                    'native_city', 'native_city_record', 'native_district_record', 'geometry_sha256')}
        assert set(self.geometries) == set(rows)
        self.dataset = dataset

    def assess(self, city, district, latitude, longitude):
        """Check exactly named source district; no automatic district assignment.

        Accepts the exact source city name or its explicitly bound native literal
        (臺北市/台北市 only differ). District names must match source literally.
        Shared boundaries are covered; this does not resolve cross-group conflict.
        """
        result = {'eligible': False, 'geometry_prerequisite_only': True,
                  'native_merge_eligible': False, 'native_district_verified': False,
                  'input_city': city, 'district': district}
        if not isinstance(city, str) or city not in self.city_aliases:
            return dict(result, status='unsupported_city')
        source_city = self.city_aliases[city]
        if not isinstance(district, str) or (source_city, district) not in self.geometries:
            return dict(result, source_city=source_city, status='source_district_unknown')
        key = (source_city, district)
        result.update(self.metadata[key])
        if isinstance(latitude, bool) or isinstance(longitude, bool):
            return dict(result, status='invalid_coordinate')
        try:
            lat, lon = Decimal(str(latitude)), Decimal(str(longitude))
        except (InvalidOperation, ValueError, TypeError):
            return dict(result, status='invalid_coordinate')
        if not lat.is_finite() or not lon.is_finite() or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return dict(result, status='invalid_global_coordinate')
        try:
            covered = self.geometries[key].covers(lat, lon)
        except (InvalidOperation, ValueError, OverflowError):
            return dict(result, status='coordinate_exceeds_source_precision')
        return dict(result, eligible=covered, source_coordinate_strings=[str(lat), str(lon)],
                    status='inside_declared_source_district' if covered else 'outside_declared_source_district')

    def assess_source_and_raw24(self, city, district, latitude, longitude, raw24):
        """Both original source and exactly encoded native point must be same district.

        raw24 is [latitude_uint24, longitude_uint24]. The exact native-grid point
        is tested rationally, without a decimal precision rounding intermediate.
        """
        result = self.assess(city, district, latitude, longitude)
        if not result['eligible']:
            return dict(result, source_point_inside=False, quantized_point_inside=False)
        result.update(eligible=False, source_point_inside=True, quantized_point_inside=False)
        if not isinstance(raw24, (list, tuple)) or len(raw24) != 2 \
                or any(type(word) is not int or not 0 <= word < (1 << 24) for word in raw24):
            return dict(result, status='invalid_raw24')
        try:
            expected = [_round24(Decimal(str(v))) for v in (latitude, longitude)]
        except (ValueError, InvalidOperation, OverflowError):
            return dict(result, status='source_not_encodable_as_raw24')
        if list(raw24) != expected:
            return dict(result, status='raw24_does_not_match_source_rounding')
        signed = [word if word < 0x800000 else word - 0x1000000 for word in raw24]
        key = (result['source_city'], district)
        inside = _rational_covers(self.geometries[key], signed[1] * 3515625, signed[0] * 3515625, 16384)
        return dict(result, eligible=inside, quantized_point_inside=inside, raw24=list(raw24),
                    status='source_and_raw24_inside_same_declared_source_district' if inside
                           else 'quantized_point_outside_declared_source_district')

    def covers(self, city, district, latitude, longitude):
        return self.assess(city, district, latitude, longitude)['eligible']
