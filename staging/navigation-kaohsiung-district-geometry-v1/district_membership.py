#!/usr/bin/env python3
"""Pinned explicit-district containment; no union or incomplete-city fallback.

Later address processing must supply the exact city AND district associated with
the native street. This module is a geometry prerequisite, not an address merge.
"""
import hashlib
import importlib.util
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
CITY = '高雄市'
PARENT_RELATION = 2127079
ENGINE_PATH = ROOT / 'scripts/prepare_taichung_city_geometry_v1.py'
PINS = {
    'district-geometries.json': (962617, '64c5219bc8ee1f8f5b779b34bc65f41e1797d1d684f9ed8ad0960894425b64b8'),
    'proof.json': (5360, '1c119734f9c1c4c524b23f8c4233fe8b413e43212721f7ceb8edb00693eb1f50'),
    'source-membership.json': (45803, '6f818e684fe5cdc248b5b9657a2526b3bb69ec5c511d3be86d91658a32403836'),
}
ENGINE_BYTES = 5776
ENGINE_SHA256 = '2fff38c613a41017553f8a59978b85811fce6b118b6db87cfc07fe1e17d74101'


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _verified_json(path, name):
    data = path.read_bytes()
    size, digest = PINS[name]
    if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError('Unverified geometry input: ' + name)
    return json.loads(data)


class DistrictMembership:
    def __init__(self, data_dir=HERE, engine_path=ENGINE_PATH):
        directory = Path(data_dir)
        dataset = _verified_json(directory / 'district-geometries.json', 'district-geometries.json')
        proof = _verified_json(directory / 'proof.json', 'proof.json')
        membership = _verified_json(directory / 'source-membership.json', 'source-membership.json')
        engine_path = Path(engine_path)
        engine_bytes = engine_path.read_bytes()
        if len(engine_bytes) != ENGINE_BYTES or hashlib.sha256(engine_bytes).hexdigest() != ENGINE_SHA256:
            raise ValueError('Unverified original CityGeometry engine')
        spec = importlib.util.spec_from_file_location('kaohsiung_existing_city_geometry_engine', engine_path)
        engine = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(engine)
        assert dataset['schema'] == 'garmin-explicit-kaohsiung-district-geometries/v1'
        assert dataset['city'] == CITY and dataset['parent_relation_id'] == PARENT_RELATION
        assert dataset['full_city_geometry_complete'] is False and dataset['union_is_city_geometry'] is False
        assert proof['all_assigned_preparation_checks_passed'] is True
        assert proof['actual_parent_subareas'] == 38 and proof['complete_districts_exported'] == 37
        assert membership['parent_relation_id'] == PARENT_RELATION
        assert membership['parent_tags']['name'] == CITY and membership['source_subarea_count'] == 38
        rows = {row['district']: row for row in membership['districts']}
        assert len(rows) == 38
        complete_names = {name for name, row in rows.items() if row['closure']['complete_reference_closed_geometry']}
        held_names = set(rows) - complete_names
        assert len(complete_names) == 37 and held_names == {'旗津區'}
        assert set(dataset['districts']) == complete_names
        assert set(dataset['held_districts']) == held_names
        self.geometries = {}
        self.metadata = {}
        self.held = dataset['held_districts']
        for district, item in dataset['districts'].items():
            row = rows[district]
            assert item['city'] == CITY and item['district'] == district
            assert item['source_parent_relation_id'] == PARENT_RELATION
            assert item['source_relation_id'] == row['source_relation_id']
            assert item['native_district_record'] == row['native_district_record']
            assert item['native_city_record'] == membership['native_city']['record']
            assert row['city'] == CITY and row['source_relation_tags']['name'] == district
            assert row['native_names_exact'] and row['parent_subarea_membership_verified']
            assert item['complete_reference_closed_geometry'] is True and item['closure'] == row['closure']
            assert not item['closure']['missing_way_ids'] and not item['closure']['missing_node_ids']
            assert hashlib.sha256(_canonical(item['geometry'])).hexdigest() == item['geometry_sha256']
            self.geometries[district] = engine.CityGeometry(item['geometry'])
            self.metadata[district] = {key: item[key] for key in (
                'source_relation_id', 'source_parent_relation_id', 'native_city_record', 'native_district_record', 'geometry_sha256')}
        self.engine = engine

    def assess(self, city, district, latitude, longitude):
        """Return a reasoned decision; only inside_verified_district is eligible.

        Boundaries are covered, following the existing covers engine. Membership
        at a shared boundary does not assign a district or resolve conflicts.
        """
        result = {'eligible': False, 'city': city, 'district': district}
        if city != CITY:
            return dict(result, status='unsupported_city')
        if not isinstance(district, str):
            return dict(result, status='district_unknown')
        if district in self.held:
            return dict(result, status='district_geometry_incomplete_held',
                        source_relation_id=self.held[district]['source_relation_id'],
                        missing_way_ids=self.held[district]['closure']['missing_way_ids'])
        if district not in self.geometries:
            return dict(result, status='district_unknown')
        if isinstance(latitude, bool) or isinstance(longitude, bool):
            return dict(result, status='invalid_coordinate')
        try:
            lat, lon = Decimal(str(latitude)), Decimal(str(longitude))
        except (InvalidOperation, TypeError, ValueError):
            return dict(result, status='invalid_coordinate')
        if not lat.is_finite() or not lon.is_finite() or not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return dict(result, status='invalid_global_coordinate')
        try:
            covered = self.geometries[district].covers(lat, lon)
        except (InvalidOperation, ValueError, OverflowError):
            return dict(result, status='coordinate_exceeds_source_precision')
        return dict(result, **self.metadata[district], eligible=covered,
                    status='inside_verified_district' if covered else 'outside_verified_district')

    def covers(self, city, district, latitude, longitude):
        return self.assess(city, district, latitude, longitude)['eligible']
