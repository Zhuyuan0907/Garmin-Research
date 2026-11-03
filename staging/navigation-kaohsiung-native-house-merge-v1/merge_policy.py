#!/usr/bin/env python3
"""New high-precision quantized-point guard over the frozen district engine."""
import hashlib
import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
BASE_PATH = ROOT / 'staging/navigation-country-native-house-merge-v1/prepare_country_house_merge.py'
BASE_SHA256 = '122a57da82a0b436511196fa114985d38e914f040878a372f0ca1117bb7b3d07'
DISTRICT_PATH = ROOT / 'staging/navigation-kaohsiung-district-geometry-v1/district_membership.py'
DISTRICT_SHA256 = 'c99ba1ad496356ca389f0bd8a8f1c7b00929a216066b7ed05a6c100359d0e998'


def verified_module(path, digest, name):
    payload = path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError('Unverified reusable source: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def country_helpers():
    return verified_module(BASE_PATH, BASE_SHA256, 'kaohsiung_reused_country_primitives')


def district_validator():
    return verified_module(DISTRICT_PATH, DISTRICT_SHA256, 'kaohsiung_frozen_district_api').DistrictMembership()


def signed24(value):
    if type(value) is not int or not 0 <= value < 1 << 24:
        raise ValueError('Raw point must be an unsigned 24-bit integer')
    return value - (1 << 24) if value & (1 << 23) else value


def quantized_assess(validator, city, district, raw24):
    """Exact signed-circle point containment, without rounding again to 7 digits.

    Polygon vertices remain in the frozen engine's integer 10^-7-degree scale.
    Ring.test supports exact Fraction points; its latitude bucket floor and all
    crossings/boundaries retain the same semantics. No city union is consulted.
    """
    result = {'eligible': False, 'city': city, 'district': district}
    if city != '高雄市':
        return dict(result, status='unsupported_city')
    if not isinstance(district, str) or district not in validator.geometries:
        if isinstance(district, str) and district in validator.held:
            return dict(result, status='district_geometry_incomplete_held')
        return dict(result, status='district_unknown')
    if not isinstance(raw24, (list, tuple)) or len(raw24) != 2:
        return dict(result, status='invalid_raw24_point')
    try:
        latitude, longitude = [signed24(v) for v in raw24]
    except ValueError:
        return dict(result, status='invalid_raw24_point')
    lat_degrees = Fraction(latitude * 360, 1 << 24)
    lon_degrees = Fraction(longitude * 360, 1 << 24)
    if not -90 <= lat_degrees <= 90 or not -180 <= lon_degrees < 180:
        return dict(result, status='invalid_global_quantized_point')
    y, x = lat_degrees * 10000000, lon_degrees * 10000000
    covered = False
    for rings in validator.geometries[district].polygons:
        outer = rings[0].test(x, y)
        if outer == 2:
            covered = True
            break
        if outer == 0:
            continue
        holes = [ring.test(x, y) for ring in rings[1:]]
        if 2 in holes or 1 not in holes:
            covered = True
            break
    return dict(result, eligible=covered,
                status='inside_verified_district' if covered else 'outside_verified_district',
                signed24=[latitude, longitude],
                quantized_exact_rational_degrees=[str(lat_degrees), str(lon_degrees)],
                **validator.metadata[district])


def exact_native_witness(row, native):
    """Original names and parent fields must match; no administrative aliases."""
    pairs = (
        ('native_street_record', 'record'), ('nativeStreetID', 'low28_id'),
        ('native_city', 'city'), ('native_district', 'district'), ('native_street', 'street'),
        ('old_child_first', 'first_child'), ('old_child_count', 'child_count'),
        ('old_child_level_and_flags', 'child_level_and_flags'), ('old_next_level', 'next_level'))
    return native is not None and all(row[a] == native[b] for a, b in pairs)


def exact_source_administration(row):
    raw = row['raw_address']
    return isinstance(raw, list) and len(raw) == 4 and raw[0] == '高雄市' and raw[1] == row['native_district']
