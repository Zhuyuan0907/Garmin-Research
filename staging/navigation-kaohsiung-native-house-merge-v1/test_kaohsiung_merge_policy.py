#!/usr/bin/env python3
"""New raw24 boundary policy and country-v1 continuation controls only."""
import hashlib
import importlib.util
import json
import sys
from fractions import Fraction
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import merge_policy as policy


def ring_reference(ring, x, y):
    count = 0
    for (ax, ay), (bx, by) in zip(ring, ring[1:]):
        if (x - ax) * (by - ay) == (y - ay) * (bx - ax) and min(ax, bx) <= x <= max(ax, bx) and min(ay, by) <= y <= max(ay, by):
            return 2
        if ay <= y < by or by <= y < ay:
            at_x = Fraction(ax) + Fraction((y - ay) * (bx - ax), by - ay)
            if at_x > x:count += 1
    return count % 2


def rational_reference(geometry, raw24):
    # Full ring scan and Fraction intersection, independent of bucketed Ring.test.
    y = Fraction(policy.signed24(raw24[0]) * 360 * 10000000, 1 << 24)
    x = Fraction(policy.signed24(raw24[1]) * 360 * 10000000, 1 << 24)
    for rings in geometry.polygons:
        outer = ring_reference(rings[0].vertices, x, y)
        if outer == 2:return True
        if not outer:continue
        holes = [ring_reference(r.vertices, x, y) for r in rings[1:]]
        if 2 in holes or 1 not in holes:return True
    return False


def raw_quantized(base, latitude, longitude):
    q = base.quantize_point24(latitude, longitude)
    return [q['latitude']['wire_u24'], q['longitude']['wire_u24']]


def bit_bytes(values, width):
    # Independent one-big-integer little-endian serialization for small controls.
    total = sum(value << (index * width) for index, value in enumerate(values))
    return total.to_bytes((len(values) * width + 7) // 8, 'little')


def main():
    base = policy.country_helpers()
    validator = policy.district_validator()
    boundary_controls, raw_checks = [], 0
    inside_after_quantization = outside_after_quantization = 0
    for district, geometry in sorted(validator.geometries.items()):
        for ring in geometry.polygons[0][:1]:
            # Five actual source vertices per district; all are source-covered.
            indices = sorted({0, len(ring.vertices)//4, len(ring.vertices)//2, 3*len(ring.vertices)//4, len(ring.vertices)-2})
            for index in indices:
                x, y = ring.vertices[index]
                latitude, longitude = str(Fraction(y, 10000000)), str(Fraction(x, 10000000))
                # Fraction text is not accepted by source API; exact 7-digit
                # decimal strings preserve the actual node coordinates.
                from decimal import Decimal
                latitude, longitude = str(Decimal(y)/10000000), str(Decimal(x)/10000000)
                assert validator.covers('高雄市', district, latitude, longitude)
                raw = raw_quantized(base, latitude, longitude)
                expected = rational_reference(geometry, raw)
                actual = policy.quantized_assess(validator, '高雄市', district, raw)
                assert actual['eligible'] == expected
                raw_checks += 1
                if expected:inside_after_quantization += 1
                else:
                    outside_after_quantization += 1
                    if len(boundary_controls) < 5:
                        boundary_controls.append(dict(district=district, source_coordinate_strings=[latitude,longitude],
                            raw24=raw, source_inside=True, quantized_inside=False, held_by_new_policy=True))
    assert raw_checks >= 180 and inside_after_quantization and outside_after_quantization
    guards = []
    for label, city, district, raw, status in [
        ('wrong_city', '臺南市', '三民區', [1,1], 'unsupported_city'),
        ('incomplete_旗津', '高雄市', '旗津區', [1,1], 'district_geometry_incomplete_held'),
        ('unknown_district', '高雄市', '未知區', [1,1], 'district_unknown'),
        ('missing_district', '高雄市', None, [1,1], 'district_unknown'),
        ('wrong_raw_length', '高雄市', '三民區', [1], 'invalid_raw24_point'),
        ('raw_overflow', '高雄市', '三民區', [1<<24,1], 'invalid_raw24_point'),
        ('raw_negative_unsigned', '高雄市', '三民區', [-1,1], 'invalid_raw24_point'),
        ('raw_boolean', '高雄市', '三民區', [True,1], 'invalid_raw24_point'),
        ('quantized_latitude_out_of_bounds', '高雄市', '三民區', [1<<22 | 1,1], 'invalid_global_quantized_point')]:
        result = policy.quantized_assess(validator,city,district,raw)
        assert not result['eligible'] and result['status'] == status
        guards.append({'name':label,'passed':True})
    template={'native_street_record':805339356,'nativeStreetID':32988,'native_city':'高雄市','native_district':'三民區',
              'native_street':'三民街','old_child_first':1558857,'old_child_count':329,'old_child_level_and_flags':4,'old_next_level':4,
              'raw_address':['高雄市','三民區','三民街','1號']}
    native={'record':805339356,'low28_id':32988,'city':'高雄市','district':'三民區','street':'三民街',
            'first_child':1558857,'child_count':329,'child_level_and_flags':4,'next_level':4}
    assert policy.exact_native_witness(template,native) and policy.exact_source_administration(template)
    assert not policy.exact_native_witness(dict(template,old_child_level_and_flags=13),native)
    assert not policy.exact_native_witness(dict(template,native_district='鼓山區'),native)
    assert not policy.exact_source_administration(dict(template,raw_address=['高雄市','三民區 ','三民街','1號']))
    guards.extend({'name':name,'passed':True} for name in ['exact_native_witness_positive','original_flags_mismatch_rejected',
                                                        'native_district_mismatch_rejected','source_district_alias_rejected'])
    continuation = []
    for level,width,start in [(4,128,3425572),(5,126,2614789),(6,68,1983085)]:
        first, second = [3], [(1<<width)-1,0,1<< (width-1)]
        prefix, suffix = bit_bytes(first,width), base.packed(second,width)
        expected = bit_bytes(first+second,width)
        # This represents significant-bit splicing; the package stage does not
        # yet have a production splicer or write a country candidate.
        combined = int.from_bytes(prefix,'little') | (int.from_bytes(suffix,'little') << width)
        actual = combined.to_bytes(((1+len(second))*width+7)//8,'little')
        assert actual == expected
        assert (prefix+suffix == expected) is (width%8 == 0)
        assert start+1 == {4:3425573,5:2614790,6:1983086}[level]
        continuation.append(dict(level=level,record_bits=width,starting_count=start,first_new_record=start+1,
            prior_fixture_unused_high_bits=(-width)%8,byte_concatenation_matches=width%8==0,
            exact_significant_bit_splice_matches=True))
    # Base merge primitive is reused once in a new policy control: original
    # subnumbers, raw13 records and relative order remain exact, not normalized.
    original = [17,29,41]
    extra = [{'number':2,'label':'2號','value':53},{'number':8,'label':'8號','value':67}]
    result = base.merge_numeric(original,['1號','1之2號','7號'],extra)
    assert result[0] == [17,29,53,41,67]
    assert base.merge_numeric(original,['7號','1號','8號'],extra) is None
    guards.extend([{'name':'preserve_existing_subnumber_record_and_order','passed':True},
                   {'name':'unproved_original_order_holds','passed':True}])
    proof={'schema':'kaohsiung-new-merge-policy-controls/v1','all_assigned_new_controls_passed':True,
           'actual_raw24_district_boundary_checks':raw_checks,'quantized_inside':inside_after_quantization,
           'source_boundary_inside_but_quantized_outside':outside_after_quantization,
           'representative_rounding_outside_controls':boundary_controls,'guards':guards,'guard_count':len(guards),
           'level_continuation_controls':continuation,'input_or_old_country_suite_rerun':False,'device_IO':False,
           'new_full_IMG_created':False,'source_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with (HERE/'new-policy-test-proof.json').open('x') as stream:
        json.dump(proof,stream,ensure_ascii=False,sort_keys=True,separators=(',',':'));stream.write('\n')
    print(json.dumps({'all_assigned_new_controls_passed':True,'raw24_checks':raw_checks,'rounded_outside_controls':outside_after_quantization,
                      'guards':len(guards),'continuation_levels':3},ensure_ascii=False))


if __name__=='__main__':main()
