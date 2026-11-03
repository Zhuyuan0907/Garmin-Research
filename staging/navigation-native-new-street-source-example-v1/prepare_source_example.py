#!/usr/bin/env python3
"""Seal one actual source-backed street-name gap from an already bounded prefix.

Never opens PBF, node/address ledgers, stock IMG, native SQLite or a device.
Only the saved shortlist/context and small geometry/label/provenance inputs
are consumed. Literal native absence is not proof against historic aliases.
"""
import ast
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import unicodedata

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
INPUTS = []


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def sig(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def read(path, limit, expected=None):
    path = ROOT / path
    before = sig(path)
    need(before[2] <= limit, 'Bounded small input: ' + str(path))
    with path.open('rb') as handle:
        raw = handle.read(limit + 1)
    after = sig(path)
    need(before == after and len(raw) == before[2], 'Immutable complete small input')
    if expected:
        need(sha(raw) == expected, 'Pinned input content: ' + str(path))
    INPUTS.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw),
                       stat_before=before, stat_after=after, stat_unchanged=True,
                       complete_small_file_EOF=True))
    return raw


def load(path, limit, expected=None):
    return json.loads(read(path, limit, expected))


def save(name, value):
    raw = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode()
    with (OUT / name).open('xb') as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return dict(path=str((OUT / name).relative_to(ROOT)), bytes=len(raw), sha256=sha(raw))


def normalized(name):
    return unicodedata.normalize('NFKC', name).strip().replace('臺', '台')


def one_edit(a, b):
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) <= 1
    if len(a) > len(b):
        a, b = b, a
    return any(a == b[:i] + b[i + 1:] for i in range(len(b)))


def pure_nodes(path, names, limit, expected, namespace):
    raw = read(path, limit, expected)
    tree = ast.parse(raw)
    selected = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    need({n.name for n in selected} == set(names), 'Explicit pure API definitions')
    module = ast.Module(body=selected, type_ignores=[])
    namespace.update({'Decimal': Decimal, 'defaultdict': defaultdict, 'need': need})
    exec(compile(module, path, 'exec'), namespace)
    return dict(path=path, sha256=sha(raw), selected_definitions=names,
                selected_AST_sha256=sha(ast.dump(module, include_attributes=False).encode()),
                historical_main_or_cases_executed=False)


def main():
    started = datetime.now(timezone.utc).isoformat()
    rel = str(OUT.relative_to(ROOT))
    shortlist = load(rel + '/final-bounded-taichung-shortlist.json', 6000,
                     '1fa31eb44328ba9d65350a83fd4a240197e4727f3fc88175d4de50445fb74905')
    context = load(rel + '/bounded-native-screen-context.json', 600000,
                   '097dd238ae1124594cebb54ef39891be4cf31435628e1ea84cb71854ab71ddae')
    prefix = load(rel + '/final-source-prefix-budget-receipt.json', 2000)
    inherited = load('staging/navigation-country-address-ready-join-v1/proof.json', 400000,
                     'b61cd949152fece0548265ccf438c14d3bbeeddfc5e3ae05140df20d3aa0a175')
    ingestion = load('staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json', 70000)
    gp = load('staging/navigation-taichung-city-geometry-v1/proof.json', 6000)
    geometry = load('staging/navigation-taichung-city-geometry-v1/geometry.json', 210000,
                    '276e0a3f7e07383d6f94c9e4d84cac17c89b83b64d656d66552a978a511c0158')
    need(gp['all_assigned_checks_passed'] and gp['polygon_count'] == 1 and gp['vertices'] == 9616,
         'Accepted complete source city geometry')
    need(prefix['complete_rows'] == 46470 and prefix['compressed_prefix_bytes'] == 3 * 1024 * 1024
         and prefix['uncompressed_prefix_bytes'] == 24 * 1024 * 1024 and not prefix['gzip_EOF'],
         'Final authorized bounded-prefix scope, not whole-ledger EOF')
    source_binding = next(r for r in inherited['inputs'] if r['path'] == prefix['source_path'])
    source_now = sig(ROOT / prefix['source_path'])  # STAT ONLY: never open the ledger.
    need(source_binding['stat_after'] == source_now == prefix['source_stat_before'],
         'Saved bounded source prefix belongs to unchanged inherited EOF/hash source')
    source_roster = next(r for r in inherited['inputs'] if r['path'].endswith('/native-hierarchy.jsonl.gz'))
    need(source_roster['sha256'] == prefix['source_roster_SHA'], 'Native roster inherited identity')

    selected = next(r for r in shortlist if (r['city'], r['district'], r['street']) ==
                    ('台中市', '北屯區', '敦富六街'))
    need(len(selected['groups']) == 1, 'One complete retained source group')
    group = selected['groups'][0]
    need(group['group_id'] == 37506 and group['source_ids'] == [8280986017]
         and group['source_node_count'] == 1, 'Full sole-node source provenance')
    need(group['coordinate_selection_ready'] and not group['needs_coordinate_review']
         and group['different_coordinate_nodes'] == 0 and not group['embedded_floor_unit']
         and group['separate_floor_unit_nodes'] == 0, 'No first-point/conflict/floor selection')
    city, district, street, label = group['normalized_planning_key']
    raw_city, raw_district, raw_street, raw_house = group['raw_address']
    need(re.fullmatch(r'[1-9][0-9]*', raw_house) and label == raw_house + '號', 'Literal positive integer house')
    need([normalized(s) for s in (raw_city, raw_district, raw_street)] == [city, district, street]
         and raw_street == street and raw_district == district, 'Only explicit city 臺/台 normalization')
    native_city = [r for r in context if r['level'] == 1 and r['city'] == city]
    native_district = [r for r in context if r['level'] == 2 and r['city'] == city and r['district'] == district]
    streets = [r for r in context if r['level'] == 3 and r['city'] == city and r['district'] == district]
    need(len(native_city) == len(native_district) == 1 and len(streets) == 441, 'Unique existing native admin context')
    exact = [r for r in streets if normalized(r['street']) == street]
    near = [r for r in streets if one_edit(normalized(r['street']), street)]
    prefix_matches = [r for r in streets if street.startswith(normalized(r['street']))]
    need(not exact and not near and not prefix_matches, 'Exact absent, conservative near/prefix screen empty')
    need(not re.search(r'[巷弄段村里鄰()（）]', street), 'No explicit lane/alley/section/village suffix')
    actual_family = load('staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json', 350000,
                         '929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6')
    need(actual_family['all_assigned_checks_passed'] and actual_family['selected_original_physical_L3_count'] == 441
         and actual_family['selected_named_info_rows'] == 441, 'Independent actual original JAI family snapshot')
    need(not any(r['label'] == street for r in actual_family['old_info_rows']), 'Literal absence in all441 actual DB street labels')
    l2 = actual_family['actual_original_L2_fields']
    need(l2['one_based_ID'] == native_district[0]['low28_id'] == 74 and l2['first_child'] == 12924
         and l2['child_count'] == 441 and l2['next_level'] == 3, 'Actual original district-to-street parent fields')
    relevant_families = [dict(parent_record=f[0], the_first_record=f[1]) for f in actual_family['original_families']
                         if f[0] in (native_city[0]['record'], native_district[0]['record'])]
    need(len(relevant_families) == 2, 'Actual original city and district family rows')

    namespace = {}
    coordinate_api = pure_nodes('scripts/native_address_records.py', ['quantize_point24'], 8000,
                               '8dfec0a03795e29fc223fbd06f0418536b6f3969024083b5023e25620319eb33',
                               namespace)
    from decimal import ROUND_HALF_UP
    namespace['ROUND_HALF_UP'] = ROUND_HALF_UP
    winding_api = pure_nodes('staging/navigation-country-merge-independent-review-v1/review_country_merge.py',
                             ['WindingRing', 'WindingCity'], 36000,
                             '7490c4015dc16f4fa8e69d8bb45cdf3f0c6c2ad93afcf1093c44d0cb3d9852ec', namespace)
    point = group['first_coordinate']
    decimals = [Decimal(x) for x in point]
    need(all(v.is_finite() for v in decimals) and 20 <= decimals[0] <= 27 and 117 <= decimals[1] <= 123,
         'Finite conservative Taiwan global bounds')
    scaled = [v * 10_000_000 for v in decimals]
    need(all(v == v.to_integral_value() for v in scaled), 'Exact original OSM point precision')
    q = namespace['quantize_point24'](*point)
    raw24 = [q[axis]['wire_u24'] for axis in ('latitude', 'longitude')]
    signed24 = [q[axis]['signed24'] for axis in ('latitude', 'longitude')]
    independent_raw = []
    for text in point:
        fraction = Fraction(text) * 16777216 / 360
        positive = abs(fraction)
        whole, remainder = divmod(positive.numerator, positive.denominator)
        if 2 * remainder >= positive.denominator:
            whole += 1
        independent_raw.append((-whole if fraction < 0 else whole) & 0xffffff)
    need(raw24 == independent_raw, 'Exact rational raw24 rounding agrees with pinned policy')
    city_geometry = namespace['WindingCity'](geometry)
    source_inside = city_geometry.covers(int(scaled[1]), int(scaled[0]))
    quantized_inside = city_geometry.covers(signed24[1] * 3515625, signed24[0] * 3515625, 16384)
    need(source_inside and quantized_inside, 'Source and exact quantized point inside full source city')

    # This small text-ref index is read once to EOF. Ref reuse never proves old-address overlap.
    hp = load('staging/navigation-native-house-label-index-v1/proof.json', 40000,
              '793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4')
    labels_raw = read('staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz', 270000,
                      hp['ledger_sha256'])
    labels_plain = gzip.decompress(labels_raw)
    need(len(labels_plain) < 8 * 1024 * 1024, 'Bounded numeric-label index plaintext')
    labels = [json.loads(line) for line in labels_plain.splitlines()]
    need(len(labels) == hp['distinct_integer_or_subnumber_house_labels'] == 50567, 'Small label index complete EOF/count')
    reusable = [r for r in labels if r['label'] == label]
    need(len(reusable) == 1, 'Existing exact house label text ref')
    INPUTS[-1].update(gzip_validated_EOF=True, json_rows=len(labels), uncompressed_bytes=len(labels_plain),
                      uncompressed_sha256=sha(labels_plain))

    candidate = dict(
        schema='garmin-source-backed-new-street-example/v1',
        status='source_backed_literal_missing_street_pending_alias_prototype_only',
        streettext=street, house_label=label, raw_city=raw_city, raw_district=raw_district,
        raw_street=raw_street, raw_house=raw_house, city=city, district=district,
        raw_address=group['raw_address'], normalized_planning_key=group['normalized_planning_key'],
        source_group_ids=[group['group_id']], source_ids=group['source_ids'],
        sourcepoint=point, coordinate_strings=point, raw24=raw24, signed24=signed24,
        coordinate_quantization=q,
        source_members=[dict(source_group_id=group['group_id'], source_node_id=group['source_ids'][0],
                             source_type='node', coordinate_strings=point, raw_address=group['raw_address'],
                             source_node_version=None, source_node_timestamp=None,
                             metadata_limit='Version/timestamp not present in prepared group; full node ledger not opened.')],
        original_prepared_group=group, native_city=native_city[0], native_district=native_district[0],
        original_city_district_relationship=dict(
            native_city_record=native_city[0]['record'], native_city_lowID=native_city[0]['low28_id'],
            native_district_record=native_district[0]['record'], native_district_lowID=native_district[0]['low28_id'],
            city_name='台中市', district_name='北屯區', relation_basis='Original JAI decoded native roster city/district fields',
            native_district_record_exists=True, same_context_named_street_rows=441,
            exactstreet_matches=[], literal_one_edit_matches=[], literal_oldstreet_prefix_matches=[],
            independent_actual_original_family_snapshot=dict(
                path='staging/navigation-native-jai-new-street-plan-v1/original-family-snapshot.json',
                sha256='929a52d912f1622f3aa9fecea8a8fc0d71517fed349a0f995e84d983e85f04d6',
                actual_original_family_rows=relevant_families, actual_original_L2_fields=l2,
                selected_family_first=actual_family['selected_family_first'],
                selected_family_end=actual_family['selected_family_end'],
                literal_missing_in_all441_actual_DB_labels=True)),
        original_JAI_exact_street_absent=True,
        absence_evidence_scope='All441 namedL3 rows of original北屯區 from cached roster plus independent actual original JAI family snapshot; original DB not reopened by this runner.',
        conservative_name_screen=dict(raw_street_literal_unchanged=True,
                                      one_character_edit_near_matches=0, oldstreet_prefix_matches=0,
                                      lane_alley_section_village_markers=False,
                                      historical_aliases_verified=False, official_street_authenticity_verified=False),
        house_text_reference=dict(label=label, primary_ref=reusable[0]['primary_ref'], existing_label_only=True,
                                  existing_address_overlap_proved=False,
                                  bounded_original_pool_proof_sha256='793ad2853b07ee3940d0e4f44b39809c612b4ed2de5632387b3a7c36123ed3b4'),
        geometry_gate=dict(city='臺中市', sourcepoint_inside_full_city=source_inside,
                           exact_quantized_raw24_inside_same_full_city=quantized_inside,
                           source_global_bounds_passed=True, source_city_geometry_complete=True,
                           geometry_sha256=gp['geometry_sha256'], geometry_vertices=gp['vertices'],
                           method='Exact signed winding with integer source vertices and rational raw24 point, boundaries covered, holes excluded.',
                           quantized_point_scaled_1e7_rational=dict(x_numerator=signed24[1]*3515625,
                                                                y_numerator=signed24[0]*3515625, denominator=16384),
                           district_polygon_membership_proved=False,
                           district_basis='Literal source addr:district equals existing original native district name only.'),
        inherited_source=dict(prepared_groups_identity=source_binding,
                              prepared_groups_full_EOF_hash_inherited_not_reread=True,
                              source_OSM_snapshot=ingestion['source'], original_native_roster_identity=source_roster,
                              bounded_prefix_receipt=prefix),
        admissibility=dict(host_only_JAI_LBL_MDR_prototype=True, install_candidate=False,
                           actual_new_physical_road_proved=False, address_authenticity_proved=False,
                           full_Taiwan_native_update_complete=False),
        restrictions=['Do not map aliases or silently assign a different district.',
                      'No automatic install eligibility from literal absence or successful geometry checks.',
                      'No existing-address overlap, road entrance, native query, route or device acceptance proved.',
                      'Source member raw address and point are complete for this sole-node prepared group; original node extra metadata was not read.'])
    candidate_artifact = save('candidate.json', candidate)
    proof = dict(schema='garmin-native-new-street-source-example-proof/v1', started_utc=started,
                 finished_utc=datetime.now(timezone.utc).isoformat(), all_assigned_checks_passed=True,
                 script_sha256=sha(Path(__file__).read_bytes()), candidate=candidate_artifact,
                 source_inputs=INPUTS, pure_api_reuse=[coordinate_api, winding_api],
                 source_members_complete_for_selected_group=True,
                 exact_old_city_and_district_unique=True, original_street_exact_absent=True,
                 original_same_context_named_street_rows=441,
                 exact_source_and_raw24_same_full_city_gate_passed=True,
                 alias_authenticity_unverified_held=True, district_geometry_unverified=True,
                 source_prefix_scope=prefix,
                 actual_new_scope_preparation_sourcegroup_content_bytes_read=0,
                 inherited_prefix_complete_rows=46470, source_total_groups_inherited=4630959,
                 inherited_prefix_fraction_of_groups=str(Decimal(46470)/Decimal(4630959)),
                 original_DB_IMG_PBF_nodeledger_opened=False, native_CPU_executed=False,
                 device_IO=False, sealed_v3_mutated=False, new_IMG_JAI_LBL_MDR_emitted=False,
                 full_Taiwan_native_update_complete=False,
                 limits=candidate['restrictions'])
    proof_artifact = save('proof.json', proof)
    print(json.dumps(dict(all_assigned_checks_passed=True, candidate=candidate_artifact,
                          proof=proof_artifact, raw24=raw24, house_ref=reusable[0]['primary_ref'],
                          source_and_quantized_city_gate=True, pending_alias_prototype_only=True), ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
