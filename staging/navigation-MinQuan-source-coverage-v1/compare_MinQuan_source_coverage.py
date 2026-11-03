#!/usr/bin/env python3
"""Compare existing OSM XML explicit addresses with frozen84 AP primary labels.

Reads only XML and small sealed proof files. No IMG, USB, codec or native CPU.
"""
from datetime import datetime, timezone
import collections
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path('/root/garmin')
OUT = ROOT / 'staging/navigation-MinQuan-source-coverage-v1'
XML = ROOT / 'staging/navigation-house184-v1/minquan-addresses.osm'
XML_ORIGIN = ROOT / 'staging/navigation-house184-v1/source-address184-proof.json'
STOCK = ROOT / 'staging/navigation-AP-MinQuan184-witness-v1/stock-MinQuan184-bounded-source-proof-v1.json'
STOCK_SEAL = ROOT / 'staging/navigation-AP-MinQuan184-witness-v1/source-file-seal.json'


def need(ok, msg):
    if not ok:
        raise ValueError(msg)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def ref(path):
    raw = path.read_bytes()
    return {'path': str(path.relative_to(ROOT)), 'bytes': len(raw), 'sha256': sha(raw)}


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def source_digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for raw in iter(lambda: f.read(1024 * 1024), b''):
            h.update(raw)
    return h.hexdigest()


def comparison_label(raw):
    # Keep literal matching separately. This one explicit display convention
    # never changes punctuation, aliases, units, lane names or source tags.
    return (raw + '號', 'ASCII_integer_append_號') if re.fullmatch(r'[0-9]+', raw) else (raw, 'literal_unchanged')


def main():
    target = OUT / 'MinQuan-source-coverage-proof-v1.json'
    need(not target.exists(), 'Refusing to overwrite coverage proof')
    need(ref(STOCK)['sha256'] == '628a5452cfe8c1097a844fe9376d620d7240319fce4488dc7783a37010bf2774',
         'Frozen original84 label evidence changed')
    need(ref(STOCK_SEAL)['sha256'] == 'e8babb717bf395b66f6955147aa79fb9d6b6a20d863fd562b022526ef6fa1e36',
         'Original84 source seal changed')
    origin = json.loads(XML_ORIGIN.read_text())
    stock = json.loads(STOCK.read_text())
    stock_by_label = collections.defaultdict(list)
    for r in stock['all84_rows_with_frozen_boundaries']:
        stock_by_label[r['label']].append({'lowID': r['lowID'], 'primary_reference': r['primary_reference']})
    need(len(stock['all84_rows_with_frozen_boundaries']) == 84, 'Frozen primary label range differs')
    initial = stat(XML)
    digest = source_digest(XML)
    need(digest == origin['filter_output_sha256'] == '0888c1046137d101f7913ca34c9d481c361c8dc67e778d9e8fc0893ee053a870',
         'Existing filtered source XML differs')
    points, qualified, uncertain = {}, [], []
    scanned = collections.Counter()
    excluded = collections.Counter()
    explicit_street_house_count = 0
    root_attrs = None
    for event, e in ET.iterparse(XML, events=('start', 'end')):
        if event == 'start' and e.tag == 'osm':
            root_attrs = dict(e.attrib)
            continue
        if event != 'end' or e.tag not in ('node', 'way', 'relation'):
            continue
        scanned[e.tag] += 1
        attrs = dict(e.attrib)
        tags = {t.attrib['k']: t.attrib['v'] for t in e.findall('tag')}
        if e.tag == 'node' and 'lat' in attrs and 'lon' in attrs:
            points[attrs['id']] = [float(attrs['lat']), float(attrs['lon'])]
        if tags.get('addr:street') != '民權路' or 'addr:housenumber' not in tags:
            e.clear()
            continue
        explicit_street_house_count += 1
        city, district = tags.get('addr:city'), tags.get('addr:district')
        if city and city not in ('臺中市', '台中市'):
            excluded['explicit_other_city'] += 1
            e.clear()
            continue
        if city in ('臺中市', '台中市') and district and district != '中區':
            excluded['explicit_other_district'] += 1
            e.clear()
            continue
        reasons = []
        if not city:
            reasons.append('missing_explicit_addr_city')
        if not district:
            reasons.append('missing_explicit_addr_district')
        full = tags.get('addr:full', '')
        full_admin = re.search(r'(?:臺|台)中市([\u4e00-\u9fff]{1,4}?區)', full)
        if full_admin and full_admin.group(1) != '中區':
            reasons.append('addr_full_district_conflicts_with_target')
        raw_hn = tags['addr:housenumber']
        label, rule = comparison_label(raw_hn)
        row = {'type': e.tag, 'id': attrs['id'], 'attributes': attrs, 'tags': tags,
            'raw_housenumber': raw_hn, 'comparison_label': label, 'comparison_rule': rule,
            'raw_literal_primary_label_matches': stock_by_label.get(raw_hn, []),
            'format_equivalent_primary_label_matches': stock_by_label.get(label, []),
            'primary_label_status': 'present_in_old84' if label in stock_by_label else 'not_observed_in_old84',
            'administrative_status': 'uncertain' if reasons else 'explicit_target_city_district_street',
            'administrative_uncertainty_reasons': reasons,
            'additional_floor_or_unit_tags': any(k in tags for k in ('addr:floor', 'addr:unit'))}
        if e.tag == 'node':
            row['coordinate'] = points.get(attrs['id'])
            row['coordinate_method'] = 'raw_OSM_node_lat_lon'
        elif e.tag == 'way':
            row['_node_refs'] = [n.attrib['ref'] for n in e.findall('nd')]
        else:
            row['coordinate'] = None
            row['coordinate_method'] = 'relation_has_no_single_explicit_lat_lon'
        (uncertain if reasons else qualified).append(row)
        e.clear()
    need(stat(XML) == initial, 'XML changed during comparison')
    for r in qualified + uncertain:
        if r['type'] != 'way':
            continue
        refs = r.pop('_node_refs')
        coords = [points[v] for v in refs if v in points]
        # Geometry mean is supplied explicitly as a source-location aid only.
        if refs and len(coords) == len(refs):
            if len(coords) > 1 and refs[0] == refs[-1]:
                coords = coords[:-1]
            r['coordinate'] = [sum(p[n] for p in coords) / len(coords) for n in (0, 1)]
            r['coordinate_method'] = 'OSM_way_vertex_mean_excluding_duplicate_closure_not_entrance_or_route_target'
        else:
            r['coordinate'] = None
            r['coordinate_method'] = 'insufficient_node_coordinates_in_existing_XML'
        r['geometry_source_node_ref_count'] = len(refs)
        r['geometry_source_known_node_ref_count'] = sum(v in points for v in refs)
    qualified.sort(key=lambda r: (r['type'], int(r['id'])))
    uncertain.sort(key=lambda r: (r['type'], int(r['id'])))
    groups = collections.defaultdict(list)
    for row in qualified:
        groups[row['comparison_label']].append(row)
    distinct = []
    for label, records in sorted(groups.items(), key=lambda item: (int(re.match(r'[0-9]+', item[0]).group(0))
                                    if re.match(r'[0-9]+', item[0]) else 1000000, item[0])):
        multi = bool(re.search(r'[,;，；]', label))
        component_labels = [part + '號' for part in label.split(',')] if re.fullmatch(r'[0-9]+(?:,[0-9]+)+', label) else []
        distinct.append({'comparison_label': label, 'raw_housenumber_forms': sorted({r['raw_housenumber'] for r in records}),
            'source_object_count': len(records), 'source_objects': [r['type'] + ':' + r['id'] for r in records],
            'old84_primary_label_matches': stock_by_label.get(label, []),
            'status': 'present_in_old84' if label in stock_by_label else 'not_observed_in_old84',
            'multi_address_literal': multi,
            'explicit_comma_integer_component_primary_matches': {part: stock_by_label.get(part, []) for part in component_labels},
            'single_simple_house_candidate_not_in_old84': label not in stock_by_label and bool(re.fullmatch(r'[0-9]+號', label))})
    present = [g for g in distinct if g['status'] == 'present_in_old84']
    absent = [g for g in distinct if g['status'] == 'not_observed_in_old84']
    simple = [g for g in absent if g['single_simple_house_candidate_not_in_old84']]
    candidates = [r for r in qualified if any(g['comparison_label'] == r['comparison_label'] for g in simple)]
    house184 = [r for r in qualified if r['comparison_label'] == '184號']
    need(any(r['id'] == '8528998711' and r['raw_housenumber'] == '184號' for r in house184),
         'Known explicit source184 not represented in this comparison')
    summary = {'qualified_source_objects': len(qualified), 'qualified_by_type': dict(collections.Counter(r['type'] for r in qualified)),
        'uncertain_source_objects': len(uncertain), 'distinct_literal_housenumber_forms': len({r['raw_housenumber'] for r in qualified}),
        'distinct_labels_after_only_ASCII_integer_append_號': len(distinct),
        'distinct_label_present_in_old84': len(present), 'distinct_label_not_observed_in_old84': len(absent),
        'simple_single_house_candidate_labels_not_in_old84': len(simple), 'single_house_candidate_objects': len(candidates),
        'qualified_object_primary_label_present_count': sum(r['primary_label_status'] == 'present_in_old84' for r in qualified),
        'qualified_object_primary_label_not_observed_count': sum(r['primary_label_status'] == 'not_observed_in_old84' for r in qualified),
        'raw_literal_primary_match_objects': sum(bool(r['raw_literal_primary_label_matches']) for r in qualified),
        'format_equivalent_only_match_objects': sum(not r['raw_literal_primary_label_matches'] and bool(r['format_equivalent_primary_label_matches']) for r in qualified),
        'additional_floor_unit_source_objects': sum(r['additional_floor_or_unit_tags'] for r in qualified),
        'house184_source_objects': len(house184), 'house184_present_in_old84_primary': '184號' in stock_by_label,
        '164號_source_object_count': len(groups.get('164號', [])),
        'old_primary_labels_not_seen_in_qualified_source_comparison_forms': len(set(stock_by_label) - set(groups))}
    proof = {'created_utc': datetime.now(timezone.utc).isoformat(), 'source': ref(Path(__file__)),
        'scope': 'Existing filtered OSM XML vs frozen84 original primary labels only; no IMG/USB/native/codec read or rerun.',
        'source_XML': {'path': str(XML.relative_to(ROOT)), 'bytes': initial[2], 'sha256': digest,
            'XML_root_attributes': root_attrs, 'source_snapshot_date': origin['source_date'],
            'source_snapshot_date_reference': str(XML_ORIGIN.relative_to(ROOT)),
            'snapshot_date_is_not_individual_address_creation_date': True, 'stat_unchanged': True},
        'dependencies': [ref(XML_ORIGIN), ref(STOCK), ref(STOCK_SEAL)],
        'administrative_matching_policy': {'required_tags': {'addr:street': '民權路', 'addr:district': '中區'},
            'allowed_explicit_city_spellings': ['臺中市', '台中市'], 'city_alias_used_for_comparison_only_source_unchanged': True,
            'missing_city_or_district_tags': 'uncertain, never inferred from same street name or coordinate proximity',
            'other_explicit_city_or_district': 'excluded', 'conflicting_explicit_addr_full_district': 'uncertain'},
        'label_comparison_policy': {'raw_literal_match_is_kept': True,
            'separate_format_equivalent_rule': 'Only full ASCII integer addr:housenumber appends號; all other strings remain literal.',
            'punctuation_ranges_or_unit_names_not_normalized_or_split_for_primary_status': True,
            'only_comma_integer_component_observation_is_separately_reported': True,
            'full_addr_floor_units_retained_in_tags_not_mislabeled_as_new_base_houses': True},
        'scan_counts': {'all_objects_by_type': dict(scanned), 'explicit_street_and_housenumber_count': explicit_street_house_count,
            'excluded_administrative_counts': dict(excluded)}, 'summary': summary,
        'distinct_qualified_housenumber_labels': distinct, 'simple_single_house_source_candidates_not_observed_in_old84': candidates,
        'known_source184_records': house184, 'qualified_source_records_complete_tags': qualified,
        'administratively_uncertain_source_records_complete_tags': uncertain,
        'old_primary_labels_not_seen_in_qualified_source_comparison_forms': [
            {'label': label, 'stock_records': stock_by_label[label]} for label in sorted(set(stock_by_label) - set(groups))],
        'original_IMG_or_USB_read': False, 'original_DB_or_map_or_canonical_modified': False,
        'codec_native_reader_or_old_analysis_suites_rerun': False,
        'primary_label_absence_equals_entire_Garmin_address_absence': False,
        'source_presence_equals_current_native_query_or_route_success': False,
        'source_absence_proves_old_address_removed': False,
        'new_candidate_labels_proven_new_construction_since2016': False,
        'all84_original_labels_equated_with_complete_Garmin_index': False,
        'new_ZIP_created': False, 'all_source_identity_and_comparison_checks_passed': True,
        'limits': ['Old84 cover only selected street primary labels, not every level6 child or supplemental index.',
            'OSM duplicate objects, apartment floor/unit rows and way geometry are not distinct new base houses.',
            'The compound16,18 literal is not a new single house; its16號/18號 components already appear in old84.',
            'Neither snapshot dates nor tag modification timestamps establish address creation or current deliverability.',
            'No native record, label, metadata or index writer and no physical navigation are exercised here.']}
    with target.open('x') as f:
        json.dump(proof, f, ensure_ascii=False, separators=(',', ':'))
        f.write('\n')
    need(target.stat().st_size < 2_000_000, 'Coverage JSON unexpectedly large')
    print(json.dumps({'output': str(target.relative_to(ROOT)), 'bytes': target.stat().st_size,
        'sha256': sha(target.read_bytes()), 'summary': summary,
        'simple_candidate_labels': [g['comparison_label'] for g in simple],
        'all_source_identity_and_comparison_checks_passed': True}, ensure_ascii=False))


if __name__ == '__main__':
    main()
