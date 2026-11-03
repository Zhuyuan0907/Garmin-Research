#!/usr/bin/env python3
"""Project completed source ledgers to coverage and current-profile capacity.

No second PBF extract and no original image, database, firmware or device reads.
The original ledger classification is retained. This projection distinguishes
the four stock city->street hierarchies, which have no district layer to match.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
import gzip
import json
from pathlib import Path
import unicodedata
import time

OUT = Path(__file__).resolve().parent


def rows(name):
    with gzip.open(OUT / name, 'rt', encoding='utf-8') as stream:
        for line in stream:
            yield json.loads(line)


def norm(text):
    return unicodedata.normalize('NFKC', text or '').strip().replace('臺', '台')


def main():
    target = OUT / 'coverage-and-profile-capacity.json'
    if target.exists():
        raise ValueError('Refusing overwrite')
    native = [row for row in rows('native-hierarchy.jsonl.gz') if row['level'] == 3]
    byrecord = {row['record']: row for row in native}
    direct_cities = {norm(row['city']) for row in native if row['district'] is None}
    corrected_match = Counter()
    matched_nodes_by_next_level = Counter()
    country = Counter()
    coordinate = Counter()
    class_samples = defaultdict(list)
    embedded_unit_groups = set()
    total_nodes = 0
    full_tagged_nodes = 0
    for row in rows('source-address-nodes.jsonl.gz'):
        total_nodes += 1
        full_tagged_nodes += int(all(row['addr_tags'].get('addr:' + key) for key in ('city', 'district', 'street', 'housenumber')))
        city = row['addr_tags'].get('addr:city', '')
        classification = row['native_match']
        if classification == 'missing_native_district' and norm(city) in direct_cities:
            classification = 'missing_native_street_in_direct_city_district_unverified'
        corrected_match[classification] += 1
        if classification in ('matched_native_street', 'matched_direct_city_street', 'matched_direct_city_street_district_unverified') and len(row['native_street_records']) == 1:
            matched_nodes_by_next_level[byrecord[row['native_street_records'][0]]['next_level']] += 1
        country[row['addr_tags'].get('addr:country') or '<absent>'] += 1
        lat, lon = row['coordinate_strings']
        in_box = bool(lat and lon) and 20.72799 <= float(lat) <= 26.60305 and 118.1036 <= float(lon) <= 122.9312
        coordinate['inside_advertised_extract_box' if in_box else 'outside_advertised_extract_box'] += 1
        number_class = row['house']['class']
        if row['planning_group_id'] is not None and row['house'].get('embedded_floor_unit'):
            embedded_unit_groups.add(row['planning_group_id'])
        if len(class_samples[number_class]) < 8:
            class_samples[number_class].append({'id': row['source_id'], 'addr_tags': row['addr_tags'],
                                                'coordinate_strings': row['coordinate_strings']})
    (OUT / 'source-counts-ready.json').write_text(json.dumps({
        'address_nodes': total_nodes, 'full_city_district_street_house_nodes': full_tagged_nodes,
        'corrected_native_match_counts': dict(corrected_match),
        'matched_source_nodes_by_existing_street_next_level': dict(matched_nodes_by_next_level),
        'source_ledger_gzip_read_to_validated_EOF': True,
        'prepared_source_statistics_only_not_full_native_update': True,
    }, ensure_ascii=False, indent=2) + '\n')
    # The node ledger is already closed before the producer starts its group
    # output. Wait for the producer's final summary to gate the closed groups.
    while True:
        try:
            summary = json.loads((OUT / 'ingestion-summary.json').read_text())
            break
        except (FileNotFoundError, json.JSONDecodeError):
            time.sleep(1)
    assert total_nodes == summary['counts']['address_nodes']
    corrected_missing = Counter()
    with gzip.open(OUT / 'missing-native-hierarchy-corrected.jsonl.gz', 'wt', encoding='utf-8') as stream:
        for row in rows('missing-native-hierarchy.jsonl.gz'):
            if row['classification'] == 'missing_native_district' and norm(row['raw_city']) in direct_cities:
                row['classification'] = 'missing_native_street_in_direct_city_district_unverified'
            corrected_missing[row['classification']] += 1
            stream.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n')
    grouped_counts = Counter()
    counts_by_street = Counter()
    ready_counts_by_street = Counter()
    direct_counts_by_street = Counter()
    matched_groups_by_next_level = Counter()
    ready_groups_by_next_level = Counter()
    matched_streets_by_next_level = defaultdict(set)
    for row in rows('address-planning-groups.jsonl.gz'):
        grouped_counts[row['native_match']] += 1
        matched = row['native_match'] == 'matched_native_street'
        direct = row['native_match'] == 'matched_direct_city_street_district_unverified'
        if (matched or direct) and len(row['native_street_records']) == 1:
            record = row['native_street_records'][0]
            counts_by_street[record] += 1
            next_level = byrecord[record]['next_level']
            matched_groups_by_next_level[next_level] += 1
            matched_streets_by_next_level[next_level].add(record)
            if direct:
                direct_counts_by_street[record] += 1
            if row['coordinate_selection_ready']:
                ready_counts_by_street[record] += 1
                ready_groups_by_next_level[next_level] += 1
    stock_count = summary['incremental_level4_capacity']['stock_level4_count']
    maximum = summary['incremental_level4_capacity']['first_child_22bit_max']
    all_level4 = [row for row in native if row['next_level'] == 4 and row['child_count']]
    assert sum(row['child_count'] for row in all_level4) == stock_count
    def projection(name, source_counts):
        cursor, cluster_starts, child_overflow = stock_count + 1, [], []
        source_groups = originals = 0
        for record, added in sorted(source_counts.items()):
            row = byrecord[record]
            if row['next_level'] != 4:
                continue
            count = row['child_count'] + added
            originals += row['child_count']
            source_groups += added
            cluster_starts.append({'record': record, 'street': [row['city'], row['district'], row['street']],
                                   'proposed_first_child': cursor, 'count': count})
            if count > 4095:
                child_overflow.append(cluster_starts[-1])
            cursor += count
        return {'scope': name, 'level4_streets': len(cluster_starts),
                'old_records_to_clone': originals, 'source_groups_assumed_all_new': source_groups,
                'appended_records': originals + source_groups, 'final_level4_count': cursor - 1,
                'highest_cluster_first_child': max((row['proposed_first_child'] for row in cluster_starts), default=0),
                'all_cluster_first_children_fit_current_22bit_field': all(row['proposed_first_child'] <= maximum for row in cluster_starts),
                'sufficient_stricter_total_count_fits_current_22bit_number': cursor - 1 <= maximum,
                'merged_child_count_over_4095': child_overflow,
                'assumptions': ['All grouped source addresses considered new; native leaf overlap unexamined.',
                                'Source→existing named street only; no missing street/admin insertion costs.',
                                'One new contiguous cloned level4 cluster per touched native street, in existing street-ID order.',
                                'Grouping is source planning, not official-address validation; ready subset only excludes conflicting coordinates.']}
    clone_all_last_first = stock_count + sum(row['child_count'] for row in all_level4[:-1]) + 1
    result = {'schema': 'taiwan-native-address-coverage-current-profile/v1',
              'created_utc': datetime.now(timezone.utc).isoformat(),
              'source_nodes_reconciled': total_nodes,
              'completed_source_extract_reused_not_repeated': True,
              'corrected_native_match_counts': dict(corrected_match),
              'corrected_missing_hierarchy_unique_triples': dict(corrected_missing),
              'direct_city_street_names': sorted(direct_cities),
              'direct_city_policy': 'Four cities lack native district layers. A city+street name match remains district-unverified; a missing street in these cities is classified separately, not as an invented new district requirement.',
              'source_addr_country_tag_counts': dict(country),
              'source_coordinate_box_counts': dict(coordinate),
              'country_coordinate_caution': 'Advertised extract box is only a diagnostic, not a Taiwan administrative polygon; absence of addr:country does not imply foreign or Taiwanese location.',
              'house_class_source_samples': dict(class_samples),
              'planning_group_match_counts': dict(grouped_counts),
              'matched_source_nodes_by_existing_street_next_level': dict(matched_nodes_by_next_level),
              'matched_planning_groups_by_existing_street_next_level': dict(matched_groups_by_next_level),
              'matched_planning_streets_by_existing_next_level': {level: len(records) for level, records in matched_streets_by_next_level.items()},
              'coordinate_ready_groups_by_existing_street_next_level': dict(ready_groups_by_next_level),
              'next_level_scope': 'Only existing next-level4 branches enter the level4 append projections. Matched next-level5/6 streets are separate native hierarchy types; their source groups and old branches are preserved for later analysis and are not counted as directly appendable level4 addresses.',
              'planning_groups_with_any_embedded_floor_unit_source': len(embedded_unit_groups),
              'embedded_unit_flag_note': 'The extraction group flag reflects its first node. This count uses all source nodes, including later repeats with embedded floor/unit suffixes; original node-level data remains authoritative.',
              'current_stock_profile': {'street_record_bits': 111, 'first_child_width': 22, 'first_child_max': maximum,
                                       'child_count_width': 12, 'child_count_max': 4095,
                                       'platform_hard_limit_claimed': False,
                                       'note': 'Widths apply to the original AP directory/profile. The directory encodes widths in six-bit fields and reader uses dynamic widths/stride; a future wider profile requires separate re-encoding and native validation, not performed here.'},
              'clone_all_old_level4_under_current_profile': {'last_street': [all_level4[-1][k] for k in ('city', 'district', 'street')],
                                                           'last_cluster_first_child': clone_all_last_first,
                                                           'first_child_overflow': clone_all_last_first - maximum,
                                                           'total_count_after_clone': 2 * stock_count},
              'incremental_projections': [projection('Existing next-level4 branches of matched district streets plus district-unverified direct-city matches', counts_by_street),
                                          projection('Same next-level4 branches using only groups with identical source coordinates', ready_counts_by_street),
                                          projection('Direct-city next-level4 branches only; district association remains unverified', direct_counts_by_street)],
              'limits': ['No original level4 labels read; actual new-address count remains unknown.',
                         'No original JAI/AP/road writes or reader/profile CPU execution.',
                         'All source-tagged node addresses are not comprehensive official Taiwan addresses; address ways/relations and inferred admin remain separate work.',
                         'No Garmin UI, destination or route validation of full Taiwan update.']}
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'source_nodes': total_nodes, 'corrected_match_counts': result['corrected_native_match_counts'],
                      'projections': result['incremental_projections']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
