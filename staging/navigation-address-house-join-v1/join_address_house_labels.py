#!/usr/bin/env python3
"""Single-pass prepared-group/native-roster/house-text-ref join.

No PBF, original map/leaf, native CPU, device, canonical, or ZIP access.
Output is an input to later native merge analysis, never an install candidate.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
import gzip
import hashlib
import json
import math
from pathlib import Path
import re
import sqlite3
import unicodedata

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
GROUPS = ROOT / 'staging/navigation-taiwan-address-ingestion-v1/address-planning-groups.jsonl.gz'
ROSTER = ROOT / 'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'
LABELS = ROOT / 'staging/navigation-native-house-label-index-v1/house-labels.jsonl.gz'
LABEL_PROOF = LABELS.parent / 'proof.json'
PLAN = ROOT / 'staging/navigation-native-Minquan-append-plan-v1/Minquan-append-only-record-plan-v1.json'
MANIFEST = ROOT / 'staging/navigation-native-address-supplement-v1/manifest.json'
HOUSE = re.compile(r'^[1-9][0-9]*(?:之[1-9][0-9]*)?號$')
DIRECT_CITIES = {'基隆市', '台北市', '新竹市', '嘉義市'}


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(row):
    return (json.dumps(row, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def stat(path):
    st = path.stat()
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns]


def norm(text):
    return unicodedata.normalize('NFKC', text or '').strip().replace('臺', '台')


class HashReader:
    def __init__(self, stream):
        self.stream, self.hash, self.count = stream, hashlib.sha256(), 0

    def read(self, amount=-1):
        value = self.stream.read(amount)
        self.hash.update(value)
        self.count += len(value)
        return value


class HashWriter:
    def __init__(self, stream):
        self.stream, self.hash, self.count = stream, hashlib.sha256(), 0

    def write(self, value):
        result = self.stream.write(value)
        need(result == len(value), 'Complete output write')
        self.hash.update(value)
        self.count += result
        return result

    def flush(self):
        self.stream.flush()


class JsonGzipOutput:
    def __init__(self, path):
        self.path, self.rows = path, 0
        self.plain_hash = hashlib.sha256()
        self.handle = path.open('xb')
        self.writer = HashWriter(self.handle)
        self.gzip = gzip.GzipFile(filename='', mode='wb', fileobj=self.writer,
                                  compresslevel=6, mtime=0)

    def write(self, row):
        raw = encoded(row)
        self.gzip.write(raw)
        self.plain_hash.update(raw)
        self.rows += 1

    def close(self):
        self.gzip.close()
        self.handle.flush()
        self.handle.close()
        need(self.path.stat().st_size == self.writer.count, 'Compressed output byte accounting')
        return {'path': str(self.path.relative_to(ROOT)), 'rows': self.rows,
                'bytes': self.writer.count, 'sha256': self.writer.hash.hexdigest(),
                'uncompressed_sha256': self.plain_hash.hexdigest(),
                'hash_computed_while_writing_not_second_read': True}


def gzip_rows(path, inputs):
    before = stat(path)
    count = 0
    with path.open('rb') as source:
        reader = HashReader(source)
        with gzip.GzipFile(fileobj=reader, mode='rb') as stream:
            for line in stream:
                count += 1
                yield json.loads(line)
        need(reader.count == before[2], 'Entire compressed input consumed: ' + str(path))
        digest = reader.hash.hexdigest()
    after = stat(path)
    need(before == after, 'Immutable source stat: ' + str(path))
    inputs.append({'path': str(path.relative_to(ROOT)), 'bytes': reader.count,
                   'sha256': digest, 'json_rows': count, 'gzip_validated_EOF': True,
                   'stat_before': before, 'stat_after': after, 'stat_unchanged': True,
                   'source_content_read_passes': 1})


def small_json(path, inputs):
    before = stat(path)
    raw = path.read_bytes()
    after = stat(path)
    need(before == after, 'Immutable small source: ' + str(path))
    inputs.append({'path': str(path.relative_to(ROOT)), 'bytes': len(raw),
                   'sha256': hashlib.sha256(raw).hexdigest(), 'stat_before': before,
                   'stat_after': after, 'stat_unchanged': True, 'source_content_read_passes': 1})
    return json.loads(raw)


def coordinate(group):
    value = group.get('first_coordinate')
    if not isinstance(value, list) or len(value) != 2 or any(x is None or x == '' for x in value):
        return 'invalid_or_missing', None
    try:
        lat, lon = map(float, value)
        need(math.isfinite(lat) and math.isfinite(lon), 'finite coordinate')
        need(-90 <= lat <= 90 and -180 <= lon < 180, 'global coordinate bounds')
        canonical = [str(Decimal(str(x)).normalize()) for x in value]
    except (ValueError, TypeError, OverflowError, InvalidOperation):
        return 'invalid_or_missing', None
    ready, differences = group.get('coordinate_selection_ready'), group.get('different_coordinate_nodes')
    if type(ready) is not bool or type(differences) is not int or differences < 0 or ready != (differences == 0):
        return 'inconsistent_source_coordinate_metadata', None
    if not ready:
        return 'source_coordinate_conflict', None
    return 'coordinate_ready_global_bounds', canonical


def main():
    started = datetime.now(timezone.utc).isoformat()
    need(not (OUT / 'proof.json').exists() and not (OUT / 'working-index.sqlite3').exists(), 'New scope outputs only')
    inputs = []
    index_proof = small_json(LABEL_PROOF, inputs)
    plan = small_json(PLAN, inputs)
    original_manifest = small_json(MANIFEST, inputs)
    plan_nine = {row['label']: row for row in plan['nine_new_source_candidates']}
    actual_nine = {row['label']: row for row in original_manifest['records'] if row.get('oldID') is None}
    need(len(plan_nine) == len(actual_nine) == 9 and set(plan_nine) == set(actual_nine), 'Nine original source/installed manifest controls')
    labels = {}
    for row in gzip_rows(LABELS, inputs):
        need(HOUSE.fullmatch(row['label']) is not None, 'Existing label index conservative numeric syntax')
        need(type(row['primary_ref']) is int and 0 <= row['primary_ref'] < (1 << 19) - 1, 'Existing source-profile label ref')
        need(row['label'] not in labels, 'Unique indexed house text')
        labels[row['label']] = row['primary_ref']
    label_input = inputs[-1]
    need(len(labels) == 50567 == index_proof['distinct_integer_or_subnumber_house_labels'], 'Pinned label index count')
    need(label_input['sha256'] == index_proof['ledger_sha256'] and label_input['bytes'] == index_proof['ledger_bytes'], 'Original label-index proof binding')
    cities, districts, exact, direct = {}, set(), defaultdict(list), defaultdict(list)
    street_by_record, roster_counts = {}, Counter()
    for row in gzip_rows(ROSTER, inputs):
        roster_counts[row['level']] += 1
        city, district = norm(row['city']), norm(row.get('district'))
        if row['level'] == 1:
            need(city not in cities, 'Unique normalized city')
            cities[city] = row['raw_name']
        elif row['level'] == 2:
            districts.add((city, district))
        elif row['level'] == 3:
            need(row['record'] not in street_by_record, 'Unique original street record')
            street_by_record[row['record']] = row
            exact[(city, district, norm(row['street']))].append(row)
            if district == '':
                direct[(city, norm(row['street']))].append(row)
    need(roster_counts == {1: 22, 2: 343, 3: 47853}, 'Complete original named hierarchy')
    need({city for city, street in direct} == DIRECT_CITIES, 'Four original direct-city layouts')
    need(Counter(row['next_level'] for row in street_by_record.values()) == {4: 20107, 5: 19036, 6: 8710}, 'Original named-street branch-type counts')

    def match(city, district, street):
        if city not in cities:
            return 'missing_native_city', []
        if not street:
            return 'missing_source_street', []
        if city in DIRECT_CITIES:
            candidates = direct.get((city, street), [])
            return ('matched_direct_city_street_unique_district_unverified' if len(candidates) == 1 else
                    'ambiguous_direct_city_street' if candidates else
                    'missing_native_street_in_direct_city_district_unverified'), candidates
        if not district:
            return 'missing_source_district', []
        if (city, district) not in districts:
            return 'missing_native_district', []
        candidates = exact.get((city, district, street), [])
        return ('matched_native_street_exact_unique' if len(candidates) == 1 else
                'ambiguous_native_street_exact' if candidates else 'missing_native_street'), candidates

    # Counters retain no address-group bodies outside the Taichung working DB.
    metrics = defaultdict(Counter)
    source_streets = defaultdict(lambda: defaultdict(set))
    native_streets = defaultdict(lambda: defaultdict(set))
    raw_city_counts, corrections, branch_groups = Counter(), Counter(), Counter()
    matched_street_ids = defaultdict(set)
    def count(city, metric, key, records=()):
        metrics[city][metric] += 1
        source_streets[city][metric].add(key)
        native_streets[city][metric].update(records)

    working = OUT / 'working-index.sqlite3'
    con = sqlite3.connect(working)
    con.execute('PRAGMA journal_mode=OFF')
    con.execute('PRAGMA synchronous=OFF')
    con.execute('PRAGMA temp_store=FILE')
    con.execute('CREATE TABLE targets (record INTEGER,house TEXT,coordinate_key TEXT,blocked INTEGER NOT NULL,coordinate_collision INTEGER NOT NULL,groups INTEGER NOT NULL,PRIMARY KEY(record,house)) WITHOUT ROWID')
    con.execute('CREATE TABLE members (record INTEGER,house TEXT,group_id INTEGER PRIMARY KEY,row_json TEXT NOT NULL,ready INTEGER NOT NULL)')
    total_groups = total_source_nodes = pre_coordinate_taichung_groups = 0
    controls = {label: [] for label in plan_nine}
    for group in gzip_rows(GROUPS, inputs):
        total_groups += 1
        need(group['group_id'] == total_groups, 'Original sequential group-ID accounting')
        need(len(group['raw_address']) == len(group['normalized_planning_key']) == 4, 'Four-field group keys')
        need(len(group['source_ids']) == group['source_node_count'] and all(type(x) is int and x > 0 for x in group['source_ids']), 'Source ID/count accounting')
        total_source_nodes += group['source_node_count']
        raw_city, raw_district, raw_street, raw_house = group['raw_address']
        city, district, street = map(norm, (raw_city, raw_district, raw_street))
        city_label = cities.get(city, city or '<absent>')
        raw_city_counts[raw_city] += 1
        key = (city, district, street)
        classification, candidates = match(*key)
        records = [row['record'] for row in candidates]
        one = len(candidates) == 1 and classification in ('matched_native_street_exact_unique', 'matched_direct_city_street_unique_district_unverified')
        count(city_label, 'all_groups', key)
        count(city_label, classification, key, records if one else ())
        if group['native_match'] == 'missing_native_district' and city in DIRECT_CITIES:
            corrections[classification] += 1
        house = group['normalized_planning_key'][3]
        numeric = isinstance(house, str) and HOUSE.fullmatch(house) is not None
        ref = labels.get(house) if numeric else None
        label_status = 'existing_numeric_label_ref' if ref is not None else 'numeric_label_ref_absent' if numeric else 'nonconservative_house_label'
        count(city_label, label_status, key, records if one else ())
        coord_status, coordinate_key = coordinate(group)
        count(city_label, coord_status, key, records if one else ())
        if group['separate_floor_unit_nodes']:
            count(city_label, 'group_with_separate_floor_unit_door_level_tags', key, records if one else ())
        if group['embedded_floor_unit']:
            count(city_label, 'first_group_source_has_embedded_floor_unit', key, records if one else ())
        if group['source_node_count'] > 1:
            count(city_label, 'multi_source_node_group', key, records if one else ())
        if one:
            native = candidates[0]
            nextlevel = native['next_level']
            branch_groups[nextlevel] += 1
            matched_street_ids[nextlevel].add(native['record'])
            count(city_label, 'matched_unique_next' + str(nextlevel), key, records)
        else:
            native = None
        semantic_eligible = classification == 'matched_native_street_exact_unique' and native['next_level'] == 4 and ref is not None if native else False
        if semantic_eligible:
            count(city_label, 'exact_unique_next4_existing_ref_before_coordinate_review', key, records)
            if coord_status == 'coordinate_ready_global_bounds':
                count(city_label, 'exact_unique_next4_existing_ref_coordinate_ready', key, records)
        taichung = city == '台中市' and semantic_eligible
        payload = None
        if taichung:
            pre_coordinate_taichung_groups += 1
            ready = coord_status == 'coordinate_ready_global_bounds'
            # A conflicting group's first coordinate is retained as explicitly
            # unselected provenance, never populated into the candidate point.
            payload = {'group_id': group['group_id'], 'source_ids': group['source_ids'],
                       'source_node_count': group['source_node_count'], 'raw_address': group['raw_address'],
                       'normalized_planning_key': group['normalized_planning_key'],
                       'coordinate_strings': group['first_coordinate'] if ready else None,
                       'coordinate_status': coord_status,
                       'unselected_first_coordinate_strings': group['first_coordinate'] if not ready else None,
                       'source_different_coordinate_nodes': group['different_coordinate_nodes'],
                       'separate_floor_unit_source_nodes': group['separate_floor_unit_nodes'],
                       'embedded_floor_unit_first_source_flag': group['embedded_floor_unit'],
                       'native_street_record': native['record'], 'nativeStreetID': native['low28_id'],
                       'native_city': native['city'], 'native_district': native['district'], 'native_street': native['street'],
                       'old_child_first': native['first_child'], 'old_child_count': native['child_count'],
                       'old_child_level_and_flags': native['child_level_and_flags'], 'old_next_level': native['next_level'],
                       'house_label': house, 'primary_ref': ref,
                       'native_house_overlap_checked': False, 'native_new_record_encoded': False}
            record = native['record']
            wire_key = json.dumps(coordinate_key, separators=(',', ':')) if ready else None
            old = con.execute('SELECT coordinate_key,blocked,coordinate_collision,groups FROM targets WHERE record=? AND house=?', (record, house)).fetchone()
            if old is None:
                con.execute('INSERT INTO targets VALUES(?,?,?,?,?,?)', (record, house, wire_key, int(not ready), 0, 1))
            else:
                collision = bool(old[2]) or (ready and old[0] is not None and wire_key != old[0])
                blocked = bool(old[1]) or not ready or collision
                con.execute('UPDATE targets SET blocked=?,coordinate_collision=?,groups=groups+1 WHERE record=? AND house=?', (int(blocked), int(collision), record, house))
            con.execute('INSERT INTO members VALUES(?,?,?,?,?)', (record, house, group['group_id'], json.dumps(payload, ensure_ascii=False, separators=(',', ':')), int(ready)))
        if city == '台中市' and district == '中區' and street == '民權路' and house in plan_nine:
            expected = plan_nine[house]
            installed = actual_nine[house]
            expected_id = int(expected['OSM_id'])
            point_equal = None
            if coord_status == 'coordinate_ready_global_bounds' or (group['source_ids'] and group['source_ids'][0] == expected_id):
                try:
                    point_equal = all(Decimal(str(a)) == Decimal(str(b)) for a, b in zip(group['first_coordinate'], expected['source_coordinate_strings']))
                except (InvalidOperation, TypeError):
                    point_equal = False
            control = {'house_label': house, 'group_id': group['group_id'], 'native_match': classification,
                       'source_id_from_original_plan': expected_id, 'source_id_present': expected_id in group['source_ids'],
                       'source_ids': group['source_ids'], 'plan_coordinate_strings': expected['source_coordinate_strings'],
                       'group_first_coordinate_strings': group['first_coordinate'], 'coordinate_status': coord_status,
                       'plan_coordinate_equals_group_point_when_verifiable': point_equal,
                       'coordinate_verification_note': 'Ready groups guarantee all recorded source coordinates equal; conflicting groups only expose the first node coordinate in this ledger.',
                       'existing_index_primary_ref': ref, 'installed_manifest_primary_ref': installed['primary_ref'],
                       'ref_equal_to_installed_manifest': ref == installed['primary_ref'],
                       'installed_manifest_source_id_equals_plan': int(installed['source_id']) == expected_id,
                       'nativeStreetID': native['low28_id'] if native else None,
                       'semantic_taichung_eligibility': taichung,
                       'candidate_before_target_collision_check': payload is not None and payload['coordinate_strings'] is not None}
            controls[house].append(control)
        if total_groups % 50000 == 0:
            con.commit()
    con.commit()
    need(total_groups == 4630959, 'Completed whole-country prepared-group pass')
    need(con.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'Working SQLite index integrity')
    members = con.execute('SELECT COUNT(*) FROM members').fetchone()[0]
    need(members == pre_coordinate_taichung_groups == con.execute('SELECT COALESCE(SUM(groups),0) FROM targets').fetchone()[0], 'Target/member index accounting')
    candidate = JsonGzipOutput(OUT / 'taichung-next4-existing-label-ready-candidates.jsonl.gz')
    review = JsonGzipOutput(OUT / 'taichung-next4-existing-label-coordinate-review.jsonl.gz')
    candidate_streets, candidate_groups, output_controls = set(), set(), defaultdict(list)
    for stored, blocked, collision, target_groups in con.execute('SELECT m.row_json,t.blocked,t.coordinate_collision,t.groups FROM members m JOIN targets t ON t.record=m.record AND t.house=m.house ORDER BY m.record,m.group_id'):
        row = json.loads(stored)
        row['same_native_street_house_group_count'] = target_groups
        row['same_native_street_house_coordinate_collision'] = bool(collision)
        if blocked:
            row['review_reason'] = 'different_coordinates_for_same_native_street_house' if collision else row['coordinate_status']
            # Even a formerly ready member of a colliding target is quarantined.
            row['unselected_first_coordinate_strings'] = row['coordinate_strings'] or row['unselected_first_coordinate_strings']
            row['coordinate_strings'] = None
            review.write(row)
        else:
            need(row['coordinate_status'] == 'coordinate_ready_global_bounds' and row['coordinate_strings'] is not None and not collision, 'Strict candidate eligibility')
            candidate.write(row)
            candidate_streets.add(row['native_street_record'])
            candidate_groups.add(row['group_id'])
        if row['nativeStreetID'] == 16707 and row['house_label'] in plan_nine:
            output_controls[row['house_label']].append({'group_id': row['group_id'], 'included_in_candidate': not blocked,
                                                       'review_reason': row.get('review_reason')})
    candidate_artifact, review_artifact = candidate.close(), review.close()
    need(candidate.rows + review.rows == members, 'All Taichung indexed input groups routed to candidate or review')
    duplicate_counts = dict(zip(('targets', 'multiple_group_targets', 'coordinate_collision_targets', 'blocked_targets'), con.execute('SELECT COUNT(*),SUM(groups>1),SUM(coordinate_collision),SUM(blocked) FROM targets').fetchone()))
    # Verify output identities using the small indexed nine controls, without
    # reopening/reparsing candidate or any large source ledger.
    nine = []
    for label in sorted(plan_nine, key=lambda text: int(text[:-1])):
        seen = controls[label]
        need(len(seen) == 1, 'Exactly one prepared group for verified source house ' + label)
        control = seen[0]
        need(control['source_id_present'] and control['ref_equal_to_installed_manifest'] and control['installed_manifest_source_id_equals_plan'], 'Nine source/ref identity ' + label)
        control['output_index_routing'] = output_controls.get(label, [])
        control['included_in_candidate'] = any(row['included_in_candidate'] for row in control['output_index_routing'])
        if control['included_in_candidate']:
            need(control['plan_coordinate_equals_group_point_when_verifiable'] is True and control['nativeStreetID'] == 16707, 'Included verified nine coordinate/street identity ' + label)
        nine.append(control)
    working_bytes = working.stat().st_size
    con.close()
    working.unlink()
    city_stats = {}
    for city in sorted(metrics):
        city_stats[city] = {metric: {'groups': amount,
                                   'unique_source_city_district_street_keys': len(source_streets[city][metric]),
                                   'unique_matched_native_street_records': len(native_streets[city][metric])}
                            for metric, amount in sorted(metrics[city].items())}
    totals = Counter()
    for values in metrics.values():
        totals.update(values)
    script_stat = stat(Path(__file__))
    script_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    need(stat(Path(__file__)) == script_stat, 'Executed source stat unchanged during final binding')
    proof = {'schema': 'prepared-taiwan-address-house-ref-join/v1', 'started_utc': started,
             'finished_utc': datetime.now(timezone.utc).isoformat(), 'all_assigned_checks_passed': True,
             'script_sha256': script_hash, 'inputs': inputs, 'input_passes': 'Exactly one content pass per complete groups/roster/house-index file; no PBF/node-ledger/leaf/map read.',
             'source_group_total': total_groups, 'source_nodes_represented_by_groups': total_source_nodes,
             'source_stat_immutable_all': all(item['stat_unchanged'] for item in inputs),
             'matching_policy': 'Host NFKC/outer-whitespace/臺→台 only. Recompute city/district/street exact keys. Four direct-city layouts match city+street with district explicitly unverified. No Chinese road/admin aliases or new streets silently substituted.',
             'house_policy': 'Positive ASCII integer or 之positive-subnumber＋號 planning keys only. Existing lowest text ref is not evidence this street already has the address. Ambiguous hyphens are not guessed.',
             'coordinate_policy': 'Finite lat/lon within global WGS84 bounds, consistent ready/different-coordinate metadata. No Taiwan polygon inference. Conflicting target or source groups have no selected coordinate in output.',
             'floor_unit_scope': 'Separate floor/unit/door/level group metadata aggregates source nodes. Embedded-floor flag reflects the first group source only; no node ledger reopened to expand it.',
             'source_raw_city_group_counts': dict(raw_city_counts), 'whole_country_group_metrics': dict(totals),
             'whole_country_city_group_and_street_metrics': city_stats,
             'four_city_raw_missing_district_group_corrections': dict(corrections),
             'unique_matched_group_next_level_counts': dict(branch_groups),
             'unique_matched_street_records_by_next_level': {level: len(records) for level, records in matched_street_ids.items()},
             'taichung_subset': {'semantic_eligible_groups_before_coordinate_review': pre_coordinate_taichung_groups,
                                 'candidate_groups': candidate.rows, 'candidate_unique_native_streets': len(candidate_streets),
                                 'coordinate_review_groups': review.rows, 'target_index': duplicate_counts,
                                 'candidate': candidate_artifact, 'review': review_artifact,
                                 'candidate_order': 'native street record then original group ID; no native house sort asserted.'},
             'nine_verified_source_controls': nine,
             'nine_all_in_candidate': all(row['included_in_candidate'] for row in nine),
             'nine_source_ID_and_existing_ref_checks_passed': True,
             'working_index': {'sqlite_integrity_check': 'ok', 'target_member_counts_reconciled': True,
                               'temporary_bytes': working_bytes, 'removed_after_output': not working.exists()},
             'limits': ['No native original house-label membership/overlap decoded; no actual new-house count.',
                        'Candidate point strings are OSM planning data, not verified all-Taiwan entrances/routing.',
                        'Only Taichung exact unique original next4 branches with existing numeric text refs emitted; all-country source scope retained in same-pass statistics.',
                        'Next5/6, ambiguous streets, missing street/admin, absent labels, source conflicts and metadata errors remain explicit categories.',
                        'No image/data/profile/firmware writer, native CPU, device, UI or full2026 address update completed.',
                        'No output full-ledger readback parse; source gzip EOF/rolling hashes and SQLite/output index accounting provide this scope validation.'],
             'device_IO': False, 'native_CPU_executed': False, 'native_house_overlap_checked': False,
             'full_Taiwan_native_update_complete': False}
    (OUT / 'proof.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'all_assigned_checks_passed': True, 'source_groups': total_groups,
                      'taichung_candidate_groups': candidate.rows, 'taichung_candidate_streets': len(candidate_streets),
                      'taichung_review_groups': review.rows, 'nine_all_in_candidate': proof['nine_all_in_candidate'],
                      'proof': str((OUT / 'proof.json').relative_to(ROOT))}, ensure_ascii=False))


if __name__ == '__main__':
    main()
