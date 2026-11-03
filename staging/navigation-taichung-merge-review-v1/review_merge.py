#!/usr/bin/env python3
"""Independent bounded review of newly prepared append data; never a writer."""
import gzip
import hashlib
import json
import math
import re
import struct
import unicodedata
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
MERGE = ROOT / 'staging/navigation-taichung-address-merge-v1'
JOIN = ROOT / 'staging/navigation-address-house-join-v1'
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
HOUSE = re.compile(r'([1-9][0-9]*)號\Z')
INPUTS = []


def need(test, reason):
    if not test:
        raise ValueError(reason)


def stat(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def small(path, parse=True):
    before = stat(path)
    raw = path.read_bytes()
    need(before == stat(path), 'Small immutable input ' + str(path))
    INPUTS.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw), stat_unchanged=True))
    return json.loads(raw) if parse else raw


class HashStream:
    def __init__(self, stream):
        self.stream, self.hash, self.count = stream, hashlib.sha256(), 0

    def read(self, n=-1):
        raw = self.stream.read(n)
        self.hash.update(raw)
        self.count += len(raw)
        return raw


def rows(path):
    before = stat(path)
    count = 0
    plain = hashlib.sha256()
    with path.open('rb') as raw:
        stream = HashStream(raw)
        with gzip.GzipFile(fileobj=stream, mode='rb') as gz:
            for line in gz:
                count += 1
                plain.update(line)
                yield json.loads(line)
        need(stream.count == before[2], 'Complete gzip EOF: ' + str(path))
    need(before == stat(path), 'Gzip source immutable')
    INPUTS.append(dict(path=str(path.relative_to(ROOT)), bytes=stream.count, sha256=stream.hash.hexdigest(),
                       json_rows=count, uncompressed_sha256=plain.hexdigest(), gzip_EOF_validated=True,
                       stat_unchanged=True, compressed_content_passes=1))


def norm(s):
    return unicodedata.normalize('NFKC', s or '').strip().replace('臺', '台')


def house_key(raw, embedded):
    text = unicodedata.normalize('NFKC', raw or '').strip()
    if embedded:
        need('號' in text, 'Embedded floor/unit has explicit house terminator')
        text, suffix = text.split('號', 1)
        need(any(x in suffix for x in ('樓', '室', 'F', 'f')), 'Declared embedded floor/unit marker')
    else:
        text = text.replace('號之', '之')
        if text.endswith('號'):
            text = text[:-1]
    parts = text.split('之')
    need(len(parts) in (1, 2) and all(re.fullmatch(r'[1-9][0-9]*', x) for x in parts), 'Conservative source integer/subnumber syntax')
    return '之'.join(str(int(x)) for x in parts) + '號'


def decode128(raw):
    # Field reader order reconstructed independently, without importing serializer.
    need(len(raw) == 16, 'Exact new/original L4 width')
    packed = int.from_bytes(raw, 'little')
    widths = [1, 19, 19, 22, 10, 9, 24, 24]
    names = ['map', 'secondary', 'primary', 'first', 'count', 'flags', 'latitude', 'longitude']
    value, shift = {}, 0
    for name, width in zip(names, widths):
        value[name] = (packed >> shift) & ((1 << width) - 1)
        shift += width
    need(shift == 128, 'Independent total record width')
    return value


def coordinate24(text):
    # Nearest-circle grid via quotient/remainder, avoiding production quantizer.
    degree = Decimal(str(text))
    numerator = degree * Decimal(1 << 24)
    magnitude = abs(numerator) / Decimal(360)
    result = int(magnitude)
    if magnitude - result >= Decimal('0.5'):
        result += 1
    if numerator < 0:
        result = -result
    need(-(1 << 23) <= result < (1 << 23), 'Signed geographic point bounds')
    error = abs(Decimal(result) * Decimal(360) / Decimal(1 << 24) - degree)
    need(error <= Decimal(180) / Decimal(1 << 24), 'Half-grid rounding error')
    return result & 0xffffff, error


class IndependentIMG:
    """Own sector/FAT reader; logical component bytes read only on demand."""
    def __init__(self, path):
        self.path, self.stream, self.read_log = path, path.open('rb'), []
        self.before = stat(path)
        header = self.physical(0, 512, 'header')
        need(header[0] == 0 and header[16:23] == b'DSKIMG\0', 'Source XOR0 DSKIMG')
        self.block = 1 << (header[0x61] + header[0x62])
        need(self.block == 4096, 'Original AP source allocation block')
        start = header[0x40] * 512
        root = self.physical(start, 512, 'root FAT')
        end = int.from_bytes(root[12:16], 'little')
        need(root[16] == 3 and start < end <= self.before[2], 'Original root directory extent')
        fat = self.physical(start + 512, end - start - 512, 'component FAT')
        self.parts = {}
        for pos in range(0, len(fat), 512):
            row = fat[pos:pos + 512]
            if row[0] == 0:
                need(row == bytes(512), 'Zero FAT filler')
                continue
            need(row[0] == 1, 'Active FAT entry')
            name = row[1:9].decode().rstrip() + '.' + row[9:12].decode().rstrip()
            part = int.from_bytes(row[17:19], 'little')
            if part == 0:
                need(name not in self.parts, 'Unique original component')
                self.parts[name] = dict(size=int.from_bytes(row[12:16], 'little'), blocks=[], next=0)
            item = self.parts[name]
            need(part == item['next'], 'FAT continuation ordinal')
            item['next'] += 1
            blocks = list(struct.unpack_from('<240H', row, 32))
            if 65535 in blocks:
                n = blocks.index(65535)
                need(all(b == 65535 for b in blocks[n:]), 'FAT sentinel tail')
                blocks = blocks[:n]
            need(all(b * 4096 < self.before[2] for b in blocks), 'Physical FAT block bounds')
            item['blocks'].extend(blocks)
        need(len(self.parts) == 6, 'Original exact six component source')

    def physical(self, offset, length, purpose):
        need(0 <= offset <= offset + length <= self.before[2], 'Bounded physical original-map read')
        self.stream.seek(offset)
        value = self.stream.read(length)
        need(len(value) == length, 'Complete physical window')
        self.read_log.append(dict(offset=offset, bytes=length, purpose=purpose))
        return value

    def get(self, name, offset, length):
        item = self.parts[name]
        need(0 <= offset <= offset + length <= item['size'], 'Logical component window bound')
        end, values = offset + length, []
        while offset < end:
            i, inner = divmod(offset, self.block)
            n = min(self.block - inner, end - offset)
            values.append(self.physical(item['blocks'][i] * self.block + inner, n, 'window:' + name))
            offset += n
        return b''.join(values)

    def close(self):
        self.stream.close()
        need(self.before == stat(self.path), 'Original map stat untouched')


class IndependentCity:
    """Float even-odd ring test, distinct from production integer winding buckets."""
    def __init__(self, geo):
        need(geo['type'] == 'MultiPolygon', 'Explicit source city polygon')
        self.polys = []
        for p in geo['coordinates']:
            rings = []
            for coords in p:
                edges = defaultdict(list)
                need(coords[0] == coords[-1], 'City ring closure')
                for a, b in zip(coords, coords[1:]):
                    ax, ay = map(float, a)
                    bx, by = map(float, b)
                    for key in range(math.floor(min(ay, by) * 100), math.floor(max(ay, by) * 100) + 1):
                        edges[key].append((ax, ay, bx, by))
                rings.append(edges)
            self.polys.append(rings)

    @staticmethod
    def ring(edges, x, y):
        inside = False
        for ax, ay, bx, by in edges.get(math.floor(y * 100), ()):
            cross = (x - ax) * (by - ay) - (y - ay) * (bx - ax)
            if abs(cross) <= 1e-14 and min(ax, bx) <= x <= max(ax, bx) and min(ay, by) <= y <= max(ay, by):
                return 2
            if (ay > y) != (by > y):
                intercept = ax + (y - ay) * (bx - ax) / (by - ay)
                if x < intercept:
                    inside = not inside
        return int(inside)

    def covers(self, coord):
        y, x = map(float, coord)
        for rings in self.polys:
            outer = self.ring(rings[0], x, y)
            if outer == 2:
                return True
            if outer == 1:
                holes = [self.ring(r, x, y) for r in rings[1:]]
                if 2 in holes or 1 not in holes:
                    return True
        return False


def main():
    need(not (OUT / 'proof.json').exists(), 'New review namespace, no overwrite')
    proof = small(MERGE / 'proof.json')
    ranges = small(MERGE / 'selected-street-ranges.json')
    blob = small(MERGE / 'appended-level4.bin', False)
    new = list(rows(MERGE / 'new-house-records.jsonl.gz'))
    jp = small(JOIN / 'proof.json')
    trial = small(ROOT / 'staging/navigation-native-address-supplement-v1/manifest.json')
    plan = small(ROOT / 'staging/navigation-native-Minquan-append-plan-v1/Minquan-append-only-record-plan-v1.json')
    cityproof = small(ROOT / 'staging/navigation-taichung-city-geometry-v1/proof.json')
    geo = small(ROOT / 'staging/navigation-taichung-city-geometry-v1/geometry.json')
    ingestion = small(ROOT / 'staging/navigation-taiwan-address-ingestion-v1/ingestion-summary.json')
    need(INPUTS[-2]['sha256'] == cityproof['geometry_sha256'], 'City geometry declared digest')
    city = IndependentCity(geo)
    need(sha(blob) == proof['appended_data_sha256'] and len(blob) == 4196608, 'Append complete digest and bytes')
    need(len(new) == 11002 and len(ranges) == 1693, 'Exact new record/street counts')
    by_street = {r['nativeStreetID']: r for r in ranges}
    need(len(by_street) == len(ranges), 'Unique updated streets')
    new_by_key, new_by_id, new_positions, street_new = {}, {}, defaultdict(set), defaultdict(list)
    max_error = Decimal(0)
    for row in new:
        street = by_street[row['nativeStreetID']]
        key = (row['nativeStreetID'], row['house_label'])
        need(key not in new_by_key and row['new_lowID'] not in new_by_id, 'Unique new street/house and ID')
        new_by_key[key], new_by_id[row['new_lowID']] = row, row
        match = HOUSE.fullmatch(row['house_label'])
        need(match is not None, 'Only new positive integer house leaves')
        need(street['new_first'] <= row['new_lowID'] < street['new_first'] + street['new_count'], 'New record own street range')
        pos = row['new_lowID'] - street['new_first']
        new_positions[row['nativeStreetID']].add(pos)
        start = street['appended_record_offset'] + pos * 16
        raw = blob[start:start + 16]
        need(raw.hex() == row['payload'], 'New receipt references actual append bytes')
        decoded = decode128(raw)
        need(decoded['map'] == 1 and decoded['secondary'] == (1 << 19) - 1 and decoded['primary'] == row['primary_ref'], 'Leaf map/refs exact')
        need(decoded['first'] == decoded['count'] == decoded['flags'] == 0, 'New leaves have explicit zero hierarchy fields')
        point = [coordinate24(v) for v in row['coordinate_strings']]
        need([a for a, e in point] == row['raw24'] == [decoded['latitude'], decoded['longitude']], 'Independent coordinates match every new packed field')
        max_error = max(max_error, *(e for a, e in point))
        need(city.covers(row['coordinate_strings']), 'Independent city membership for new point')
        need(row['old_child_first'] == street['original_first'] and row['old_child_count'] == street['original_count'], 'New receipt original street witness')
        street_new[row['nativeStreetID']].append(row)
    cursor, cloned = 0, 0
    for street in ranges:
        need(street['appended_record_offset'] == cursor * 16 and street['new_first'] == 2133948 + cursor + 1, 'Contiguous one-based append ranges')
        need(street['new_count'] == street['original_count'] + street['new_integer_house_count'] <= 4095, 'Street count fits 12-bit profile')
        need(len(street_new[street['nativeStreetID']]) == street['new_integer_house_count'], 'Every new entry counted once')
        chunk = blob[cursor * 16:(cursor + street['new_count']) * 16]
        need(sha(chunk) == street['new_group_sha256'], 'All new street group digests')
        keep = b''.join(chunk[i * 16:(i + 1) * 16] for i in range(street['new_count']) if i not in new_positions[street['nativeStreetID']])
        need(sha(keep) == street['original_group_verbatim_sha256'], 'All retained-original receipt digests and relative order')
        ids = [r['new_lowID'] for r in street_new[street['nativeStreetID']]]
        numbers = [int(r['house_label'][:-1]) for r in street_new[street['nativeStreetID']]]
        need(ids == sorted(ids) and numbers == sorted(numbers), 'New receipt and placement integer order')
        cursor += street['new_count']; cloned += street['original_count']
    need(cursor * 16 == len(blob) and cursor == 262288 and cloned == 251286, 'Complete new/retained allocation accounting')
    need(2133948 + cursor == proof['proposed_level4_count'] == 2396236, 'Complete proposed L4 count')

    # Roster comes from earlier sealed prepared hierarchy, never a new map table scan.
    roster = {}
    for row in rows(ROOT / 'staging/navigation-taiwan-address-ingestion-v1/native-hierarchy.jsonl.gz'):
        if row['level'] == 3 and row['low28_id'] in by_street:
            street = by_street[row['low28_id']]
            need([row[k] for k in ('record', 'city', 'district', 'street', 'first_child', 'child_count', 'child_level_and_flags')] ==
                 [street[k] for k in ('native_street_record', 'city', 'district', 'street', 'original_first', 'original_count', 'original_flags')], 'Every updated street exact sealed roster witness')
            roster[row['low28_id']] = row
    need(len(roster) == 1693, 'Every updated street matched unique named native hierarchy')

    # Source subset single pass; memberships checked against new outputs, no full-country node pass.
    counts, found = Counter(), set()
    previous_key = None
    target_seen, held_examples = set(), []
    for row in rows(JOIN / 'taichung-next4-existing-label-ready-candidates.jsonl.gz'):
        counts['source_candidate_groups'] += 1
        sortkey = (row['native_street_record'], row['group_id'])
        need(previous_key is None or previous_key < sortkey, 'Prepared source candidate order is strictly increasing')
        previous_key = sortkey
        key = (row['nativeStreetID'], row['house_label'])
        need(key not in target_seen, 'No duplicate same native street/house source target')
        target_seen.add(key)
        normalized = [norm(x) for x in row['raw_address'][:3]] + [house_key(row['raw_address'][3], row['embedded_floor_unit_first_source_flag'])]
        need(normalized == row['normalized_planning_key'], 'Source raw address normalized exactly')
        need(normalized == [norm(row[k]) for k in ('native_city', 'native_district', 'native_street', 'house_label')], 'Exact city/district/street/house source match')
        need(row['coordinate_status'] == 'coordinate_ready_global_bounds' and row['source_different_coordinate_nodes'] == 0 and not row['same_native_street_house_coordinate_collision'], 'No disputed source coordinate in ready subset')
        need(len(row['source_ids']) == row['source_node_count'] and len(set(row['source_ids'])) == len(row['source_ids']), 'Source node membership count and IDs')
        if not HOUSE.fullmatch(row['house_label']):
            counts['subnumber_or_other_house_deferred'] += 1
            if len(held_examples) < 8: held_examples.append({k: row[k] for k in ('nativeStreetID', 'house_label', 'group_id', 'source_ids')})
            need(key not in new_by_key, 'No source subnumber inserted')
            continue
        counts['positive_integer_ready'] += 1
        output = new_by_key.get(key)
        if output is None:
            counts['positive_integer_not_added'] += 1
            continue
        need(output['source_ids'] == row['source_ids'] and output['coordinate_strings'] == row['coordinate_strings'] and output['primary_ref'] == row['primary_ref'], 'Every new leaf exact source IDs/coordinates/ref')
        street = by_street[row['nativeStreetID']]
        need([row[k] for k in ('native_street_record', 'native_city', 'native_district', 'native_street', 'old_child_first', 'old_child_count', 'old_child_level_and_flags')] ==
             [street[k] for k in ('native_street_record', 'city', 'district', 'street', 'original_first', 'original_count', 'original_flags')], 'New source branch witness bound')
        found.add(key)
    need(found == set(new_by_key), 'All new outputs have exact source candidate')
    inp = INPUTS[-1]
    need(inp['sha256'] == jp['taichung_subset']['candidate']['sha256'] and inp['uncompressed_sha256'] == jp['taichung_subset']['candidate']['uncompressed_sha256'], 'Source subset exact compressed/plain proof hashes')
    need(counts['source_candidate_groups'] == 282574 and counts['subnumber_or_other_house_deferred'] == 64285 and counts['positive_integer_not_added'] == 207287, 'Independent ready/subnumber/new/not-added counts')
    del target_seen
    quarantine = Counter()
    for row in rows(JOIN / 'taichung-next4-existing-label-coordinate-review.jsonl.gz'):
        quarantine[row['review_reason']] += 1
        need(row['coordinate_strings'] is None and (row['nativeStreetID'], row['house_label']) not in new_by_key, 'Coordinate discrepancy quarantined and never new output')
    need(sum(quarantine.values()) == 8421, 'Every declared discrepancy held')
    need(INPUTS[-1]['sha256'] == jp['taichung_subset']['review']['sha256'], 'Quarantine ledger bound')

    # Nine previously installed payload controls, checked against independent old plan and new data.
    golden = []
    plan_nine = {r['label']: r for r in plan['nine_new_source_candidates']}
    for original in trial['records']:
        if original['oldID'] is not None:
            continue
        row = new_by_key[(16707, original['label'])]
        p = plan_nine[original['label']]
        need(row['payload'] == original['payload'] and int(original['source_id']) in row['source_ids'], 'Golden payload and original source ID')
        need(int(p['OSM_id']) == int(original['source_id']) and row['coordinate_strings'] == p['source_coordinate_strings'], 'Golden original planning coordinate')
        golden.append(dict(label=original['label'], new_lowID=row['new_lowID'], original_trial_new_lowID=original['new_lowID'], payload_same=True, source_same=True))
    need(len(golden) == 9, 'Exact nine controls')

    # Limited original-image windows: deterministic spread plus all important extreme groups.
    selected = {ranges[0]['nativeStreetID'], ranges[-1]['nativeStreetID'], 16707,
                max(ranges, key=lambda r: r['new_count'])['nativeStreetID'],
                max(ranges, key=lambda r: r['new_integer_house_count'])['nativeStreetID'],
                min(ranges, key=lambda r: r['original_count'])['nativeStreetID']}
    selected.update(ranges[round(i * (len(ranges) - 1) / 19)]['nativeStreetID'] for i in range(20))
    image = IndependentIMG(AP)
    header = image.get('00004171.MDR', 0, 772)
    dstart, dlength, dstride, dpresent = struct.unpack_from('<4I', header, 600)
    need((dstart, dlength, dstride, dpresent) == (92653480, 120, 20, 1), 'Actual original MDR directory pointer')
    directory = image.get('00004171.MDR', dstart, dlength)
    d3 = struct.unpack_from('<5I', directory, 40)
    d4 = struct.unpack_from('<5I', directory, 60)
    need(d3[:3] == (91983716, 664197, 111) and d4[:3] == (57840548, 34143168, 128), 'Actual original native L3/L4 directory fields')
    labels = {}
    def label(ref):
        need(0 <= ref < (1 << 19) - 1, 'Source primary ref is not sentinel')
        if ref not in labels:
            start = ref * 8
            need(start < 3805432, 'Actual source LBL window')
            raw = image.get('I053061A.GMP', 6566 + start, min(96, 3805432 - start))
            end = raw.find(b'\0')
            need(end >= 0, 'Representative source label null terminator in 96-byte cap')
            labels[ref] = raw[:end].decode('cp950', 'strict')
        return labels[ref]
    # Every newly added ref decoded from original GMP with bounded small windows.
    for row in new:
        need(label(row['primary_ref']) == row['house_label'], 'Every new actual original-map label reference and text')
    representative = []
    for streetID in sorted(selected):
        s = by_street[streetID]
        parent_offset, shift = divmod((streetID - 1) * 111, 8)
        parent = int.from_bytes(image.get('00004171.MDR', d3[0] + parent_offset, 16), 'little') >> shift
        need(((parent >> 20) & ((1 << 22) - 1), (parent >> 42) & 4095, (parent >> 54) & 511) ==
             (s['original_first'], s['original_count'], s['original_flags']), 'Representative actual L3 source parent')
        old = image.get('00004171.MDR', d4[0] + (s['original_first'] - 1) * 16, s['original_count'] * 16)
        merged = blob[s['appended_record_offset']:s['appended_record_offset'] + s['new_count'] * 16]
        old_records = [old[i:i + 16] for i in range(0, len(old), 16)]
        merged_records = [merged[i:i + 16] for i in range(0, len(merged), 16)]
        retained = [r for i, r in enumerate(merged_records) if i not in new_positions[streetID]]
        need(old_records == retained and sha(old) == s['original_group_verbatim_sha256'], 'Representative actual source bytes and order preserved')
        old_names = [label(decode128(r)['primary']) for r in old_records]
        merged_names = [label(decode128(r)['primary']) for r in merged_records]
        old_exact = set(old_names)
        need(not any(r['house_label'] in old_exact for r in street_new[streetID]), 'Representative added houses absent from original street')
        anchors = [int(m.group()) for name in merged_names if (m := re.match(r'^[0-9]+', name))]
        need(anchors == sorted(anchors), 'Representative combined numeric-base ordering monotone')
        need(all(decode128(r)['map'] == 1 for r in old_records), 'Representative original ordinal1')
        for row in street_new[streetID]:
            k = row['new_lowID'] - s['new_first']
            before = [int(m.group()) for name in merged_names[:k] if (m := re.match(r'^[0-9]+', name))]
            after = [int(m.group()) for name in merged_names[k + 1:] if (m := re.match(r'^[0-9]+', name))]
            n = int(row['house_label'][:-1])
            need((not before or max(before) <= n) and (not after or min(after) >= n), 'Representative source numeric interleave bracket')
        representative.append(dict(nativeStreetID=streetID, district=s['district'], street=s['street'],
            original_count=s['original_count'], added_count=s['new_integer_house_count'], combined_count=s['new_count'],
            actual_original_bytes=len(old), original_bytes_and_relative_order_equal=True, merged_numeric_bases_monotone=True,
            original_subnumber_labels=sum('之' in n for n in old_names), original_nonnumeric_labels=sum(re.match(r'^[0-9]+', n) is None for n in old_names),
            original_nonzero_hierarchy_records=sum(any(decode128(r)[k] for k in ('first', 'count', 'flags')) for r in old_records),
            retained_crossroads_lanes_and_flags_unchanged=True))
    image.close()
    need(sum(r['actual_original_bytes'] for r in representative) < 300000, 'Explicit small original-house window budget')
    result = dict(schema='independent-new-taichung-native-merge-review/v1', created_utc=datetime.now(timezone.utc).isoformat(),
        all_assigned_checks_passed=True, offline_append_data_review_passed=True,
        source_candidate_groups=counts['source_candidate_groups'], source_ready_subnumbers_deferred=counts['subnumber_or_other_house_deferred'],
        source_ready_integer_not_added=counts['positive_integer_not_added'], source_new_integer_records=len(new),
        new_exact_source_membership_all=True, new_fields_and_rounding_all_independently_decoded=True,
        new_points_independently_inside_city=True, max_coordinate_rounding_error_degrees=str(max_error),
        actual_reused_label_refs_checked=len(labels), every_new_ref_actual_original_GMP_label_checked=True,
        updated_street_groups=len(ranges), appended_records=cursor, original_clones=cloned, proposed_L4_records=2133948 + cursor,
        all_new_groups_complete_hash_checked=True, all_retained_originals_match_root_source_window_digests=True,
        all_new_leaf_integer_order_monotone=True, exact_native_roster_and_source_addresses_all=True,
        actual_source_ordinal1_checked_in_representative_only=True,
        bounded_original_groups=representative, bounded_original_records=sum(r['original_count'] for r in representative),
        actual_source_map_bytes_read=sum(r['bytes'] for r in image.read_log), map_read_log=image.read_log,
        discrepancy_quarantine=dict(quarantine), withheld_subnumber_examples=held_examples, golden_controls=golden,
        source_provenance=ingestion['source'], inputs=INPUTS,
        production_source_review=dict(parent_L3_reads_from_actual_directory=True, packed128_leaf_fields_correct=True,
           original_leaf_bytes_children_secondary_refs_and_flags_preserved=True, newly_added_subnumbers=False,
           exact_original_house_coordinates_updated=False, only_OSM_node_address_sources=True),
        blockers_before_offline_larger_candidate=[],
        gates_before_install=['Assemble and independently validate complete MDR directory/profiles, rewritten parent ranges and streaming container.',
            'Exercise actual native reader on larger-candidate representative streets and new/old addresses before installing.',
            'Retain controlled install/readback/rollback and bounded UI destination/route acceptance; old nine payload equality is not larger candidate acceptance.'],
        limits=['All 11,002 new payloads and exact small-join membership checked; original table was not fully reread.',
           'All 251,286 cloned records verified against root original-window hashes; 26 or fewer deterministic original groups additionally compared to actual original map.',
           'Numeric-base monotonicity is a host policy; full native comparator subnumber/Chinese collation and UI prefix search remain unproved.',
           'Coordinates inherited from prepared OSM node ledger; this review does not independently reopen giant original PBF/source-node ledger, verify districts/entrances, or update old exact-house coordinates. Explicit 號 plus floor/unit suffix and separate floor/unit tags are grouped by the earlier conservative planning policy; no unit-specific point is newly invented.',
           'Missing/new streets/admins, next5/6, missing reusable labels, 64,285 source subnumbers and 8,421 coordinate-review groups remain outside this integer next4 preparation.',
           'No complete IMG/MDR rewrite, native CPU execution, USB, physical navigation, canonical report or ZIP mutation.'],
        native_CPU_executed=False, device_IO=False, full_IMG_written=False, full_Taiwan_native_update_complete=False)
    with (OUT / 'proof.json').open('x') as f:
        json.dump(result, f, ensure_ascii=False, indent=2); f.write('\n')
    print(json.dumps({k: result[k] for k in ('all_assigned_checks_passed', 'source_new_integer_records', 'updated_street_groups', 'bounded_original_records', 'actual_source_map_bytes_read', 'discrepancy_quarantine', 'blockers_before_offline_larger_candidate')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
