#!/usr/bin/env python3
"""Street-streamed original native L4/L5/L6 integer-house append preparation.

No IMG/container writer, native CPU, device, PBF, canonical report or ZIP I/O.
Original records are copied as significant bits; their child links/flags and
coordinates are never converted. New leaves use only known stock profiles.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from functools import lru_cache
import gzip
import hashlib
import importlib.util
import itertools
import json
import math
import os
from pathlib import Path
import re
import resource
import struct
import sys
import time
import unicodedata

sys.dont_write_bytecode = True
ROOT = Path('/root/garmin')
OUT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'scripts'))
from native_address_records import AddressRecord, RecordLayout, encode_record, quantize_point24
from prepare_taichung_city_geometry_v1 import CityGeometry

JOIN = ROOT / 'staging/navigation-country-address-ready-join-v1'
GEOMETRY = ROOT / 'staging/navigation-country-city-geometry-v1'
AP = ROOT / 'backups/20261002T154458Z/files/.System/gmapprom1.img'
TRIAL = ROOT / 'staging/navigation-native-address-supplement-v1/manifest.json'
CORE = ROOT / 'staging/navigation-native-general-writer-v1/native_ap_writer.py'
CORE_SHA = 'cb190d5f3c70f0e81e9d49808dff044e4717b5061f749e7720af56aee39b0cf8'
# CORE_SHA is set to the actual sealed reader hash during source preparation.
STRIDES = {4: 128, 5: 126, 6: 68}
TOTALS = {4: 2133948, 5: 2341096, 6: 1973316}
DESCRIPTORS = {4: (57840548, 34143168, 128), 5: (20968286, 36872262, 126), 6: (4195100, 16773186, 68)}
LAYOUTS = {
    4: RecordLayout((22, 9, 24, 19, 1, 10, 0, 0), (1, 1), 128),
    5: RecordLayout((21, 9, 24, 19, 1, 9, 0, 0), (1, 1), 126),
    6: RecordLayout((0, 0, 24, 19, 1, 0, 0, 0), (1, 0), 68),
}
INTEGER = re.compile(r'([1-9][0-9]*)號\Z')
INPUTS = []


def need(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def norm(text):
    return unicodedata.normalize('NFKC', text or '').strip().replace('臺', '台')


def small_json(path):
    before = signature(path)
    raw = path.read_bytes()
    need(signature(path) == before, 'Immutable small input')
    INPUTS.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw), stat_unchanged=True))
    return json.loads(raw)


def save(name, data):
    path = OUT / name
    with path.open('xb') as f:
        raw = data if isinstance(data, bytes) else (json.dumps(data, ensure_ascii=False, indent=2) + '\n').encode()
        need(f.write(raw) == len(raw), 'Complete small output write')
        f.flush(); os.fsync(f.fileno())
    path.chmod(0o444)


class HashReader:
    def __init__(self, stream):
        self.stream, self.digest, self.bytes = stream, hashlib.sha256(), 0

    def read(self, n=-1):
        raw = self.stream.read(n)
        self.digest.update(raw); self.bytes += len(raw)
        return raw


def source_rows(path, expected, level):
    before = signature(path)
    need(before[2] == expected['bytes'], 'Pinned ready source byte count')
    count, plain, previous = 0, hashlib.sha256(), None
    with path.open('rb') as raw:
        reader = HashReader(raw)
        with gzip.GzipFile(fileobj=reader) as stream:
            for line in stream:
                plain.update(line); count += 1
                row = json.loads(line)
                key = (row['native_street_record'], row['house_label'], row['group_id'])
                need(previous is None or previous < key, 'Ready input exact street/house/group order')
                previous = key
                need(row['native_match_scope'] == 'exact_city_district_street' and row['district_verified'] is True,
                     'Only district-verified exact source scope')
                need(row['old_next_level'] == level and row['old_child_level_and_flags'] & 7 == level,
                     'Actual source next level and raw flags preserved')
                need(row['coordinate_status'] == 'coordinate_ready_global_bounds' and row['coordinate_strings'] is not None and
                     row['source_different_coordinate_nodes'] == 0 and not row['same_native_street_house_coordinate_collision'] and
                     row['same_native_street_house_unready_coordinate_members'] == 0 and row['same_native_street_house_collision_checked'] is True,
                     'No conflicting or unready target admitted')
                need(row['native_merge_eligible'] is True and row['native_street_record'] == (3 << 28) | row['nativeStreetID'], 'Known native street identity')
                need(len(row['source_ids']) == row['source_node_count'] and all(type(n) is int and n > 0 for n in row['source_ids']), 'Source ID and node membership')
                need(len(row['coordinate_strings']) == 2, 'Direct source point required')
                lat, lon = map(Decimal, row['coordinate_strings'])
                need(lat.is_finite() and lon.is_finite() and -90 <= lat <= 90 and -180 <= lon < 180, 'Global point bounds')
                yield row
        need(reader.bytes == before[2] and reader.digest.hexdigest() == expected['sha256'] and plain.hexdigest() == expected['uncompressed_sha256'], 'Ready source compressed/plain hashes and EOF')
    need(count == expected['rows'] and signature(path) == before, 'Complete row count and immutable ready source')
    INPUTS.append(dict(path=str(path.relative_to(ROOT)), bytes=reader.bytes, sha256=reader.digest.hexdigest(),
                       uncompressed_sha256=plain.hexdigest(), rows=count, gzip_EOF_validated=True,
                       stat_before=before, stat_after=signature(path), stat_unchanged=True, compressed_content_passes=1))


class OutputHash:
    def __init__(self, path):
        self.path, self.stream, self.digest, self.bytes = path, path.open('xb'), hashlib.sha256(), 0

    def write(self, raw):
        n = self.stream.write(raw)
        need(n == len(raw), 'Complete streaming output write')
        self.digest.update(raw); self.bytes += n
        return n

    def flush(self):
        self.stream.flush()

    def close(self):
        self.stream.flush(); os.fsync(self.stream.fileno()); self.stream.close()
        need(self.path.stat().st_size == self.bytes, 'Streaming output byte accounting')
        self.path.chmod(0o444)
        return dict(path=self.path.name, bytes=self.bytes, sha256=self.digest.hexdigest())


class JsonLines:
    def __init__(self, name):
        self.raw = OutputHash(OUT / name)
        self.stream = gzip.GzipFile(filename='', fileobj=self.raw, mode='wb', mtime=0, compresslevel=6)
        self.rows, self.plain = 0, hashlib.sha256()

    def write(self, value):
        raw = (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode()
        self.stream.write(raw); self.plain.update(raw); self.rows += 1

    def close(self):
        self.stream.close()
        artifact = self.raw.close()
        artifact.update(rows=self.rows, uncompressed_sha256=self.plain.hexdigest())
        return artifact


class JsonArray:
    def __init__(self, name):
        self.raw, self.rows = OutputHash(OUT / name), 0
        self.raw.write(b'[\n')

    def write(self, row):
        if self.rows:self.raw.write(b',\n')
        self.raw.write(json.dumps(row, ensure_ascii=False, separators=(',', ':')).encode())
        self.rows += 1

    def close(self):
        self.raw.write(b'\n]\n')
        artifact = self.raw.close(); artifact['rows'] = self.rows
        return artifact


class BitAppend:
    """One table-wide LSB stream; retains partial byte across street boundaries."""
    def __init__(self, output, width):
        self.output, self.width = output, width
        self.accumulator = self.pending = self.records = 0
        self.buffer = bytearray()

    @property
    def bits(self):return self.records * self.width

    def add(self, value):
        need(type(value) is int and 0 <= value < 1 << self.width, 'Significant packed record width')
        self.accumulator |= value << self.pending; self.pending += self.width; self.records += 1
        while self.pending >= 8:
            self.buffer.append(self.accumulator & 255); self.accumulator >>= 8; self.pending -= 8
        if len(self.buffer) >= 65536:
            self.output.write(bytes(self.buffer)); self.buffer.clear()

    def finish(self):
        need(0 <= self.pending < 8, 'Small final bit carry')
        if self.pending:self.buffer.append(self.accumulator)
        if self.buffer:self.output.write(bytes(self.buffer)); self.buffer.clear()
        artifact = self.output.close()
        need(artifact['bytes'] == (self.bits + 7) // 8, 'Table-wide tight packed byte count')
        artifact.update(record_count=self.records, bit_length=self.bits, record_bits=self.width,
                        unused_final_high_bits=(-self.bits) % 8, final_padding_zero=True)
        return artifact


def packed(values, width):
    sink = io_sink = type('MemorySink', (), {'write': lambda self, x: self.data.extend(x)})()
    sink.data = bytearray()
    acc, pending = 0, 0
    for value in values:
        need(0 <= value < 1 << width, 'Packed significant record')
        acc |= value << pending; pending += width
        while pending >= 8:
            sink.data.append(acc & 255); acc >>= 8; pending -= 8
    if pending:sink.data.append(acc)
    return bytes(sink.data)


def unpack(raw, start_bit, count, width):
    result, mask = [], (1 << width) - 1
    for index in range(count):
        at = start_bit + index * width
        pos, shift = divmod(at, 8)
        n = (shift + width + 7) // 8
        need(pos + n <= len(raw), 'Group window record bounds')
        result.append((int.from_bytes(raw[pos:pos + n], 'little') >> shift) & mask)
    return result


def record_hash(values, width):
    digest = hashlib.sha256()
    for value in values:digest.update(value.to_bytes((width + 7) // 8, 'little'))
    return digest.hexdigest()


def merge_numeric(old, names, new):
    """Host base-number interleave only; never changes original relative order."""
    anchors = [int(m.group()) for label in names if (m := re.match(r'^[0-9]+', label))]
    if not anchors or anchors != sorted(anchors):return None
    new = sorted(new, key=lambda r: r['number'])
    merged, positions, index = [], {}, 0
    for value, name in zip(old, names):
        m = re.match(r'^[0-9]+', name)
        if m:
            while index < len(new) and new[index]['number'] < int(m.group()):
                positions[new[index]['label']] = len(merged); merged.append(new[index]['value']); index += 1
        merged.append(value)
    for row in new[index:]:positions[row['label']] = len(merged); merged.append(row['value'])
    inserted = set(positions.values())
    need([v for i, v in enumerate(merged) if i not in inserted] == old, 'Every original significant bit and relative order retained')
    return merged, positions, new


def main():
    need(not (OUT / 'proof.json').exists() and not (OUT / 'appended-level4.bin').exists(), 'New preparation namespace only')
    started = datetime.now(timezone.utc).isoformat()
    before_ap = signature(AP)
    jp, gp, geos, trial = (small_json(p) for p in (JOIN / 'proof.json', GEOMETRY / 'proof.json', GEOMETRY / 'city-geometries.json', TRIAL))
    need(jp['all_assigned_checks_passed'] and gp['all_assigned_checks_passed'] and len(geos) == 21, 'Pinned complete upstream join/geometries')
    need(INPUTS[-2]['sha256'] == gp['geometries_sha256'] and INPUTS[-2]['bytes'] == gp['geometry_bytes'], 'Complete city geometry hash')
    cities = {norm(name): CityGeometry(row['geometry']) for name, row in geos.items()}
    need('高雄市' not in cities, 'Incomplete Kaohsiung remains held')
    expected_nine = {r['label']: r for r in trial['records'] if r['oldID'] is None}
    core_raw = CORE.read_bytes(); need(sha(core_raw) == CORE_SHA, 'Sealed original StreamIMG reader')
    spec = importlib.util.spec_from_file_location('country_source_reader_only', CORE)
    core = importlib.util.module_from_spec(spec); sys.modules[spec.name] = core; spec.loader.exec_module(core)
    source_hashes = [dict(path=str(p.relative_to(ROOT)), bytes=p.stat().st_size, sha256=sha(p.read_bytes()))
        for p in (Path(__file__), ROOT / 'scripts/native_address_records.py', ROOT / 'scripts/prepare_taichung_city_geometry_v1.py', CORE)]
    selected = JsonArray('selected-street-ranges.json')
    ledger = JsonLines('new-house-records.jsonl.gz')
    held = JsonLines('held-street-groups.jsonl.gz')
    readlog = JsonLines('original-map-read-log.jsonl.gz')
    total_counts, level_counts, city_counts = Counter(), {}, defaultdict(Counter)
    appended = {level: BitAppend(OutputHash(OUT / f'appended-level{level}.bin'), STRIDES[level]) for level in STRIDES}
    controls, max_street_rows, max_old_records, map_bytes, map_reads = {}, 0, 0, 0, 0
    runtime = []; last_update = time.monotonic()
    with AP.open('rb') as source:
        image = core.StreamIMG(source)
        def flush_reads():
            nonlocal map_bytes, map_reads
            for r in image.read_log:
                readlog.write(r); map_bytes += r['bytes']; map_reads += 1
            image.read_log.clear()
        def read(name, offset, length):return b''.join(image.iter_component(name, offset=offset, length=length))
        header = read('00004171.MDR', 0, 772)
        ds, db, de, df = struct.unpack_from('<4I', header, 600)
        need((ds, db, de, df) == (92653480, 120, 20, 1), 'Actual source MDR directory')
        directory = read('00004171.MDR', ds, 120)
        tables = {lev: struct.unpack_from('<5I', directory, (lev - 1) * 20) for lev in range(1, 7)}
        need(tables[3][:3] == (91983716, 664197, 111), 'Actual street L3 profile')
        for level in STRIDES:
            need(tables[level][:3] == DESCRIPTORS[level] and tables[level][1] * 8 == TOTALS[level] * STRIDES[level], 'Exact original byte-aligned L4/L5/L6 table counts')
        pool = read('I053061A.GMP', 6566, 3805432)
        @lru_cache(maxsize=65536)
        def label(ref):
            if ref == 524287:return None
            offset = ref * 8
            if not 0 <= offset < len(pool):return None
            end = pool.find(b'\0', offset, min(len(pool), offset + 512))
            if end < 0:return None
            try:return pool[offset:end].decode('cp950', errors='strict')
            except UnicodeDecodeError:return None
        flush_reads()
        for level in (4, 5, 6):
            counts = level_counts[level] = Counter()
            width, output = STRIDES[level], appended[level]
            expected = jp['artifacts'][f'exact_{level}_ready']
            input_path = ROOT / expected['path']
            iterator = source_rows(input_path, expected, level)
            for streetID, source_street in itertools.groupby(iterator, key=lambda r: r['nativeStreetID']):
                # At most one source street is retained; every input still streams through hash/EOF.
                rows = list(source_street); max_street_rows = max(max_street_rows, len(rows))
                counts['source_groups'] += len(rows); city_name = norm(rows[0]['native_city'])
                city_counts[city_name]['source_groups'] += len(rows)
                witness = rows[0]
                first, count, flags = (witness[k] for k in ('old_child_first', 'old_child_count', 'old_child_level_and_flags'))
                need(1 <= streetID <= 47870 and 0 < count <= 4095 and 1 <= first <= first + count - 1 <= TOTALS[level], 'Original parent/group range bounds')
                need(all([r[k] for k in ('old_child_first', 'old_child_count', 'old_child_level_and_flags', 'native_city', 'native_district', 'native_street')] ==
                     [witness[k] for k in ('old_child_first', 'old_child_count', 'old_child_level_and_flags', 'native_city', 'native_district', 'native_street')] for r in rows), 'Same street actual source witness')
                parent_at, parent_shift = divmod((streetID - 1) * 111, 8)
                parent = int.from_bytes(read('00004171.MDR', tables[3][0] + parent_at, 16), 'little') >> parent_shift
                need(((parent >> 20) & ((1 << 22) - 1), (parent >> 42) & 4095, (parent >> 54) & 511) == (first, count, flags), 'Actual original L3 raw parent fields')
                def hold(reason, **extra):
                    counts['held_streets_' + reason] += 1; counts['held_source_groups_' + reason] += len(rows)
                    city_counts[city_name]['held_streets_' + reason] += 1
                    held.write(dict(nativeStreetID=streetID, native_street_record=witness['native_street_record'], city=witness['native_city'],
                        district=witness['native_district'], street=witness['native_street'], next_level=level,
                        original_first=first, original_count=count, original_flags=flags, source_groups=len(rows), reason=reason, **extra))
                if city_name not in cities:
                    hold('incomplete_city_geometry'); flush_reads(); continue
                start, shift = divmod((first - 1) * width, 8)
                body = read('00004171.MDR', tables[level][0] + start, (shift + count * width + 7) // 8)
                old = unpack(body, shift, count, width); max_old_records = max(max_old_records, count)
                primary_shift = 1 if level == 6 else 20
                names = [label((r >> primary_shift) & 524287) for r in old]
                if any(n is None for n in names):hold('unreadable_original_primary_label'); flush_reads(); continue
                anchors = [int(m.group()) for n in names if (m := re.match(r'^[0-9]+', n))]
                if not anchors or anchors != sorted(anchors):hold('unproved_original_numeric_order'); flush_reads(); continue
                ordinal1 = all(r & 1 == 1 for r in old)
                existing = set(names); new = []
                for house, members_iter in itertools.groupby(rows, key=lambda r: r['house_label']):
                    members = list(members_iter)
                    counts['source_distinct_street_house_targets'] += 1
                    match = INTEGER.fullmatch(house)
                    if not match:
                        counts['subnumber_or_other_house_source_groups_deferred'] += len(members)
                        counts['subnumber_or_other_house_targets_deferred'] += 1; continue
                    counts['positive_integer_source_groups'] += len(members)
                    refs = {r['primary_ref'] for r in members}
                    coords = {tuple(map(Decimal, r['coordinate_strings'])) for r in members}
                    need(len(refs) == len(coords) == 1, 'Same-target members have exact shared label ref and Decimal point')
                    need(label(members[0]['primary_ref']) == house, 'Reusable original GMP label text')
                    if len(members) > 1:
                        counts['coalesced_multiple_group_targets'] += 1; counts['coalesced_extra_source_groups'] += len(members) - 1
                    if house in existing:
                        counts['original_exact_integer_house_targets_unchanged'] += 1
                        counts['source_integer_groups_already_in_original'] += len(members); continue
                    if not ordinal1:
                        counts['new_integer_targets_deferred_non1_original_mapordinal'] += 1; continue
                    point = members[0]['coordinate_strings']
                    if not cities[city_name].covers(*point):
                        counts['new_integer_targets_outside_complete_source_city'] += 1; continue
                    q = quantize_point24(*point)
                    raw24 = [q['latitude']['wire_u24'], q['longitude']['wire_u24']]
                    payload = encode_record(LAYOUTS[level], AddressRecord(1, members[0]['primary_ref'], None, 0, 0, 0, *raw24)).payload
                    value = int.from_bytes(payload, 'little'); need(value >> width == 0, 'New per-record unused bits zero')
                    provenance = [dict(group_id=r['group_id'], source_ids=r['source_ids'], raw_address=r['raw_address'],
                        coordinate_strings=r['coordinate_strings'], source_node_count=r['source_node_count'],
                        separate_floor_unit_source_nodes=r['separate_floor_unit_source_nodes'],
                        embedded_floor_unit_first_source_flag=r['embedded_floor_unit_first_source_flag']) for r in members]
                    source_ids = sorted({n for r in members for n in r['source_ids']})
                    new.append(dict(label=house, number=int(match.group(1)), value=value, payload=payload.hex(), raw24=raw24,
                        coordinate_strings=point, primary_ref=members[0]['primary_ref'], source_ids=source_ids,
                        source_group_ids=[r['group_id'] for r in members], source_members=provenance))
                if not new:
                    counts['streets_without_new_eligible_integer_house'] += 1; flush_reads(); continue
                if count + len(new) > 4095:
                    hold('merged_parent_count_over_12bit', proposed_count=count + len(new), held_new_integer_targets=len(new)); flush_reads(); continue
                first_new = TOTALS[level] + output.records + 1
                if first_new + count + len(new) - 1 > 0x7fffff:
                    hold('proposed_first_or_last_over_23bit', proposed_first=first_new, held_new_integer_targets=len(new)); flush_reads(); continue
                merged, positions, ordered = merge_numeric(old, names, new)
                need(len(merged) == count + len(new), 'Merged actual count')
                offset_bits = output.bits
                for value in merged:output.add(value)
                selected.write(dict(nativeStreetID=streetID, native_street_record=witness['native_street_record'],
                    city=witness['native_city'], district=witness['native_district'], street=witness['native_street'],
                    next_level=level, record_bits=width, original_first=first, original_count=count, original_flags=flags,
                    new_first=first_new, new_count=len(merged), appended_bit_offset=offset_bits,
                    appended_record_ordinal=offset_bits // width, new_integer_house_count=len(new),
                    original_source_window_sha256=sha(body), original_source_initial_bit_shift=shift,
                    original_significant_records_sha256=record_hash(old, width),
                    new_significant_records_sha256=record_hash(merged, width), new_group_tight_packed_sha256=sha(packed(merged, width)),
                    significant_hash_policy='Concatenate ceil(stride/8)-byte records with per-record unused high bits zero; original significant bits unchanged.'))
                for row in ordered:
                    newID = first_new + positions[row['label']]
                    ledger.write(dict(nativeStreetID=streetID, next_level=level, new_lowID=newID,
                        appended_bit_offset=offset_bits + positions[row['label']] * width, record_bits=width,
                        house_label=row['label'], primary_ref=row['primary_ref'], source_ids=row['source_ids'],
                        source_group_ids=row['source_group_ids'], source_members=row['source_members'],
                        coordinate_strings=row['coordinate_strings'], raw24=row['raw24'], payload=row['payload'],
                        old_child_first=first, old_child_count=count, old_parent_flags=flags,
                        city=witness['native_city'], district=witness['native_district'], street=witness['native_street']))
                    if level == 4 and streetID == 16707 and row['label'] in expected_nine:
                        expected_row = expected_nine[row['label']]
                        need(row['payload'] == expected_row['payload'] and int(expected_row['source_id']) in row['source_ids'], 'Nine Minquan installed-trial payload/source equality')
                        controls[row['label']] = dict(next_level=4, new_lowID=newID, payload_and_source_equal=True)
                counts['updated_streets'] += 1; counts['new_integer_house_records'] += len(new)
                counts['cloned_original_records'] += count; counts['appended_records'] += len(merged)
                city_counts[city_name]['updated_streets'] += 1; city_counts[city_name]['new_integer_house_records'] += len(new)
                city_counts[city_name]['cloned_original_records'] += count
                flush_reads()
                if time.monotonic() - last_update > 25:
                    observation = dict(level=level, processed_source_groups=counts['source_groups'], updated_streets=counts['updated_streets'],
                        appended_records=output.records, new_integer_house_records=counts['new_integer_house_records'],
                        max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
                    runtime.append(observation); print(json.dumps(dict(progress=observation), ensure_ascii=False), flush=True)
                    last_update = time.monotonic()
            total_counts.update(counts)
            print(json.dumps(dict(level_finished=level, counts=dict(counts), appended_records=output.records), ensure_ascii=False), flush=True)
        flush_reads()
    need(signature(AP) == before_ap, 'Original AP metadata unchanged')
    need(set(controls) == set(expected_nine), 'All nine golden controls included')
    artifacts = {f'level{level}': output.finish() for level, output in appended.items()}
    artifacts.update(selected_ranges=selected.close(), new_records=ledger.close(), held=held.close(), read_log=readlog.close())
    for level in STRIDES:
        need(artifacts[f'level{level}']['record_count'] == level_counts[level]['appended_records'], 'Final appended records equal street counts')
    need(artifacts['new_records']['rows'] == total_counts['new_integer_house_records'], 'Every new record ledger written once')
    save('proof.json', dict(schema='country-original-native-integer-house-merge-preparation/v1', started_utc=started,
        finished_utc=datetime.now(timezone.utc).isoformat(), all_assigned_checks_passed=True,
        original_counts=TOTALS, proposed_counts={level:TOTALS[level] + appended[level].records for level in STRIDES},
        strides=STRIDES, counts=dict(total_counts), counts_by_level={lev:dict(c) for lev,c in level_counts.items()},
        counts_by_city={city:dict(c) for city,c in city_counts.items()}, artifacts=artifacts, inputs=INPUTS,
        source_code_bindings=source_hashes, original_map_stat_before=before_ap, original_map_stat_after=signature(AP),
        original_map_bytes_read=map_bytes, original_map_read_operations=map_reads, max_source_street_rows=max_street_rows,
        max_original_street_records=max_old_records, max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        runtime_resource_receipts=runtime, nine_Minquan_payload_controls=controls,
        original_significant_bits_relative_order_coordinates_flags_and_childrefs_preserved=True,
        original_flag13_cleared_or_converted=False, original_exact_house_coordinates_updated=False,
        separate_record_or_street_output_padding=False, only_table_final_padding_zero=True,
        directcity_district_unverified_inputs_used=False, incomplete_Kaohsiung_city_geometry_held=True,
        subnumber_generation_deferred=True, only_mapordinal1_new_leaves=True,
        source_coordinate_conflicts_coalesced=False, same_Decimal_coordinate_members_coalesced_with_full_provenance=True,
        country_PBF_or_source_node_ledger_reopened=False, native_CPU_executed=False, device_IO=False,
        whole_IMG_written=False, full_Taiwan_native_update_complete=False,
        limits=['Existing exact district-verified next4/5/6 streets, existing stock house text refs and positive integer house leaves only.',
            'Incomplete city geometry (Kaohsiung), new street/admin, direct-city district-unverified, missing labels, subnumbers and upstream coordinate conflicts remain held.',
            'Old exact house points are deliberately unchanged; source direct OSM points are not verified entrances/districts/routing.',
            'Original significant bits are preserved; record padding used only for hash/payload receipts is not part of emitted packed table.',
            'Host numeric-base ordering is not complete native comparator/prefix search or UI acceptance proof.',
            'This preparation is not a complete map/container, candidate install, all-Taiwan coverage guarantee, or physical navigation test.']))
    print(json.dumps(dict(all_assigned_checks_passed=True, counts=dict(total_counts), proposed_counts={lev: TOTALS[lev]+appended[lev].records for lev in STRIDES}, max_RSS_KiB=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss), ensure_ascii=False), flush=True)


if __name__ == '__main__':main()
