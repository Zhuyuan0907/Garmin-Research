#!/usr/bin/env python3
"""Finite v2 MDR producer-order query, never a Garmin UI implementation.

Only in-memory MDR/SRT and referenced LBL labels are read. No image copy,
whole-image digest, NET/RGN replay, huge table JSON, device or canonical writes.
Run only after ROOT selects a successful final v2 build and producer controls.
The source's preparation does not execute this reader or establish compatibility.
"""
import argparse
import bisect
import hashlib
import json
import mmap
import re
import struct
from collections import Counter
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = Path(__file__).resolve().parent
BUILD = ROOT / 'staging/navigation-repair-v2/build-manifest.json'
TARGETS = ['民權路', '民和路一段', '民和路二段']
SORT_ROOT = ROOT / 'staging/navigation-firmware-sort-v1'


def need(condition, message):
    if not condition:
        raise ValueError(message)


def uint(data, offset, width):
    need(0 <= offset <= len(data) - width and 1 <= width <= 4, 'Integer outside component')
    return int.from_bytes(data[offset:offset + width], 'little')


def pointer_size(count):
    return max(1, (count.bit_length() + 7) // 8)


def small_digest(path):
    need(path.is_file() and path.stat().st_size <= 2 * 1024 * 1024,
         'Only small frozen source/manifest/fixture digest inputs are permitted')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rooted_path(relative):
    path = (ROOT / relative).resolve()
    need(path.is_relative_to(ROOT), 'Dependency outside workspace')
    return path


def selected_build(controls_path):
    """Read successful final build metadata BEFORE opening the IMG.

    ROOT must explicitly select the completed build at invocation; an existing
    manifest or a finite prototype pass is not a live Garmin/UI success.
    """
    before = BUILD.read_bytes()
    manifest = json.loads(before)
    need(manifest.get('state') == 'compiled_candidate_not_device_verified' and
         manifest.get('exit_code') == 0 and manifest.get('finished_utc'),
         'V2 build is not terminal and successful; do not read unfinished IMG')
    expected = dict(family_id=7053, map_id_start=70530001, tile_count=36,
                    sort_id1=19, sort_id2=7053, code_page=65001)
    need(all(manifest.get(k) == v for k, v in expected.items()), 'V2 build identity')
    need(manifest.get('candidate') is True and
         all(manifest.get(k) is False for k in
             ['device_installed', 'device_search_verified', 'device_routing_verified',
              'stock_maps_modified', 'GarminOS_recompiled']), 'Declared offline candidate scope')
    proof_path = rooted_path(manifest['finite_prototype_validation'])
    need(proof_path.is_relative_to(SORT_ROOT), 'Finite validation namespace')
    proof_sha = small_digest(proof_path)
    need(proof_sha == manifest['finite_prototype_validation_sha256'],
         'Finite validation differs from producer build binding')
    proof = json.loads(proof_path.read_text())
    need(proof.get('all_passed') is True, 'Finite prototype validation failed')
    source_path = rooted_path(manifest['native_sort_source'])
    need(source_path.is_relative_to(SORT_ROOT), 'Producer Sort source namespace')
    need(small_digest(source_path) == manifest['native_sort_source_sha256'],
         'Producer Sort source differs from build binding')
    controls_path = controls_path.resolve()
    need(controls_path.is_relative_to(SORT_ROOT), 'Producer controls namespace')
    need(controls_path.suffix == '.tsv', 'Frozen Java producer KEY/CMP controls required')
    need(small_digest(controls_path) == manifest.get('producer_controls_sha256'),
         'ROOT final manifest must bind selected Java producer controls SHA-256')
    need(rooted_path(manifest.get('producer_controls', '')) == controls_path,
         'ROOT final manifest must name selected Java producer controls')
    image_path = rooted_path(manifest['image'])
    need(image_path == ROOT / 'staging/navigation-repair-v2/compiled/gmapsupp.img',
         'Read only ROOT selected compiled v2 IMG')
    need(re.fullmatch('[0-9a-f]{64}', manifest['image_sha256']), 'ROOT image digest declaration')
    return manifest, image_path, before, proof_path, proof_sha


def producer_controls(path):
    keys, comparisons, meta, after = {}, {}, None, None
    for line in path.read_text().splitlines():
        fields = line.split('\t')
        if fields[0] == 'META':
            need(len(fields) == 5, 'Producer META shape')
            meta = dict(maxPrimary=int(fields[1]), maxExpSize=int(fields[2]),
                        maxPage=int(fields[3]), tables_sha256=fields[4])
        elif fields[0] == 'KEY':
            need(len(fields) == 3 and fields[1] not in keys, 'Producer KEY shape/uniqueness')
            data, position, levels = bytes.fromhex(fields[2]), 0, []
            primary = []
            while True:
                need(position + 2 <= len(data), 'Producer primary terminator')
                unit = int.from_bytes(data[position:position + 2], 'big')
                position += 2
                if not unit:
                    break
                primary.append(unit)
            levels.append(tuple(primary))
            for _ in range(2):
                level = []
                while True:
                    need(position < len(data), 'Producer level terminator')
                    unit, position = data[position], position + 1
                    if not unit:
                        break
                    level.append(unit)
                levels.append(tuple(level))
            need(not any(data[position:]), 'Producer trailing key padding')
            keys[fields[1]] = tuple(levels)
        elif fields[0] == 'CMP':
            need(len(fields) == 5, 'Producer CMP shape')
            a, b, strength, sign = fields[1], fields[2], int(fields[3]), int(fields[4])
            need(strength in (0, 1, 2) and sign in (-1, 0, 1), 'Producer CMP domains')
            need((a, b, strength) not in comparisons, 'Producer CMP uniqueness')
            comparisons[a, b, strength] = sign
        elif fields[0] == 'TABLES_AFTER':
            need(len(fields) == 2, 'Producer final table digest')
            after = fields[1]
        else:
            need(fields[0] == 'MAXIMA', 'Unsupported producer control line')
    need(meta is not None and keys and comparisons and meta['tables_sha256'] == after,
         'Producer control table consistency')
    need(meta['maxPrimary'] == 10690 and meta['maxPage'] == 255,
         'Reader only supports selected official r4924 UTF8 producer table')
    return keys, comparisons, meta


class Image:
    def __init__(self, name):
        self.name = name
        self.stream = name.open('rb')
        self.data = mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ)
        d = self.data
        need(d[0] == 0 and d[0x10:0x17] == b'DSKIMG\0', 'Unlocked IMG expected')
        self.bs = 1 << (d[0x61] + d[0x62])
        first = d[0x40] * 512
        end = uint(d, first + 12, 4)
        need(first < end <= len(d) and end % 512 == 0, 'Directory extent')
        self.components = {}
        for pos in range(first, end, 512):
            row = d[pos:pos + 512]
            if row[0] != 1 or row[16] == 3:
                continue
            key = row[1:9].decode('ascii').strip() + '.' + row[9:12].decode('ascii')
            part = uint(row, 17, 2)
            if part == 0:
                need(key not in self.components, 'Duplicate component')
                self.components[key] = dict(bytes=uint(row, 12, 4), blocks=[], next_part=0)
            c = self.components[key]
            need(part == c['next_part'], 'Allocation continuation order')
            c['next_part'] += 1
            c['blocks'].extend(b for b in struct.unpack_from('<240H', row, 32) if b != 0xffff)
        self.read_bytes = Counter()

    def read(self, key, pos=0, size=None):
        c = self.components[key]
        if size is None:
            size = c['bytes'] - pos
        need(0 <= pos <= c['bytes'] - size, key + ' reference outside component')
        result = bytearray()
        stop = pos + size
        while pos < stop:
            block, within = divmod(pos, self.bs)
            need(block < len(c['blocks']), key + ' missing allocation block')
            physical = c['blocks'][block] * self.bs + within
            count = min(self.bs - within, stop - pos)
            need(physical + count <= len(self.data), 'Physical allocation outside image')
            result.extend(self.data[physical:physical + count])
            pos += count
        self.read_bytes[key.rsplit('.', 1)[1]] += size
        return bytes(result)


def sections(data):
    need(data[2:12] == b'GARMIN MDR' and uint(data, 0, 2) == 568, 'Exact MDR header568 expected')
    need(struct.unpack_from('<4H', data, 21) == (65001, 19, 7053, 14), 'MDR sort metadata')
    pos, result = 29, {}
    for number in range(1, 31):
        start, size = struct.unpack_from('<2I', data, pos)
        pos += 8
        item = 0
        if number not in (10, 15, 17):
            item = uint(data, pos, 2)
            pos += 2
        magic = 0
        if number != 15:
            magic = uint(data, pos, 4)
            pos += 4
        else:
            need(data[pos] == 0, 'MDR15 trailing byte')
            pos += 1
        need(568 <= start <= len(data) - size, 'MDR section outside file: ' + str(number))
        need(not item or size % item == 0, 'Fractional MDR record: ' + str(number))
        result[number] = dict(position=start, bytes=size, item_size=item, magic=magic,
                              records=size // item if item else None)
    spans = sorted((r['position'], r['position'] + r['bytes']) for r in result.values() if r['bytes'])
    need(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])), 'MDR sections overlap')
    return result


class Sort:
    def __init__(self, data):
        self.data = data
        need(data[2:12] == b'GARMIN SRT' and uint(data, 0, 2) == 29,
             'Selected official SRT main header29 expected')
        h2 = uint(data, 23, 4)
        need(uint(data, 27, 2) == 16 and h2 + 16 <= len(data), 'SRT header2 bounds')
        self.sp = uint(data, h2 + 8, 4)
        sp = self.sp
        self.subheader_bytes = uint(data, h2 + 12, 4)
        need(sp + self.subheader_bytes <= len(data) and self.subheader_bytes >= 92,
             'SRT header3/component bound')
        need(uint(data, sp, 2) == 92, 'Unicode SRT header3 length92')
        need(struct.unpack_from('<3H', data, sp + 2) == (19, 7053, 65001), 'SRT metadata')
        self.flags = uint(data, sp + 8, 4)
        need(self.flags == 0x6f02, 'Native packed 16/10/6 SRT flags must be exactly0x6F02')
        self.cp = sp + uint(data, sp + 12, 4)
        cp_bytes = uint(data, sp + 16, 4)
        need(cp_bytes == 255 * 5 and uint(data, sp + 20, 2) == 5, 'SRT 5byte base records')
        self.ep = sp + uint(data, sp + 28, 4)
        ep_bytes = uint(data, sp + 32, 4)
        need(ep_bytes % 4 == 0 and uint(data, sp + 36, 2) == 4, 'SRT 4byte expansion records')
        self.exp_count = ep_bytes // 4
        self.max_page = uint(data, sp + 56, 4)
        need(self.max_page == 255, 'Selected full BMP SRT page range255')
        self.page_index = sp + uint(data, sp + 60, 4)
        index_bytes = uint(data, sp + 64, 4)
        need(index_bytes == self.max_page * 4 and uint(data, sp + 68, 2) == 4,
             'SRT page pointer count/item size')
        self.page_data = sp + uint(data, sp + 76, 4)
        page_bytes = uint(data, sp + 80, 4)
        need(page_bytes % (256 * 5) == 0 and uint(data, sp + 84, 2) == 5,
             'SRT complete 256char pages')
        spans = [(self.cp, cp_bytes), (self.ep, ep_bytes),
                 (self.page_index, index_bytes), (self.page_data, page_bytes)]
        need(all(sp + 92 <= start <= sp + self.subheader_bytes - size
                 for start, size in spans), 'SRT subsection bounds')
        positive_spans = sorted((start, start + size) for start, size in spans if size)
        need(all(a[1] <= b[0] for a, b in zip(positive_spans, positive_spans[1:])),
             'SRT subsections overlap')
        self.pages, page_offsets = {}, []
        for page in range(1, self.max_page + 1):
            relative = struct.unpack_from('<i', data, self.page_index + (page - 1) * 4)[0]
            need(relative == -1 or (relative >= 0 and relative % (256 * 5) == 0 and
                                   relative + 256 * 5 <= page_bytes), 'SRT page pointer bounds')
            self.pages[page] = relative
            if relative != -1:
                page_offsets.append(relative)
        need(len(page_offsets) == len(set(page_offsets)), 'SRT pages must not alias')
        need(len(page_offsets) == 255, 'Selected writer must materialize all missing BMP pages')
        maxima = [0, 0, 0]
        record_count = 0
        for start, size in [(self.cp, cp_bytes), (self.page_data, page_bytes)]:
            for position in range(start, start + size, 5):
                flags, primary, packed = struct.unpack_from('<BHH', data, position)
                secondary, tertiary = self.unpack(primary, packed)
                expansion = flags >> 4
                need(not expansion or 1 <= primary <= primary + expansion <= self.exp_count,
                     'SRT character expansion pointer bounds')
                for level, value in enumerate((primary, secondary, tertiary)):
                    maxima[level] = max(maxima[level], value)
                record_count += 1
        expansion_maxima = [0, 0, 0]
        for position in range(self.ep, self.ep + ep_bytes, 4):
            primary, packed = struct.unpack_from('<HH', data, position)
            secondary, tertiary = self.unpack(primary, packed)
            for level, value in enumerate((primary, secondary, tertiary)):
                expansion_maxima[level] = max(expansion_maxima[level], value)
        need(maxima[1] <= 255 and expansion_maxima[1] <= 255,
             'Producer secondary KEY uses byte units; larger stored values unsupported here')
        self.metadata = dict(raw_flags=hex(self.flags), char_record_bytes=5, expansion_record_bytes=4,
            primary_bits=16, secondary_bits=10, tertiary_bits=6,
            actual_char_records_checked=record_count, actual_expansion_records_checked=self.exp_count,
            materialized_page_count=len(page_offsets), char_maxima=maxima,
            expansion_maxima=expansion_maxima, all_SRT_section_and_pointer_bounds_checked=True)

    @staticmethod
    def unpack(primary, packed):
        secondary, tertiary = packed & 0x3ff, packed >> 10
        need(0 <= primary <= 0xffff and 0 <= secondary <= 0x3ff and 0 <= tertiary <= 0x3f,
             'Native 16/10/6 packed field ranges')
        return secondary, tertiary

    @lru_cache(maxsize=65536)
    def weights(self, ch):
        need(0 <= ch <= 0xffff, 'Stored SRT access uses one BMP code unit')
        if ch == 0:
            return ()
        if ch < 256:
            pos = self.cp + (ch - 1) * 5
        else:
            relative = self.pages[ch >> 8]
            if relative == -1:
                # Exact official host Sort missing-page fallback, not device policy.
                return (((ch + 10690) & 0xffff, 0, 0),)
            pos = self.page_data + relative + (ch & 255) * 5
        flags, primary, packed = struct.unpack_from('<BHH', self.data, pos)
        secondary, tertiary = self.unpack(primary, packed)
        expansion = flags >> 4
        if not expansion:
            return ((primary, secondary, tertiary),)
        need(primary > 0 and primary + expansion <= self.exp_count, 'Expansion bound')
        result = []
        for i in range(expansion + 1):
            primary_value, packed = struct.unpack_from('<HH', self.data, self.ep + (primary - 1 + i) * 4)
            secondary, tertiary = self.unpack(primary_value, packed)
            result.append((primary_value, secondary, tertiary))
        return tuple(result)

    @staticmethod
    def implicit_base(codepoint):
        if 0x4e00 <= codepoint <= 0x9fbb:
            return 0xfb40
        if 0x3400 <= codepoint <= 0x4dbf or 0x20000 <= codepoint <= 0x2a6d6:
            return 0xfb80
        return None

    @lru_cache(maxsize=300000)
    def key(self, name):
        weights = []
        for character in name:
            codepoint = ord(character)
            base = self.implicit_base(codepoint)
            if base is not None:
                # Selected Java producer shadow combines valid ExtB surrogates.
                # Use verified Han implicit units at all three strengths only.
                weights.extend(((base + (codepoint >> 15), 32, 2),
                                (0x8000 + (codepoint & 0x7fff), 32, 2)))
            else:
                # Other supplementary values retain the producer's original
                # per-UTF16-code-unit behavior. No broader native claim.
                for (unit,) in struct.iter_unpack('<H', character.encode('utf-16-le')):
                    weights.extend(self.weights(unit))
        return tuple(tuple(w[level] for w in weights if w[level]) for level in range(3))


class Labels:
    def __init__(self, image):
        self.image = image
        self.headers = {}
        for key in image.components:
            if not key.endswith('.LBL'):
                continue
            h = image.read(key, 0, 196)
            need(h[2:12] == b'GARMIN LBL' and h[30] == 10, 'Unicode LBL expected')
            need(struct.unpack_from('<3H', h, 170) == (65001, 19, 7053 | 0x8000), 'LBL sort metadata')
            start, size = struct.unpack_from('<2I', h, 21)
            need(start + size <= image.components[key]['bytes'], 'LBL section bound')
            places = {}
            for number, (kind, width) in enumerate([('country', 3), ('region', 5), ('city', 5)]):
                position = 31 + number * 14
                place_start, place_bytes, item = struct.unpack_from('<IIH', h, position)
                need(item == width and place_bytes % item == 0 and
                     place_start + place_bytes <= image.components[key]['bytes'],
                     'LBL ' + kind + ' record bounds/layout')
                places[kind] = dict(start=place_start, item_size=item, records=place_bytes // item)
            self.headers[int(key[:8])] = dict(key=key, start=start, bytes=size,
                                              multiplier=1 << h[29], places=places)

    @lru_cache(maxsize=65536)
    def place_record(self, tile, kind, index):
        h = self.headers[tile]
        section = h['places'][kind]
        need(1 <= index <= section['records'], 'LBL ' + kind + ' index bounds')
        return self.image.read(h['key'], section['start'] + (index - 1) * section['item_size'],
                               section['item_size'])

    @lru_cache(maxsize=65536)
    def city_region_country(self, tile, city_index):
        city = self.place_record(tile, 'city', city_index)
        region_country = uint(city, 3, 2)
        index = region_country & 0x3fff
        if region_country & 0x4000:
            region_name, country_index = '', index
        else:
            region = self.place_record(tile, 'region', index)
            country_index = uint(region, 0, 2)
            region_name = self.name(tile, uint(region, 2, 3))
        country = self.place_record(tile, 'country', country_index)
        country_name = self.name(tile, uint(country, 0, 3))
        return region_name, country_name

    @lru_cache(maxsize=300000)
    def name(self, tile, offset):
        h = self.headers[tile]
        relative = offset * h['multiplier']
        need(0 <= relative < h['bytes'], 'Label pointer bound')
        data = self.image.read(h['key'], h['start'] + relative, min(1024, h['bytes'] - relative))
        zero = data.find(b'\0')
        need(zero >= 0, 'Unterminated label within bounded1024bytes')
        return data[:zero].decode('utf-8')


def partial(name, offset):
    prefix = 1 if name and ord(name[0]) < 7 else 0
    sep = name.find('\x1e')
    if sep < 0:
        sep = name.find('\x1b')
    if sep > 0:
        prefix = sep + 1
    suffix = name.find('\x1f')
    if suffix < 0:
        suffix = name.find('\x1c')
    end = suffix if suffix > 0 else len(name)
    return name[prefix:end].encode('utf-8')[offset:].decode('utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--producer-controls', type=Path, required=True,
                        help='ROOT-selected frozen Java KEY/CMP TSV bound in final build manifest')
    args = parser.parse_args()
    out = BASE / 'candidate-mdr-query-proof-v2.json'
    need(not out.exists(), 'Do not rerun a completed source')
    manifest, image_path, manifest_bytes, finite_path, finite_sha = selected_build(args.producer_controls)
    expected_keys, expected_comparisons, producer_meta = producer_controls(args.producer_controls)
    before_stat = image_path.stat()
    need(before_stat.st_size == manifest['image_bytes'], 'Candidate size differs from ROOT terminal build')
    image = Image(image_path)
    mdr_names = [k for k in image.components if k.endswith('.MDR')]
    srt_names = [k for k in image.components if k.endswith('.SRT')]
    need(mdr_names == ['00007053.MDR'] and srt_names == ['00007053.SRT'], 'V2 product components')
    mdr_name = mdr_names[0]
    mdr = image.read(mdr_name)
    sec = sections(mdr)
    need(sec[1]['records'] == 36 and sec[1]['item_size'] == 4, 'MDR1 exact36 map records')
    maps = [uint(mdr, sec[1]['position'] + i * 4, 4) for i in range(sec[1]['records'])]
    need(set(maps) == set(range(70530001, 70530037)), 'Map identity list')
    map_size = pointer_size(len(maps))
    srt_name = srt_names[0]
    sort, labels = Sort(image.read(srt_name)), Labels(image)
    need(set(labels.headers) == set(maps), 'All36 actual LBL tiles match MDR1 map IDs')
    key_control_failures, comparator_control_failures = [], []
    for name, key in expected_keys.items():
        actual = sort.key(name)
        if actual != key:
            key_control_failures.append(dict(name=name, reader_levels=actual, Java_producer_levels=key))
    for (left, right, strength), sign in expected_comparisons.items():
        a, b = sort.key(left)[:strength + 1], sort.key(right)[:strength + 1]
        actual_sign = (a > b) - (a < b)
        if actual_sign != sign:
            comparator_control_failures.append(dict(left=left, right=right, strength=strength,
                                                   reader_sign=actual_sign, Java_producer_sign=sign))
    # Fail before indexing all street labels if selected actual SRT cannot
    # reconstruct the final Java producer controls. Preserve a small result.
    if key_control_failures or comparator_control_failures:
        failure = dict(checked_utc=datetime.now(timezone.utc).isoformat(), all_passed=False,
            scope='Actual v2 SRT vs final Java producer controls only; MDR query not yet attempted',
            candidate=manifest['image'], SRT_metadata=sort.metadata,
            key_control_failures=key_control_failures[:12],
            comparator_control_failures=comparator_control_failures[:12],
            native_all_levels_compatibility_verified=False, native_Garmin_address_caller_verified=False)
        with out.open('x') as stream:
            stream.write(json.dumps(failure, ensure_ascii=False, indent=2) + '\n')
        print(json.dumps(dict(all_passed=False, proof=str(out),
                              key_failures=len(key_control_failures),
                              comparator_failures=len(comparator_control_failures)), ensure_ascii=False), flush=True)
        raise SystemExit(1)
    need(all(sec[n]['bytes'] == 0 for n in [8, 12, 13, 14, 15, 17, 21, 23, 26, 27, 28]),
         'Expected official Unicode device omissions')
    need(sec[7]['magic'] == 0x62 and sec[7]['item_size'] == map_size + 5, 'MDR7 layout unsupported')
    need(all(sec[n]['magic'] == 0xe and sec[n]['item_size'] == map_size + 5 for n in [20, 22]),
         'Device MDR20/22 direct-label layout unsupported')

    def streets(number):
        s = sec[number]
        for i in range(s['records']):
            pos = s['position'] + i * s['item_size']
            map_index = uint(mdr, pos, map_size)
            need(1 <= map_index <= len(maps), 'Street map pointer bound')
            raw_label = uint(mdr, pos + map_size, 3)
            tile = maps[map_index - 1]
            name_offset = mdr[pos + map_size + 3]
            name = labels.name(tile, raw_label & 0x7fffff)
            p = partial(name, name_offset)
            yield dict(record=i + 1, tile=tile, map_index=map_index, label_offset=raw_label & 0x7fffff,
                name=name, partial=p, name_offset_bytes=name_offset,
                new_full_or_partial_name_flag=bool(raw_label & 0x800000),
                partial_flag=mdr[pos + map_size + 4])

    index7, target7, previous, mixed = {}, [], None, []
    order7_bad, flags7_bad = [], []
    for row in streets(7):
        pkey, fullkey = sort.key(row['partial']), sort.key(row['name'])
        key = (pkey[:2], fullkey, row['map_index'])
        if previous is not None and key < previous['key'] and len(order7_bad) < 12:
            order7_bad.append(dict(before=previous['row'], after=row))
        expected_partial = previous is None or pkey[:2] != previous['pkey'][:2]
        expected_full = previous is None or fullkey[:2] != previous['fullkey'][:2]
        if (row['partial_flag'] != int(expected_partial) or row['new_full_or_partial_name_flag'] !=
                (expected_partial or expected_full)) and len(flags7_bad) < 12:
            flags7_bad.append(row)
        key_id = (row['tile'], row['name'], row['name_offset_bytes'])
        need(key_id not in index7, 'Ambiguous MDR7 map/full-name/partial-byte key')
        index7[key_id] = row['record']
        if row['name'] in TARGETS:
            target7.append(row)
        if len(mixed) < 160 and re.search('[A-Za-z]', row['partial']) and re.search('[\u3400-\u9fff]', row['partial']):
            mixed.append(row)
        previous = dict(key=key, pkey=pkey, fullkey=fullkey, row=row)

    city_size = (sec[5]['magic'] & 3) + 1
    ptr20_size = pointer_size(sec[20]['records'])
    need(sec[5]['magic'] == 0x111 and sec[5]['item_size'] == map_size + city_size + 3 + ptr20_size,
         'MDR5 device city/label/20-pointer layout unsupported')
    cities, positive, city_order_bad, city_flags_bad, last_city_key = [], [], [], [], None
    last_city_triple = None
    city_identity_seen = set()
    for i in range(sec[5]['records']):
        pos = sec[5]['position'] + i * sec[5]['item_size']
        mi = uint(mdr, pos, map_size)
        need(1 <= mi <= len(maps), 'City map pointer bound')
        local_city = uint(mdr, pos + map_size, city_size)
        lab = uint(mdr, pos + map_size + city_size, 3)
        pointer = uint(mdr, pos + map_size + city_size + 3, ptr20_size)
        need(0 <= pointer <= sec[20]['records'], 'City MDR20 pointer bound')
        name = labels.name(maps[mi - 1], lab & 0x7fffff)
        region, country_name = labels.city_region_country(maps[mi - 1], local_city)
        triple = (sort.key(name), sort.key(region), sort.key(country_name))
        key = (triple, mi)
        if last_city_key is not None and key < last_city_key:
            if len(city_order_bad) < 12:
                city_order_bad.append(i + 1)
        expected_new = triple != last_city_triple
        if bool(lab & 0x800000) != expected_new and len(city_flags_bad) < 12:
            city_flags_bad.append(i + 1)
        need((triple, mi) not in city_identity_seen,
             'MDR5 producer city/region/country/map deduplication')
        city_identity_seen.add((triple, mi))
        last_city_key = key
        last_city_triple = triple
        row = dict(record=i + 1, map_index=mi, tile=maps[mi - 1], local_city_index=local_city,
            label_offset=lab & 0x7fffff, city=name, mdr20_first_record=pointer,
            region=region, country=country_name,
            new_city_region_country_flag=bool(lab & 0x800000))
        cities.append(row)
        if pointer:
            positive.append(pointer)
    need(positive == sorted(positive), 'City MDR20 pointers not monotonic')
    starts = sorted(set(positive))
    need(starts and starts[0] == 1, 'City street groups must start at1')
    target_cities = [r for r in cities if r['city'] in ['臺中市', '台中市']]
    wanted_starts = {r['mdr20_first_record'] for r in target_cities if r['mdr20_first_record']}
    pointer_names = {}
    for row in cities:
        if row['mdr20_first_record']:
            pointer_names.setdefault(row['mdr20_first_record'], set()).add(row['city'])
    target20, target22, misses, order20_bad, order22_bad = [], [], [], [], []
    selected_city_group_count = 0
    previous_id, previous_group = 0, None
    for row in streets(20):
        group = starts[bisect.bisect_right(starts, row['record']) - 1]
        street_id = index7.get((row['tile'], row['name'], row['name_offset_bytes']))
        if street_id is None:
            if len(misses) < 12:
                misses.append(row)
        elif group == previous_group and street_id < previous_id and len(order20_bad) < 12:
            order20_bad.append(row)
        previous_id, previous_group = street_id or 0, group
        if group in wanted_starts:
            selected_city_group_count += 1
            if row['name'] in TARGETS:
                row.update(mdr7_record=street_id, city_group_first_record=group,
                           city_group_names=sorted(pointer_names[group]))
                target20.append(row)
    previous_id = 0
    for row in streets(22):
        street_id = index7.get((row['tile'], row['name'], row['name_offset_bytes']))
        if street_id is None:
            if len(misses) < 12:
                misses.append(row)
        elif street_id < previous_id and len(order22_bad) < 12:
            order22_bad.append(row)
        previous_id = street_id or 0
        if row['name'] in TARGETS:
            row['mdr7_record'] = street_id
            target22.append(row)

    cities25 = [uint(mdr, sec[25]['position'] + i * sec[25]['item_size'], sec[25]['item_size'])
                for i in range(sec[25]['records'])]
    need(all(1 <= city <= len(cities) for city in cities25), 'MDR25 city pointer bound')
    need(cities25 == sorted(cities25), 'Single-country MDR25 city order')
    size24, size22, size25 = [pointer_size(sec[n]['records']) for n in [24, 22, 5]]
    need(sec[29]['records'] == 1 and sec[29]['magic'] == 6 and
         sec[29]['item_size'] == size24 + size22 + size25, 'MDR29 exact Unicode layout')
    pos = sec[29]['position']
    country = dict(mdr24_first=uint(mdr, pos, size24),
        mdr22_first=uint(mdr, pos + size24, size22),
        mdr25_first=uint(mdr, pos + size24 + size22, size25),
        fast_prefix_key_saved=False, mdr17_pointer_saved=False)
    need(all(country[k] == 1 for k in ['mdr24_first', 'mdr22_first', 'mdr25_first']), 'MDR29 starts')
    names24 = []
    for i in range(sec[24]['records']):
        pos = sec[24]['position'] + i * sec[24]['item_size']
        mi = uint(mdr, pos, map_size)
        need(1 <= mi <= len(maps), 'MDR24 map pointer')
        names24.append(labels.name(maps[mi - 1], uint(mdr, pos + map_size + 2, 3) & 0x7fffff))
    need(len(set(names24)) == 1, 'Single-country assumption must be explicit')
    country['country_name'] = names24[0]
    after_stat = image_path.stat()
    need((before_stat.st_ino, before_stat.st_size, before_stat.st_mtime_ns, before_stat.st_ctime_ns) ==
         (after_stat.st_ino, after_stat.st_size, after_stat.st_mtime_ns, after_stat.st_ctime_ns), 'Candidate changed')
    need(BUILD.read_bytes() == manifest_bytes, 'ROOT final build manifest changed during finite read')
    need(small_digest(args.producer_controls) == manifest['producer_controls_sha256'] and
         small_digest(finite_path) == finite_sha, 'Frozen producer inputs changed during read')
    reachability = {name:dict(mdr7_count=sum(r['name'] == name for r in target7),
        Taichung_mdr20_count=sum(r['name'] == name for r in target20),
        country_mdr22_count=sum(r['name'] == name for r in target22)) for name in TARGETS}
    checks = dict(final_ROOT_build_and_finite_validation_binding=True,
        actual_SRT_nativepacked_section_and_pointer_bounds=True,
        actual_SRT_matches_finite_Java_producer_keys=True,
        actual_SRT_matches_finite_Java_producer_comparator_signs=True,
        MDR_header_and_all30_section_bounds=True, city_label_and20_pointer_bounds=True,
        street_label_and_map_bounds=True, all20_and22_names_join_exact_MDR7_records=not misses,
        MDR7_producer_shadow_secondary_partial_full_map_order=not order7_bad,
        MDR7_repeat_flags_match_producer_shadow_secondary_collator=not flags7_bad,
        MDR5_producer_shadow_city_region_country_map_order=not city_order_bad,
        MDR5_repeat_flags_match_producer_city_region_country_keys=not city_flags_bad,
        MDR5_local_LBL_city_region_country_pointer_bounds=True,
        MDR5_city_region_country_map_deduplication=True, MDR5_positive20_pointers_monotonic=True,
        MDR20_each_city_group_MDR7_order=not order20_bad, MDR22_single_country_MDR7_order=not order22_bad,
        MDR25_city_pointer_bounds_and_monotonic=True, MDR29_exact_three_pointer_layout=True,
        all3_names_reachable_under_Taichung_city=all(v['Taichung_mdr20_count'] > 0 for v in reachability.values()))
    result = dict(checked_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()), checks=checks,
        scope='New finite exact-r4924 v2 MDR records, actual packed SRT and final Java producer-shadow order/flags/joins only. No native function, Garmin UI, NET/RGN geometry or route execution.',
        candidate=dict(path=manifest['image'], bytes=manifest['image_bytes'], ROOT_terminal_build_sha256=manifest['image_sha256'],
            whole_IMG_hash_repeated=False, bytes_or_metadata_changed=False,
            compatibility_status='producer_order_checked_native_address_caller_and_physical_search_unverified'),
        build_manifest=dict(path=str(BUILD.relative_to(ROOT)), sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            state=manifest['state'], family_id=manifest['family_id'], map_id_start=manifest['map_id_start'],
            tile_count=manifest['tile_count'], sort_id1=manifest['sort_id1'], sort_id2=manifest['sort_id2'],
            code_page=manifest['code_page'], finished_utc=manifest['finished_utc']),
        finite_producer_controls=dict(path=str(args.producer_controls.resolve().relative_to(ROOT)),
            sha256=manifest['producer_controls_sha256'], Java_KEY_labels_checked=len(expected_keys),
            Java_CMP_level_comparisons_checked=len(expected_comparisons), producer_meta=producer_meta,
            original_native_probe_rerun=False, root_finite_validation_path=str(finite_path.relative_to(ROOT)),
            root_finite_validation_sha256=finite_sha, root_finite_validation_pass_inherited=True,
            native_sort_source=manifest['native_sort_source'],
            native_sort_source_sha256=manifest['native_sort_source_sha256']),
        SRT_component=srt_name, SRT_metadata=sort.metadata,
        producer_weight_policy=dict(verified_Han_ranges_inclusive=[['0x4e00', '0x9fbb'],
                ['0x3400', '0x4dbf'], ['0x20000', '0x2a6d6']],
            Han_primary='base+(codepoint>>15),0x8000+(codepoint&0x7fff)',
            Han_secondary=[32, 32], Han_tertiary=[2, 2], supplementary_Han_is_one_codepoint=True,
            other_values='Actual nativepacked SRT stored weights/expansions; original producer UTF16 code-unit policy retained'),
        MDR_component=mdr_name, MDR_component_bytes=len(mdr), sections=sec, country=country,
        Taichung_city_records=target_cities, Taichung_city_group_street_records=selected_city_group_count,
        target_reachability=reachability, target_MDR7_records=target7, target_Taichung_MDR20_records=target20,
        target_country_MDR22_records=target22,
        target_producer_shadow_keys={name:sort.key(name) for name in ['臺中市', '台中市'] + TARGETS},
        bounded_mixed_Latin_Han_MDR7_samples=mixed,
        exceptions=dict(MDR7_order=order7_bad, MDR7_flags=flags7_bad,
            MDR5_city_region_country_map_order=city_order_bad, MDR5_repeat_flags=city_flags_bad,
            MDR20_order=order20_bad, MDR22_order=order22_bad, unresolved_street_joins=misses),
        source_sha256=small_digest(Path(__file__)),
        reused_official_source_receipts=['staging/navigation-mdr-query-v1/official-source-receipt-v2.json',
                                       'staging/navigation-mdr-query-v1/official-prefix-source-receipt-v3.json'],
        inherited_v1_layout_source=dict(path='staging/navigation-mdr-query-v1/query_candidate_mdr_v1.py',
            sha256='38d879f8f668b097294c98c75d834b7225a30c9c711a7a4a99641a9fc2635b4b', rerun=False, edited=False),
        image_logical_read_bytes_by_extension=dict(image.read_bytes), full_MDR_table_serialized=False,
        candidate_installation_or_device_search_verified=False, native_Garmin_address_caller_verified=False,
        native_all_levels_compatibility_verified=False, native_probe_executed_by_this_reader=False,
        full_instruction_semantics_or_UI_success_verified=False,
        key_byte_difference_alone_proves_incompatibility=False,
        limitations=['MDR21 is omitted by official device output; no region fast table is invented.',
            'MDR29 magic0x6 stores country pointers, not host SortKey first bytes; Unicode MDR17/8/12 are empty.',
            'Producer-shadow agreement with actual MDR is distinct from Garmin address UI comparison/key policy; UI/caller remains unverified.',
            'Finite ROOT native unit/comparator proof is inherited as producer build dependency; this source executes no original instructions.',
            'Non-Han absent-page/general supplementary behavior outside the selected producer controls has no broad native compatibility claim.',
            'MDR5 region/country pointers and producer key grouping are checked through actual LBL place records; point-referenced city geometry is not replayed.',
            'Target records are index names per map, not physical road segments, source ways or address/house-number counts.',
            'No USB, device installation, canonical changes, old suite rerun, full IMG or backup hash.'])
    with out.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=result['all_passed'], checks=checks, target_reachability=reachability,
        proof=str(out), target_city_records=len(target_cities), Taichung_group_records=selected_city_group_count),
        ensure_ascii=False), flush=True)
    if not result['all_passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
