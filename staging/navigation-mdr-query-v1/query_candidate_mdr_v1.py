#!/usr/bin/env python3
"""Finite exact-r4924 MDR host query, never a Garmin UI implementation.

Only in-memory MDR/SRT and referenced LBL labels are read. No image copy,
whole-image digest, NET/RGN replay, huge table JSON, device or canonical writes.
"""
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
PACKAGE = ROOT / 'staging/navigation-repair-v1/package-result.json'
TARGETS = ['民權路', '民和路一段', '民和路二段']


def need(condition, message):
    if not condition:
        raise ValueError(message)


def uint(data, offset, width):
    need(0 <= offset <= len(data) - width and 1 <= width <= 4, 'Integer outside component')
    return int.from_bytes(data[offset:offset + width], 'little')


def pointer_size(count):
    return max(1, (count.bit_length() + 7) // 8)


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
    need(struct.unpack_from('<4H', data, 21) == (65001, 19, 7052, 14), 'MDR sort metadata')
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
        h2 = uint(data, 23, 4)
        self.sp = uint(data, h2 + 8, 4)
        sp = self.sp
        need(struct.unpack_from('<3H', data, sp + 2) == (19, 7052, 65001), 'SRT metadata')
        self.cp = sp + uint(data, sp + 12, 4)
        self.ep = sp + uint(data, sp + 28, 4)
        self.exp_count = uint(data, sp + 32, 4) // 4
        self.page_index = sp + uint(data, sp + 60, 4)
        self.page_data = sp + uint(data, sp + 76, 4)

    @lru_cache(maxsize=65536)
    def weights(self, ch):
        if ch == 0:
            return ()
        if ch < 256:
            pos = self.cp + (ch - 1) * 5
        else:
            relative = struct.unpack_from('<i', self.data, self.page_index + ((ch >> 8) - 1) * 4)[0]
            if relative == -1:
                # Exact official host Sort missing-page fallback, not device policy.
                return (((ch + 10690) & 0xffff, 0, 0),)
            pos = self.page_data + relative + (ch & 255) * 5
        flags, primary, secondary, tertiary = struct.unpack_from('<BHBB', self.data, pos)
        expansion = flags >> 4
        if not expansion:
            return ((primary, secondary, tertiary),)
        need(primary > 0 and primary + expansion <= self.exp_count, 'Expansion bound')
        return tuple(struct.unpack_from('<HBB', self.data, self.ep + (primary - 1 + i) * 4)
                     for i in range(expansion + 1))

    @lru_cache(maxsize=300000)
    def key(self, name):
        utf16 = name.encode('utf-16-le')
        weights = [w for (ch,) in struct.iter_unpack('<H', utf16) for w in self.weights(ch)]
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
            need(struct.unpack_from('<3H', h, 170) == (65001, 19, 7052 | 0x8000), 'LBL sort metadata')
            start, size = struct.unpack_from('<2I', h, 21)
            need(start + size <= image.components[key]['bytes'], 'LBL section bound')
            self.headers[int(key[:8])] = dict(key=key, start=start, bytes=size, multiplier=1 << h[29])

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
    out = BASE / 'candidate-mdr-query-proof-v1.json'
    need(not out.exists(), 'Do not rerun a completed source')
    package = json.loads(PACKAGE.read_text())
    image_path = ROOT / package['map_path']
    before_stat = image_path.stat()
    need(before_stat.st_size == package['map_bytes'], 'Candidate size differs from ROOT sealed package')
    image = Image(image_path)
    mdr_name = next(k for k in image.components if k.endswith('.MDR'))
    mdr = image.read(mdr_name)
    sec = sections(mdr)
    maps = [uint(mdr, sec[1]['position'] + i * 4, 4) for i in range(sec[1]['records'])]
    need(set(maps) == set(range(70520001, 70520037)), 'Map identity list')
    map_size = pointer_size(len(maps))
    srt_name = next(k for k in image.components if k.endswith('.SRT'))
    sort, labels = Sort(image.read(srt_name)), Labels(image)
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
    cities, positive, city_order_bad, last_city_key = [], [], [], None
    for i in range(sec[5]['records']):
        pos = sec[5]['position'] + i * sec[5]['item_size']
        mi = uint(mdr, pos, map_size)
        need(1 <= mi <= len(maps), 'City map pointer bound')
        local_city = uint(mdr, pos + map_size, city_size)
        lab = uint(mdr, pos + map_size + city_size, 3)
        pointer = uint(mdr, pos + map_size + city_size + 3, ptr20_size)
        need(0 <= pointer <= sec[20]['records'], 'City MDR20 pointer bound')
        name = labels.name(maps[mi - 1], lab & 0x7fffff)
        key = sort.key(name)
        if last_city_key is not None and key < last_city_key:
            city_order_bad.append(i + 1)
        last_city_key = key
        row = dict(record=i + 1, map_index=mi, tile=maps[mi - 1], local_city_index=local_city,
            label_offset=lab & 0x7fffff, city=name, mdr20_first_record=pointer,
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
    reachability = {name:dict(mdr7_count=sum(r['name'] == name for r in target7),
        Taichung_mdr20_count=sum(r['name'] == name for r in target20),
        country_mdr22_count=sum(r['name'] == name for r in target22)) for name in TARGETS}
    checks = dict(MDR_header_and_all30_section_bounds=True, city_label_and20_pointer_bounds=True,
        street_label_and_map_bounds=True, all20_and22_names_join_exact_MDR7_records=not misses,
        MDR7_secondary_partial_full_map_order=not order7_bad,
        MDR7_repeat_flags_match_official_secondary_collator=not flags7_bad,
        MDR5_city_name_order=not city_order_bad, MDR5_positive20_pointers_monotonic=True,
        MDR20_each_city_group_MDR7_order=not order20_bad, MDR22_single_country_MDR7_order=not order22_bad,
        MDR25_city_pointer_bounds_and_monotonic=True, MDR29_exact_three_pointer_layout=True,
        all3_names_reachable_under_Taichung_city=all(v['Taichung_mdr20_count'] > 0 for v in reachability.values()))
    result = dict(checked_utc=datetime.now(timezone.utc).isoformat(), all_passed=all(checks.values()), checks=checks,
        scope='New finite exact-r4924 candidate MDR host record query only; no Garmin UI, native comparison implementation, NET/RGN geometry or route execution.',
        candidate=dict(path=package['map_path'], bytes=package['map_bytes'], ROOT_sealed_sha256=package['map_sha256'],
            whole_IMG_hash_repeated=False, bytes_or_metadata_changed=False, compatibility_status='held_pending_native_key_order_and_physical_search_clarification'),
        MDR_component=mdr_name, MDR_component_bytes=len(mdr), sections=sec, country=country,
        Taichung_city_records=target_cities, Taichung_city_group_street_records=selected_city_group_count,
        target_reachability=reachability, target_MDR7_records=target7, target_Taichung_MDR20_records=target20,
        target_country_MDR22_records=target22,
        target_host_keys={name:sort.key(name) for name in ['臺中市', '台中市'] + TARGETS},
        bounded_mixed_Latin_Han_MDR7_samples=mixed,
        exceptions=dict(MDR7_order=order7_bad, MDR7_flags=flags7_bad, MDR5_city_order=city_order_bad[:12],
            MDR20_order=order20_bad, MDR22_order=order22_bad, unresolved_street_joins=misses),
        source_receipt='staging/navigation-mdr-query-v1/official-source-receipt-v2.json',
        image_logical_read_bytes_by_extension=dict(image.read_bytes), full_MDR_table_serialized=False,
        candidate_installation_or_device_search_verified=False, native_Garmin_address_caller_verified=False,
        native_CJK_key_equivalence_verified=False, key_byte_difference_alone_proves_incompatibility=False,
        limitations=['MDR21 is omitted by official device output; no region fast table is invented.',
            'MDR29 magic0x6 stores country pointers, not host SortKey first bytes; Unicode MDR17/8/12 are empty.',
            'The reader uses official host Sort semantics and cannot prove Garmin address UI comparison/key policy.',
            'City-name monotonicity does not independently validate equal-name region/country secondary grouping.',
            'Target records are index names per map, not physical road segments, source ways or address/house-number counts.',
            'No USB, device installation, canonical changes, old suite rerun, full IMG or backup hash.'])
    with out.open('x') as stream:
        stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(all_passed=result['all_passed'], checks=checks, target_reachability=reachability,
        proof=str(out), target_city_records=len(target_cities), Taichung_group_records=selected_city_group_count),
        ensure_ascii=False), flush=True)


if __name__ == '__main__':
    main()
