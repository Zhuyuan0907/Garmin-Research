#!/usr/bin/env python3
"""Strict allocation and sort metadata checks for unlocked mkgmap IMG output.

This does NOT execute Garmin searches, check city/street associations, validate
routing correctness, or prove device compatibility. Exact metadata offsets are
from official mkgmap r4924 LBLHeader, MDRHeader, SRTHeader and Section sources.
"""
import argparse
from collections import Counter, defaultdict
import datetime as dt
import hashlib
import json
import mmap
from pathlib import Path
import struct
import sys

BASE = Path(__file__).resolve().parent


def need(condition, message):
    if not condition:
        raise ValueError(message)


def u16(data, offset):
    need(0 <= offset <= len(data) - 2, f'uint16 outside component at {offset}')
    return struct.unpack_from('<H', data, offset)[0]


def u32(data, offset):
    need(0 <= offset <= len(data) - 4, f'uint32 outside component at {offset}')
    return struct.unpack_from('<I', data, offset)[0]


def components(image):
    """Allocation algorithm follows scripts/verify_garmin_map.py, without its label fixtures."""
    with Path(image).open('rb') as stream:
        need(Path(image).stat().st_size >= 1024, 'Image too short')
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
            digest = hashlib.sha256(data).hexdigest()
            need(data[0] == 0, 'Only unlocked non-XOR mkgmap IMG is supported')
            need(data[0x10:0x17] == b'DSKIMG\0', 'DSKIMG signature missing')
            need(data[0x41:0x48] == b'GARMIN\0', 'GARMIN signature missing')
            need(data[0x1fe:0x200] == b'\x55\xaa', 'IMG end marker missing')
            exponent = data[0x61] + data[0x62]
            need(9 <= exponent <= 16, 'Unsupported allocation exponent')
            block_size = 1 << exponent
            need(len(data) % block_size == 0, 'Partial allocation block at EOF')
            block_count = len(data) // block_size
            first = data[0x40] * 512
            need(first + 512 <= len(data), 'Directory start outside IMG')
            root = data[first:first + 512]
            need(root[0] == 1 and root[0x10] == 3, 'Directory root metadata missing')
            end = u32(root, 0x0c)
            need(first + 512 <= end <= len(data) and end % 512 == 0, 'Bad directory extent')
            records = {}
            directory_blocks = set()
            current = None
            expected_part = 0
            entries = 0
            for offset in range(first, end, 512):
                entry = data[offset:offset + 512]
                if entry[0] == 0:
                    continue
                need(entry[0] == 1, f'Unexpected directory marker at {offset}')
                name = entry[1:9].decode('ascii').rstrip()
                ext = entry[9:12].decode('ascii').rstrip()
                size, part = u32(entry, 12), u16(entry, 0x11)
                blocks = []
                padding = False
                for block in struct.unpack_from('<240H', entry, 0x20):
                    if block == 0xffff:
                        padding = True
                    else:
                        need(not padding, 'Allocation after table padding')
                        need(block < block_count, 'Block outside IMG')
                        blocks.append(block)
                if entry[0x10] == 3:
                    need(name == ext == '', 'Unexpected directory metadata filename')
                    need(not directory_blocks.intersection(blocks), 'Repeated directory allocation')
                    directory_blocks.update(blocks)
                    current = None
                    continue
                key = f'{name}.{ext}'
                if part == 0:
                    need(key not in records, f'Duplicate component {key}')
                    need(size > 0 and blocks, f'Empty component {key}')
                    records[key] = {'name': name, 'extension': ext, 'bytes': size, 'blocks': [], 'parts': 0}
                    current, expected_part = key, 0
                need(current == key and part == expected_part, f'Unordered continuation of {key}')
                need(part == 0 or size == 0, f'Nonzero continuation size {key}')
                records[key]['blocks'].extend(blocks)
                records[key]['parts'] += 1
                expected_part += 1
                entries += 1
            need(directory_blocks == set(range((end + block_size - 1) // block_size)),
                 'Directory allocation differs from metadata extent')
            owners = {block: '<directory>' for block in directory_blocks}
            result = {}
            for key, item in records.items():
                need(len(item['blocks']) == (item['bytes'] + block_size - 1) // block_size,
                     f'Allocation count differs for {key}')
                for block in item['blocks']:
                    need(block not in owners, f'Overlapping allocation {key} with {owners.get(block)}')
                    owners[block] = key
                content = b''.join(data[b * block_size:(b + 1) * block_size]
                                   for b in item['blocks'])[:item['bytes']]
                if item['extension'] != 'MPS':
                    need(21 <= u16(content, 0) <= len(content), f'Bad component header {key}')
                    need(content[2:12] == ('GARMIN ' + item['extension']).encode('ascii'),
                         f'Component signature mismatch {key}')
                    need(content[13] == 0, f'Locked component {key}')
                result[key] = (item, content)
            return result, {'image_bytes': len(data), 'image_sha256': digest, 'block_size': block_size,
                            'directory_entries': entries, 'allocation_overlap': False,
                            'allocation_verified': True}


def srt_parse(data):
    need(data[2:12] == b'GARMIN SRT', 'Bad SRT signature')
    hl = u16(data, 0)
    need(hl in (29, 37), 'Unsupported SRT real header layout')
    h2 = u32(data, 23)
    need(u16(data, 27) == 16 and hl <= h2 <= len(data) - 16, 'Bad SRT header2')
    dp, ds, sp, ss = struct.unpack_from('<4I', data, h2)
    need(dp >= h2 + 16 and dp + ds <= len(data) and ds > 0, 'SRT description outside file')
    need(sp >= dp + ds and sp + ss <= len(data) and ss >= 92, 'SRT main section outside file')
    need(u16(data, sp) == 92, 'Expected Unicode multi-page SRT header3 length92')
    id1, id2, cp = struct.unpack_from('<3H', data, sp + 2)
    need(u32(data, sp + 8) == 0x6f02, 'Expected Unicode SRT flags')
    cp_pos, cp_bytes = u32(data, sp + 12), u32(data, sp + 16)
    exp_pos, exp_bytes = u32(data, sp + 28), u32(data, sp + 32)
    maxpage = u32(data, sp + 56)
    s7pos, s7bytes = u32(data, sp + 60), u32(data, sp + 64)
    s8pos, s8bytes = u32(data, sp + 76), u32(data, sp + 80)
    need(cp_bytes == 255 * 5 and u16(data, sp + 20) == 5, 'Bad SRT single-page table size')
    need(u16(data, sp + 36) == 4 and exp_bytes % 4 == 0, 'Bad SRT expansion table layout')
    need(maxpage == 255 and s7bytes == maxpage * 4 and u16(data, sp + 68) == 4,
         'Bad SRT page-pointer array')
    need(u16(data, sp + 84) == 5 and s8bytes % 1280 == 0, 'Bad SRT page data layout')
    sections = [(cp_pos, cp_bytes), (exp_pos, exp_bytes), (s7pos, s7bytes), (s8pos, s8bytes)]
    for pos, size in sections:
        need(pos >= 92 and pos + size <= ss, 'SRT nested section outside parent section')
    nonempty = sorted((p, p + n) for p, n in sections if n)
    need(all(a[1] <= b[0] for a, b in zip(nonempty, nonempty[1:])), 'SRT sections overlap')
    pages = {}
    seen_offsets = set()
    for page in range(1, 256):
        off = struct.unpack_from('<i', data, sp + s7pos + (page - 1) * 4)[0]
        if off == -1:
            pages[page] = None
            continue
        need(off >= 0 and off % 1280 == 0 and off + 1280 <= s8bytes,
             f'SRT page{page:02x} extent invalid')
        need(off not in seen_offsets, f'SRT page alias at {page:02x}')
        seen_offsets.add(off)
        pages[page] = off
    need(len(seen_offsets) * 1280 == s8bytes, 'Unreferenced SRT page data')

    def weight(ch):
        if ch == 0:
            return (0, 0, 0, 0)
        page = ch >> 8
        if page == 0:
            pos = sp + cp_pos + (ch - 1) * 5
        elif pages[page] is None:
            return None
        else:
            pos = sp + s8pos + pages[page] + (ch & 0xff) * 5
        return struct.unpack_from('<BHBB', data, pos)

    meta = {'bytes': len(data), 'code_page': cp, 'id1': id1, 'id2': id2,
            'description': data[dp:dp + ds].rstrip(b'\0').decode('ascii'),
            'max_page': maxpage, 'srt7_offset': s7pos, 'srt7_bytes': s7bytes,
            'srt8_offset': s8pos, 'srt8_bytes': s8bytes,
            'serialized_pages': sum(v is not None for v in pages.values())}
    return meta, pages, weight


def verify(args):
    comps, allocation = components(args.image)
    errors = []
    types = Counter(item['extension'] for item, _ in comps.values())
    tiles = defaultdict(set)
    lbls = []
    for key, (item, data) in comps.items():
        ext = item['extension']
        if ext in ('TRE', 'RGN', 'LBL', 'NET', 'NOD'):
            tiles[item['name']].add(ext)
        if ext == 'LBL':
            need(u16(data, 0) >= 196, f'LBL layout unsupported {key}')
            cp, id1, raw_id2 = struct.unpack_from('<3H', data, 0xaa)
            id2 = raw_id2 & 0x7fff
            labpos, labsz = struct.unpack_from('<2I', data, 21)
            need(u16(data, 0) <= labpos <= len(data) and labpos + labsz <= len(data),
                 f'LBL label table outside component {key}')
            need(data[0x1e] == 10, f'Unexpected LBL encoding {key}')
            rec = {'file': key, 'code_page': cp, 'id1': id1, 'id2': id2,
                   'raw_id2': raw_id2, 'id2_present_flag': bool(raw_id2 & 0x8000)}
            lbls.append(rec)
            if (cp, id1, id2) != (args.code_page, args.sort_id1, args.sort_id2):
                errors.append(f'{key}: LBL code page/sort IDs differ: {cp}/{id1}/{id2}')
            if id1 and id2 and not raw_id2 & 0x8000:
                errors.append(f'{key}: LBL sort ID2 present flag missing')
    if args.expected_tiles is not None and len(tiles) != args.expected_tiles:
        errors.append(f'Expected{args.expected_tiles} tiles, found{len(tiles)}')
    if args.map_id_start is not None:
        count = args.expected_tiles if args.expected_tiles is not None else len(tiles)
        if set(tiles) != {str(args.map_id_start + n) for n in range(count)}:
            errors.append('Tile IDs differ from requested consecutive IDs')
    if not tiles or len(lbls) != len(tiles):
        errors.append('One LBL per tile required')
    if not all(parts == {'TRE', 'RGN', 'LBL', 'NET', 'NOD'} for parts in tiles.values()):
        errors.append('Tile lacks complete TRE/RGN/LBL/NET/NOD set')
    if not (types['MDR'] == types['SRT'] == types['MPS'] == 1):
        errors.append('Expected exactly one MDR, SRT and MPS')

    mdrs, srts, products, mpsmaps = [], [], [], []
    for key, (item, data) in comps.items():
        if item['extension'] == 'MDR':
            need(u16(data, 0) >= 29, f'MDR header too short {key}')
            cp, id1, id2 = struct.unpack_from('<3H', data, 21)
            rec = {'file': key, 'code_page': cp, 'id1': id1, 'id2': id2}
            mdrs.append(rec)
            if (cp, id1, id2) != (args.code_page, args.sort_id1, args.sort_id2):
                errors.append(f'{key}: MDR code page/sort IDs differ: {cp}/{id1}/{id2}')
            if item['name'] != f'{args.family_id:08d}':
                errors.append(f'{key}: MDR filename differs from family ID')
        elif item['extension'] == 'SRT':
            sm, pages, weight = srt_parse(data)
            sm['file'] = key
            srts.append(sm)
            if (sm['code_page'], sm['id1'], sm['id2']) != (args.code_page, args.sort_id1, args.sort_id2):
                errors.append(f'{key}: SRT code page/sort IDs differ')
            if item['name'] != f'{args.family_id:08d}':
                errors.append(f'{key}: SRT filename differs from family ID')
            baseline_data = args.baseline_srt.read_bytes()
            bm, bp, bw = srt_parse(baseline_data)
            need(bm['code_page'] == 65001 and bm['id1'] == 19 and bm['id2'] == 4,
                 'Baseline is not original CP65001 sort19/4')
            max_primary = max(w[1] for ch in range(1, 65536) if (w := bw(ch)) is not None)
            need(max_primary == 10690, 'Unexpected baseline implicit primary bias')
            preserved, materialized, mismatches = 0, 0, []
            for ch in range(1, 65536):
                if 0xd800 <= ch < 0xe000:
                    continue
                original = bw(ch)
                expected = original if original is not None else (0, (ch + max_primary) & 0xffff, 0, 0)
                if weight(ch) != expected:
                    mismatches.append(f'U+{ch:04X}')
                if original is None:
                    materialized += 1
                else:
                    preserved += 1
            sm.update({'baseline_srt_sha256': hashlib.sha256(baseline_data).hexdigest(),
                       'implicit_primary_bias': max_primary, 'defined_weights_preserved_count': preserved,
                       'missing_page_weights_checked_count': materialized, 'weight_mismatch_count': len(mismatches),
                       'weight_mismatch_samples': mismatches[:20], 'weight_verification_passed': not mismatches,
                       'major_cjk_4e00_9fff_has_no_uint16_wrap': 0x9fff + max_primary <= 65535,
                       'all_originally_missing_non_surrogate_pages_present':
                           all(pages[p] is not None for p in range(1, 256)
                               if not 0xd8 <= p <= 0xdf and bp[p] is None)})
            sm['target_characters'] = [{'character': c, 'codepoint': f'U+{ord(c):04X}',
                                        'page_present': (pages.get(ord(c) >> 8) is not None) if 0 < ord(c) < 65536 else False,
                                        'weight': weight(ord(c)) if 0 < ord(c) < 65536 and not 0xd800 <= ord(c) < 0xe000 else None}
                                       for c in dict.fromkeys(args.target_chars)]
            if mismatches:
                errors.append(f'{key}: {len(mismatches)} baseline/materialized weight mismatches')
            for c in args.target_chars:
                if ord(c) == 0 or ord(c) > 65535 or 0xd800 <= ord(c) < 0xe000:
                    errors.append(f'Unsupported target character {c!r}')
                elif weight(ord(c)) is None or weight(ord(c))[1] == 0:
                    errors.append(f'{key}: target character {c} lacks nonzero primary')
        elif item['extension'] == 'MPS':
            pos = 0
            while pos < len(data):
                need(pos + 3 <= len(data), 'Truncated MPS record header')
                kind, size = data[pos], u16(data, pos + 1)
                body = data[pos + 3:pos + 3 + size]
                need(len(body) == size, 'Truncated MPS body')
                if kind in (0x46, 0x4c):
                    need(len(body) >= (4 if kind == 0x46 else 8), 'MPS product/map record too short')
                    product, family = struct.unpack_from('<2H', body)
                    rec = {'product_id': product, 'family_id': family}
                    if family != args.family_id:
                        errors.append(f'MPS family{family} differs from requested{args.family_id}')
                    if kind == 0x46:
                        products.append(rec)
                    else:
                        rec['map_number'] = u32(body, 4)
                        mpsmaps.append(rec)
                pos += 3 + size
    if len(products) != 1 or len(mpsmaps) != len(tiles):
        errors.append('MPS must describe one product and each tile')
    if {r['map_number'] for r in mpsmaps} != {int(n) for n in tiles}:
        errors.append('MPS tile IDs differ from allocated tiles')
    return {'checked_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'state': 'passed' if not errors else 'mismatch', 'all_passed': not errors,
            'image': str(args.image.resolve()), 'expected': {'family_id': args.family_id,
                 'code_page': args.code_page, 'sort_id1': args.sort_id1, 'sort_id2': args.sort_id2,
                 'expected_tiles': args.expected_tiles, 'map_id_start': args.map_id_start},
            'allocation': allocation, 'component_counts': dict(types), 'tile_count': len(tiles),
            'lbls': sorted(lbls, key=lambda r: r['file']), 'mdrs': mdrs, 'srts': srts,
            'products': products, 'mps_maps': mpsmaps, 'errors': errors,
            'exact_metadata_offsets': {'LBL': {'code_page': 170, 'sort_id1': 172, 'raw_sort_id2': 174},
                 'MDR': {'code_page': 21, 'sort_id1': 23, 'sort_id2': 25},
                 'SRT_header3': {'sort_id1': 2, 'sort_id2': 4, 'code_page': 6}},
            'device_search_verified': False, 'device_routing_verified': False,
            'device_compatibility_verified': False, 'city_street_association_verified': False,
            'all_bmp_characters_searchable': False,
            'scope': 'Unlocked IMG allocation, routing-component presence, exact LBL/MDR/SRT code-page and sort-ID consistency, original BMP weights and materialized missing-page weights; no Garmin execution or navigation correctness claim',
            'limitations': ['Original partial-page holes remain unchanged', 'Surrogate and supplementary characters unverified',
                 'Garmin use of SRT and missing-page policy unmeasured', 'Address lookup performance and exact physical results require device tests']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('image', type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--family-id', type=int, default=7052)
    p.add_argument('--code-page', type=int, default=65001)
    p.add_argument('--sort-id1', type=int, default=19)
    p.add_argument('--sort-id2', type=int, default=7052)
    p.add_argument('--expected-tiles', type=int)
    p.add_argument('--map-id-start', type=int)
    p.add_argument('--target-chars', default='民權和路臺台中市西區')
    p.add_argument('--baseline-srt', type=Path, default=BASE / 'installed-map.SRT')
    args = p.parse_args()
    try:
        result = verify(args)
    except (ValueError, OSError, UnicodeError, struct.error, IndexError) as exc:
        result = {'state': 'invalid_or_mismatch', 'all_passed': False, 'image': str(args.image),
                  'errors': [str(exc)], 'device_search_verified': False, 'device_routing_verified': False,
                  'device_compatibility_verified': False}
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.output:
        args.output.write_text(encoded)
    print(encoded, end='')
    return 0 if result['all_passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
