#!/usr/bin/env python3
"""Read-only structure checks for this project's unlocked mkgmap IMG output.

Layout references: mkgmap ImgHeader, Directory, Dirent and LBLHeader classes.
This verifies allocation and component headers, not navigation correctness.
"""
import argparse
from collections import Counter, defaultdict
import datetime as dt
import hashlib
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / 'staging/maps/Taiwan_OSM_20261001_UTF8/manifest.json'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(manifest_path=DEFAULT):
    manifest_path = Path(manifest_path)
    manifest = json.loads(manifest_path.read_text())
    image = Path(manifest['image'])
    data = image.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    require(len(data) == manifest['image_bytes'], 'Image size differs from manifest')
    require(digest == manifest['image_sha256'], 'Image SHA-256 differs from manifest')
    require(data[0] == 0, 'Only unencrypted, non-XOR mkgmap output is supported')
    require(data[0x10:0x17] == b'DSKIMG\0', 'Missing DSKIMG signature')
    require(data[0x41:0x48] == b'GARMIN\0', 'Missing GARMIN signature')
    require(data[0x1fe:0x200] == b'\x55\xaa', 'Missing header end marker')
    global_description = data[0x49:0x5d] + data[0x65:0x83]
    global_encoding = manifest.get('global_description_encoding', 'ascii')
    global_description = global_description.rstrip(b' ').decode(global_encoding)
    if manifest.get('global_description'):
        require(global_description == manifest['global_description'],
                'Global description differs from manifest')
    exponent = data[0x61] + data[0x62]
    require(9 <= exponent <= 16, 'Unexpected allocation block size')
    block_size = 1 << exponent
    require(len(data) % block_size == 0, 'Partial allocation block at EOF')
    block_count = len(data) // block_size
    first = data[0x40] * 512
    root = data[first:first + 512]
    require(len(root) == 512 and root[0] == 1 and root[0x10] == 3,
            'Missing directory metadata entry')
    directory_end = struct.unpack_from('<I', root, 0x0c)[0]
    require(first + 512 <= directory_end <= len(data), 'Directory extent outside image')
    require(directory_end % 512 == 0, 'Unaligned directory extent')
    records = {}
    directory_blocks = set()
    current = None
    expected_part = 0
    entries = 0
    for offset in range(first, directory_end, 512):
        entry = data[offset:offset + 512]
        if entry[0] == 0:
            continue
        require(entry[0] == 1, 'Unknown directory entry marker')
        name = entry[1:9].decode('ascii').rstrip()
        ext = entry[9:12].decode('ascii').rstrip()
        size = struct.unpack_from('<I', entry, 0x0c)[0]
        part = struct.unpack_from('<H', entry, 0x11)[0]
        table = struct.unpack_from('<240H', entry, 0x20)
        blocks = []
        padding_started = False
        for block in table:
            if block == 0xffff:
                padding_started = True
            else:
                require(not padding_started, 'Data block follows allocation padding')
                require(block < block_count, 'Allocated block outside image')
                blocks.append(block)
        if entry[0x10] == 3:
            require(name == '' and ext == '', 'Unexpected metadata filename')
            directory_blocks.update(blocks)
            current = None
            continue
        key = f'{name}.{ext}'
        if part == 0:
            require(key not in records, f'Duplicate file {key}')
            require(size > 0 and blocks, f'Empty file {key}')
            records[key] = {'name': name, 'extension': ext, 'bytes': size,
                            'blocks': [], 'parts': 0}
            current = key
            expected_part = 0
        require(current == key and part == expected_part,
                f'Unordered continuation for {key}')
        require(part == 0 or size == 0, f'Unexpected continuation size for {key}')
        records[key]['blocks'].extend(blocks)
        records[key]['parts'] += 1
        expected_part += 1
        entries += 1
    required_metadata = set(range((directory_end + block_size - 1) // block_size))
    require(directory_blocks == required_metadata, 'Directory allocation differs from extent')
    owner = {block: '<directory>' for block in directory_blocks}
    types = Counter()
    tiles = defaultdict(set)
    code_pages = set()
    samples = {text: False for text in ('臺北', '中山路', '臺灣')}
    summaries = []
    product_names = []
    series_names = set()
    map_descriptions = set()
    for key, item in records.items():
        blocks = item['blocks']
        require(len(blocks) == (item['bytes'] + block_size - 1) // block_size,
                f'Allocation length does not match size for {key}')
        for block in blocks:
            require(block not in owner, f'Overlapping allocation for {key}')
            owner[block] = key
        content = b''.join(data[b * block_size:(b + 1) * block_size]
                           for b in blocks)[:item['bytes']]
        ext = item['extension']
        types[ext] += 1
        if ext == 'MPS':
            position = 0
            while position < len(content):
                require(position + 3 <= len(content), 'Truncated MPS record header')
                kind = content[position]
                length = struct.unpack_from('<H', content, position + 1)[0]
                body = content[position + 3:position + 3 + length]
                require(len(body) == length, 'Truncated MPS record body')
                if kind == 0x46:
                    require(len(body) >= 5, 'Truncated MPS product record')
                    product_names.append(body[4:].split(b'\0', 1)[0].decode('utf-8'))
                elif kind == 0x4c:
                    require(len(body) >= 9, 'Truncated MPS map record')
                    strings = body[8:].split(b'\0', 2)
                    require(len(strings) == 3, 'Truncated MPS map-name strings')
                    series_names.add(strings[0].decode('utf-8'))
                    map_descriptions.add(strings[1].decode('utf-8'))
                position += 3 + length
        if ext != 'MPS':
            header_len = struct.unpack_from('<H', content)[0]
            require(21 <= header_len <= len(content), f'Invalid header length for {key}')
            require(content[2:12] == ('GARMIN ' + ext).encode(),
                    f'Component signature mismatch for {key}')
            require(content[13] == 0, f'Unexpected locked component {key}')
        if ext in ('TRE', 'RGN', 'LBL', 'NET', 'NOD'):
            tiles[item['name']].add(ext)
        if ext == 'LBL':
            require(header_len >= 196, f'Unexpected LBL layout for {key}')
            code_page = struct.unpack_from('<H', content, 0xaa)[0]
            require(code_page == 65001, f'Unexpected code page for {key}')
            require(content[0x1e] == 10, f'Unexpected label encoding for {key}')
            code_pages.add(code_page)
            label_start, label_size = struct.unpack_from('<II', content, 21)
            require(header_len <= label_start <= len(content), f'Bad label start for {key}')
            require(label_start + label_size <= len(content), f'Bad label extent for {key}')
            labels = content[label_start:label_start + label_size]
            for text in samples:
                samples[text] |= text.encode('utf-8') in labels
        summary = {k: item[k] for k in ('name', 'extension', 'bytes', 'parts')}
        summary['sha256'] = hashlib.sha256(content).hexdigest()
        summaries.append(summary)
    expected_tiles = {str(manifest['map_id_start'] + i) for i in range(manifest['tile_count'])}
    require(set(tiles) == expected_tiles, 'Tile identifiers differ from build manifest')
    require(all(parts == {'TRE', 'RGN', 'LBL', 'NET', 'NOD'} for parts in tiles.values()),
            'A tile is missing a display, label or routing component')
    require(types['MDR'] == types['SRT'] == types['MPS'] == 1,
            'Missing global search index, sort table or mapset metadata')
    require(all(samples.values()), 'Expected Chinese label samples were not found')
    if manifest.get('credit_text'):
        require(any(manifest['credit_text'] in name for name in product_names),
                'User credit is missing from map product name')
        require(all(manifest['credit_text'] in name for name in series_names),
                'User credit is missing from map series name')
    if manifest.get('map_description'):
        require(map_descriptions == {manifest['map_description']},
                'Map descriptions differ from manifest')
    return {'checked_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'state': 'structural_checks_passed', 'image': str(image),
            'bytes': len(data), 'sha256': digest, 'block_size': block_size,
            'directory_entries': entries, 'component_counts': dict(types),
            'tile_count': len(tiles), 'label_code_pages': sorted(code_pages),
            'chinese_label_samples': samples, 'allocation_overlap': False,
            'product_names': product_names, 'series_names': sorted(series_names),
            'map_descriptions': sorted(map_descriptions),
            'global_description': global_description,
            'global_description_encoding': global_encoding,
            'device_display_verified': False, 'device_search_verified': False,
            'device_routing_verified': False,
            'scope': 'Generated IMG allocation, signatures, routing components, index and UTF-8 labels; no route correctness or device compatibility assertion',
            'files': summaries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DEFAULT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = verify(args.manifest)
    if args.output:
        args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'files'}, ensure_ascii=False))


if __name__ == '__main__':
    main()
