#!/usr/bin/env python3
"""Prepare a display-name encoding experiment on our generated map only.

mkgmap forces the global IMG description to ASCII. The navigator ignored the
Unicode MPS credit in the previous test. Change only the two description spans;
device rendering of UTF-8 or Big5 in this field remains an experiment.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import shutil
import struct

import verify_garmin_map

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'staging/maps/Taiwan_OSM_20261001_ZhuYuan/manifest.json'
TITLE = '修改者:竺原 | OSM Taiwan 2026-10-01'
SPANS = ((0x49, 0x5d), (0x65, 0x83))


def patch_map_descriptions(data):
    block_size = 1 << (data[0x61] + data[0x62])
    first = data[0x40] * 512
    directory_end = struct.unpack_from('<I', data, first + 12)[0]
    for entry in range(first, directory_end, 512):
        if data[entry] != 1 or data[entry + 1:entry + 12] != b'MAKEGMAPMPS':
            continue
        if struct.unpack_from('<H', data, entry + 0x11)[0] != 0:
            continue
        size = struct.unpack_from('<I', data, entry + 12)[0]
        blocks = [n for n in struct.unpack_from('<240H', data, entry + 32) if n != 0xffff]
        if len(blocks) != 1:
            raise RuntimeError('This metadata patch expects a single MPS allocation block')
        offset = blocks[0] * block_size
        content = bytes(data[offset:offset + size])
        records = []
        position = 0
        changed_maps = 0
        while position < len(content):
            kind = content[position]
            length = struct.unpack_from('<H', content, position + 1)[0]
            body = content[position + 3:position + 3 + length]
            if len(body) != length:
                raise RuntimeError('Truncated MPS metadata record')
            if kind == 0x4c:
                series_end = body.index(b'\0', 8)
                description_end = body.index(b'\0', series_end + 1)
                body = (body[:series_end + 1] + TITLE.encode('utf-8') + b'\0'
                        + body[description_end + 1:])
                changed_maps += 1
            records.append(bytes([kind]) + struct.pack('<H', len(body)) + body)
            position += 3 + length
        payload = b''.join(records)
        if len(payload) > block_size or changed_maps != 36:
            raise RuntimeError('Unexpected map count or metadata exceeds its existing allocation')
        data[offset:offset + block_size] = payload.ljust(block_size, b'\0')
        struct.pack_into('<I', data, entry + 12, len(payload))
        return {'map_description_records_updated': changed_maps,
                'mps_original_bytes': size, 'mps_new_bytes': len(payload),
                'mps_allocation_unchanged': True}
    raise RuntimeError('Mapset metadata file was not found')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--encoding', choices=('utf-8', 'big5'), default='utf-8')
    args = parser.parse_args()
    original = json.loads(BASE.read_text())
    before = verify_garmin_map.verify(BASE)
    data = bytearray(Path(original['image']).read_bytes())
    text = TITLE.encode(args.encoding)
    if len(text) > 50:
        raise RuntimeError('Encoded description exceeds 50 bytes')
    allowed_offsets = set()
    padded = text.ljust(50, b' ')
    position = 0
    for start, end in SPANS:
        data[start:end] = padded[position:position + end - start]
        allowed_offsets.update(range(start, end))
        position += end - start
    source = Path(original['image']).read_bytes()
    changes = [i for i in range(512) if source[i] != data[i]]
    if not set(changes) <= allowed_offsets or source[512:] != data[512:]:
        raise RuntimeError('Change escaped the global description spans')
    mps_changes = patch_map_descriptions(data)
    output = ROOT / ('staging/maps/Taiwan_OSM_20261001_Display_' + args.encoding.replace('-', '') + '_HeaderAndMPS')
    output.mkdir()
    image = output / 'Taiwan_OSM_20261001.img'
    image.write_bytes(data)
    for name in ('copyright.txt', 'license.txt'):
        shutil.copyfile(BASE.parent / name, output / name)
    manifest = dict(original)
    manifest.update(image=str(image), output=str(output), image_bytes=len(data),
                    image_sha256=hashlib.sha256(data).hexdigest(),
                    base_manifest=str(BASE), device_installed=False,
                    state='header_description_experiment_pending_device_test',
                    global_description=TITLE, global_description_encoding=args.encoding,
                    map_description=TITLE,
                    header_unicode_rendering_verified=False,
                    route_and_label_components_identical=True, changed_header_bytes=len(changes),
                    prepared_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                    preparation_method='Patch only global IMG description spans and MPS map-description strings; compiler normally forces global description to ASCII',
                    metadata_changes=mps_changes)
    manifest_path = output / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    checked = verify_garmin_map.verify(manifest_path)
    immutable = lambda result: [f for f in result['files'] if f['extension'] != 'MPS']
    if immutable(before) != immutable(checked):
        raise RuntimeError('A display, routing or search component changed')
    checked.update(all_non_mps_components_identical_to_signed_base=True,
                   header_description_device_rendering_verified=False)
    check_path = output / 'structural-verification.json'
    check_path.write_text(json.dumps(checked, ensure_ascii=False, indent=2) + '\n')
    manifest['structural_evidence'] = str(check_path)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: manifest[k] for k in ('image', 'image_sha256',
        'global_description', 'global_description_encoding', 'changed_header_bytes',
        'route_and_label_components_identical', 'metadata_changes')}, ensure_ascii=False))


if __name__ == '__main__':
    main()
